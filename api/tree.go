package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/contextwtf/lanyard/merkle"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
)

func (s *Server) TreeHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		s.CreateTree(w, r)
		return
	case http.MethodGet:
		s.GetTree(w, r)
		return
	default:
		http.Error(w, "unsupported method", http.StatusMethodNotAllowed)
		return
	}
}

func leaf2Addr(leaf []byte, ltd []string, packed bool) []byte {
	if len(ltd) == 0 || (len(ltd) == 1 && ltd[0] == "address" && len(leaf) == 20) {
		return leaf
	}
	if ltd[len(ltd)-1] == "address" && len(leaf) > 20 {
		return leaf[len(leaf)-20:]
	}

	if packed {
		return addrPacked(leaf, ltd)
	}
	return addrUnpacked(leaf, ltd)
}

func addrUnpacked(leaf []byte, ltd []string) []byte {
	var addrStart, pos int
	for _, desc := range ltd {
		if desc == "address" {
			addrStart = pos
			break
		}
		pos += 32
	}

	if len(leaf) >= addrStart+32 {
		l := leaf[addrStart:(addrStart + 32)]
		return l[len(l)-20:] // take last 20 bytes
	}
	return []byte{}
}

func addrPacked(leaf []byte, ltd []string) []byte {
	var addrStart, pos int
	for _, desc := range ltd {
		t, err := abi.NewType(desc, "", nil)
		if err != nil {
			return []byte{}
		} else if desc == "address" {
			addrStart = pos
			break
		}
		pos += int(t.GetType().Size())
	}
	if addrStart == 0 && pos != 0 {
		return []byte{}
	}
	if len(leaf) >= addrStart+20 {
		return leaf[addrStart:(addrStart + 20)]
	}
	return []byte{}
}

func hashProof(p [][]byte) []byte {
	return crypto.Keccak256(p...)
}

type createTreeReq struct {
	Leaves []string `json:"unhashedLeaves"`
	Ltd    []string `json:"leafTypeDescriptor"`
	Packed bool     `json:"packedEncoding"`
}

type createTreeResp struct {
	MerkleRoot string `json:"merkleRoot"`
}

func (s *Server) CreateTree(w http.ResponseWriter, r *http.Request) {
	var (
		req createTreeReq
		ctx = r.Context()
	)
	defer r.Body.Close()
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendJSONError(r, w, err, http.StatusBadRequest, "invalid request body")
		return
	}
	switch len(req.Leaves) {
	case 0:
		s.sendJSONError(r, w, nil, http.StatusBadRequest, "No leaves provided")
		return
	case 1:
		s.sendJSONError(r, w, nil, http.StatusBadRequest, "You must provide at least two values")
		return
	}

	var leaves [][]byte
	for _, l := range req.Leaves {
		// use the go-ethereum FromHex method because it is more
		// lenient and will allow for odd-length hex strings (by padding them)
		leaves = append(leaves, common.FromHex(l))
	}

	var (
		tree   = merkle.New(leaves)
		root   = tree.Root()
		exists bool
	)

	const existsQ = `
	select exists(
		select 1 from trees where root = $1
	)
	`

	err := s.db.QueryRow(ctx, existsQ, root).Scan(&exists)

	if err != nil {
		s.sendJSONError(r, w, err, http.StatusInternalServerError, "failed to check if tree already exists")
		return
	}

	if exists {
		s.sendJSON(r, w, createTreeResp{hexutil.Encode(root)})
		return
	}

	var (
		proofHashes = make([][]any, 0, len(leaves))
		allProofs   = tree.LeafProofs()
	)

	for _, p := range allProofs {
		proofHash := hashProof(p)
		proofHashes = append(proofHashes, []any{root, proofHash})
	}

	if err != nil {
		s.sendJSONError(r, w, err, http.StatusBadRequest, "generating proofs for tree")
		return
	}

	const q = `
		INSERT INTO trees(
			root,
			unhashed_leaves,
			ltd,
			packed
		) VALUES ($1, $2, $3, $4)
		ON CONFLICT (root)
		DO NOTHING
	`

	tx, err := s.db.Begin(ctx)
	if err != nil {
		s.sendJSONError(r, w, err, http.StatusInternalServerError, "creating transaction")
		return
	}
	defer tx.Rollback(ctx)

	_, err = tx.Exec(ctx, q,
		tree.Root(),
		leaves,
		req.Ltd,
		req.Packed,
	)
	if err != nil {
		s.sendJSONError(r, w, err, http.StatusInternalServerError, "inserting tree")
		return
	}

	_, err = tx.CopyFrom(ctx, pgx.Identifier{"proofs_hashes"},
		[]string{"root", "hash"},
		pgx.CopyFromRows(proofHashes),
	)

	if err != nil {
		s.sendJSONError(r, w, err, http.StatusInternalServerError, "inserting proof hashes")
		return
	}

	err = tx.Commit(ctx)
	if err != nil {
		s.sendJSONError(r, w, err, http.StatusInternalServerError, "committing transaction")
		return
	}

	s.sendJSON(r, w, createTreeResp{hexutil.Encode(root)})
}

type getTreeResp struct {
	UnhashedLeaves []hexutil.Bytes `json:"unhashedLeaves"`
	LeafCount      int             `json:"leafCount"`
	Ltd            []string        `json:"leafTypeDescriptor"`
	Packed         bool            `json:"packedEncoding"`
}

func getTree(ctx context.Context, db *pgxpool.Pool, root []byte) (getTreeResp, error) {
	const q = `
		SELECT unhashed_leaves, ltd, packed
		FROM trees
		WHERE root = $1
	`
	tr := getTreeResp{}
	err := db.QueryRow(ctx, q, root).Scan(
		&tr.UnhashedLeaves,
		&tr.Ltd,
		&tr.Packed,
	)
	if err != nil {
		return tr, err
	}
	return tr, nil
}

func (s *Server) GetTree(w http.ResponseWriter, r *http.Request) {
	var (
		ctx  = r.Context()
		root = r.URL.Query().Get("root")
	)
	if root == "" {
		s.sendJSONError(r, w, nil, http.StatusBadRequest, "missing root")
		return
	}

	tr, err := getTree(ctx, s.db, common.FromHex(root))

	if errors.Is(err, pgx.ErrNoRows) {
		s.sendJSONError(r, w, nil, http.StatusNotFound, "tree not found for root")
		w.Header().Set("Cache-Control", "public, max-age=60")
		return
	} else if err != nil {
		s.sendJSONError(r, w, err, http.StatusInternalServerError, "selecting tree")
		return
	}

	tr.LeafCount = len(tr.UnhashedLeaves)

	w.Header().Set("Cache-Control", "public, max-age=86400")
	s.sendJSON(r, w, tr)
}

func (s *Server) PinTree(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "unsupported method", http.StatusMethodNotAllowed)
		return
	}

	type pinTreeReq struct {
		MerkleRoot hexutil.Bytes `json:"merkleRoot"`
	}

	var (
		req pinTreeReq
		ctx = r.Context()
	)
	defer r.Body.Close()
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendJSONError(r, w, err, http.StatusBadRequest, "unhashedLeaves must be a list of hex strings")
		return
	}

	hash, err := s.pinTree(ctx, req.MerkleRoot)

	if errors.Is(err, pgx.ErrNoRows) {
		s.sendJSONError(r, w, err, http.StatusNotFound, "tree not found for root")
		return
	} else if err != nil {
		s.sendJSONError(r, w, err, http.StatusInternalServerError, "selecting tree")
		return
	}

	s.sendJSON(r, w, map[string]any{
		"ipfsHash": "ipfs://" + hash,
	})
}
