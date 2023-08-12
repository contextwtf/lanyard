package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"time"

	"github.com/contextwtf/lanyard/api/tracing"
	"github.com/ethereum/go-ethereum/common/hexutil"
)

var (
	ipfsPinningServiceURL = os.Getenv("IPFS_PINNING_SERVICE_URL")
	ipfsPinningSecret     = os.Getenv("IPFS_PINNING_SECRET")
	hc                    = &http.Client{
		Timeout: time.Second * 10,
	}
)

func (s *Server) pinTree(ctx context.Context, root hexutil.Bytes) (string, error) {
	if ipfsPinningServiceURL == "" {
		return "", errors.New("IPFS_PINNING_SERVICE_URL not set")
	}

	const q = `
		SELECT unhashed_leaves, ltd, packed
		FROM trees
		WHERE root = $1
	`
	tr := struct {
		Root           hexutil.Bytes   `json:"root"`
		UnhashedLeaves []hexutil.Bytes `json:"unhashedLeaves"`
		Ltd            []string        `json:"leafTypeDescriptor"`
		Packed         jsonNullBool    `json:"packedEncoding"`
	}{
		Root: root,
	}

	err := s.db.QueryRow(ctx, q, root).Scan(
		&tr.UnhashedLeaves,
		&tr.Ltd,
		&tr.Packed,
	)

	if err != nil {
		return "", err
	}

	msg, err := json.Marshal(tr)

	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(
		ctx, "POST", ipfsPinningServiceURL, bytes.NewReader(msg),
	)

	if err != nil {
		return "", err
	}

	req.Header.Set("Authorization", "Bearer "+ipfsPinningSecret)
	req.Header.Set("Content-Type", "application/json")

	span, ctx := tracing.SpanFromContext(ctx, "ipfs.pinTree")
	res, err := hc.Do(req)
	span.Finish()

	if err != nil {
		return "", err
	}

	if res.StatusCode >= 400 {
		return "", errors.New(res.Status)
	}

	type resp struct {
		Hash string `json:"IpfsHash"`
	}

	defer res.Body.Close()

	var r resp
	err = json.NewDecoder(res.Body).Decode(&r)
	if err != nil {
		return "", err
	}

	return r.Hash, nil
}
