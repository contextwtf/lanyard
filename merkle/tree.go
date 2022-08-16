// merkle tree for nft allow lists
package merkle

import (
	"bytes"

	"github.com/ethereum/go-ethereum/crypto"
)

type Tree [][][]byte

// Returns a complete Tree using items for the leaves.
// Intermediary nodes and items will be hashed using Keccak256.
func New(items [][]byte) Tree {
	var leaves [][]byte
	for i := range items {
		leaves = append(leaves, crypto.Keccak256(items[i]))
	}
	var t Tree
	t = append(t, leaves)

	for {
		level := t[len(t)-1]
		if len(level) == 1 { //root node
			break
		}
		t = append(t, hashMerge(level))
	}
	return t
}

func hashPair(a, b []byte) []byte {
	if bytes.Compare(a, b) == -1 { // a < b
		return crypto.Keccak256(a, b)
	}
	return crypto.Keccak256(b, a)
}

// Iterates through the level pairwise merging each
// pair with a hash function creating a new level that
// is half the size of the level.
func hashMerge(level [][]byte) [][]byte {
	var newLevel [][]byte
	for i := 0; i < len(level); i += 2 {
		switch {
		case i+1 == len(level):
			//In the case of a level with an odd number of nodes
			//we leave the parent with a single child.
			//Some merkle tree designs allow for the parent
			//to duplicate the child so that it has both children
			//thus leaving the level with an even number of nodes.
			//We don't have that requirement yet and if one day we do
			//this is the spot to change:
			newLevel = append(newLevel, level[i])
		default:
			newLevel = append(newLevel, hashPair(level[i], level[i+1]))
		}
	}
	return newLevel
}

func (t Tree) Root() []byte {
	return t[len(t)-1][0]
}

// Produces a list of hashes that represent the path
// from the target's sibling to the root node.
func (t Tree) Proof(target []byte) [][]byte {
	var (
		proof [][]byte
		index int
	)
	for i, h := range t[0] {
		if bytes.Equal(crypto.Keccak256(target), h) {
			index = i
		}
	}
	for _, level := range t {
		var i int
		switch {
		case index%2 == 0:
			i = index + 1
		case index%2 == 1:
			i = index - 1
		}
		if i < len(level) {
			proof = append(proof, level[i])
		}
		index = index / 2
	}
	return proof
}

func Valid(root []byte, proof [][]byte, target []byte) bool {
	target = crypto.Keccak256(target)
	for i := range proof {
		target = hashPair(target, proof[i])
	}
	return bytes.Equal(target, root)
}
