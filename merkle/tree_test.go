package merkle

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"golang.org/x/sync/errgroup"
)

func ExampleTree() {
	var addrStrs = []string{
		"0xE124F06277b5AC791bA45B92853BA9A0ea93327D",
		"0x07d048f78B7C093B3Ef27D478B78026a70D9734e",
		"0x38976611f5f7bEAd7e79E752f5B80AE72dD3eFa7",
		"0x1Ab00ffedD724B930080aD30269083F1453cF34E",
		"0x860a6bC426C3bb1186b2E11Ac486ABa000C209B4",
		"0x0B3eC21fc53AD8b17AF4A80723c1496541fCb35f",
		"0x2D13F6CEe6dA8b30a84ee7954594925bd5E47Ab7",
		"0x3C64Cd43331beb5B6fAb76dbAb85226955c5CC3A",
		"0x238dA873f984188b4F4c7efF03B5580C65a49dcB",
		"0xbAfC038aDfd8BcF6E632C797175A057714416d04",
	}
	var addrs [][]byte
	for i := range addrStrs {
		addrs = append(addrs, common.HexToAddress(addrStrs[i]).Bytes())
	}
	var tr Tree
	tr = New(addrs)
	fmt.Println(common.Bytes2Hex(tr.Root()))

	// Output:
	// ed40d49077a2cd13601cf79a512e6b92c7fd0f952e7dc9f4758d7134f9712bc4
}

func TestRoot(t *testing.T) {
	cases := []struct {
		desc     string
		leaves   [][]byte
		wantRoot []byte
	}{
		{
			leaves: [][]byte{
				[]byte("a"),
				[]byte("b"),
				[]byte("c"),
				[]byte("d"),
				[]byte("e"),
				[]byte("f"),
			},
			wantRoot: common.Hex2Bytes("9012f1e18a87790d2e01faace75aaaca38e53df437cdce2c0552464dda4af49c"),
		},
	}

	for _, tc := range cases {
		mt := New(tc.leaves)
		if !bytes.Equal(mt.Root(), tc.wantRoot) {
			t.Errorf("got: %s want: %s",
				common.Bytes2Hex(mt.Root()),
				common.Bytes2Hex(tc.wantRoot),
			)
		}
	}
}

func TestProof(t *testing.T) {
	cases := []struct {
		leaves [][]byte
	}{
		{
			leaves: [][]byte{
				[]byte("a"),
				[]byte("b"),
				[]byte("c"),
				[]byte("d"),
				[]byte("e"),
			},
		},
	}

	for _, tc := range cases {
		mt := New(tc.leaves)
		for i, l := range tc.leaves {
			pf := mt.Proof(i)
			if !Valid(mt.Root(), pf, l) {
				t.Error("invalid proof")
			}
		}
	}
}

func TestIndex(t *testing.T) {
	leaves := [][]byte{
		[]byte("a"),
		[]byte("b"),
		[]byte("c"),
		[]byte("d"),
		[]byte("e"),
	}
	mt := New(leaves)
	for i, l := range leaves {
		r := mt.Index(l)
		if r != i {
			t.Errorf("incorrect index, expected %d, got %d", i, r)
		}
	}
}

func TestMissingIndex(t *testing.T) {
	mt := New([][]byte{
		[]byte("a"),
		[]byte("b"),
		[]byte("c"),
		[]byte("d"),
		[]byte("e"),
	})

	pf := mt.Index([]byte("f"))
	if pf != -1 {
		t.Errorf("incorrect index, expected %d, got %d", -1, pf)
	}
}

func BenchmarkNew(b *testing.B) {
	var leaves [][]byte
	for i := 0; i < 50000; i++ {
		leaves = append(leaves, []byte{byte(i)})
	}

	for i := 0; i < b.N; i++ {
		New(leaves)
	}
}

func BenchmarkProof(b *testing.B) {
	var leaves [][]byte
	for i := 0; i < 50000; i++ {
		leaves = append(leaves, []byte{byte(i)})
	}
	mt := New(leaves)
	for i := 0; i < b.N; i++ {
		var eg errgroup.Group
		for i := range leaves {
			i := i
			eg.Go(func() error {
				mt.Proof(i)
				return nil
			})
		}
		eg.Wait()
	}
}

func BenchmarkProofs(b *testing.B) {
	var leaves [][]byte
	for i := 0; i < 50000; i++ {
		leaves = append(leaves, []byte{byte(i)})
	}
	mt := New(leaves)
	for i := 0; i < b.N; i++ {
		mt.LeafProofs()
	}
}
