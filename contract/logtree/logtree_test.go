package logtree

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// RFC 6962 test data (as used by Certificate Transparency implementations):
// the eight leaves below give these roots for the first n leaves.
var rfcLeaves = []string{"", "00", "10", "2021", "3031", "40414243", "5051525354555657", "606162636465666768696a6b6c6d6e6f"}

var rfcRoots = []string{
	"6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
	"fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
	"aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
	"d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
	"4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
	"76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
	"ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
	"5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
}

func TestRFC6962Roots(t *testing.T) {
	var leaves []Hash
	var f Frontier
	for i, l := range rfcLeaves {
		d, _ := hex.DecodeString(l)
		leaves = append(leaves, LeafHash(d))
		f.Append(LeafHash(d))
		if got := hex.EncodeToString(func() []byte { h := Root(leaves); return h[:] }()); got != rfcRoots[i] {
			t.Errorf("root of %d leaves: %s, want %s", i+1, got, rfcRoots[i])
		}
		if r := f.Root(); Root(leaves) != r {
			t.Errorf("frontier root of %d leaves differs", i+1)
		}
	}
	if EmptyRoot() != sha256.Sum256(nil) {
		t.Fatal("empty root")
	}
	var empty Frontier
	if empty.Root() != EmptyRoot() {
		t.Fatal("empty frontier")
	}
}

func TestFrontierMatchesRecursive(t *testing.T) {
	var leaves []Hash
	var f Frontier
	for i := 0; i < 300; i++ {
		h := LeafHash([]byte{byte(i), byte(i >> 8)})
		leaves = append(leaves, h)
		f.Append(h)
		if f.Root() != Root(leaves) {
			t.Fatalf("size %d: frontier and recursive root differ", i+1)
		}
	}
}

func TestCheck(t *testing.T) {
	env := "sha256:" + hex.EncodeToString(make([]byte, 32))
	es := []Entry{
		{Index: 0, Time: "2026-10-26T12:00:00Z", Kind: "proposal", Ref: "prop-0001", Digest: env, Summary: "proposal prop-0001 approved"},
		{Index: 1, Time: "2026-10-26T12:00:05Z", Kind: "bundle", Ref: "1", Digest: env, Summary: "bundle 1 published", EnvelopeSHA256: &env},
	}
	var f Frontier
	for _, e := range es {
		f.Append(LeafHash(LeafData(e)))
	}
	if err := Check(es, 2, Format(f.Root())); err != nil {
		t.Fatal(err)
	}
	if err := Check(es, 2, Format(EmptyRoot())); err == nil {
		t.Fatal("wrong root accepted")
	}
	es[1].Summary = "bundle 1 published!"
	if err := Check(es, 2, Format(f.Root())); err == nil {
		t.Fatal("changed entry accepted")
	}
}
