// Package logtree is the tree hash of a lab's public log (contracts v0.1,
// contracts/cosign.md): an RFC 6962 Merkle tree hash (section 2.1) over the
// leaf data of every log entry.
//
//	leaf hash  = SHA-256(0x00 || leaf data)
//	node hash  = SHA-256(0x01 || left || right)
//	MTH({})    = SHA-256("")
//	MTH(D[n])  = node(MTH(D[0:k]), MTH(D[k:n])), k the largest power of two < n
//
// The leaf data of an entry is line-based text (no JSON, so every language
// produces the same bytes):
//
//	schild.log-leaf/1\n
//	index:<decimal>\n
//	time:<RFC 3339 UTC>\n
//	kind:<proposal|bundle|withdrawal|checkpoint>\n
//	ref:<ref>\n
//	digest:<sha256:hex>\n
//	summary:<printable ASCII>\n
//	envelope:<sha256:hex of the envelope bytes, or empty>\n
//
// The checkpoint signs {size, root} with root = "sha256:" + hex(MTH).
package logtree

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/bits"
	"strconv"
	"strings"

	"github.com/deutschland-schild/schild/contract"
)

// Entry holds the fields of a log entry that enter its leaf.
type Entry struct {
	Index          uint64  `json:"index"`
	Time           string  `json:"time"`
	Kind           string  `json:"kind"`
	Ref            string  `json:"ref"`
	Digest         string  `json:"digest"`
	Summary        string  `json:"summary"`
	EnvelopeSHA256 *string `json:"envelope_sha256"`
}

// LeafData returns the canonical leaf bytes of an entry.
func LeafData(e Entry) []byte {
	env := ""
	if e.EnvelopeSHA256 != nil {
		env = *e.EnvelopeSHA256
	}
	var b strings.Builder
	b.WriteString("schild.log-leaf/1\n")
	b.WriteString("index:" + strconv.FormatUint(e.Index, 10) + "\n")
	b.WriteString("time:" + e.Time + "\n")
	b.WriteString("kind:" + e.Kind + "\n")
	b.WriteString("ref:" + e.Ref + "\n")
	b.WriteString("digest:" + e.Digest + "\n")
	b.WriteString("summary:" + e.Summary + "\n")
	b.WriteString("envelope:" + env + "\n")
	return []byte(b.String())
}

// Hash is one SHA-256 tree hash.
type Hash [32]byte

// LeafHash is SHA-256(0x00 || data).
func LeafHash(data []byte) Hash {
	h := sha256.New()
	h.Write([]byte{0})
	h.Write(data)
	var out Hash
	h.Sum(out[:0])
	return out
}

// NodeHash is SHA-256(0x01 || left || right).
func NodeHash(l, r Hash) Hash {
	h := sha256.New()
	h.Write([]byte{1})
	h.Write(l[:])
	h.Write(r[:])
	var out Hash
	h.Sum(out[:0])
	return out
}

// EmptyRoot is MTH of the empty log: SHA-256 of the empty string.
func EmptyRoot() Hash { return sha256.Sum256(nil) }

// Format renders a hash as "sha256:<hex>".
func Format(h Hash) string { return "sha256:" + hex.EncodeToString(h[:]) }

// Root computes MTH over the given leaf hashes (recursive definition).
func Root(leaves []Hash) Hash {
	switch n := len(leaves); n {
	case 0:
		return EmptyRoot()
	case 1:
		return leaves[0]
	default:
		k := 1 << (bits.Len(uint(n-1)) - 1) // largest power of two < n
		return NodeHash(Root(leaves[:k]), Root(leaves[k:]))
	}
}

// Frontier appends leaves in O(log n) memory: it keeps the roots of the
// perfect subtrees that make up the tree (largest first), which is all
// that is needed to compute MTH of the current size.
type Frontier struct {
	Size  uint64 `json:"size"`
	Nodes []Hash `json:"nodes"` // one per set bit of Size, largest subtree first
}

// Append adds one leaf hash.
func (f *Frontier) Append(leaf Hash) {
	h := leaf
	// Merge equal-sized perfect subtrees: one merge per trailing 1-bit of Size.
	for s := f.Size; s&1 == 1; s >>= 1 {
		h = NodeHash(f.Nodes[len(f.Nodes)-1], h)
		f.Nodes = f.Nodes[:len(f.Nodes)-1]
	}
	f.Nodes = append(f.Nodes, h)
	f.Size++
}

// Root returns MTH of the leaves appended so far.
func (f *Frontier) Root() Hash {
	if len(f.Nodes) == 0 {
		return EmptyRoot()
	}
	h := f.Nodes[len(f.Nodes)-1]
	for i := len(f.Nodes) - 2; i >= 0; i-- {
		h = NodeHash(f.Nodes[i], h)
	}
	return h
}

// Check verifies a log copy from index 0 against a head: indices must be
// 0..n-1, size must equal the number of entries, and the root must match.
// Mismatches are *contract.Error with code schema (shape) or log_root.
func Check(entries []Entry, size uint64, root string) error {
	if uint64(len(entries)) != size {
		return contract.Errf(contract.CodeSchema, "head size %d, %d entries", size, len(entries))
	}
	leaves := make([]Hash, len(entries))
	for i, e := range entries {
		if e.Index != uint64(i) {
			return contract.Errf(contract.CodeSchema, "entry %d has index %d", i, e.Index)
		}
		leaves[i] = LeafHash(LeafData(e))
	}
	if got := Format(Root(leaves)); got != root {
		return contract.Errf(contract.CodeLogRoot, "root %s, head says %s", got, root)
	}
	return nil
}

// ParseHash parses "sha256:<hex>".
func ParseHash(s string) (Hash, error) {
	var h Hash
	b, err := hex.DecodeString(strings.TrimPrefix(s, "sha256:"))
	if err != nil || len(b) != 32 || !strings.HasPrefix(s, "sha256:") {
		return h, fmt.Errorf("logtree: bad hash %q", s)
	}
	copy(h[:], b)
	return h, nil
}
