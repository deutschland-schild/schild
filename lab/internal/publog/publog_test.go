package publog

import (
	"path/filepath"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/deutschland-schild/schild/contract/logtree"
	"github.com/deutschland-schild/schild/contract/msg"
	"github.com/deutschland-schild/schild/lab/internal/store"
)

func TestChainAndNoClientData(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	d := msg.Digest([]byte("x"))
	now := time.Now()
	err = db.Update(func(tx *bolt.Tx) error {
		for i := 0; i < 5; i++ {
			if _, err := Append(tx, now, KindProposal, "prop-0001", d, "proposal prop-0001 approved: rule schild-2026-0001", nil); err != nil {
				return err
			}
		}
		// Refused: address-like text, free text, envelopes on proposals, unknown kinds.
		for _, bad := range []func() error{
			func() error {
				_, err := Append(tx, now, KindProposal, "p", d, "seen from 203.0.113.7", nil)
				return err
			},
			func() error { _, err := Append(tx, now, KindProposal, "p", d, "line\nbreak", nil); return err },
			func() error { _, err := Append(tx, now, KindProposal, "p", d, "x", []byte(`{}`)); return err },
			func() error { _, err := Append(tx, now, "signal", "p", d, "x", nil); return err },
			func() error { _, err := Append(tx, now, KindBundle, "a b", d, "x", nil); return err },
		} {
			if bad() == nil {
				t.Error("unsafe entry accepted")
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	var entries []*Entry
	var head Head
	db.View(func(tx *bolt.Tx) error { entries = Range(tx, 0, 100); head = HeadTx(tx); return nil })
	got, err := Verify(entries)
	if err != nil || got != head || head.Size != 5 {
		t.Fatalf("verify: %v %+v %+v", err, got, head)
	}
	// The head is the RFC 6962 root the contract checker computes too.
	tree := make([]logtree.Entry, len(entries))
	for i, e := range entries {
		tree[i] = e.TreeEntry()
	}
	if err := logtree.Check(tree, head.Size, head.Root); err != nil {
		t.Fatalf("contract check: %v", err)
	}
	// Tampering with any entry changes the root.
	entries[2].Summary = "proposal prop-0001 rejected"
	if got, _ := Verify(entries); got.Root == head.Root {
		t.Fatal("tampered log has the same root")
	}
	// A log written before v0.1 (no stored frontier) is rebuilt to the same head.
	db.Update(func(tx *bolt.Tx) error { return tx.Bucket(store.Meta).Delete([]byte("log_frontier")) })
	db.View(func(tx *bolt.Tx) error {
		if h := HeadTx(tx); h != head {
			t.Fatalf("rebuilt head %+v, want %+v", h, head)
		}
		return nil
	})
	// Newest first listing with cursor.
	db.View(func(tx *bolt.Tx) error {
		l := List(tx, "", 0, 2)
		if len(l) != 2 || l[0].Index != 4 {
			t.Fatalf("list %+v", l)
		}
		l = List(tx, "", l[1].Index, 10)
		if len(l) != 3 || l[0].Index != 2 {
			t.Fatalf("page 2 %+v", l)
		}
		return nil
	})
}
