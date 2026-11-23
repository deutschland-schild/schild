package store

import (
	"context"
	"path/filepath"
	"testing"
)

// The watcher sees a write of this process and one of another process that
// opened the same file (a command on the host), and nothing when nothing
// was written.
func TestWatcherSeesEveryCommitAndNothingElse(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "schild.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	w := s.Watch()
	defer w.Close()
	if !w.Changed(ctx) {
		t.Fatal("the first look has to say yes")
	}
	for i := 0; i < 3; i++ {
		if w.Changed(ctx) {
			t.Fatal("changed although nothing was written")
		}
	}
	// A connection the pool opens sets its pragmas, which may count once;
	// reads on an open connection never do.
	if _, err := s.Get(ctx, "nothing"); err != ErrNotFound {
		t.Fatal(err)
	}
	w.Changed(ctx)
	for i := 0; i < 5; i++ {
		if _, err := s.Get(ctx, "nothing"); err != ErrNotFound {
			t.Fatal(err)
		}
		if w.Changed(ctx) {
			t.Fatal("a read counted as a change")
		}
	}
	if err := s.Put(ctx, "some_key_v1", []byte("1")); err != nil {
		t.Fatal(err)
	}
	if !w.Changed(ctx) || w.Changed(ctx) {
		t.Fatal("a write of this process: want one yes, then no")
	}
	// Another handle on the same file stands for the command line.
	other, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	w.Changed(ctx) // opening it may count
	if err := other.Put(ctx, "some_key_v1", []byte("2")); err != nil {
		t.Fatal(err)
	}
	if !w.Changed(ctx) || w.Changed(ctx) {
		t.Fatal("a write through another handle: want one yes, then no")
	}
}
