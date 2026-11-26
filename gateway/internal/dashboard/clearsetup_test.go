package dashboard

import (
	"context"
	"path/filepath"
	"sync"
	"testing"

	"github.com/deutschland-schild/schild/contract/config"
	"github.com/deutschland-schild/schild/gateway/internal/store"
)

// A reset on the host next to logins that arrive from the cluster: the code
// the reset shows works whenever it left no user behind, in the running
// gateway and, by its stored hash, after a restart.
func TestResetNextToTakenLoginsKeepsItsCode(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "schild.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	s := &Server{St: st, Config: func() *config.Site { return &config.Site{NodeName: "test-node"} }}
	var memory, stored int
	const n = 300
	for range n {
		if err := st.ClearPendingSetup(ctx); err != nil {
			t.Fatal(err)
		}
		if err := st.CreateFirstUser(ctx, store.User{Name: "admin", Hash: "x", Role: "admin"}); err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = s.ClearSetup(ctx)
		}()
		code, _, err := s.ResetAccess(ctx, "op")
		if err != nil {
			t.Fatal(err)
		}
		wg.Wait()
		if st.HasUsers(ctx) {
			t.Fatal("the reset left a user")
		}
		if !s.setupCodeOK(code) {
			memory++
		}
		if st.PendingSetupHash(ctx) == nil {
			stored++
		}
	}
	if memory+stored > 0 {
		t.Errorf("of %d resets the code of %d does not work, the hash of %d is gone", n, memory, stored)
	}
	// Without users a code of a reset stays.
	code, _, err := s.ResetAccess(ctx, "op")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ClearSetup(ctx); err != nil {
		t.Fatal(err)
	}
	if !s.setupCodeOK(code) {
		t.Error("the code of a reset is gone although there are no users")
	}
	// Once there are users the code is gone, in both places.
	if err := st.CreateFirstUser(ctx, store.User{Name: "admin", Hash: "x", Role: "admin"}); err != nil {
		t.Fatal(err)
	}
	if err := s.ClearSetup(ctx); err != nil {
		t.Fatal(err)
	}
	if s.setupHash != nil || st.PendingSetupHash(ctx) != nil {
		t.Error("the code of a reset is still there although users arrived")
	}
}
