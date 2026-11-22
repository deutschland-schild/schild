//go:build !release

package app_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/gateway/internal/app"
	"github.com/deutschland-schild/schild/gateway/internal/apptest"
	"github.com/deutschland-schild/schild/gateway/internal/cluster"
)

// An address with a running block is erased while a node is down. When the
// node is back and in step with the group, it must not refuse the address
// any more (finding of the measurement, 08t).
func TestReturningNodeDropsTheBlockOfAnErasedAddressBeforeItIsInStep(t *testing.T) {
	a, b := pair(t)
	const ip = "203.0.113.200"
	a.block(ip, "S-ERASED-AWAY", 7*24*time.Hour)
	b.h.WaitFor("web-2 blocks the address", func() bool { return b.blocked(ip) == "S-ERASED-AWAY" })
	b.h.App.FlushBlocks()
	if err := b.h.Stop(); err != nil {
		t.Fatal(err)
	}
	a.h.Login()
	if code, body := a.h.API("POST", "/privacy/delete", map[string]any{"ip": ip, "confirm": true}); code != 200 {
		t.Fatalf("erasure: %d %s", code, body)
	}
	time.Sleep(time.Second) // web-1 told the group
	b.start(t)
	b.h.WaitFor("web-2 is in step", func() bool { return b.h.App.Cluster.Synced() })
	if got := b.blocked(ip); got != "" {
		t.Errorf("in step with the group, web-2 still blocks the erased address (%s)", got)
		b.h.WaitFor("web-2 drops it later", func() bool { return b.blocked(ip) == "" })
	}
	if resp := b.h.Visit("GET", "/", ip, "", ""); resp.StatusCode != 200 {
		t.Errorf("a request of the erased address on web-2: %d", resp.StatusCode)
	}
}

// A node that never was in step with its group holds nothing of it: it
// stays out of traffic however long it reaches no member (finding H1 of the
// hardening measurement: it answered ready after ten seconds and let an
// address pass that the group blocks).
func TestFreshNodeThatReachesNoMemberStaysOutOfTraffic(t *testing.T) {
	defer app.SetFirstSyncWait(300 * time.Millisecond)()
	secretFile := filepath.Join(t.TempDir(), "cluster.secret")
	secret, err := cluster.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(secretFile, []byte(secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The named peer is an address nothing listens on.
	h := apptest.New(t, apptest.Options{Extra: fmt.Sprintf("cluster: {enabled: true, listen: %q, secret_file: %q, peers: [%q]}\n", apptest.FreeAddr(t), secretFile, apptest.FreeAddr(t))})
	if h.App.Cluster == nil {
		t.Fatal("no cluster node")
	}
	time.Sleep(1500 * time.Millisecond)
	if h.App.InService() {
		t.Fatal("a node that never reached its group answers ready")
	}
	// It orders no certificate either: the lock of an order waits until the
	// node knows what the group holds (finding F6 of the lab measurement).
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	if err := h.App.WaitInStep(ctx); err == nil {
		t.Fatal("a node that never reached its group may take the lock of a certificate order")
	}
}

// A node that was in step once and finds nobody after a restart serves with
// the state it has, after the wait and not before.
func TestNodeThatWasInStepServesAloneAfterTheWait(t *testing.T) {
	defer app.SetFirstSyncWait(1500 * time.Millisecond)()
	a, b := pair(t)
	b.h.WaitFor("web-2 is in service", func() bool { return b.h.App.InService() })
	if err := b.h.App.WaitInStep(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := a.h.Stop(); err != nil {
		t.Fatal(err)
	}
	if err := b.h.Stop(); err != nil {
		t.Fatal(err)
	}
	b.start(t)
	if b.h.App.InService() {
		t.Fatal("web-2 answers ready at once although it reached nobody")
	}
	b.h.WaitFor("web-2 serves alone after the wait", func() bool { return b.h.App.InService() })
}
