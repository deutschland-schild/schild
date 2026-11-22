//go:build !release

package app_test

import (
	"context"
	"fmt"
	"net/http"
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

// A node that is not in service listens all the same and answers 503 on the
// readiness path: a balancer and a person who looks at the server see why
// it is out, not a closed port (finding N3 of the second lab run: a fresh
// node that reached nobody refused every connection on its web ports).
func TestNodeNotInStepListensAndAnswers503(t *testing.T) {
	secretFile := filepath.Join(t.TempDir(), "cluster.secret")
	secret, err := cluster.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(secretFile, []byte(secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	h := apptest.New(t, apptest.Options{Listeners: true, Caddyfile: groupCaddyfile,
		Extra: fmt.Sprintf("cluster: {enabled: true, listen: %q, secret_file: %q, peers: [%q]}\n", apptest.FreeAddr(t), secretFile, apptest.FreeAddr(t))})
	if d := time.Since(start); d > 8*time.Second {
		t.Fatalf("the web listener of a node that is not in step came up after %s", d)
	}
	req, _ := http.NewRequest("GET", "http://"+h.IngressAddr+"/.schild/readyz", nil)
	req.Host = "shop.example"
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("readiness of a node that is not in step: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("readiness of a node that never reached its group: %d, want 503", resp.StatusCode)
	}
}

// A node that was in step once and restarts alone listens at once, answers
// 503 during the wait and 200 after it (N3: its ports were closed for the
// ten seconds of the wait, and with them the certificate it holds).
func TestNodeThatRestartsAloneListensDuringTheWait(t *testing.T) {
	defer app.SetFirstSyncWait(3 * time.Second)()
	a, b := pair(t)
	b.h.WaitFor("web-2 is in service", func() bool { return b.h.App.InService() })
	if err := a.h.Stop(); err != nil {
		t.Fatal(err)
	}
	if err := b.h.Stop(); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	h := apptest.New(t, apptest.Options{Dir: b.dir, Listeners: true, Caddyfile: groupCaddyfile, Extra: fmt.Sprintf("cluster: {enabled: true, listen: %q}\n", b.addr)})
	listening := time.Since(start)
	ready := func() int {
		req, _ := http.NewRequest("GET", "http://"+h.IngressAddr+"/.schild/readyz", nil)
		req.Host = "shop.example"
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return 0
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if listening < 2500*time.Millisecond {
		if got := ready(); got != http.StatusServiceUnavailable {
			t.Fatalf("readiness during the wait: %d, want 503", got)
		}
	} else {
		t.Logf("the start took %s on this machine, the 503 during the wait was not looked at", listening)
	}
	h.WaitFor("web-2 answers ready after the wait", func() bool { return ready() == http.StatusOK })
}

func TestOnlyLocksOfAnOrderWaitForTheGroup(t *testing.T) {
	for name, want := range map[string]bool{
		"issue_cert_shop.example":                  true,
		"register_acme_account":                    true,
		"register_acme_account_admin@shop.example": true,
		"stek_check":                               false,
		"storage_clean":                            false,
		"ari_abc":                                  false,
	} {
		if got := app.OrderLock(name); got != want {
			t.Errorf("lock %q waits for the group: %v, want %v", name, got, want)
		}
	}
}

// A node that was in step once and finds nobody after a restart serves with
// the state it has, after the wait and not before.
func TestNodeThatWasInStepServesAloneAfterTheWait(t *testing.T) {
	// The claim is "after the wait and not before", so the test measures
	// from before the start: a slow machine (the race detector in CI) may
	// take longer to start the node than the wait itself, and a look "right
	// after the start" would then come after the wait.
	const wait = 3 * time.Second
	defer app.SetFirstSyncWait(wait)()
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
	begun := time.Now()
	b.start(t)
	if early := b.h.App.InService(); early && time.Since(begun) < wait {
		t.Fatal("web-2 answers ready before the wait although it reached nobody")
	}
	b.h.WaitFor("web-2 serves alone after the wait", func() bool { return b.h.App.InService() })
	if since := time.Since(begun); since < wait {
		t.Fatalf("web-2 serves alone after %s, before the wait of %s", since, wait)
	}
}
