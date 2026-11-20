package nftfw

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/contract/firewall"
)

type fake struct {
	mu       sync.Mutex
	held     []Element
	ensured  int
	removed  bool
	failNext bool
}

func (f *fake) Ensure() error { f.mu.Lock(); defer f.mu.Unlock(); f.ensured++; return nil }
func (f *fake) Replace(els []Element) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failNext {
		f.failNext = false
		return errors.New("set blocked4: no such file or directory")
	}
	f.held = els
	return nil
}
func (f *fake) Held() ([]Held, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]Held, len(f.held))
	for i, e := range f.held {
		out[i] = Held{Client: e.Client, Expires: e.Timeout}
	}
	return out, nil
}
func (f *fake) Remove() error { f.mu.Lock(); defer f.mu.Unlock(); f.removed = true; return nil }

// gateway is a fake agent API: it answers at once when the revision differs.
type gateway struct {
	mu      sync.Mutex
	blocks  []firewall.Block
	reports []firewall.SyncRequest
}

func (g *gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer sat1_test" {
		http.Error(w, `{"code":"unauthenticated"}`, 401)
		return
	}
	var req firewall.SyncRequest
	_ = json.NewDecoder(r.Body).Decode(&req)
	g.mu.Lock()
	g.reports = append(g.reports, req)
	ans := firewall.SyncResponse{Revision: firewall.Revision(g.blocks), Blocks: g.blocks}
	g.mu.Unlock()
	if ans.Revision == req.Applied {
		time.Sleep(50 * time.Millisecond)
	}
	_ = json.NewEncoder(w).Encode(ans)
}

func TestRunAppliesAndReports(t *testing.T) {
	now := time.Now()
	g := &gateway{blocks: []firewall.Block{{Client: "203.0.113.7", Until: now.Add(15 * time.Minute)}, {Client: "2001:db8:1:2::/64", Until: now.Add(time.Hour)}}}
	srv := httptest.NewServer(g)
	defer srv.Close()
	f := &fake{failNext: true}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, f, Config{API: srv.URL, Token: "sat1_test", Version: "test", Retry: 10 * time.Millisecond})
	}()
	wait := func(what string, ok func() bool) {
		t.Helper()
		for end := time.Now().Add(5 * time.Second); !ok(); time.Sleep(10 * time.Millisecond) {
			if time.Now().After(end) {
				t.Fatalf("timed out: %s", what)
			}
		}
	}
	// The first apply fails (table gone): it is built again and applied.
	wait("applied", func() bool {
		g.mu.Lock()
		defer g.mu.Unlock()
		n := len(g.reports)
		return n > 0 && g.reports[n-1].Applied == firewall.Revision(g.blocks) && g.reports[n-1].Held == 2
	})
	f.mu.Lock()
	if f.ensured < 2 || len(f.held) != 2 || f.held[0].Timeout < 14*time.Minute {
		t.Fatalf("table: ensured %d, held %+v", f.ensured, f.held)
	}
	f.mu.Unlock()
	// A lift in the gateway: the next answer has one block less.
	g.mu.Lock()
	g.blocks = g.blocks[1:]
	g.mu.Unlock()
	wait("lifted", func() bool {
		f.mu.Lock()
		defer f.mu.Unlock()
		return len(f.held) == 1 && f.held[0].Client == "2001:db8:1:2::/64"
	})
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !f.removed {
		t.Fatal("a clean stop leaves the table")
	}
}

func TestElementsAndAfter(t *testing.T) {
	now := time.Now()
	els := Elements([]firewall.Block{{Client: "203.0.113.7", Until: now.Add(time.Minute)}, {Client: "198.51.100.9", Until: now.Add(-time.Second)}}, now)
	if len(els) != 1 || els[0].Client != "203.0.113.7" {
		t.Fatalf("%+v", els)
	}
}
