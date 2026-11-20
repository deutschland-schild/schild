package nftfw

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
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

type errFake struct {
	fake
	replaceErr error
}

func (f *errFake) Replace(els []Element) error {
	if f.replaceErr != nil {
		err := f.replaceErr
		f.replaceErr = nil
		return err
	}
	return f.fake.Replace(els)
}

func TestApplyOnlyEnsuresWhenTableMissing(t *testing.T) {
	now := time.Now()
	ans := firewall.SyncResponse{
		Revision: "rev-1",
		Blocks:   []firewall.Block{{Client: "203.0.113.7", Until: now.Add(time.Minute)}},
	}

	// Transient / non-ENOENT error must NOT trigger Ensure (which would flush an intact table).
	f1 := &errFake{replaceErr: errors.New("netlink: device or resource busy")}
	if err := apply(f1, ans, now); err == nil {
		t.Fatal("expected error from transient Replace failure")
	}
	if f1.ensured != 0 {
		t.Fatalf("Ensure called %d times on non-missing error, want 0", f1.ensured)
	}

	// Table-missing error (os.ErrNotExist) must trigger Ensure and retry Replace.
	f2 := &errFake{replaceErr: os.ErrNotExist}
	if err := apply(f2, ans, now); err != nil {
		t.Fatalf("expected recovery on ENOENT, got %v", err)
	}
	if f2.ensured != 1 || len(f2.held) != 1 {
		t.Fatalf("ensured=%d held=%d, want 1, 1", f2.ensured, len(f2.held))
	}
}

func TestMergeIPv6AndBatching(t *testing.T) {
	items := []v6Item{
		// Out-of-order numerically (string order would put :10:: before :2::).
		{Prefix: netip.MustParsePrefix("2001:db8:0:10::/64"), Timeout: 5 * time.Minute},
		// Adjacent pair (:2::/64 and :3::/64) must merge keeping the longer timeout.
		{Prefix: netip.MustParsePrefix("2001:db8:0:3::/64"), Timeout: 2 * time.Minute},
		{Prefix: netip.MustParsePrefix("2001:db8:0:2::/64"), Timeout: 10 * time.Minute},
		// Overlapping duplicate of :2::/64 with an even longer timeout.
		{Prefix: netip.MustParsePrefix("2001:db8:0:2::/64"), Timeout: 15 * time.Minute},
		// End of IPv6 address space (no upper bound element).
		{Prefix: netip.MustParsePrefix("ffff:ffff:ffff:ffff::/64"), Timeout: time.Hour},
	}
	merged := mergeIPv6(items)
	if len(merged) != 3 {
		t.Fatalf("merged len=%d, want 3: %+v", len(merged), merged)
	}
	// First: merged :2::/64 + :3::/64 -> end is :4::, timeout 15m.
	if merged[0].Start != netip.MustParseAddr("2001:db8:0:2::") ||
		!merged[0].HasEnd ||
		merged[0].End != netip.MustParseAddr("2001:db8:0:4::") ||
		merged[0].Timeout != 15*time.Minute {
		t.Fatalf("range 0: %+v", merged[0])
	}
	// Second: :10::/64 -> end is :11::.
	if merged[1].Start != netip.MustParseAddr("2001:db8:0:10::") ||
		!merged[1].HasEnd ||
		merged[1].End != netip.MustParseAddr("2001:db8:0:11::") {
		t.Fatalf("range 1: %+v", merged[1])
	}
	// Third: ffff:ffff:ffff:ffff::/64 has no end.
	if merged[2].HasEnd {
		t.Fatalf("end-of-space range should have HasEnd=false: %+v", merged[2])
	}

	// Batching with maxElems=3 must never split a 2-element (Start, IntervalEnd) range.
	batches := batchV6Ranges(merged, 3)
	if len(batches) != 2 || len(batches[0]) != 1 || len(batches[1]) != 2 {
		t.Fatalf("unexpected batches: %+v", batches)
	}
}
