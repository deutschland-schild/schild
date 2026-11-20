package reqring

import (
	"bytes"
	"context"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func ipRequests(t *testing.T, r *Ring, now time.Time, ip string) int {
	t.Helper()
	f := AnyFilter()
	f.IP = netip.MustParseAddr(ip)
	p, err := r.Query(context.Background(), QueryParams{From: now.Add(-time.Hour), To: now.Add(time.Minute), Filter: f, Limit: 100}, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, x := range p.Items {
		if x.IP != ip {
			t.Fatalf("record of %s in the list of %s", x.IP, ip)
		}
	}
	return len(p.Items)
}

// The User-Agent is kept as sent (D85), without control characters.
func TestUserAgentFilterAsSent(t *testing.T) {
	r, c := newTestRing(t, Config{})
	for _, ua := range []string{"Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)", "curl/8.0", "x\tmail me@example.org"} {
		e := entry(c, "203.0.113.9", "/")
		e.UA = ua
		r.Add(&e)
		c.add(time.Second)
	}
	r.Flush()
	now := c.now()
	f := AnyFilter()
	f.UserAgent = "bingbot"
	p, err := r.Query(context.Background(), QueryParams{From: now.Add(-time.Hour), To: now.Add(time.Minute), Filter: f, Limit: 100}, now)
	if err != nil || len(p.Items) != 1 || p.Items[0].UserAgent == "" {
		t.Fatalf("%v %+v", err, p.Items)
	}
	f.UserAgent = "me@example.org"
	if p, _ = r.Query(context.Background(), QueryParams{From: now.Add(-time.Hour), To: now.Add(time.Minute), Filter: f, Limit: 100}, now); len(p.Items) != 1 || p.Items[0].UserAgent != "xmail me@example.org" {
		t.Fatalf("the user agent as sent, without the tab: %+v", p.Items)
	}
}

func TestAddressRoundTripAndFilter(t *testing.T) {
	r, c := newTestRing(t, Config{})
	for _, ip := range []string{"203.0.113.9", "2001:db8::1", "::ffff:198.51.100.7", "203.0.113.9"} {
		e := entry(c, ip, "/")
		r.Add(&e)
		c.add(time.Second)
	}
	r.Flush()
	now := c.now()
	if n := ipRequests(t, r, now, "203.0.113.9"); n != 2 {
		t.Fatalf("%d requests", n)
	}
	if n := ipRequests(t, r, now, "2001:db8::1"); n != 1 {
		t.Fatalf("%d requests", n)
	}
	if n := ipRequests(t, r, now, "198.51.100.7"); n != 1 {
		t.Fatalf("a mapped address: %d requests", n)
	}
}

// A record ends with its address and user agent; an erased trailer reads as
// none, a record without the trailer is corrupt.
func TestRecordTrailer(t *testing.T) {
	rec := Rec{T: 5, Site: "s", IP: netip.MustParseAddr("203.0.113.9"), UA: "bingbot/2.0"}
	b := appendRec(nil, &rec, 0, nil)
	var got Rec
	if err := decodeRec(b, 0, nil, &got); err != nil || got.IP != rec.IP || got.UA != rec.UA {
		t.Fatalf("%v %v %q", err, got.IP, got.UA)
	}
	tail := got.tail
	if err := decodeRec(b[:tail], 0, nil, &got); err != errCorrupt {
		t.Fatalf("without trailer: %v", err)
	}
	clear(b[tail:]) // erased
	if err := decodeRec(b, 0, nil, &got); err != nil || got.IP.IsValid() || got.UA != "" {
		t.Fatalf("%v %v %q", err, got.IP, got.UA)
	}
}

func TestForgetIP(t *testing.T) {
	dir := t.TempDir()
	r, c := newTestRing(t, Config{StoragePath: dir})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r.Start(ctx)
	for _, ip := range []string{"203.0.113.9", "198.51.100.7", "203.0.113.9"} {
		e := entry(c, ip, "/")
		e.UA = "agent-of-" + ip
		r.Add(&e)
		c.add(time.Second)
	}
	r.Flush()
	n, err := r.ForgetIP(ctx, netip.MustParseAddr("203.0.113.9"))
	if err != nil || n != 2 {
		t.Fatalf("erased %d, %v", n, err)
	}
	now := c.now()
	if n := ipRequests(t, r, now, "203.0.113.9"); n != 0 {
		t.Fatalf("%d requests left", n)
	}
	if n := ipRequests(t, r, now, "198.51.100.7"); n != 1 {
		t.Fatalf("the other address: %d requests", n)
	}
	all, err := r.Query(ctx, QueryParams{From: now.Add(-time.Hour), To: now.Add(time.Minute), Filter: AnyFilter(), Limit: 100}, now)
	if err != nil || len(all.Items) != 3 {
		t.Fatalf("%d records stay, %v", len(all.Items), err)
	}
	files, _ := filepath.Glob(filepath.Join(dir, Dir, "*"))
	if len(files) == 0 {
		t.Fatal("no segment")
	}
	want := netip.MustParseAddr("203.0.113.9").AsSlice()
	for _, f := range files {
		frames, _, _, _, err := readFrames(f)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			t.Fatal(err)
		}
		if bytes.Contains(frames, want) || bytes.Contains(frames, []byte("agent-of-203.0.113.9")) {
			t.Fatalf("%s still holds the address or its user agent", f)
		}
		if !bytes.Contains(frames, []byte("agent-of-198.51.100.7")) {
			t.Fatalf("%s lost the other client", f)
		}
	}
}

// TestPathFilterMatchesRealPaths: D63, records keep real paths, the top lists
// show templates, and a template from a top list finds its real paths.
func TestPathFilterMatchesRealPaths(t *testing.T) {
	r, c := newTestRing(t, Config{RawPath: func(string) bool { return true }})
	for _, p := range []string{"/blog/erster-beitrag", "/blog/zweiter-beitrag", "/kontakt"} {
		e := entry(c, "203.0.113.9", "/")
		e.RawPath = p
		r.Add(&e)
		c.add(time.Second)
	}
	r.Flush()
	now := c.now()
	for path, want := range map[string]int{"/blog/{slug}": 2, "/blog/erster-beitrag": 1, "/kontakt": 1, "/{slug}": 0} {
		f := AnyFilter()
		f.Path = path
		p, err := r.Query(context.Background(), QueryParams{From: now.Add(-time.Hour), To: now.Add(time.Minute), Filter: f, Limit: 100}, now)
		if err != nil || len(p.Items) != want {
			t.Fatalf("path %s: %v, %d records, want %d", path, err, len(p.Items), want)
		}
		for _, x := range p.Items {
			if x.PathKind != "redacted" {
				t.Fatalf("path %s: %+v", path, x)
			}
		}
	}
}

// Erasures of different addresses at the same time (two privacy deletions)
// each keep their effect: none brings back an address another one erased.
func TestForgetIPConcurrent(t *testing.T) {
	dir := t.TempDir()
	r, c := newTestRing(t, Config{StoragePath: dir})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r.Start(ctx)
	var ips []string
	for i := 1; i <= 8; i++ {
		ips = append(ips, fmt.Sprintf("203.0.113.%d", i))
	}
	for round := 0; round < 20; round++ {
		for _, ip := range ips {
			e := entry(c, ip, "/")
			r.Add(&e)
		}
		c.add(time.Second)
	}
	r.Flush()
	var wg sync.WaitGroup
	errs := make(chan error, len(ips))
	for _, ip := range ips {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			if _, err := r.ForgetIP(ctx, netip.MustParseAddr(ip)); err != nil {
				errs <- err
			}
		}(ip)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	now := c.now()
	for _, ip := range ips {
		if n := ipRequests(t, r, now, ip); n != 0 {
			t.Errorf("%s: %d requests still hold the address", ip, n)
		}
	}
	// The writer's visitor key cache is keyed by address and goes too.
	if n := len(r.vkeys); n != 0 {
		t.Errorf("visitor key cache keeps %d addresses", n)
	}
}
