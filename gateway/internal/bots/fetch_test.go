package bots

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/contract/config"
	"github.com/deutschland-schild/schild/contract/msg"
	"github.com/deutschland-schild/schild/gateway/internal/bots/rangesrc"
)

// The optional range fetch swaps in fresh snapshots that pass the contract
// check (source "fetch"), keeps the last good one for a list that fails,
// and makes a stale release snapshot fresh again.
func TestRangesFetch(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/googlebot.json":
			w.Write([]byte(`{"prefixes":[{"ipv4Prefix":"192.0.2.0/24"},{"ipv6Prefix":"2001:db8:4860::/48"}]}`))
		case "/gptbot.json":
			w.Write([]byte(`{"prefixes":[{"ipv4Prefix":"198.51.100.16/28"}]}`))
		default:
			http.Error(w, "down", http.StatusServiceUnavailable)
		}
	}))
	defer srv.Close()
	c := shipped(t)
	gen, _ := msg.ParseTime(c.GeneratedAt)
	now := gen.Add(40 * 24 * time.Hour) // release snapshot stale
	e, err := NewFromCatalogue(c, config.Bots{RangesFetch: boolp(true)}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	e.client = srv.Client()
	e.sources = []rangesrc.Source{
		{ID: "googlebot", Format: rangesrc.FormatJSON, URLs: []string{srv.URL + "/googlebot.json"}},
		{ID: "gptbot", Format: rangesrc.FormatJSON, URLs: []string{srv.URL + "/gptbot.json"}},
		{ID: "bingbot", Format: rangesrc.FormatJSON, URLs: []string{srv.URL + "/bingbot.json"}},
	}
	g, _ := e.MatchUA("Mozilla/5.0 (compatible; Googlebot/2.1)")
	if v := e.Verify(g, netip.MustParseAddr("192.0.2.10")); v != VerUnknownStale {
		t.Fatalf("before fetch: %s", VerificationName(v))
	}
	if err := e.FetchRanges(context.Background()); err == nil {
		t.Error("the failing bingbot list must be reported")
	}
	if v := e.Verify(g, netip.MustParseAddr("192.0.2.10")); v != VerVerified {
		t.Errorf("fetched googlebot: %s", VerificationName(v))
	}
	if v := e.Verify(g, netip.MustParseAddr("66.249.66.1")); v != VerMismatch {
		t.Errorf("address of the old snapshot: %s", VerificationName(v))
	}
	b, _ := e.MatchUA("Mozilla/5.0 (compatible; bingbot/2.0)")
	if v := e.Verify(b, netip.MustParseAddr("192.0.2.10")); v != VerUnknownStale {
		t.Errorf("bingbot keeps its stale release snapshot: %s", VerificationName(v))
	}
	src := map[string]string{}
	for _, r := range e.Ranges() {
		src[r.ID] = r.Source
	}
	if src["googlebot"] != "fetch" || src["gptbot"] != "fetch" || src["bingbot"] != "release" {
		t.Errorf("sources %v", src)
	}

	// The loop runs with Start and stops with Close.
	e.every = time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	e.Start(ctx)
	time.Sleep(20 * time.Millisecond)
	cancel()
	e.Close()
}
