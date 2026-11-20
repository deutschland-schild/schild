package gate

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/contract/events"
	"github.com/deutschland-schild/schild/contract/storage"
	"github.com/deutschland-schild/schild/gateway/internal/decide"
	"github.com/deutschland-schild/schild/gateway/internal/stats"
	"github.com/deutschland-schild/schild/gateway/internal/store"
)

// pending stays bounded while the writer does not run (security review
// 2.4): hits beyond the bound are counted as dropped, the number holds.
func TestAggregatePendingBounded(t *testing.T) {
	a := newAggregator(2)
	n := 0
	draw := func() string { n++; return fmt.Sprintf("incident-%d", n) }
	for _, c := range []string{"a", "b"} {
		a.assign(aggKey{client: c}, 0, draw)
		if _, joined := a.assign(aggKey{client: c}, 1, draw); !joined {
			t.Fatal("second hit did not join")
		}
	}
	if len(a.pending) != 2 {
		t.Fatalf("pending %d", len(a.pending))
	}
	// Every minute opens new aggregates; without a flush nothing leaves.
	id, _ := a.assign(aggKey{client: "x"}, 60000, draw)
	got, joined := a.assign(aggKey{client: "x"}, 60001, draw)
	if !joined || got != id {
		t.Fatalf("number changed: %s %s", id, got)
	}
	if len(a.pending) != 2 || a.dropped.Load() != 1 {
		t.Fatalf("pending %d, dropped %d", len(a.pending), a.dropped.Load())
	}
	// Hits whose row never appears count as dropped too (one hit each here).
	hits, tries := a.take()
	for range aggMaxTries {
		a.retry(hits, tries)
		hits, tries = a.take()
	}
	if len(a.pending) != 0 || a.dropped.Load() != 3 {
		t.Fatalf("pending %d, dropped %d", len(a.pending), a.dropped.Load())
	}
}

// The streaming aggregator of the gate gives the results of the
// storage-bounds incident_aggregate vectors (D38): the numbers on the block
// pages and the rows after folding the pending hits.
func TestIncidentAggregateVectors(t *testing.T) {
	files, _ := filepath.Glob("../../../contracts/vectors/storage-bounds/valid/*.json")
	n := 0
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var v struct {
			Input struct {
				Op       string `json:"op"`
				MaxOpen  int    `json:"max_open"`
				Requests []struct {
					Client string   `json:"client"`
					Rules  []string `json:"rules"`
					Limit  string   `json:"limit"`
					T      int64    `json:"t"`
					Draw   string   `json:"draw"`
				} `json:"requests"`
			} `json:"input_decoded"`
			Expect struct {
				Result storage.AggregateResult `json:"result"`
			} `json:"expect"`
		}
		if err := json.Unmarshal(raw, &v); err != nil {
			t.Fatal(f, err)
		}
		if v.Input.Op != "incident_aggregate" {
			continue
		}
		n++
		t.Run(filepath.Base(f), func(t *testing.T) {
			a := newAggregator(v.Input.MaxOpen)
			rows := map[string]*storage.Aggregated{}
			var numbers []string
			for _, r := range v.Input.Requests {
				k := aggKey{client: r.Client, rule: storage.RuleKey(r.Rules, r.Limit)}
				id, joined := a.assign(k, r.T, func() string { return r.Draw })
				numbers = append(numbers, id)
				if !joined {
					if rows[id] != nil {
						t.Fatalf("number %s drawn twice", id)
					}
					rows[id] = &storage.Aggregated{Incident: id, Client: r.Client, RuleKey: k.rule, MinuteMS: r.T - r.T%60000, Count: 1, FirstMS: r.T, LastMS: r.T}
				}
			}
			hits, _ := a.take()
			for _, h := range hits {
				x := rows[h.Incident]
				x.Count += h.Count
				x.FirstMS, x.LastMS = min(x.FirstMS, h.FirstMS), max(x.LastMS, h.LastMS)
			}
			want := v.Expect.Result
			if strings.Join(numbers, " ") != strings.Join(want.Numbers, " ") {
				t.Fatalf("numbers %v, want %v", numbers, want.Numbers)
			}
			if len(rows) != len(want.Incidents) {
				t.Fatalf("%d incidents, want %d", len(rows), len(want.Incidents))
			}
			for _, w := range want.Incidents {
				if got := rows[w.Incident]; got == nil || *got != w {
					t.Fatalf("incident %s: %+v, want %+v", w.Incident, got, w)
				}
			}
		})
	}
	if n < 7 {
		t.Fatalf("%d incident_aggregate vectors, want at least 7 (021-027)", n)
	}
}

// clock is a settable g.Now.
type clock struct{ ms atomic.Int64 }

func (c *clock) now() time.Time      { return time.UnixMilli(c.ms.Load()) }
func (c *clock) set(t time.Time)     { c.ms.Store(t.UnixMilli()) }
func (c *clock) add(d time.Duration) { c.ms.Add(d.Milliseconds()) }

// blockFrom sends a blocked request from ip and returns the incident
// number on its block page.
func (e *tenv) blockFrom(t *testing.T, ip, path string) string {
	t.Helper()
	req, _ := http.NewRequest("GET", e.srv.URL+path, nil)
	req.Host = "shop.example"
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0")
	req.Header.Set("Accept", "text/html")
	req.Header.Set("X-Forwarded-For", ip)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	_, _ = b.ReadFrom(resp.Body)
	resp.Body.Close()
	inc := resp.Header.Get("X-Schild-Incident")
	if resp.StatusCode != 403 || inc == "" || !strings.Contains(b.String(), inc) {
		t.Fatalf("%s %s: status %d, incident %q", ip, path, resp.StatusCode, inc)
	}
	return inc
}

// waitCount waits until the incident row has count n (the hits are folded
// in every aggFlushInterval).
func (e *tenv) waitCount(t *testing.T, id string, n int64) *store.Incident {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		in, err := e.st.GetIncident(context.Background(), id)
		if err == nil && in.Count == n {
			return in
		}
		if time.Now().After(deadline) {
			t.Fatalf("incident %s: %+v %v, want count %d", id, in, err, n)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

const xss = "/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"

func TestIncidentAggregateFlood(t *testing.T) {
	e := newEnv(t, decide.ModeAutoblock)
	var c clock
	t0 := time.Date(2026, 10, 29, 12, 0, 10, 0, time.UTC)
	c.set(t0)
	e.g.Now = c.now

	// A flood of one client and rule in one minute: one row, one number.
	const n = 40
	first := e.blockFrom(t, "203.0.113.9", sqli)
	for i := 1; i < n; i++ {
		c.add(time.Second)
		if got := e.blockFrom(t, "203.0.113.9", sqli); got != first {
			t.Fatalf("request %d: incident %s, want %s", i, got, first)
		}
	}
	in := e.waitCount(t, first, n)
	if !in.Time.Equal(t0) || !in.FirstSeen.Equal(t0) || !in.LastSeen.Equal(t0.Add((n-1)*time.Second)) {
		t.Fatalf("aggregate times: %+v", in)
	}
	rows, err := e.st.IncidentsBetween(context.Background(), t0.Add(-time.Hour), t0.Add(time.Hour), "", 100)
	if err != nil || len(rows) != 1 || rows[0].Count != n {
		t.Fatalf("rows: %v %d", err, len(rows))
	}
	blocked := e.events(t, store.EventFilter{Type: events.RequestBlocked})
	if len(blocked) != n {
		t.Fatalf("%d blocked events, want %d", len(blocked), n)
	}
	for _, b := range blocked {
		if b.Incident != first {
			t.Fatalf("event carries %s, want %s", b.Incident, first)
		}
	}
	if got := e.g.Counters.Rolling.Sum(stats.Incidents, time.Hour, c.now()); got != 1 {
		t.Fatalf("incident counter %d, want 1", got)
	}

	// Another client, and the same client with another rule key, get their
	// own incidents; both aggregate on their own.
	other := e.blockFrom(t, "203.0.113.10", sqli)
	rule := e.blockFrom(t, "203.0.113.9", xss)
	if other == first || rule == first || other == rule {
		t.Fatalf("not separated: %s %s %s", first, other, rule)
	}
	if e.blockFrom(t, "203.0.113.10", sqli) != other || e.blockFrom(t, "203.0.113.9", xss) != rule {
		t.Fatal("separate keys must aggregate on their own")
	}
	// IPv6: one /64 is one client.
	v6 := e.blockFrom(t, "2001:db8:1:2::1", sqli)
	if e.blockFrom(t, "2001:db8:1:2:ffff::9", sqli) != v6 || e.blockFrom(t, "2001:db8:1:3::1", sqli) == v6 {
		t.Fatal("IPv6 key must be the /64")
	}

	// The next minute closes every open aggregate.
	c.set(t0.Add(time.Minute))
	next := e.blockFrom(t, "203.0.113.9", sqli)
	if next == first {
		t.Fatal("a later minute must start a new incident")
	}
	if e.blockFrom(t, "203.0.113.9", sqli) != next {
		t.Fatal("the new minute must aggregate")
	}
	e.waitCount(t, next, 2)
	e.waitCount(t, other, 2)
	e.waitCount(t, rule, 2)
	if in := e.waitCount(t, first, n); in.Count != n {
		t.Fatal("closed incident changed")
	}
	// A request of the closed minute gets its own incident.
	c.set(t0.Add(30 * time.Second))
	late := e.blockFrom(t, "203.0.113.9", sqli)
	if late == first || late == next {
		t.Fatal("a request of a closed minute must get its own incident")
	}
	e.waitCount(t, late, 1)
}

func TestIncidentAggregateOpenCap(t *testing.T) {
	e := newEnv(t, decide.ModeAutoblock)
	var c clock
	c.set(time.Date(2026, 10, 29, 12, 0, 10, 0, time.UTC))
	e.g.Now = c.now
	e.g.agg = newAggregator(1)
	a := e.blockFrom(t, "203.0.113.1", sqli)
	b1 := e.blockFrom(t, "203.0.113.2", sqli)
	b2 := e.blockFrom(t, "203.0.113.2", sqli)
	if b1 == b2 || b1 == a {
		t.Fatalf("with every slot taken each request gets its own incident: %s %s %s", a, b1, b2)
	}
	if e.blockFrom(t, "203.0.113.1", sqli) != a {
		t.Fatal("the open aggregate keeps aggregating")
	}
	e.waitCount(t, a, 2)
	e.waitCount(t, b1, 1)
	e.waitCount(t, b2, 1)
}

// Concurrent requests of one key all show the one number (run with -race).
func TestIncidentAggregateConcurrent(t *testing.T) {
	e := newEnv(t, decide.ModeAutoblock)
	e.patient()
	var c clock
	c.set(time.Date(2026, 10, 29, 12, 0, 10, 0, time.UTC))
	e.g.Now = c.now
	const workers, per = 8, 10
	var mu sync.Mutex
	seen := map[string]int{}
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < per; i++ {
				id := e.blockFrom(t, "198.51.100.7", sqli)
				mu.Lock()
				seen[id]++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if len(seen) != 1 {
		t.Fatalf("numbers %v, want one", seen)
	}
	for id := range seen {
		e.waitCount(t, id, workers*per)
	}
}

// TestFlushIncidents: FlushIncidents stores the queued incident and folds
// the pending hits at once, without waiting for the 500 ms tick (flaky
// TestAPIContract, evening measurement 2026-10-29 6).
func TestFlushIncidents(t *testing.T) {
	e := newEnv(t, decide.ModeAutoblock)
	var c clock
	c.set(time.Date(2026, 10, 29, 12, 0, 10, 0, time.UTC))
	e.g.Now = c.now
	first := e.blockFrom(t, "203.0.113.19", sqli)
	c.add(time.Second)
	if got := e.blockFrom(t, "203.0.113.19", sqli); got != first {
		t.Fatalf("second block: %s, want %s", got, first)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	e.g.FlushIncidents(ctx)
	in, err := e.st.GetIncident(context.Background(), first)
	if err != nil || in.Count != 2 {
		t.Fatalf("after FlushIncidents: %+v %v, want count 2", in, err)
	}
}

// A hit whose row is missing is retried and dropped after aggMaxTries.
func TestIncidentAggregateRetry(t *testing.T) {
	a := newAggregator(storage.MaxOpenAggregates)
	k := aggKey{client: "c1", rule: "942100"}
	id, _ := a.assign(k, 1000, func() string { return "K7QM-4XWD" })
	if got, joined := a.assign(k, 2000, nil); got != id || !joined {
		t.Fatal("join")
	}
	for i := 0; i < aggMaxTries; i++ {
		hits, tries := a.take()
		if len(hits) != 1 || hits[0].Count != 1 {
			t.Fatalf("try %d: %+v", i, hits)
		}
		a.retry(hits, tries)
	}
	if hits, _ := a.take(); len(hits) != 0 {
		t.Fatalf("hits kept after %d tries", aggMaxTries)
	}
	// forget closes the aggregate: the next request draws a new number.
	a.forget(k, id)
	if got, joined := a.assign(k, 3000, func() string { return "A2BC-3DEF" }); got != "A2BC-3DEF" || joined {
		t.Fatal("forget")
	}
}
