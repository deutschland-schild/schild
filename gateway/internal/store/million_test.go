package store

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
	"time"
)

// millionStore builds a store with n events over 7 days (half of them in
// the last 24 h, as in the D36 re-measurement's bulk store): five websites,
// few client addresses with many events each, a frequent path prefix
// /search next to /p/N, about 10 % alert events, and incidents of the same
// addresses, one every 12 s over 7 days.
func millionStore(t testing.TB, n, incidents int) (*Store, time.Time) {
	t.Helper()
	s, err := Open(t.TempDir() + "/schild.db")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	now := time.Now().UTC()
	sites := []string{"shop.test", "app.test", "blog.test", "slow.test", "down.test"}
	// Bodies of a realistic size (stored events are 1-2 KB).
	body := []byte(`{"data":{"client":{"geo":{"net_class":"residential"}},"pad":"` + strings.Repeat("x", 1400) + `"}}`)
	var batch []*EventRow
	for i := 0; i < n; i++ {
		// Oldest first: the second half in the last 24 h.
		var at time.Time
		if i < n/2 {
			at = now.Add(-7 * 24 * time.Hour).Add(time.Duration(i) * (6 * 24 * time.Hour) / time.Duration(n/2))
		} else {
			at = now.Add(-24 * time.Hour).Add(time.Duration(i-n/2) * (24 * time.Hour) / time.Duration(n-n/2))
		}
		site := sites[[]int{0, 0, 0, 1, 1, 2, 3, 4, 0, 1}[i%10]]
		path := fmt.Sprintf("/p/%d", i%40)
		if i%3 == 0 {
			path = fmt.Sprintf("/search/%d", i%7)
		}
		e := &EventRow{ID: fmt.Sprintf("e-%d", i), Time: at, Type: "schild.request.evaluated.v1", Outcome: "passed",
			IP: fmt.Sprintf("198.51.100.%d", i%200), Country: "DE", ASN: 3320, Host: site, Site: site, Path: path,
			Body: body}
		switch {
		case i%20 == 0:
			e.Type, e.Outcome, e.Rules = "schild.request.blocked.v1", "blocked", []string{"941100"}
		case i%25 == 0:
			e.Outcome, e.Rules = "would_block", []string{"942100"}
		}
		batch = append(batch, e)
		if len(batch) >= 5000 {
			if err := s.InsertEvents(ctx, batch); err != nil {
				t.Fatal(err)
			}
			batch = batch[:0]
		}
	}
	if err := s.InsertEvents(ctx, batch); err != nil {
		t.Fatal(err)
	}
	tx, err := s.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < incidents; i++ {
		if _, err := tx.Exec(`INSERT INTO incidents(incident, event_id, time_ms, ip, status, sources, site) VALUES(?,?,?,?,?,?,?)`,
			fmt.Sprintf("I%07d", i), fmt.Sprintf("e-%d", i*20), ms(now.Add(-time.Duration(i)*12*time.Second)), fmt.Sprintf("198.51.100.%d", i%200),
			"blocked", "crs", sites[i%5]); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	return s, now
}

func p95(t testing.TB, name string, runs int, f func()) time.Duration {
	t.Helper()
	f() // warm
	d := make([]time.Duration, runs)
	for i := range d {
		t0 := time.Now()
		f()
		d[i] = time.Since(t0)
	}
	sort.Slice(d, func(a, b int) bool { return d[a] < d[b] })
	p := d[(runs*95+99)/100-1]
	t.Logf("%-40s p50 %8.2f ms  p95 %8.2f ms", name, float64(d[runs/2].Microseconds())/1000, float64(p.Microseconds())/1000)
	return p
}

// TestWebsiteReadsMillion (D36 fix round 2, re-measurement B 3.3 c):
// listAlerts with a frequent path prefix and listIncidents over 7 days
// (with the sites_affected lookup of every listed incident) stay under
// 100 ms with a million events. SCHILD_BENCH_MILLION=1 (builds the store
// first, about a minute).
func TestWebsiteReadsMillion(t *testing.T) {
	if os.Getenv("SCHILD_BENCH_MILLION") == "" {
		t.Skip("set SCHILD_BENCH_MILLION=1")
	}
	s, now := millionStore(t, 1_000_000, 50_400)
	defer s.Close()
	ctx := context.Background()
	limit := 100 * time.Millisecond
	for _, f := range []AlertFilter{{Path: "/search"}, {Path: "/search/3"}, {Path: "/p/1"}, {Path: "/nothing"}, {}} {
		f.Site, f.From, f.To = "shop.test", now.Add(-7*24*time.Hour), now
		if d := p95(t, "listAlerts path "+f.Path, 20, func() {
			if _, err := s.AlertEvents(ctx, f, 500); err != nil {
				t.Fatal(err)
			}
		}); d > limit {
			t.Errorf("listAlerts path %q p95 %v", f.Path, d)
		}
	}
	for _, site := range []string{"", "blog.test"} {
		if d := p95(t, "listIncidents 7d site="+site, 20, func() {
			rows, err := s.IncidentsInRange(ctx, now.Add(-7*24*time.Hour), now.Add(time.Second), IncidentFilter{Site: site}, 0, "", 51)
			if err != nil || len(rows) != 51 {
				t.Fatalf("%v %d", err, len(rows))
			}
			for _, in := range rows {
				if _, _, err := s.SitesOfIP(ctx, in.IP, in.Time.Add(-24*time.Hour), in.Time.Add(time.Millisecond), 64); err != nil {
					t.Fatal(err)
				}
			}
		}); d > limit {
			t.Errorf("listIncidents site %q p95 %v", site, d)
		}
	}
}
