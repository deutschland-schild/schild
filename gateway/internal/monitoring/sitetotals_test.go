package monitoring

import (
	"fmt"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/contract/config"
	cm "github.com/deutschland-schild/schild/contract/monitoring"
)

// sitesMonitor fills the 10 min ring (14 days) with heavy buckets of w
// websites, each with its top lists, and different counters per website.
func sitesMonitor(tb testing.TB, end time.Time, w int) *Monitor {
	tb.Helper()
	m, err := New(Config{StoragePath: tb.TempDir(), Keep: config.MonitoringKeep{TenSecondsHours: 6, MinuteHours: 48, TenMinuteDays: 14}}, end)
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { _ = m.Close() })
	for i := 1; i <= 2016; i++ {
		start := end.Add(-time.Duration(i) * 10 * time.Minute)
		b := heavyBucket(start, cm.Res10m, 600, i)
		for j := 0; j < w; j++ {
			st := siteTraffic(fmt.Sprintf("site-%02d.example", j), true)
			st.Traffic.Requests, st.Traffic.Stopped, st.Traffic.WouldBlock = int64(100+j+i%7), int64(j%5), int64(i%3)
			b.Sites = append(b.Sites, st)
		}
		if err := m.store.put(m.rings[2], start, &b); err != nil {
			tb.Fatal(err)
		}
	}
	return m
}

// TestBreakdownBySiteTotalsRow: the breakdown by=site reads the totals row
// of every bucket and sums the counters of each website.
func TestBreakdownBySiteTotalsRow(t *testing.T) {
	end := time.Now().UTC().Truncate(10 * time.Minute)
	m := sitesMonitor(t, end, 4)
	from := end.Add(-14 * 24 * time.Hour)
	withRow, err := m.Breakdown("site", from, end, "", nil, 50, end)
	if err != nil || len(withRow.Items) != 4 {
		t.Fatalf("by=site: %v %+v", err, withRow.Items)
	}
	var want int64
	for i := 1; i < 2016; i++ { // the oldest slot is outside the 14 days kept
		want += int64(100 + 2 + i%7)
	}
	for _, it := range withRow.Items {
		if it.Key == "site-02.example" && it.Requests != want {
			t.Fatalf("site-02 requests %d, want %d", it.Requests, want)
		}
	}
}

// TestBreakdownBySiteLatency (evening measurement 2026-10-29 4.2): the
// breakdown by=site over 14 days must not scale with the number of
// websites; targets 300 ms up to 8 websites, 1 s at 32. The bound here is
// twice the target so a busy CI machine passes; the numbers are logged.
func TestBreakdownBySiteLatency(t *testing.T) {
	if testing.Short() || raceEnabled {
		t.Skip("timing guard")
	}
	end := time.Now().UTC().Truncate(10 * time.Minute)
	for _, c := range []struct {
		w     int
		limit time.Duration
	}{{8, 600 * time.Millisecond}, {32, 2 * time.Second}} {
		m := sitesMonitor(t, end, c.w)
		d := time.Hour
		for i := 0; i < 3; i++ {
			t0 := time.Now()
			bd, err := m.Breakdown("site", end.Add(-14*24*time.Hour), end, "", nil, 50, end)
			if err != nil || len(bd.Items) != c.w {
				t.Fatal(err, len(bd.Items))
			}
			d = min(d, time.Since(t0))
		}
		t.Logf("by=site 14 d, %d websites: %v", c.w, d)
		if d > c.limit {
			t.Errorf("by=site with %d websites: %v (target %v)", c.w, d, c.limit/2)
		}
	}
}

// BenchmarkBreakdownBySite: go test -run - -bench BySite ./internal/monitoring
func BenchmarkBreakdownBySite(b *testing.B) {
	end := time.Now().UTC().Truncate(10 * time.Minute)
	for _, w := range []int{8, 32} {
		m := sitesMonitor(b, end, w)
		b.Run(fmt.Sprintf("w%d", w), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				if _, err := m.Breakdown("site", end.Add(-14*24*time.Hour), end, "", nil, 50, end); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
