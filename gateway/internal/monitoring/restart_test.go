package monitoring

import (
	"testing"
	"time"

	"github.com/deutschland-schild/schild/contract/config"
	cm "github.com/deutschland-schild/schild/contract/monitoring"
)

// TestRestartKeepsBucketInProgress (D36 fix round 1, finding D.1): a
// graceful shutdown in the middle of a 10 min bucket writes its part
// (partial), the next process merges its own part into the same bucket,
// and the KPIs over a range with that bucket or a gap are never exact.
func TestRestartKeepsBucketInProgress(t *testing.T) {
	dir := t.TempDir()
	base := time.Now().UTC().Truncate(10 * time.Minute).Add(-2 * time.Hour)
	open := func(started time.Time) *Monitor {
		m, err := New(Config{StoragePath: dir, Keep: config.MonitoringKeep{TenSecondsHours: 6, MinuteHours: 48, TenMinuteDays: 14},
			Sampler: SamplerConfig{Root: fixtureRoot(t), Linux: true, Host: true, Started: started, Version: "test"}, Sites: testSites(t)}, started)
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	run := func(m *Monitor, from, to int) int {
		calls := 0
		for s := from; s <= to; s++ {
			m.flushWrites()
			if s%10 == 1 {
				siteTrafficMix(m)
				calls++
			}
			m.Tick(base.Add(time.Duration(s) * time.Second))
		}
		m.flushWrites()
		return calls
	}
	const perCall = 8 // siteTrafficMix: 6 shop + 2 verein

	// Process 1: one full bucket, then half of the next; graceful stop.
	// The first bucket of a process is always partial; start one earlier.
	m1 := open(base.Add(-601 * time.Second))
	run(m1, -599, 0)
	full := run(m1, 1, 600)
	before := run(m1, 601, 930)
	if err := m1.Close(); err != nil {
		t.Fatal(err)
	}
	// Process 2 starts 5 s later inside the same buckets (1 min and 10 min).
	m2 := open(base.Add(935 * time.Second))
	after := run(m2, 936, 1200)

	page, err := m2.Buckets("10m", base, "", 10, base.Add(1200*time.Second))
	if err != nil || len(page.Items) != 2 {
		t.Fatalf("%v %d buckets", err, len(page.Items))
	}
	b0, b1 := page.Items[0], page.Items[1]
	if b0.Partial || b0.Traffic.Requests != int64(full*perCall) {
		t.Fatalf("first bucket: partial %v requests %d", b0.Partial, b0.Traffic.Requests)
	}
	if !b1.Partial || b1.Traffic.Requests != int64((before+after)*perCall) {
		t.Fatalf("restart bucket: partial %v requests %d, want %d", b1.Partial, b1.Traffic.Requests, (before+after)*perCall)
	}
	// An orderly stop and start: gap_kind restart (contracts v0.5).
	if b0.GapKind != "" || b1.GapKind != cm.GapRestart {
		t.Fatalf("gap kinds: %q %q", b0.GapKind, b1.GapKind)
	}
	var siteSum int64
	for _, s := range b1.Sites {
		siteSum += s.Traffic.Requests
	}
	if siteSum != b1.Traffic.Requests || b1.Sites[0].Top == nil {
		t.Fatalf("sites of the merged bucket: %d != %d, %+v", siteSum, b1.Traffic.Requests, b1.Sites)
	}
	// The 1 min bucket of the restart minute is merged too.
	p1, _ := m2.Buckets("1m", base.Add(900*time.Second), "", 1, base.Add(1200*time.Second))
	if len(p1.Items) != 1 || !p1.Items[0].Partial || p1.Items[0].Traffic.Requests != int64(5*perCall) {
		t.Fatalf("1 min restart bucket: %+v", p1.Items)
	}

	k, err := m2.Kpis("shop.example.org", base, base.Add(1200*time.Second), nil, base.Add(1200*time.Second))
	if err != nil || k.Requests.Value == nil {
		t.Fatal(err)
	}
	// A restart makes the window partial; exact stays "counted" (contracts
	// v0.5, D36 fix round 1: partial next to exact).
	if *k.Requests.Value != float64((full+before+after)*6) || !k.Requests.Partial || !k.Stopped.Partial || !k.Requests.Exact || !k.Stopped.Exact ||
		k.Requests.GapKind != cm.GapRestart {
		t.Fatalf("kpis over the restart: %v %+v", *k.Requests.Value, k.Requests)
	}
	if k.Visitors.Value != nil && (!k.Visitors.Partial || k.Visitors.Exact) {
		t.Fatalf("visitors over the restart: %+v", k.Visitors)
	}
	k, _ = m2.Kpis("shop.example.org", base, base.Add(600*time.Second), nil, base.Add(1200*time.Second))
	if !k.Requests.Exact || k.Requests.Partial || k.Requests.GapKind != "" {
		t.Fatal("kpis over a complete range must be exact and not partial")
	}
	// Totals coverage (traffic_24h_partial and _since, D36 open items).
	now2 := base.Add(1200 * time.Second)
	if _, cov, err := m2.TotalsCovered("shop.example.org", base, base.Add(600*time.Second), now2); err != nil || cov.Partial || !cov.Since.IsZero() {
		t.Fatalf("complete range: %v %+v", err, cov)
	}
	if _, cov, _ := m2.TotalsCovered("shop.example.org", base, now2, now2); !cov.Partial || !cov.Since.IsZero() {
		t.Fatalf("range over the restart: %+v", cov)
	}
	if tc, cov, _ := m2.TotalsCovered("shop.example.org", base.Add(-time.Hour), now2, now2); !cov.Partial || !cov.Since.Equal(base.Add(-600*time.Second)) || tc.Requests == 0 {
		t.Fatalf("range before the first start: %+v", cov)
	}
	bd, err := m2.Breakdown("method", base, base.Add(1200*time.Second), "shop.example.org", nil, 10, base.Add(1200*time.Second))
	if err != nil || !bd.Exact || !bd.Partial || bd.Source != "rings" || bd.GapKind != cm.GapRestart {
		t.Fatalf("breakdown over the restart: %v exact %v partial %v", err, bd.Exact, bd.Partial)
	}
	bd, _ = m2.Breakdown("method", base, base.Add(600*time.Second), "shop.example.org", nil, 10, base.Add(1200*time.Second))
	if !bd.Exact || bd.Partial {
		t.Fatalf("breakdown over a complete range: exact %v partial %v", bd.Exact, bd.Partial)
	}

	// status_class filter (finding B.4.4 a): the WAF blocks answered 403
	// are the stopped requests of 4xx, never 0 marked exact.
	k, err = m2.Kpis("shop.example.org", base, base.Add(600*time.Second), []string{"status_class:4xx"}, base.Add(1200*time.Second))
	if err != nil || k.Requests.Value == nil || k.Stopped.Value == nil {
		t.Fatal(err)
	}
	if *k.Requests.Value != float64(full) || *k.Stopped.Value != float64(full) || k.Stopped.Exact || !k.Requests.Exact || k.WouldBlock.Unavailable != "filter_needs_requests" {
		t.Fatalf("status_class:4xx: requests %v stopped %v exact %v would %+v", *k.Requests.Value, *k.Stopped.Value, k.Stopped.Exact, k.WouldBlock)
	}
	k, _ = m2.Kpis("shop.example.org", base, base.Add(600*time.Second), []string{"status_class:5xx"}, base.Add(1200*time.Second))
	if *k.Stopped.Value != 0 {
		t.Fatalf("status_class:5xx stopped %v", *k.Stopped.Value)
	}

	// A crash: process 2 ends without Close (nothing flushed), process 3
	// starts two buckets later; the lost bucket is a gap, not exact.
	m2.cancel = nil
	_ = m2.store.close()
	m3 := open(base.Add(2405 * time.Second))
	defer m3.Close()
	run(m3, 2406, 3000)
	end := base.Add(3000 * time.Second)
	if g := m3.Gaps(base, end, end, 10); len(g) != 1 || !g[0].From.Equal(base.Add(1200*time.Second)) {
		t.Fatalf("gaps %+v", g)
	}
	k, _ = m3.Kpis("shop.example.org", base.Add(1200*time.Second), end, nil, end)
	if !k.Requests.Partial || !k.Requests.Exact || k.Requests.GapKind != cm.GapLost {
		t.Fatalf("kpis over a lost bucket must be partial (lost) and still counted: %+v", k.Requests)
	}
	if _, cov, _ := m3.TotalsCovered("shop.example.org", base.Add(1200*time.Second), end, end); !cov.Partial || !cov.Since.Equal(base.Add(2400*time.Second)) {
		t.Fatalf("range starting with a lost bucket: %+v", cov)
	}
	if _, cov, _ := m3.TotalsCovered("shop.example.org", base, end, end); !cov.Partial || !cov.Since.IsZero() {
		t.Fatalf("range with a gap inside: %+v", cov)
	}
}

// TestHardKillKpisFromMinutes (D36 fix round 2, re-measurement A 2.2 and
// D): a hard kill loses the 10 min bucket in progress up to the kill; the
// KPIs and totals read that bucket from the 1 min ring, so only the minute
// of the kill is missing, and the range stays partial.
func TestHardKillKpisFromMinutes(t *testing.T) {
	dir := t.TempDir()
	base := time.Now().UTC().Truncate(10 * time.Minute).Add(-2 * time.Hour)
	open := func(started time.Time) *Monitor {
		m, err := New(Config{StoragePath: dir, Keep: config.MonitoringKeep{TenSecondsHours: 6, MinuteHours: 48, TenMinuteDays: 14},
			Sampler: SamplerConfig{Root: fixtureRoot(t), Linux: true, Host: true, Started: started, Version: "test"}, Sites: testSites(t)}, started)
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	run := func(m *Monitor, from, to int) int {
		calls := 0
		for s := from; s <= to; s++ {
			m.flushWrites()
			if s%10 == 1 {
				siteTrafficMix(m)
				calls++
			}
			m.Tick(base.Add(time.Duration(s) * time.Second))
		}
		m.flushWrites()
		return calls
	}
	const shop = 6 // shop requests per siteTrafficMix (8 with verein)
	m1 := open(base.Add(-601 * time.Second))
	run(m1, -599, 0)
	written := run(m1, 1, 299) // the minutes up to 5:00 are written
	run(m1, 300, 330)          // the minute of the kill is lost
	m1.cancel = nil            // SIGKILL: nothing flushed
	_ = m1.store.close()
	m2 := open(base.Add(340 * time.Second))
	defer m2.Close()
	after := run(m2, 341, 1200)
	now := base.Add(1205 * time.Second)
	want := float64((written + after) * shop)
	k, err := m2.Kpis("shop.example.org", base, base.Add(1200*time.Second), nil, now)
	if err != nil || k.Requests.Value == nil {
		t.Fatal(err)
	}
	if *k.Requests.Value != want || !k.Requests.Partial || !k.Requests.Exact || k.Requests.GapKind != cm.GapLost {
		t.Fatalf("requests over the kill: %v %+v, want %v", *k.Requests.Value, k.Requests, want)
	}
	tot, err := m2.Totals("shop.example.org", base, base.Add(1200*time.Second), now)
	if err != nil || float64(tot.Requests) != want {
		t.Fatalf("totals over the kill: %v %+v, want %v", err, tot, want)
	}
	whole, _ := m2.Kpis("", base, base.Add(1200*time.Second), nil, now)
	if *whole.Requests.Value != float64((written+after)*8) || !whole.Requests.Partial {
		t.Fatalf("gateway requests over the kill: %+v", whole.Requests)
	}
}

// TestHardKillBreakdownSeriesFromMinutes (evening measurement 2026-10-29
// 4.3): after a SIGKILL the breakdowns and series of the 10 min ring read
// the damaged 10 min bucket from the 1 min ring like the KPIs (only the
// minute of the kill is missing, -51 % before), and stay partial. A
// website's list breakdown has no per-website lists in the 1 min ring: it
// reads the 10 min bucket as it is, partial.
func TestHardKillBreakdownSeriesFromMinutes(t *testing.T) {
	dir := t.TempDir()
	base := time.Now().UTC().Truncate(10 * time.Minute).Add(-2 * time.Hour)
	open := func(started time.Time) *Monitor {
		m, err := New(Config{StoragePath: dir, Keep: config.MonitoringKeep{TenSecondsHours: 6, MinuteHours: 48, TenMinuteDays: 14},
			Sampler: SamplerConfig{Root: fixtureRoot(t), Linux: true, Host: true, Started: started, Version: "test"}, Sites: testSites(t)}, started)
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	run := func(m *Monitor, from, to int) int {
		calls := 0
		for s := from; s <= to; s++ {
			m.flushWrites()
			if s%10 == 1 {
				siteTrafficMix(m)
				calls++
			}
			m.Tick(base.Add(time.Duration(s) * time.Second))
		}
		m.flushWrites()
		return calls
	}
	m1 := open(base.Add(-601 * time.Second))
	run(m1, -599, 0)
	written := run(m1, 1, 299)
	run(m1, 300, 330) // the minute of the kill is lost
	m1.cancel = nil   // SIGKILL: nothing flushed
	_ = m1.store.close()
	m2 := open(base.Add(340 * time.Second))
	defer m2.Close()
	inKill := written + run(m2, 341, 600)
	run(m2, 601, 1200)
	now := base.Add(1205 * time.Second)
	// More than 1000 minutes: the breakdown reads the 10 min ring.
	from, to := base.Add(-22*time.Hour), base.Add(1200*time.Second)
	k, err := m2.Kpis("", from, to, nil, now)
	if err != nil || k.Requests.Value == nil {
		t.Fatal(err)
	}
	bd, err := m2.Breakdown("method", from, to, "", nil, 10, now)
	if err != nil || bd.Resolution != "10m" || !bd.Partial {
		t.Fatalf("breakdown: %v resolution %s partial %v", err, bd.Resolution, bd.Partial)
	}
	if float64(bd.Total.Requests) != *k.Requests.Value || float64(bd.Total.Stopped) != *k.Stopped.Value {
		t.Fatalf("breakdown total %+v, KPIs requests %v stopped %v", bd.Total, *k.Requests.Value, *k.Stopped.Value)
	}
	var items int64
	for _, it := range bd.Items {
		items += it.Requests
	}
	if items != bd.Total.Requests {
		t.Fatalf("method items %d, total %d", items, bd.Total.Requests)
	}
	// The kill bucket by website: every minute but the one of the kill.
	kb, _ := m2.Breakdown("site", base.Add(-22*time.Hour), base.Add(600*time.Second), "", nil, 10, now)
	var shop int64
	for _, it := range kb.Items {
		if it.Key == "shop.example.org" {
			shop = it.Requests
		}
	}
	kbOld, _ := m2.Breakdown("site", base.Add(-22*time.Hour), base, "", nil, 10, now)
	for _, it := range kbOld.Items {
		if it.Key == "shop.example.org" {
			shop -= it.Requests
		}
	}
	if want := int64(inKill * 6); shop != want || !kb.Partial {
		t.Fatalf("kill bucket by=site shop %d (partial %v), want %d", shop, kb.Partial, want)
	}
	sk, _ := m2.Kpis("shop.example.org", from, to, nil, now)
	sbd, err := m2.Breakdown("status_class", from, to, "shop.example.org", nil, 10, now)
	if err != nil || float64(sbd.Total.Requests) != *sk.Requests.Value || !sbd.Partial {
		t.Fatalf("website status_class: %v total %+v, KPIs %v", err, sbd.Total, *sk.Requests.Value)
	}
	// A website's list breakdown: the 10 min bucket as stored, partial.
	pbd, err := m2.Breakdown("path", from, to, "shop.example.org", nil, 10, now)
	if err != nil || !pbd.Partial {
		t.Fatalf("website path breakdown: %v partial %v", err, pbd.Partial)
	}
	// Series at 10 min: the kill bucket counts its minutes and is partial.
	sr, err := m2.Series(SeriesQuery{Metrics: []string{"traffic.requests"}, From: base, To: base.Add(1200 * time.Second), Resolution: "10m"}, now)
	if err != nil || len(sr.Series) != 1 || sr.Points != 2 {
		t.Fatalf("series: %v %+v", err, sr)
	}
	v := sr.Series[0].Values[0]
	// The rate divides by the seconds covered: minutes 0-4, 20 s of minute 5 after the start, 6-9.
	if want := float64(inKill*8) / 560; v == nil || *v != want || sr.Partial == nil || !sr.Partial[0] {
		t.Fatalf("series kill bucket %v partial %v, want %v", *v, sr.Partial, float64(inKill*8)/560)
	}
}

// TestMinuteCheckpoint (contracts v0.5, D33/D36 amendment 2026-10-29):
// the running 10 min bucket is written every minute with its websites and
// their top lists (partial, gap_kind lost) and hidden from reads while it
// is collected; after a hard kill the checkpoint stays, so at most the
// last minute is lost, also from a website's top lists, and a process
// starting inside the same bucket resumes from it.
func TestMinuteCheckpoint(t *testing.T) {
	for _, resume := range []bool{false, true} {
		dir := t.TempDir()
		base := time.Now().UTC().Truncate(10 * time.Minute).Add(-3 * time.Hour)
		open := func(started time.Time) *Monitor {
			m, err := New(Config{StoragePath: dir, Keep: config.MonitoringKeep{TenSecondsHours: 6, MinuteHours: 48, TenMinuteDays: 14},
				Sampler: SamplerConfig{Root: fixtureRoot(t), Linux: true, Host: true, Started: started, Version: "test"}, Sites: testSites(t)}, started)
			if err != nil {
				t.Fatal(err)
			}
			return m
		}
		run := func(m *Monitor, from, to int) int {
			calls := 0
			for s := from; s <= to; s++ {
				m.flushWrites()
				if s%10 == 1 {
					siteTrafficMix(m)
					calls++
				}
				m.Tick(base.Add(time.Duration(s) * time.Second))
			}
			m.flushWrites()
			return calls
		}
		const perCall, shop = 8, 6
		m1 := open(base.Add(-601 * time.Second))
		run(m1, -599, 600)
		kept := run(m1, 601, 900) // checkpoint at 15:00
		run(m1, 901, 950)         // lost with the kill
		at := base.Add(950 * time.Second)
		if p, _ := m1.Buckets("10m", base, "", 10, at); len(p.Items) != 1 {
			t.Fatalf("the bucket in progress must stay hidden: %d buckets", len(p.Items))
		}
		m1.cancel = nil // SIGKILL: nothing flushed
		_ = m1.store.close()

		start := 2405 // a later bucket
		if resume {
			start = 955 // inside the same bucket
		}
		m2 := open(base.Add(time.Duration(start) * time.Second))
		after := 0
		if resume {
			after = run(m2, start+1, 1200)
		} else {
			run(m2, start+1, 3000)
		}
		now := base.Add(3000 * time.Second)
		p, err := m2.Buckets("10m", base.Add(600*time.Second), "", 1, now)
		if err != nil || len(p.Items) != 1 {
			t.Fatalf("%v %+v", err, p.Items)
		}
		b := p.Items[0]
		if !b.Partial || b.GapKind != cm.GapLost || b.Traffic.Requests != int64((kept+after)*perCall) {
			t.Fatalf("resume %v: partial %v gap %q requests %d, want %d", resume, b.Partial, b.GapKind, b.Traffic.Requests, (kept+after)*perCall)
		}
		var shopTop int64
		for _, st := range b.Sites {
			if st.Site == "shop.example.org" {
				if st.Top == nil || st.Clients == nil {
					t.Fatalf("website without top lists or clients: %+v", st)
				}
				for _, e := range st.Top.Method {
					shopTop += e.Requests
				}
			}
		}
		if shopTop != int64((kept+after)*shop) {
			t.Fatalf("resume %v: website method list %d, want %d", resume, shopTop, (kept+after)*shop)
		}
		// A website's list breakdown reads the 10 min bucket as it is.
		bd, err := m2.Breakdown("path", base.Add(600*time.Second), base.Add(1200*time.Second), "shop.example.org", nil, 10, now)
		if err != nil || bd.Total.Requests != int64((kept+after)*shop) || !bd.Partial || bd.GapKind != cm.GapLost {
			t.Fatalf("resume %v: breakdown %v %+v", resume, err, bd)
		}
		_ = m2.Close()
	}
}
