package monitoring

import (
	"testing"
	"time"

	"github.com/deutschland-schild/schild/contract/config"
	cm "github.com/deutschland-schild/schild/contract/monitoring"
	"github.com/deutschland-schild/schild/contract/storage"
)

const gib = int64(1) << 30

// projNow: a UTC noon; the complete days are the 7 days before.
var projNow = time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)

func newDiskMonitor(t *testing.T) *Monitor {
	t.Helper()
	m, err := New(Config{StoragePath: t.TempDir(), Keep: config.MonitoringKeep{TenSecondsHours: 6, MinuteHours: 48, TenMinuteDays: 14}}, projNow)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Close() })
	return m
}

// replay writes 10 min buckets of server.disk_used for mount from 8 days
// before projNow up to projNow; used(t) gives the value (bytes), ok false
// leaves the bucket out (schild was not running).
func replay(t testing.TB, m *Monitor, mount string, used func(t time.Time) (int64, bool)) {
	t.Helper()
	r := m.rings[2]
	tx, err := m.store.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	for at := projNow.Add(-8 * 24 * time.Hour); at.Before(projNow); at = at.Add(r.Step) {
		v, ok := used(at)
		if !ok {
			continue
		}
		f := float64(v)
		b := &cm.MetricBucket{T: ts(at), Resolution: r.Resolution, StepS: int(r.Step.Seconds()), Sites: []cm.SiteTraffic{},
			Objects: []cm.ObjectValues{{Object: mount, Kind: "mount", Values: cm.MetricValues{Gauges: map[string]cm.GaugeStats{
				"server.disk_used": {Avg: f, Min: f, Max: f}}}}}}
		if err := putTx(tx, r, r.Slot(at), at.Unix(), b); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func setMount(m *Monitor, mount string, total, used int64) {
	m.last.Store(&sample{at: projNow, snap: ServerSnapshot{Mounts: []MountSnapshot{{Mount: mount, SizeBytes: total, UsedBytes: used}}}})
}

// utcDay: index of the UTC day of at in the projection window (0 = the
// oldest complete day).
func utcDay(at time.Time) int { return at.YearDay() - projNow.YearDay() + storage.ProjectionDays }

// daysIn: fractional days since the start of the replay.
func daysIn(at time.Time) float64 {
	return at.Sub(projNow.Add(-8*24*time.Hour)).Hours() / 24
}

func TestProjectionSteadyGrowth(t *testing.T) {
	m := newDiskMonitor(t)
	// 2 GiB a day with some noise inside the day; 20 GiB left now.
	rate := 2 * gib
	replay(t, m, "/var/lib/docker", func(at time.Time) (int64, bool) {
		noise := int64(at.Minute()) * (16 << 20)
		return 60*gib + int64(daysIn(at)*float64(rate)) + noise, true
	})
	setMount(m, "/var/lib/docker", 100*gib, 80*gib)
	m.refreshProjection(projNow)
	p := m.Projections()["/var/lib/docker"]
	if !p.Hint || *p.Level != "notice" || *p.DaysLeft != 10 {
		t.Fatalf("steady: %+v", p)
	}
	if got := float64(*p.RateBytesPerDay) / float64(rate); got < 0.7 || got > 1.3 {
		t.Errorf("rate %d is not within 30 %% of %d", *p.RateBytesPerDay, rate)
	}
	// The hint: object = mount, value = days left, reaches the server list.
	m.mu.Lock()
	m.hints.diskHints(m, projNow)
	l := m.hints.list(projNow)
	m.mu.Unlock()
	if len(l) != 1 || l[0].Code != cm.HintDiskFillProjection || l[0].Object != "/var/lib/docker" || *l[0].Value != 10 || *l[0].Threshold != 14 || l[0].Level != "notice" {
		t.Errorf("hint %+v", l)
	}

	// 4 GiB left: warning (under 3 days).
	m2 := newDiskMonitor(t)
	replay(t, m2, "/", func(at time.Time) (int64, bool) { return 60*gib + int64(daysIn(at)*float64(rate)), true })
	setMount(m2, "/", 80*gib, 76*gib)
	m2.refreshProjection(projNow)
	if p := m2.Projections()["/"]; !p.Hint || *p.Level != "warning" || *p.DaysLeft != 2 {
		t.Errorf("warning: %+v", p)
	}
}

func TestProjectionNoHint(t *testing.T) {
	cases := []struct {
		name string
		used func(time.Time) (int64, bool)
	}{
		// Logs grow 8 GiB a day and are rotated at midnight: the daily
		// minima stay flat.
		{"sawtooth", func(at time.Time) (int64, bool) {
			h := float64(at.Hour()*60+at.Minute()) / 1440
			return 70*gib + int64(h*8*float64(gib)), true
		}},
		// One copy of 25 GiB on day 4, flat before and after.
		{"one-off copy", func(at time.Time) (int64, bool) {
			if daysIn(at) >= 4.5 {
				return 95 * gib, true
			}
			return 70 * gib, true
		}},
		// Shrinking.
		{"shrinking", func(at time.Time) (int64, bool) { return 90*gib - int64(daysIn(at)*float64(gib)), true }},
		// Steady growth, but schild ran only 2 h (12 points) on 4 of the 7
		// days: 3 counted days are not enough.
		{"restart gaps", func(at time.Time) (int64, bool) {
			if d := utcDay(at); d >= 0 && d%2 == 0 && at.Hour() >= 2 {
				return 0, false
			}
			return 70*gib + int64(daysIn(at)*float64(2*gib)), true
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := newDiskMonitor(t)
			replay(t, m, "/", c.used)
			setMount(m, "/", 100*gib, 96*gib)
			m.refreshProjection(projNow)
			if p, ok := m.Projections()["/"]; ok {
				t.Errorf("hint %+v", p)
			}
		})
	}
}

func TestProjectionRestartGapsStillCount(t *testing.T) {
	m := newDiskMonitor(t)
	// Down for 18 h on 3 days: each still has 6 h (36 points); a day with 5
	// h is left out; growth 1 GiB a day, 5 GiB left.
	replay(t, m, "/", func(at time.Time) (int64, bool) {
		d := utcDay(at)
		switch {
		case d == 2 && at.Hour() >= 5:
			return 0, false
		case d >= 4 && d <= 6 && at.Hour() >= 6:
			return 0, false
		}
		return 50*gib + int64(daysIn(at)*float64(gib)), true
	})
	setMount(m, "/", 100*gib, 95*gib)
	m.refreshProjection(projNow)
	p := m.Projections()["/"]
	if !p.Hint || *p.DaysLeft != 5 || *p.Level != "notice" {
		t.Fatalf("%+v", p)
	}
}

func TestProjectionCachedHourly(t *testing.T) {
	m := newDiskMonitor(t)
	replay(t, m, "/", func(at time.Time) (int64, bool) { return 60*gib + int64(daysIn(at)*float64(2*gib)), true })
	setMount(m, "/", 100*gib, 80*gib)
	m.refreshProjection(projNow)
	if p := m.Projections()["/"]; !p.Hint || *p.DaysLeft != 10 {
		t.Fatalf("%+v", p)
	}
	// The ring changes (it would not for complete days): within the hour
	// nothing is recomputed; after it the cached days are used, only the
	// current usage is new.
	replay(t, m, "/", func(time.Time) (int64, bool) { return 60 * gib, true })
	setMount(m, "/", 100*gib, 90*gib)
	m.refreshProjection(projNow.Add(30 * time.Minute))
	if p := m.Projections()["/"]; *p.DaysLeft != 10 {
		t.Errorf("recomputed within the hour: %+v", p)
	}
	m.refreshProjection(projNow.Add(time.Hour))
	if p := m.Projections()["/"]; !p.Hint || *p.DaysLeft != 5 {
		t.Errorf("after an hour: %+v", p)
	}
	// No longer a hint once the mount is gone from the sample.
	m.last.Store(&sample{at: projNow})
	m.refreshProjection(projNow.Add(2 * time.Hour))
	if len(m.Projections()) != 0 {
		t.Errorf("%+v", m.Projections())
	}
}

func TestStorageBudgetHint(t *testing.T) {
	m := newDiskMonitor(t)
	m.SetStorageBudget(StorageBudget{Active: true, Path: "/var/lib/schild", Value: float64(512 << 20), Threshold: float64(storage.Reserve(20 << 30))})
	m.mu.Lock()
	m.hints.diskHints(m, projNow)
	l := m.hints.list(projNow)
	m.mu.Unlock()
	if len(l) != 1 || l[0].Code != cm.HintStorageBudget || l[0].Level != "notice" || l[0].Object != "/var/lib/schild" || *l[0].Threshold != float64(1<<30) {
		t.Fatalf("%+v", l)
	}
	m.SetStorageBudget(StorageBudget{Path: "/var/lib/schild"})
	m.mu.Lock()
	m.hints.diskHints(m, projNow.Add(6*time.Minute))
	l = m.hints.list(projNow.Add(6 * time.Minute))
	m.mu.Unlock()
	if len(l) != 0 {
		t.Errorf("not cleared: %+v", l)
	}
}

// BenchmarkProjectionRefresh: the first refresh after a start reads 7 days
// of the 10 min ring (1008 buckets).
func BenchmarkProjectionRefresh(b *testing.B) {
	m, err := New(Config{StoragePath: b.TempDir()}, projNow)
	if err != nil {
		b.Fatal(err)
	}
	defer m.Close()
	replay(b, m, "/", func(at time.Time) (int64, bool) { return 60*gib + int64(daysIn(at)*float64(2*gib)), true })
	setMount(m, "/", 100*gib, 80*gib)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.disk.next = time.Time{}
		m.disk.days = nil
		m.refreshProjection(projNow)
	}
}
