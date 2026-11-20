package monitoring

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/deutschland-schild/schild/contract/config"
	cm "github.com/deutschland-schild/schild/contract/monitoring"
	"github.com/deutschland-schild/schild/contract/storage"
)

// Disk hints of D38 (contracts/storage-bounds.md sections 2 and 7):
// storage_budget, decided by the app (it knows the configuration) and handed
// in with SetStorageBudget, and disk_fill_projection, computed here from the
// existing 10 min ring of server.disk_used (no new sampling).

const (
	// projectionEvery: the projection is recomputed at most once an hour
	// (the daily minima of complete days are cached, so a refresh reads at
	// most the days not cached yet).
	projectionEvery = time.Hour
	// dayCompleteAfter: a UTC day is cached once its last 10 min bucket was
	// surely written (the writer is asynchronous).
	dayCompleteAfter = 15 * time.Minute
)

// StorageBudget is the storage_budget hint as the app decided it.
type StorageBudget struct {
	// Active: available - max(0, budget - used) < reserve.
	Active bool
	// Path is storage.path (the hint's object).
	Path string
	// Value: the bytes that would stay available once the bounds filled
	// (available - need); Threshold: the reserve.
	Value, Threshold float64
}

// RingsFor returns the rings New opens for monitoring.keep (defaults when
// keep is unset): the input of MetricsBoundBytes for the disk budget.
func RingsFor(k config.MonitoringKeep) []cm.Ring {
	if k.TenSecondsHours == 0 {
		k = config.MonitoringKeep{TenSecondsHours: config.DefaultKeepTenSecondsHours, MinuteHours: config.DefaultKeepMinuteHours, TenMinuteDays: config.DefaultKeepTenMinuteDays}
	}
	return cm.Rings(k.TenSecondsHours, k.MinuteHours, k.TenMinuteDays)
}

// diskState holds the inputs of the D38 disk hints.
type diskState struct {
	budget atomic.Pointer[StorageBudget]
	proj   atomic.Pointer[map[string]storage.ProjectionResult]

	mu   sync.Mutex
	next time.Time
	// days caches the per-mount minima of complete UTC days (day number
	// unix/86400 -> mount -> day).
	days map[int64]map[string]storage.Day
}

// SetStorageBudget sets the storage_budget hint (at start and once an hour).
func (m *Monitor) SetStorageBudget(b StorageBudget) {
	if m == nil {
		return
	}
	m.disk.budget.Store(&b)
}

// Projections returns the last disk_fill_projection results per mount
// (only mounts with a hint; nil before the first refresh).
func (m *Monitor) Projections() map[string]storage.ProjectionResult {
	if m == nil {
		return nil
	}
	if p := m.disk.proj.Load(); p != nil {
		return *p
	}
	return nil
}

// refreshProjection recomputes disk_fill_projection for every mount of the
// latest sample when an hour passed since the last refresh (sampler
// goroutine, outside mu). Complete days are read from metrics.db once and
// cached.
func (m *Monitor) refreshProjection(now time.Time) {
	d := &m.disk
	d.mu.Lock()
	defer d.mu.Unlock()
	if now.Before(d.next) {
		return
	}
	d.next = now.Add(projectionEvery)
	s := m.last.Load()
	if s == nil || len(s.snap.Mounts) == 0 {
		d.proj.Store(nil)
		return
	}
	if d.days == nil {
		d.days = map[int64]map[string]storage.Day{}
	}
	today := now.Unix() / 86400
	first := today - storage.ProjectionDays
	for k := range d.days {
		if k < first {
			delete(d.days, k)
		}
	}
	missing := int64(-1)
	for day := first; day < today; day++ {
		if _, ok := d.days[day]; !ok {
			missing = day
			break
		}
	}
	fresh := map[int64]map[string]storage.Day{}
	if missing >= 0 {
		fresh = m.dailyMinima(time.Unix(missing*86400, 0).UTC(), time.Unix(today*86400, 0).UTC().Add(-m.rings[2].Step))
		for day := missing; day < today; day++ {
			if !now.Before(time.Unix((day+1)*86400, 0).Add(dayCompleteAfter)) {
				if fresh[day] == nil {
					fresh[day] = map[string]storage.Day{}
				}
				d.days[day] = fresh[day]
			}
		}
	}
	out := map[string]storage.ProjectionResult{}
	for _, mt := range s.snap.Mounts {
		days := make([]storage.Day, storage.ProjectionDays)
		for i := range days {
			day := first + int64(i)
			src := d.days[day]
			if src == nil {
				src = fresh[day]
			}
			days[i] = src[mt.Mount]
		}
		if r := storage.Projection(mt.SizeBytes, mt.UsedBytes, days); r.Hint {
			out[mt.Mount] = r
		}
	}
	d.proj.Store(&out)
}

// dailyMinima reads the 10 min ring from..to (bucket starts) and returns per
// UTC day and mount the minimum of server.disk_used (the gauge's min of each
// bucket) and the number of buckets that carry it.
func (m *Monitor) dailyMinima(from, to time.Time) map[int64]map[string]storage.Day {
	out := map[int64]map[string]storage.Day{}
	_ = m.store.read(m.rings[2], from, to, readParts{core: coreAll, only: "-"}, func(t time.Time, b *cm.MetricBucket) {
		day := t.Unix() / 86400
		for _, o := range b.Objects {
			if o.Kind != "mount" {
				continue
			}
			g, ok := o.Values.Gauges["server.disk_used"]
			if !ok {
				continue
			}
			if out[day] == nil {
				out[day] = map[string]storage.Day{}
			}
			v := int64(g.Min)
			x, seen := out[day][o.Object]
			if !seen || v < x.MinUsedBytes {
				x.MinUsedBytes = v
			}
			x.Samples++
			out[day][o.Object] = x
		}
	})
	return out
}

// diskHints sets storage_budget and disk_fill_projection from the inputs
// above (every 10 s from evaluate, mu held; no I/O).
func (st *hintState) diskHints(m *Monitor, now time.Time) {
	if b := m.disk.budget.Load(); b != nil {
		st.set(now, b.Active, 0, cm.HintStorageBudget, "notice", b.Path, b.Value, b.Threshold)
	}
	if p := m.disk.proj.Load(); p != nil {
		for mount, r := range *p {
			if r.Hint && r.Level != nil && r.DaysLeft != nil {
				st.set(now, true, 0, cm.HintDiskFillProjection, *r.Level, mount, float64(*r.DaysLeft), storage.ProjectionHintDays)
			}
		}
	}
}
