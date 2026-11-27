// Package monitoring is the traffic and server monitoring of `schild run`
// (MVP-21, contracts v0.4, DECISIONS D33): exact counters of every request
// that reaches the schild handler, host samples from /proc and /sys every
// 10 s, three fixed rings in <storage.path>/metrics.db, health hints, and the
// read handlers of the dashboard tag `monitoring` (also served by the agent
// API). Aggregates only: no IP address, client key, keyed hash or sketch is
// ever written or returned.
//
// Request path (Record): no allocation for a request whose path, ASN,
// referrer and rules are already in the per-second top tables; nothing
// blocks on the aggregation or on metrics.db.
package monitoring

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/deutschland-schild/schild/contract/config"
	cm "github.com/deutschland-schild/schild/contract/monitoring"
	"github.com/deutschland-schild/schild/gateway/internal/ratelog"
	"github.com/deutschland-schild/schild/gateway/internal/reqring"
	"github.com/deutschland-schild/schild/gateway/internal/sites"
)

// Internals are schild's own queues and stores (SchildInternals), read at
// every host sample.
type Internals struct {
	EventQueueUsed, EventQueueCapacity int64
	// EventsDroppedTotal is a counter since process start.
	EventsDroppedTotal          int64
	EvalSlotsUsed, EvalSlotsMax int64
	StoreBytes, StoreMaxBytes   int64
	// StoreCapUnreachable: the last size-cap pass stopped above the cap
	// (hint store_cap_unreachable, D38).
	StoreCapUnreachable bool
}

// Config of the monitor.
type Config struct {
	StoragePath string
	Keep        config.MonitoringKeep
	Sampler     SamplerConfig
	// Internals: full false is the cheap per-second part (queue, slots);
	// full true adds the store sizes (every 10 s).
	Internals func(full bool) Internals
	Log       *slog.Logger
	// Sites maps requests to websites (D36): per-website counters in every
	// ring, top lists in the 10 min ring. nil: no per-website numbers.
	Sites *sites.Registry
	// Requests is the MVP-22 request ring (nil: off). The recorder hands
	// every request to it; filters the rings cannot answer within its
	// window come from it.
	Requests *reqring.Ring
}

// Monitor collects, aggregates, stores and serves the monitoring data.
type Monitor struct {
	cfg   Config
	rec   *recorder
	store *ringStore
	// nodes: the ring stores of the other members of a group (nodes.go).
	nodes   nodeSet
	sampler *sampler
	// sampleMu serialises Sample: the sampler keeps the previous reading
	// for its rates, and Snapshot samples on the HTTP goroutine until the
	// sampler loop's first sample is there.
	sampleMu sync.Mutex
	rings    []cm.Ring
	started  time.Time
	log      *slog.Logger

	mu      sync.Mutex
	sec     *accum // scratch per second
	total   *accum // since start (Prometheus)
	a10     *accum
	a1m     *accum
	a10m    *accum
	v10     *valAgg
	v1m     *valAgg
	v10m    *valAgg
	window  [60]secStat // rolling 60 s for MonitoringNow
	winPos  int
	winN    int
	tenS    [360]tenStat // rolling hour of 10 s steps for hints
	tenPos  int
	tenN    int
	live    [cm.LiveRingSeconds]liveEntry
	livePos int
	subs    map[chan []byte]struct{}
	partial [3]bool
	// runLost: the process before this one stopped hard (run state
	// "running" at start), so the part of the first buckets before the
	// start may miss answered requests (gap_kind lost, else restart).
	runLost bool
	// base10m is the stored row of the 10 min bucket this process started
	// in (a minute checkpoint or a shutdown write of the process before);
	// checkpoints and the final write of that bucket add it (resume).
	base10m   *cm.MetricBucket
	baseStart time.Time
	lastSec   int64
	hints     *hintState
	site      siteState
	dropped   []dropPoint
	lastDrop  int64
	ticked    bool // a second was closed (flush has something to write)
	// disk: storage_budget and disk_fill_projection inputs (D38).
	disk diskState
	// audit: audit_stuck and audit_size inputs (contracts/audit.md).
	audit auditState

	// botVerify: bot verification runs (MVP-22; TrafficBreakdown.bot_verification).
	botVerify atomic.Bool

	last      atomic.Pointer[sample]
	writes    chan writeJob
	degraded  atomic.Int64 // unix second of the last skipped sample or write
	closeOnce sync.Once
	cancel    context.CancelFunc
	done      chan struct{}
}

type secStat struct {
	sec    int64
	c      [nCounters]int64
	hist   [nHist][cm.HistogramBuckets]int64
	unique hll
}

type tenStat struct {
	sec int64
	c   [nCounters]int64
	up  [cm.HistogramBuckets]int64
}

type liveEntry struct {
	sec  int64
	data []byte
}

type writeJob struct {
	ring  cm.Ring
	start time.Time
	b     cm.MetricBucket
	// replace: the bucket replaces the stored row (the 10 min ring, whose
	// earlier part is already in b, see base10m); else a partial bucket is
	// merged with a stored row of the same start (putMerging).
	replace bool
	// checkpoint: a minute checkpoint of the 10 min bucket in progress.
	checkpoint bool
}

type dropPoint struct {
	at time.Time
	n  int64
}

// ErrOff is returned by operations while monitoring.enabled is false.
var ErrOff = errors.New("monitoring off")

// New opens metrics.db and returns a monitor; Start runs it.
func New(cfg Config, now time.Time) (*Monitor, error) {
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	k := cfg.Keep
	if k.TenSecondsHours == 0 {
		k = config.MonitoringKeep{TenSecondsHours: config.DefaultKeepTenSecondsHours, MinuteHours: config.DefaultKeepMinuteHours, TenMinuteDays: config.DefaultKeepTenMinuteDays}
	}
	rings := cm.Rings(k.TenSecondsHours, k.MinuteHours, k.TenMinuteDays)
	st, err := openRingStore(cfg.StoragePath+"/metrics.db", rings)
	if err != nil {
		return nil, err
	}
	m := &Monitor{cfg: cfg, rec: newRecorder(now), store: st, rings: rings, started: now.UTC(), log: cfg.Log,
		sec: newAccum(false, 0), total: newAccum(false, 0), a10: newAccum(false, 0), a1m: newAccum(true, 2*cm.TopK), a10m: newAccum(true, 2*cm.TopK),
		v10: newValAgg(), v1m: newValAgg(), v10m: newValAgg(), subs: map[chan []byte]struct{}{}, partial: [3]bool{true, true, true},
		hints: newHintState(), writes: make(chan writeJob, 64), done: make(chan struct{})}
	m.a10m.siteTop = true
	m.rec.sites = cfg.Sites
	m.rec.ring = cfg.Requests
	m.site.dayNum = now.Unix() / 86400
	if cfg.Sampler.Started.IsZero() {
		cfg.Sampler.Started = now
	}
	cfg.Sampler.StoragePath = cfg.StoragePath
	m.sampler = newSampler(cfg.Sampler)
	m.runLost = st.swapRunState(runStateRunning) == runStateRunning
	st.addStart(now, !m.runLost)
	m.lastSec = now.Unix()
	// Resume the 10 min bucket in progress from its stored row (minute
	// checkpoint or shutdown write).
	r := rings[2]
	m.baseStart = r.Start(now)
	if err := st.read(r, m.baseStart, m.baseStart, readAll, func(t time.Time, b *cm.MetricBucket) {
		if t.Equal(m.baseStart) {
			m.base10m = b
		}
	}); err != nil {
		ratelog.Warn(m.log, "monitoring: metrics.db read of the bucket in progress failed", "err", err)
	}
	return m, nil
}

// SetBotVerification records whether claimed bots are verified (MVP-22).
func (m *Monitor) SetBotVerification(on bool) { m.botVerify.Store(on) }

// BotVerification reports whether claimed bots are verified.
func (m *Monitor) BotVerification() bool { return m != nil && m.botVerify.Load() }

// Rings returns the configured rings.
func (m *Monitor) Rings() []cm.Ring { return m.rings }

// Started is the process start the monitor knows.
func (m *Monitor) Started() time.Time { return m.started }

// Record counts one finished request (request path; never blocks on I/O).
func (m *Monitor) Record(q *Req) {
	if m == nil {
		return
	}
	m.rec.record(q)
}

// Start runs the aggregation, the sampler and the writer until ctx ends.
func (m *Monitor) Start(ctx context.Context) {
	ctx, m.cancel = context.WithCancel(ctx)
	var wg sync.WaitGroup
	wg.Add(3)
	go func() { defer wg.Done(); m.writer(ctx) }()
	go func() { defer wg.Done(); m.samplerLoop(ctx) }()
	go func() { defer wg.Done(); m.tickLoop(ctx) }()
	go func() { wg.Wait(); close(m.done) }()
}

// Close stops the loops, writes the buckets that are still being collected
// (marked partial, see flush) and closes metrics.db.
func (m *Monitor) Close() error {
	var err error
	m.closeOnce.Do(func() {
		if m.cancel != nil {
			m.cancel()
			<-m.done
		}
		m.mu.Lock()
		ran := m.ticked
		m.mu.Unlock()
		if ran {
			m.flush()
		}
		m.store.swapRunState(runStateClean)
		err = m.store.close()
		m.closeNodes()
	})
	return err
}

// flush writes what a graceful shutdown would otherwise lose (D36 fix
// round 1, finding D.1): the queued writes and the 10 s, 1 min and 10 min
// buckets in progress, each marked partial. The next process merges its
// part of the same bucket into the stored one (putMerging), so a restart
// costs only the seconds the process was down, and the bucket stays
// partial (gap_kind restart) so no reader calls the range exact. After a
// crash nothing is flushed: the 10 s and 1 min buckets in progress are
// missing (a gap), the 10 min bucket keeps its last minute checkpoint
// (gap_kind lost, see checkpoint), and the next process resumes from it
// when it starts inside that bucket.
func (m *Monitor) flush() {
	for drained := false; !drained; {
		select {
		case j := <-m.writes:
			m.writeJob(j)
		default:
			drained = true
		}
	}
	m.mu.Lock()
	m.sec.reset()
	m.rec.swap(func(o *accum) {
		m.sec.merge(o)
		m.a1m.merge(o)
		m.a10m.merge(o)
	})
	m.a10.merge(m.sec)
	m.total.merge(m.sec)
	m.addDay(m.sec)
	last := time.Unix(m.lastSec, 0).UTC()
	var jobs []writeJob
	for i, ag := range []struct {
		a *accum
		v *valAgg
	}{{m.a10, m.v10}, {m.a1m, m.v1m}, {m.a10m, m.v10m}} {
		start := m.rings[i].Start(last)
		jobs = append(jobs, m.finishAt(i, start, true, ag.a, ag.v))
	}
	m.mu.Unlock()
	for _, j := range jobs {
		m.writeJob(j)
	}
}

func (m *Monitor) safe(what string, f func()) {
	defer func() {
		if p := recover(); p != nil {
			ratelog.Error(m.log, "monitoring: recovered (request handling is not affected)", "in", what, "panic", p)
			m.degraded.Store(time.Now().Unix())
		}
	}()
	f()
}

func (m *Monitor) tickLoop(ctx context.Context) {
	for {
		now := time.Now()
		next := now.Truncate(time.Second).Add(time.Second)
		t := time.NewTimer(next.Sub(now))
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
		m.safe("tick", func() { m.Tick(next) })
	}
}

func (m *Monitor) samplerLoop(ctx context.Context) {
	// Sample in the middle of each 10 s bucket so it is ready at its end.
	m.safe("sample", func() { m.Sample(time.Now()) })
	for {
		now := time.Now()
		next := now.Truncate(10 * time.Second).Add(5 * time.Second)
		if !next.After(now) {
			next = next.Add(10 * time.Second)
		}
		t := time.NewTimer(next.Sub(now))
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
		m.safe("sample", func() { m.Sample(next) })
	}
}

// Sample takes one host sample (exported for tests).
func (m *Monitor) Sample(now time.Time) {
	m.sampleMu.Lock()
	defer m.sampleMu.Unlock()
	s := m.sampler.take(now.UTC())
	if m.cfg.Internals != nil {
		in := m.cfg.Internals(true)
		si := &s.snap.Schild
		si.EventQueueUsed, si.EventQueueCapacity = in.EventQueueUsed, max(1, in.EventQueueCapacity)
		si.EvalSlotsUsed, si.EvalSlotsMax = in.EvalSlotsUsed, max(1, in.EvalSlotsMax)
		si.StoreBytes, si.StoreMaxBytes = in.StoreBytes, in.StoreMaxBytes
		si.StoreCapUnreachable = in.StoreCapUnreachable
		m.mu.Lock()
		if prev := m.lastDrop; in.EventsDroppedTotal >= prev {
			s.counters["schild.events_dropped"] = float64(in.EventsDroppedTotal - prev)
		}
		m.lastDrop = in.EventsDroppedTotal
		m.dropped = append(m.dropped, dropPoint{now, in.EventsDroppedTotal})
		for len(m.dropped) > 1 && now.Sub(m.dropped[0].at) > time.Hour {
			m.dropped = m.dropped[1:]
		}
		si.EventsDropped1h = in.EventsDroppedTotal - m.dropped[0].n
		m.mu.Unlock()
		if si.EventQueueCapacity > 0 {
			s.gauges["schild.event_queue_fill"] = clamp01(float64(si.EventQueueUsed) / float64(si.EventQueueCapacity))
		}
		s.gauges["schild.eval_slots_used"] = clamp01(float64(si.EvalSlotsUsed) / float64(si.EvalSlotsMax))
		s.gauges["schild.store_bytes"] = float64(si.StoreBytes)
	}
	s.snap.Schild.MetricsStoreBytes = m.store.sizeBytes()
	s.snap.Schild.SamplerMS = float64(s.took.Microseconds()) / 1000
	s.snap.Schild.SamplerBudgetMS = float64(samplerBudget.Milliseconds())
	s.gauges["schild.sampler_ms"] = s.snap.Schild.SamplerMS
	if s.took > samplerBudget {
		m.degraded.Store(now.Unix())
	}
	m.last.Store(s)
	m.refreshProjection(now.UTC())
	m.mu.Lock()
	m.v10.add(s)
	m.v1m.add(s)
	m.v10m.add(s)
	m.mu.Unlock()
}

// Tick closes the second that ends at now (exported for tests).
func (m *Monitor) Tick(now time.Time) {
	sec := now.Unix() // the second [sec-1, sec) ended
	m.mu.Lock()
	m.sec.reset()
	m.rec.swap(func(o *accum) {
		m.sec.merge(o)
		m.a1m.merge(o)
		m.a10m.merge(o)
	})
	m.a10.merge(m.sec)
	m.total.merge(m.sec)
	m.addDay(m.sec)
	// Rolling minute.
	w := &m.window[m.winPos]
	w.sec, w.c, w.hist = sec-1, m.sec.c, m.sec.hist
	w.unique = m.sec.unique
	m.winPos = (m.winPos + 1) % len(m.window)
	m.winN = min(m.winN+1, len(m.window))
	tick := m.liveTick(sec-1, m.sec)
	if sec%10 == 0 {
		if s := m.last.Load(); s != nil {
			n := s.now
			tick.Server = &n
		}
	}
	data, _ := json.Marshal(tick)
	m.live[m.livePos] = liveEntry{sec - 1, data}
	m.livePos = (m.livePos + 1) % len(m.live)
	for ch := range m.subs {
		select {
		case ch <- data:
		default: // a slow subscriber misses a tick; it can resume with Last-Event-ID
		}
	}
	var jobs []writeJob
	if sec%10 == 0 {
		t := &m.tenS[m.tenPos]
		t.sec, t.c, t.up = sec-10, m.a10.c, m.a10.hist[hUpstream]
		m.tenPos = (m.tenPos + 1) % len(m.tenS)
		m.tenN = min(m.tenN+1, len(m.tenS))
		m.pushTen(now, m.a10)
		jobs = append(jobs, m.finish(0, now, m.a10, m.v10))
		m.hints.evaluate(m, now)
	}
	if sec%60 == 0 {
		jobs = append(jobs, m.finish(1, now, m.a1m, m.v1m))
	}
	if sec%600 == 0 {
		jobs = append(jobs, m.finish(2, now, m.a10m, m.v10m))
	} else if sec%cm.CheckpointIntervalS == 0 {
		jobs = append(jobs, m.checkpoint(now))
	}
	m.rollDay(now)
	m.lastSec = sec
	m.ticked = true
	m.mu.Unlock()
	for _, j := range jobs {
		select {
		case m.writes <- j:
		default:
			m.degraded.Store(sec)
		}
	}
}

// finish builds the bucket of ring i that ends at now and resets it (mu held).
func (m *Monitor) finish(i int, now time.Time, a *accum, v *valAgg) writeJob {
	return m.finishAt(i, now.Add(-m.rings[i].Step), false, a, v)
}

// finishAt builds the bucket of ring i that starts at start and resets the
// accumulators (mu held); cut marks a bucket that ends early (shutdown).
func (m *Monitor) finishAt(i int, start time.Time, cut bool, a *accum, v *valAgg) writeJob {
	byStart := m.partial[i] || start.Before(m.started)
	degraded := m.degraded.Load() >= start.Unix()
	partial := cut || byStart || degraded
	m.partial[i] = false
	b := m.build(i, start, partial, a, v)
	if partial {
		// lost: a skipped sample or write, or the part before a start
		// after a hard stop; else an orderly stop or start (restart).
		b.GapKind = cm.GapRestart
		if degraded || byStart && m.runLost {
			b.GapKind = cm.GapLost
		}
	}
	if i == 2 {
		m.addBase(&b, start)
		m.base10m = nil
	}
	a.reset()
	v.reset()
	return writeJob{ring: m.rings[i], start: start, b: b, replace: i == 2}
}

// build returns the bucket of ring i starting at start from a and v
// without resetting them (mu held).
func (m *Monitor) build(i int, start time.Time, partial bool, a *accum, v *valAgg) cm.MetricBucket {
	r := m.rings[i]
	values, objects := v.values()
	b := a.bucket(start, r.Resolution, int(r.Step.Seconds()), partial, values, objects)
	b.Sites = a.siteBuckets(m.view(), &m.site.day)
	if b.Clients.Unique != nil {
		d := m.site.dayAll.estimate()
		b.Clients.UniqueDay = &d
	}
	return b
}

// addBase adds the stored part of the 10 min bucket this process started
// in (base10m) to b (mu held).
func (m *Monitor) addBase(b *cm.MetricBucket, start time.Time) {
	if m.base10m != nil && m.baseStart.Equal(start) {
		mergeBucket(b, m.base10m)
	}
}

// checkpoint is the minute checkpoint of the running 10 min bucket
// (contracts v0.5, CheckpointIntervalS): the bucket as it stands, with
// the websites, their top lists and clients estimates, partial with
// gap_kind lost, written into its slot; the final write at the end of the
// bucket (or at an orderly shutdown) replaces it. After a hard stop the
// row stays, so at most the last minute is lost (mu held).
func (m *Monitor) checkpoint(now time.Time) writeJob {
	start := m.rings[2].Start(now.Add(-time.Second))
	b := m.build(2, start, true, m.a10m, m.v10m)
	m.addBase(&b, start)
	b.Partial, b.GapKind = true, cm.GapLost
	m.store.hide.Store(start.Unix())
	return writeJob{ring: m.rings[2], start: start, b: b, replace: true, checkpoint: true}
}

func (m *Monitor) writer(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case j := <-m.writes:
			m.writeJob(j)
		}
	}
}

func (m *Monitor) writeJob(j writeJob) {
	put := m.store.putMerging
	if j.replace {
		put = m.store.put
	}
	err := put(j.ring, j.start, &j.b)
	if j.replace && !j.checkpoint {
		// The final write replaced the checkpoint row: show it again.
		m.store.hide.CompareAndSwap(j.start.Unix(), 0)
	}
	if err != nil {
		ratelog.Warn(m.log, "monitoring: metrics.db write failed (request handling is not affected)", "err", err)
		m.degraded.Store(time.Now().Unix())
	}
}

func (m *Monitor) liveTick(sec int64, a *accum) cm.LiveTick {
	t := cm.LiveTick{T: ts(time.Unix(sec, 0)), Traffic: a.traffic(), LatencyTotalP95MS: a.quantile(hTotal, 0.95), LatencyOverheadP95MS: a.quantile(hOverhead, 0.95),
		Schild: m.liveSchild()}
	// v0.5 (D36): the websites of this second (Echtzeit per website).
	if v := m.view(); v != nil {
		for i, s := range a.sites {
			if s.used() && v.SlotName(i) != "" {
				t.Sites = append(t.Sites, cm.LiveSite{Site: v.SlotName(i), Requests: s.c[cRequests], Stopped: s.c[cStopped]})
			}
		}
	}
	return t
}

func (m *Monitor) liveSchild() *cm.LiveSchild {
	if m.cfg.Internals == nil {
		return nil
	}
	in := m.cfg.Internals(false)
	fill := 0.0
	if in.EventQueueCapacity > 0 {
		fill = clamp01(float64(in.EventQueueUsed) / float64(in.EventQueueCapacity))
	}
	return &cm.LiveSchild{EventQueueFill: fill, EvalSlotsUsed: int(in.EvalSlotsUsed), EvalSlotsMax: max(1, int(in.EvalSlotsMax))}
}

// ---------------------------------------------------------------- values

type gaugeAgg struct {
	sum, min, max float64
	n             int
}

func (g *gaugeAgg) add(v float64) {
	if g.n == 0 || v < g.min {
		g.min = v
	}
	if g.n == 0 || v > g.max {
		g.max = v
	}
	g.sum += v
	g.n++
}

type objAgg struct {
	object, kind string
	gauges       map[string]*gaugeAgg
	counters     map[string]float64
}

// valAgg aggregates host samples into the MetricValues of one bucket.
type valAgg struct {
	gauges   map[string]*gaugeAgg
	counters map[string]float64
	objects  map[string]*objAgg
	order    []string
}

func newValAgg() *valAgg {
	return &valAgg{gauges: map[string]*gaugeAgg{}, counters: map[string]float64{}, objects: map[string]*objAgg{}}
}

func (v *valAgg) reset() {
	clear(v.gauges)
	clear(v.counters)
	clear(v.objects)
	v.order = v.order[:0]
}

func (v *valAgg) add(s *sample) {
	for k, x := range s.gauges {
		g := v.gauges[k]
		if g == nil {
			g = &gaugeAgg{}
			v.gauges[k] = g
		}
		g.add(x)
	}
	for k, x := range s.counters {
		v.counters[k] += x
	}
	for _, o := range s.objects {
		key := o.kind + "\x00" + o.object
		a := v.objects[key]
		if a == nil {
			if len(v.objects) >= 48 {
				continue
			}
			a = &objAgg{object: o.object, kind: o.kind, gauges: map[string]*gaugeAgg{}, counters: map[string]float64{}}
			v.objects[key] = a
			v.order = append(v.order, key)
		}
		for k, x := range o.gauges {
			g := a.gauges[k]
			if g == nil {
				g = &gaugeAgg{}
				a.gauges[k] = g
			}
			g.add(x)
		}
		for k, x := range o.counters {
			a.counters[k] += x
		}
	}
}

func metricValues(g map[string]*gaugeAgg, c map[string]float64) cm.MetricValues {
	var out cm.MetricValues
	if len(g) > 0 {
		out.Gauges = map[string]cm.GaugeStats{}
		for k, x := range g {
			out.Gauges[k] = cm.GaugeStats{Avg: x.sum / float64(x.n), Min: x.min, Max: x.max}
		}
	}
	if len(c) > 0 {
		out.Counters = map[string]float64{}
		for k, x := range c {
			out.Counters[k] = x
		}
	}
	return out
}

func (v *valAgg) values() (cm.MetricValues, []cm.ObjectValues) {
	var objs []cm.ObjectValues
	for _, k := range v.order {
		o := v.objects[k]
		objs = append(objs, cm.ObjectValues{Object: o.object, Kind: o.kind, Values: metricValues(o.gauges, o.counters)})
	}
	return metricValues(v.gauges, v.counters), objs
}
