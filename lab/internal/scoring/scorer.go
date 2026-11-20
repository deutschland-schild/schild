// Package scoring is scoring v0 of the lab (MVP-03): rules and statistics
// over action signatures, no AI. It runs apart from ingest (own goroutine,
// own state file) and drains the durable queue in priority order.
//
// Rules applied to every signal:
//   - defence in depth: a payload with anything address-like in a free-text
//     field, or a forbidden key, is dropped (ingest already rejects these);
//   - G6 canary: tips whose origin is on the client's protection list are
//     dropped and counted against the issuer;
//   - sampled baseline (score < min_score) is stored but never counts as a tip;
//   - tips count once per (issuer, request_sig, time_bucket): many client
//     keys of one issuer (Sybil) or many repeats add nothing.
//
// Statistics per pattern (action_sig): signals, issuers, max issuer share,
// countries, ASNs, net classes, agents, WAF rules, first/last seen, an hourly
// timeline. A pattern becomes "watching" when tips of at least min_issuers
// issuers arrive with no issuer above max_issuer_share inside the window:
// that is the observe level of G2, and the only level tips can ever reach.
package scoring

import (
	"context"
	"encoding/json"
	"log/slog"
	"regexp"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/deutschland-schild/schild/contract/jsonx"
	"github.com/deutschland-schild/schild/contract/msg"
	"github.com/deutschland-schild/schild/contract/verify"
	"github.com/deutschland-schild/schild/lab/internal/queue"
	"github.com/deutschland-schild/schild/lab/internal/store"
	"github.com/deutschland-schild/schild/relay/metrics"
)

// Config of scoring v0 (lab.yaml scoring).
type Config struct {
	MinIssuers     int
	MaxIssuerShare float64
	WindowMinutes  int
	MinScore       int
}

// Window returns the scoring window.
func (c Config) Window() time.Duration { return time.Duration(c.WindowMinutes) * time.Minute }

// Metrics of the scorer.
type Metrics struct {
	Processed *metrics.CounterVec // by result
	Lag       *metrics.Gauge
}

// NewMetrics registers scorer metrics.
func NewMetrics(r *metrics.Registry) *Metrics {
	return &Metrics{
		Processed: r.Counter("schild_lab_scoring_processed_total", "Queue items processed by scoring, by result.", "result"),
		Lag:       r.Gauge("schild_lab_scoring_lag_seconds", "Age of the newest item the scorer processed when it processed it.").With(),
	}
}

// IssuerFlags counts G6 canary hits per issuer (poisoning indicator).
type IssuerFlags struct {
	mu sync.Mutex
	m  map[string]int64
}

// Get returns the canary hits of an issuer.
func (f *IssuerFlags) Get(issuer string) int64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.m[issuer]
}

func (f *IssuerFlags) add(issuer string) {
	f.mu.Lock()
	if f.m == nil {
		f.m = map[string]int64{}
	}
	f.m[issuer]++
	f.mu.Unlock()
}

// Scorer drains the queue into the pattern store.
type Scorer struct {
	Q       *queue.Queue
	DB      *store.DB
	Log     *slog.Logger
	Metrics *Metrics
	Now     func() time.Time
	Canary  IssuerFlags
	// OnSignal is called after a signal was stored (dashboard live view).
	OnSignal func(ReceivedSignal)

	cfg       atomic.Pointer[Config]
	wake      chan struct{}
	processed atomic.Int64
	lastErr   atomic.Pointer[string]
	busy      atomic.Bool
	lagMS     atomic.Int64
	rate      rateCounter
}

// New returns a scorer.
func New(q *queue.Queue, db *store.DB, cfg Config, log *slog.Logger, m *Metrics) *Scorer {
	s := &Scorer{Q: q, DB: db, Log: log, Metrics: m, Now: time.Now, wake: make(chan struct{}, 1)}
	s.SetConfig(cfg)
	return s
}

// SetConfig replaces the thresholds (dashboard settings).
func (s *Scorer) SetConfig(c Config) { s.cfg.Store(&c) }

// Config returns the current thresholds.
func (s *Scorer) Config() Config { return *s.cfg.Load() }

// Wake tells the scorer that new items are queued.
func (s *Scorer) Wake() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// Status for the health view.
type Status struct {
	Running        bool
	Busy           bool
	ProcessedPerS  float64
	LagS           float64
	LastError      string
	ProcessedTotal int64
}

// Status returns worker status.
func (s *Scorer) Status() Status {
	st := Status{Running: true, Busy: s.busy.Load(), ProcessedPerS: s.rate.perSecond(), LagS: float64(s.lagMS.Load()) / 1000, ProcessedTotal: s.processed.Load()}
	if e := s.lastErr.Load(); e != nil {
		st.LastError = *e
	}
	return st
}

// Run drains the queue until ctx ends.
func (s *Scorer) Run(ctx context.Context) {
	t := time.NewTicker(250 * time.Millisecond)
	defer t.Stop()
	for ctx.Err() == nil {
		n, err := s.Step(512)
		if err != nil {
			msg := err.Error()
			s.lastErr.Store(&msg)
			s.Log.Error("scoring step failed", "err", err)
		}
		if n > 0 {
			continue
		}
		select {
		case <-ctx.Done():
		case <-s.wake:
		case <-t.C:
		}
	}
}

// Step processes up to max queued items; it returns how many.
func (s *Scorer) Step(max int) (int, error) {
	items, err := s.Q.Read(max)
	if err != nil || len(items) == 0 {
		return 0, err
	}
	s.busy.Store(true)
	defer s.busy.Store(false)
	now := s.Now().UTC()
	cfg := s.Config()
	var stored []ReceivedSignal
	touched := map[string]bool{}
	results := map[string]float64{}
	err = s.DB.Update(func(tx *bolt.Tx) error {
		stored = stored[:0]
		clear(touched)
		clear(results)
		for _, it := range items {
			res, rs, err := s.process(tx, it, cfg)
			if err != nil {
				return err
			}
			results[res]++
			if rs != nil {
				stored = append(stored, *rs)
				touched[rs.PatternID] = true
			}
		}
		for pid := range touched {
			if err := refresh(tx, pid, now, cfg); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		// Items stay queued; they are read again after a restart. Mark them
		// done only on success so nothing is lost.
		return 0, err
	}
	if err := s.Q.Done(items); err != nil {
		return 0, err
	}
	var newest int64
	for _, it := range items {
		if it.ReceivedMS > newest {
			newest = it.ReceivedMS
		}
	}
	lag := now.Sub(time.UnixMilli(newest))
	s.lagMS.Store(lag.Milliseconds())
	s.processed.Add(int64(len(items)))
	s.rate.add(now, len(items))
	if s.Metrics != nil {
		s.Metrics.Lag.Set(lag.Seconds())
		for r, n := range results {
			s.Metrics.Processed.With(r).Add(n)
		}
	}
	if s.OnSignal != nil {
		for _, rs := range stored {
			s.OnSignal(rs)
		}
	}
	return len(items), nil
}

// ReceivedSignal is a stored signal (API ReceivedSignal).
type ReceivedSignal struct {
	ReceivedAt string          `json:"received_at"`
	Issuer     string          `json:"issuer"`
	KeyID      string          `json:"keyid,omitempty"`
	PatternID  string          `json:"pattern_id"`
	Payload    json.RawMessage `json:"payload"`
}

// addressLike matches IPv4 (dotted, dashed, underscored), IPv6 and long
// digit/hex runs in free-text tokens (the noLeak rule, again).
var addressLike = regexp.MustCompile(`[0-9]{1,3}[._-][0-9]{1,3}[._-][0-9]{1,3}[._-][0-9]{1,3}|[0-9a-fA-F]{0,4}:[0-9a-fA-F]{0,4}:|[0-9]{7,}|[0-9a-f]{8,}`)

func (s *Scorer) process(tx *bolt.Tx, it queue.Item, cfg Config) (string, *ReceivedSignal, error) {
	switch it.Kind {
	case "feedback":
		var f msg.Feedback
		if err := strictDecode(it.Payload, &f); err != nil {
			return "dropped_malformed", nil, nil
		}
		if tx.Bucket(store.SignalIDs).Get([]byte(f.ID)) != nil {
			return "duplicate", nil, nil
		}
		// Feedback ids are kept (8-byte receive time) for the replay set.
		if err := tx.Bucket(store.SignalIDs).Put([]byte(f.ID), store.U64(uint64(it.ReceivedMS))); err != nil {
			return "", nil, err
		}
		k := store.Key([]byte(f.RuleID), []byte{0}, []byte(it.Issuer))
		n := store.FromU64(tx.Bucket(store.Feedback).Get(k)) + 1
		return "feedback", nil, tx.Bucket(store.Feedback).Put(k, store.U64(n))
	case "signal":
	default:
		return "dropped_malformed", nil, nil
	}
	var sig msg.Signal
	if err := strictDecode(it.Payload, &sig); err != nil {
		return "dropped_malformed", nil, nil
	}
	// ja4 is a fingerprint (hex by design) and is not a free-text token.
	for _, f := range []string{sig.ActionSig, sig.Category, sig.Agent.Family} {
		if addressLike.MatchString(f) {
			return "dropped_address_like", nil, nil
		}
	}
	if tx.Bucket(store.SignalIDs).Get([]byte(sig.ID)) != nil {
		return "duplicate", nil, nil
	}
	if sig.Origin.Protected {
		s.Canary.add(it.Issuer)
		return "dropped_canary", nil, nil
	}
	recv := time.UnixMilli(it.ReceivedMS).UTC()
	pid := PatternID(sig.ActionSig)
	rs := &ReceivedSignal{ReceivedAt: msg.FormatTime(recv), Issuer: it.Issuer, KeyID: it.KeyID, PatternID: pid, Payload: it.Payload}
	key := store.Key(store.U64(uint64(it.ReceivedMS)), store.U64(it.Seq))
	if err := store.PutJSON(tx, store.Signals, key, rs); err != nil {
		return "", nil, err
	}
	if err := tx.Bucket(store.SignalIDs).Put([]byte(sig.ID), key); err != nil {
		return "", nil, err
	}
	if err := tx.Bucket(store.SignalByPattern).Put(store.Key([]byte(pid), key), nil); err != nil {
		return "", nil, err
	}
	p, ok, err := GetPattern(tx, pid)
	if err != nil {
		return "", nil, err
	}
	if !ok {
		p = newPattern(sig.ActionSig, recv)
	}
	p.Signals++
	p.ScoreSum += int64(sig.Score)
	p.Categories[sig.Category]++
	p.ByIssuer[it.Issuer]++
	p.Countries[sig.Origin.Country]++
	p.ASNs[strconv.FormatUint(uint64(sig.Origin.ASN), 10)]++
	p.NetClasses[sig.Origin.NetClass]++
	p.Agents[sig.Agent.Family+"/"+strconv.Itoa(sig.Agent.Major)]++
	for _, r := range sig.WAFRules {
		p.WAFRules[strconv.Itoa(r)]++
	}
	if recv.Before(p.FirstSeen) {
		p.FirstSeen = recv
	}
	if recv.After(p.LastSeen) {
		p.LastSeen = recv
	}
	if b := tx.Bucket(store.PatternClients); it.KeyID != "" && b.Get(store.Key([]byte(pid), []byte(it.KeyID))) == nil {
		p.Clients++
		if err := b.Put(store.Key([]byte(pid), []byte(it.KeyID)), nil); err != nil {
			return "", nil, err
		}
	}
	if b := tx.Bucket(store.PatternReqSigs); b.Get(store.Key([]byte(pid), []byte(sig.RequestSig))) == nil {
		p.RequestSigs++
		if err := b.Put(store.Key([]byte(pid), []byte(sig.RequestSig)), nil); err != nil {
			return "", nil, err
		}
	}
	result := "baseline"
	if sig.Score >= cfg.MinScore {
		result = "tip"
		p.Tips++
		bucket, err := msg.ParseTime(sig.TimeBucket)
		if err != nil {
			return "dropped_malformed", nil, nil
		}
		if err := tx.Bucket(store.Units).Put(unitKey(pid, bucket, it.Issuer, sig.RequestSig), nil); err != nil {
			return "", nil, err
		}
	} else {
		p.Baseline++
	}
	tk := store.Key([]byte(pid), store.U64(uint64(recv.Truncate(time.Hour).Unix())))
	var te TimelineEntry
	if _, err := store.GetJSON(tx, store.Timeline, tk, &te); err != nil {
		return "", nil, err
	}
	if te.Issuers == nil {
		te.Issuers = map[string]int64{}
	}
	te.Signals++
	te.Issuers[it.Issuer]++
	if err := store.PutJSON(tx, store.Timeline, tk, &te); err != nil {
		return "", nil, err
	}
	return result, rs, PutPattern(tx, p)
}

// refresh recomputes the window statistics and the automatic status.
func refresh(tx *bolt.Tx, pid string, now time.Time, cfg Config) error {
	p, ok, err := GetPattern(tx, pid)
	if !ok || err != nil {
		return err
	}
	p.Window = ComputeWindow(tx, pid, now, cfg.Window())
	if p.Status == StatusNew || p.Status == StatusWatching {
		if MeetsTipThreshold(p.Window, cfg) {
			p.Status = StatusWatching
		} else {
			p.Status = StatusNew
		}
	}
	return PutPattern(tx, p)
}

// MeetsTipThreshold reports whether tips alone reach observe (G2): at least
// min_issuers issuers (never fewer than 3) and no issuer above
// max_issuer_share (never above 0.34).
func MeetsTipThreshold(w Window, cfg Config) bool {
	minIss := max(cfg.MinIssuers, 3)
	share := cfg.MaxIssuerShare
	if share <= 0 || share > 0.34 {
		share = 0.34
	}
	return w.Issuers >= minIss && w.MaxIssuerShare <= share
}

func strictDecode(raw []byte, out any) error {
	v, err := jsonx.ParseObject(raw)
	if err != nil {
		return err
	}
	if err := verify.CheckForbidden(v); err != nil {
		return err
	}
	return jsonx.Decode(v, out)
}

type rateCounter struct {
	mu   sync.Mutex
	secs [60]struct{ at, n int64 }
}

func (r *rateCounter) add(now time.Time, n int) {
	s := now.Unix()
	r.mu.Lock()
	e := &r.secs[s%60]
	if e.at != s {
		e.at, e.n = s, 0
	}
	e.n += int64(n)
	r.mu.Unlock()
}

func (r *rateCounter) perSecond() float64 {
	s := time.Now().Unix()
	var n int64
	r.mu.Lock()
	for _, e := range r.secs {
		if e.at > s-60 {
			n += e.n
		}
	}
	r.mu.Unlock()
	return float64(n) / 60
}
