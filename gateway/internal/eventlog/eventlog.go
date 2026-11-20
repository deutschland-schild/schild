// Package eventlog writes local events (contract/events, CloudEvents 1.0)
// asynchronously in batches to the store and publishes them to live
// subscribers (dashboard SSE). The request path only does a non-blocking
// channel send; when the writer falls behind, events are dropped and
// counted, requests are never slowed down.
package eventlog

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/deutschland-schild/schild/contract/events"
	"github.com/deutschland-schild/schild/gateway/internal/metrics"
	"github.com/deutschland-schild/schild/gateway/internal/ratelog"
	"github.com/deutschland-schild/schild/gateway/internal/sites"
	"github.com/deutschland-schild/schild/gateway/internal/store"
)

// Index carries the columns used for filtering.
type Index struct {
	IP       string
	Country  string
	ASN      uint32
	Method   string
	Host     string
	Path     string
	Status   int
	Score    int
	Outcome  string
	Rules    []string
	Incident string
	Session  string
	UA       string
	Summary  string
	// Site is the website id; empty: resolved from Host by Log.Sites
	// (v0.5, D36).
	Site string
}

// Log is the event writer.
type Log struct {
	st      *store.Store
	node    string
	ch      chan *store.EventRow
	m       *metrics.Metrics
	log     *slog.Logger
	bus     *Bus
	flushed chan chan struct{}
	// Validate checks each event against events.schema.json before it is
	// written (on in tests; costs ~50 µs per event).
	Validate bool
	// Mirror, when set, receives every written event as one NDJSON line
	// after it is stored (test lab evaluation, see NDJSONMirror).
	Mirror Mirror
	// dropped counts events dropped since start (MVP-21 schild internals).
	dropped  atomic.Int64
	lastDrop atomic.Int64 // unix nanos of the last drop
	// Sites resolves the website of an event from its Host (v0.5, D36).
	Sites *sites.Registry
}

// Queue returns the writer queue fill (MVP-21 schild internals).
func (l *Log) Queue() (used, capacity int) { return len(l.ch), cap(l.ch) }

// Dropped returns the number of events dropped since start.
func (l *Log) Dropped() int64 { return l.dropped.Load() }

// LastDropped returns when an event was last dropped (zero: never since
// start); Overview.counters_24h.partial (D36 open items).
func (l *Log) LastDropped() time.Time {
	if n := l.lastDrop.Load(); n != 0 {
		return time.Unix(0, n)
	}
	return time.Time{}
}

func (l *Log) markDropped(n int64) {
	l.dropped.Add(n)
	l.lastDrop.Store(time.Now().UnixNano())
}

// Mirror receives written events (never on the request path).
type Mirror interface {
	Write(rows []*store.EventRow)
}

// New returns a log for node; call Run to start writing.
func New(st *store.Store, node string, m *metrics.Metrics, log *slog.Logger) *Log {
	return &Log{st: st, node: node, ch: make(chan *store.EventRow, 8192), m: m, log: log, bus: NewBus(), flushed: make(chan chan struct{})}
}

// Bus returns the live subscriber hub.
func (l *Log) Bus() *Bus { return l.bus }

// Emit builds a CloudEvent and queues it. It never blocks. It returns the event id.
func (l *Log) Emit(typ string, t time.Time, data any, idx Index) string {
	return l.EmitWithID("", typ, t, data, idx)
}

// EmitWithID is Emit with a pre-assigned event id ("" = new).
func (l *Log) EmitWithID(id, typ string, t time.Time, data any, idx Index) string {
	ev := events.New(typ, l.node, t, data)
	if id != "" {
		ev.ID = id
	}
	if l.Validate {
		if err := ev.Validate(); err != nil {
			ratelog.Error(l.log, "local event does not match events.schema.json", "type", typ, "err", err)
			if l.m != nil {
				l.m.EventsDropped.Inc()
				l.markDropped(1)
			}
			return ev.ID
		}
	}
	if idx.Site == "" && idx.Host != "" && l.Sites != nil {
		idx.Site = l.Sites.ID(idx.Host)
	}
	row, err := RowOf(ev, t, idx)
	if err != nil {
		ratelog.Error(l.log, "marshal event", "err", err)
		return ev.ID
	}
	// The sampled flag sets the value class of the size cap (D38).
	switch d := data.(type) {
	case events.Request:
		row.Sampled = d.Sampled
	case *events.Request:
		row.Sampled = d != nil && d.Sampled
	case RequestData:
		row.Sampled = d.Sampled
	}
	select {
	case l.ch <- row:
	default:
		if l.m != nil {
			l.m.EventsDropped.Inc()
			l.markDropped(1)
		}
	}
	return ev.ID
}

// RowOf returns the stored form of ev with the index columns of idx (for
// writers outside the queue, e.g. `schild dashboard reset-password`).
// t is the time ev was built for (events.New).
func RowOf(ev *events.Event, t time.Time, idx Index) (*store.EventRow, error) {
	body, err := json.Marshal(ev)
	if err != nil {
		return nil, err
	}
	return &store.EventRow{ID: ev.ID, Time: t.UTC(), Type: ev.Type, IP: idx.IP, Country: idx.Country, ASN: idx.ASN, Method: idx.Method,
		Host: idx.Host, Path: idx.Path, Status: idx.Status, Score: idx.Score, Outcome: idx.Outcome, Rules: idx.Rules,
		Incident: idx.Incident, Session: idx.Session, UA: idx.UA, Summary: idx.Summary, Body: body, Site: idx.Site}, nil
}

// Run writes batches until ctx ends, then flushes what is queued.
func (l *Log) Run(ctx context.Context) {
	tick := time.NewTicker(200 * time.Millisecond)
	defer tick.Stop()
	batch := make([]*store.EventRow, 0, 512)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		wctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		err := l.st.InsertEvents(wctx, batch)
		cancel()
		if err != nil {
			ratelog.Error(l.log, "write events", "err", err, "n", len(batch))
			if l.m != nil {
				l.m.EventsDropped.Add(float64(len(batch)))
				l.markDropped(int64(len(batch)))
			}
		} else {
			if l.m != nil {
				l.m.EventsWritten.Add(float64(len(batch)))
			}
			for _, r := range batch {
				l.bus.Publish(r)
			}
			if l.Mirror != nil {
				l.Mirror.Write(batch)
			}
		}
		batch = make([]*store.EventRow, 0, 512)
	}
	for {
		select {
		case r := <-l.ch:
			batch = append(batch, r)
			if len(batch) >= 512 {
				flush()
			}
		case <-tick.C:
			flush()
		case done := <-l.flushed:
			for drained := false; !drained; {
				select {
				case r := <-l.ch:
					batch = append(batch, r)
				default:
					drained = true
				}
			}
			flush()
			close(done)
		case <-ctx.Done():
			for drained := false; !drained; {
				select {
				case r := <-l.ch:
					batch = append(batch, r)
				default:
					drained = true
				}
			}
			flush()
			return
		}
	}
}

// Flush waits until everything emitted so far is written (tests, shutdown).
func (l *Log) Flush(ctx context.Context) {
	done := make(chan struct{})
	select {
	case l.flushed <- done:
	case <-ctx.Done():
		return
	}
	select {
	case <-done:
	case <-ctx.Done():
	}
}

// Bus fans out written events to live subscribers.
type Bus struct {
	mu   sync.Mutex
	subs map[*Sub]struct{}
}

// Sub is one subscriber. C is closed when the subscriber falls behind.
type Sub struct {
	C      chan *store.EventRow
	closed bool
}

// NewBus returns an empty hub.
func NewBus() *Bus { return &Bus{subs: map[*Sub]struct{}{}} }

// Subscribe registers a subscriber with a bounded buffer.
func (b *Bus) Subscribe() *Sub {
	s := &Sub{C: make(chan *store.EventRow, 256)}
	b.mu.Lock()
	b.subs[s] = struct{}{}
	b.mu.Unlock()
	return s
}

// Unsubscribe removes a subscriber.
func (b *Bus) Unsubscribe(s *Sub) {
	b.mu.Lock()
	if _, ok := b.subs[s]; ok {
		delete(b.subs, s)
		if !s.closed {
			close(s.C)
			s.closed = true
		}
	}
	b.mu.Unlock()
}

// Publish delivers r to every subscriber; a full subscriber is disconnected
// (it reconnects with Last-Event-ID and replays from the store).
func (b *Bus) Publish(r *store.EventRow) {
	b.mu.Lock()
	for s := range b.subs {
		select {
		case s.C <- r:
		default:
			delete(b.subs, s)
			if !s.closed {
				close(s.C)
				s.closed = true
			}
		}
	}
	b.mu.Unlock()
}

// RequestData is the data of a request event with checked_paths (D33
// amendment 2026-10-29: a request schild evaluated more than once lists
// the paths it inspected, 2..4 items). events.Request does not carry the
// field yet.
type RequestData struct {
	events.Request
	CheckedPaths []string `json:"checked_paths,omitempty"`
}
