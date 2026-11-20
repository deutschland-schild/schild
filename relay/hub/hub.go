// Package hub is the SSE fan-out of contracts/stream.md, shared by
// schild-relay (port 7480) and the lab feed (port 7444).
//
// Ids are "<epoch>-<seq>". The epoch is random per process start, seq counts
// every event this hub numbers. Broadcast events go into a bounded ring; a
// client that reconnects with a Last-Event-ID from this epoch that is still
// covered by the ring receives every later broadcast event. Any other id (other
// relay, restart, too old, malformed) triggers a full sync: the current state
// (newest bundle, withdrawals that still apply, newest checkpoint per lab) is
// sent with fresh ids. Bundles are full state, so a full sync never leaves gaps.
//
// Ids on one connection are strictly increasing and the hub never reorders
// broadcast events, so "everything after my Last-Event-ID" is always exactly
// what a client misses. Priorities (withdrawal > bundle > checkpoint >
// heartbeat) are applied where they cannot create gaps: a full sync is sent in
// priority order, and a backlog sheds superseded lower-priority events first
// (an older checkpoint of the same lab, an older heartbeat). A client whose
// backlog still exceeds the buffer (256 events) is disconnected and resyncs on
// reconnect; the hub never buffers without limit.
//
// Callers must update the state behind Options.Snapshot before calling
// Publish, so that a concurrent full sync can never miss an event.
package hub

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/deutschland-schild/schild/contract/msg"
	"github.com/deutschland-schild/schild/contract/stream"
	"github.com/deutschland-schild/schild/relay/metrics"
)

// Options configure a hub.
type Options struct {
	// ID is the relay or lab id written into heartbeats (relay.id).
	ID string
	// Epoch overrides the random epoch (tests only).
	Epoch string
	// Buffer is the maximum number of pending events per client (default 256).
	Buffer int
	// Ring is the number of broadcast events kept for resume (default 4096).
	Ring int
	// Heartbeat is the heartbeat interval (default 15 s, negative disables).
	Heartbeat time.Duration
	// WriteTimeout bounds one write to a client (default 30 s).
	WriteTimeout time.Duration
	// Snapshot returns the full state in priority order; ids are assigned by
	// the hub. Called with the hub lock held: it must not call the hub.
	Snapshot func() []stream.Event
	// HeartbeatCheckpoint returns the newest lab-signed checkpoint envelope
	// for heartbeats, or nil when none is known yet (then only a keep-alive
	// comment is sent).
	HeartbeatCheckpoint func() json.RawMessage
	// Now is the clock (default time.Now).
	Now func() time.Time
	// Metrics are optional.
	Metrics *Metrics
	// Track is called when a stream client connects and disconnects
	// (optional; the lab uses it to list subscribed relays).
	Track func(r *http.Request, connected bool)
	// Delivered is called after an event was flushed to a stream client
	// (optional; the lab uses it to show what each relay has received).
	Delivered func(r *http.Request, typ, id string, data []byte)
}

// Metrics of a hub.
type Metrics struct {
	Clients     *metrics.Gauge
	Events      *metrics.CounterVec // by type
	Disconnects *metrics.CounterVec // by reason
	Syncs       *metrics.CounterVec // by mode: full | resume
	Fanout      *metrics.Histogram  // seconds from Publish to written
}

// NewMetrics registers hub metrics with the given prefix (schild_relay, schild_lab_feed).
func NewMetrics(r *metrics.Registry, prefix string) *Metrics {
	return &Metrics{
		Clients:     r.Gauge(prefix+"_clients", "Connected stream clients.").With(),
		Events:      r.Counter(prefix+"_events_total", "Events numbered by this hub, by type.", "type"),
		Disconnects: r.Counter(prefix+"_disconnects_total", "Clients disconnected, by reason.", "reason"),
		Syncs:       r.Counter(prefix+"_syncs_total", "Connections by start mode (full sync or resume).", "mode"),
		Fanout:      r.Histogram(prefix+"_fanout_seconds", "Time from publish to the event being written to a client.", metrics.LatencyBuckets).With(),
	}
}

type item struct {
	seq      uint64
	typ      string
	frame    []byte // complete SSE frame
	data     []byte // JSON data line
	coalesce string
	at       time.Time
}

type client struct {
	mu      sync.Mutex
	pending []*item
	notify  chan struct{}
	closed  bool
	reason  string
}

// push appends it; it returns false when the client overflows.
func (c *client) push(it *item, max int) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return true
	}
	if it.coalesce != "" {
		for i, p := range c.pending {
			if p.coalesce == it.coalesce {
				c.pending = append(c.pending[:i], c.pending[i+1:]...)
				break
			}
		}
	}
	if len(c.pending) >= max {
		c.shed()
	}
	if len(c.pending) >= max {
		return false
	}
	c.pending = append(c.pending, it)
	select {
	case c.notify <- struct{}{}:
	default:
	}
	return true
}

// shed drops the oldest pending heartbeat, then the oldest pending
// checkpoint: both are superseded by newer ones, so dropping them leaves no
// gap that matters (stream.md: the newest checkpoint is what counts).
func (c *client) shed() {
	for _, typ := range []string{stream.TypeHeartbeat, stream.TypeCheckpoint} {
		for i, p := range c.pending {
			if p.typ == typ {
				c.pending = append(c.pending[:i], c.pending[i+1:]...)
				return
			}
		}
	}
}

func (c *client) kill(reason string) {
	c.mu.Lock()
	if !c.closed {
		c.closed, c.reason = true, reason
	}
	c.mu.Unlock()
	select {
	case c.notify <- struct{}{}:
	default:
	}
}

func (c *client) take() ([]*item, bool, string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	p := c.pending
	c.pending = nil
	return p, c.closed, c.reason
}

// Hub fans out stream events.
type Hub struct {
	o       Options
	epoch   string
	mu      sync.Mutex
	seq     uint64
	ring    []*item // circular
	start   int
	n       int
	dropped uint64 // highest seq evicted from the ring
	clients map[*client]struct{}
	wake    chan struct{}
	closed  bool
}

// New returns a hub.
func New(o Options) *Hub {
	if o.Buffer <= 0 {
		o.Buffer = stream.ClientBuffer
	}
	if o.Ring <= 0 {
		o.Ring = 4096
	}
	if o.Heartbeat == 0 {
		o.Heartbeat = stream.HeartbeatInterval
	}
	if o.WriteTimeout <= 0 {
		o.WriteTimeout = 30 * time.Second
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	h := &Hub{o: o, epoch: o.Epoch, ring: make([]*item, o.Ring), clients: map[*client]struct{}{}, wake: make(chan struct{})}
	if h.epoch == "" {
		h.epoch = NewEpoch()
	}
	return h
}

// NewEpoch returns a random epoch of 10 characters [a-z0-9].
func NewEpoch() string {
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 10)
	_, _ = rand.Read(b)
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(b)
}

// Epoch returns the epoch of this hub.
func (h *Hub) Epoch() string { return h.epoch }

// Clients returns the number of connected stream clients.
func (h *Hub) Clients() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.clients)
}

// LastID returns the id of the newest numbered event ("" if none).
func (h *Hub) LastID() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.seq == 0 {
		return ""
	}
	return stream.FormatID(h.epoch, h.seq)
}

func (h *Hub) render(ev *stream.Event, seq uint64, coalesce string) (*item, error) {
	ev.ID = stream.FormatID(h.epoch, seq)
	data, err := ev.Marshal()
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	buf.Grow(len(data) + len(ev.ID) + len(ev.Type) + 32)
	if err := stream.WriteEvent(&buf, ev); err != nil {
		return nil, err
	}
	return &item{seq: seq, typ: ev.Type, frame: buf.Bytes(), data: data, coalesce: coalesce, at: h.o.Now()}, nil
}

// Publish numbers ev, keeps it for resume and sends it to every client.
// coalesce names a supersession key: a pending older event with the same key
// is dropped from a client's backlog (for example "checkpoint:lab-a").
func (h *Hub) Publish(ev stream.Event, coalesce string) (string, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return "", errors.New("hub: closed")
	}
	it, err := h.render(&ev, h.seq+1, coalesce)
	if err != nil {
		return "", err
	}
	h.seq++
	if h.n == len(h.ring) {
		h.dropped = h.ring[h.start].seq
		h.ring[h.start] = it
		h.start = (h.start + 1) % len(h.ring)
	} else {
		h.ring[(h.start+h.n)%len(h.ring)] = it
		h.n++
	}
	for c := range h.clients {
		if !c.push(it, h.o.Buffer) {
			c.kill("overflow")
			delete(h.clients, c)
			h.metricDisconnect("overflow")
		}
	}
	close(h.wake)
	h.wake = make(chan struct{})
	if m := h.o.Metrics; m != nil {
		m.Events.With(ev.Type).Inc()
	}
	return ev.ID, nil
}

// backlogLocked returns what a client with lastID needs.
func (h *Hub) backlogLocked(lastID string) ([]*item, bool) {
	if lastID != "" {
		epoch, seq, err := stream.ParseID(lastID)
		if err == nil && epoch == h.epoch && seq <= h.seq && seq >= h.dropped {
			var out []*item
			for i := 0; i < h.n; i++ {
				it := h.ring[(h.start+i)%len(h.ring)]
				if it.seq > seq {
					out = append(out, it)
				}
			}
			return out, false
		}
	}
	return h.snapshotLocked(), true
}

func (h *Hub) snapshotLocked() []*item {
	if h.o.Snapshot == nil {
		return nil
	}
	evs := h.o.Snapshot()
	out := make([]*item, 0, len(evs))
	for i := range evs {
		it, err := h.render(&evs[i], h.seq+1, "")
		if err != nil {
			continue
		}
		h.seq++
		out = append(out, it)
	}
	return out
}

func (h *Hub) metricDisconnect(reason string) {
	if m := h.o.Metrics; m != nil {
		m.Disconnects.With(reason).Inc()
		m.Clients.Set(float64(len(h.clients)))
	}
}

// LastEventID extracts the resume id from a request (header, or the
// last_event_id query parameter for clients that cannot set headers).
func LastEventID(r *http.Request) string {
	if v := r.Header.Get("Last-Event-ID"); v != "" {
		return v
	}
	return r.URL.Query().Get("last_event_id")
}

// ServeHTTP serves GET /v0/stream.
func (h *Hub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	rc := http.NewResponseController(w)
	c := &client{notify: make(chan struct{}, 1)}
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		http.Error(w, "shutting down", http.StatusServiceUnavailable)
		return
	}
	backlog, full := h.backlogLocked(LastEventID(r))
	c.pending = backlog
	h.clients[c] = struct{}{}
	if m := h.o.Metrics; m != nil {
		m.Clients.Set(float64(len(h.clients)))
		if full {
			m.Syncs.With("full").Inc()
		} else {
			m.Syncs.With("resume").Inc()
		}
	}
	h.mu.Unlock()
	if h.o.Track != nil {
		h.o.Track(r, true)
		defer h.o.Track(r, false)
	}
	defer func() {
		h.mu.Lock()
		if _, ok := h.clients[c]; ok {
			delete(h.clients, c)
			h.metricDisconnect("closed")
		}
		h.mu.Unlock()
	}()

	hd := w.Header()
	hd.Set("Content-Type", stream.ContentType)
	hd.Set("Cache-Control", "no-store")
	hd.Set("X-Accel-Buffering", "no")
	hd.Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	bw := bufio.NewWriterSize(w, 16<<10)
	_ = stream.WriteRetry(bw, stream.RetryMS)
	if err := h.flush(bw, rc); err != nil {
		return
	}
	if len(backlog) > 0 {
		c.notify <- struct{}{}
	}
	keep := h.o.Heartbeat
	if keep < 0 {
		keep = stream.HeartbeatInterval
	}
	idle := time.NewTimer(keep)
	defer idle.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-idle.C:
			_ = stream.WriteComment(bw, "keep-alive")
			if err := h.flush(bw, rc); err != nil {
				return
			}
			idle.Reset(keep)
		case <-c.notify:
			items, closed, _ := c.take()
			for _, it := range items {
				if _, err := bw.Write(it.frame); err != nil {
					return
				}
			}
			if len(items) > 0 {
				if err := h.flush(bw, rc); err != nil {
					return
				}
				if m := h.o.Metrics; m != nil {
					now := h.o.Now()
					for _, it := range items {
						m.Fanout.Observe(now.Sub(it.at).Seconds())
					}
				}
				if h.o.Delivered != nil {
					for _, it := range items {
						h.o.Delivered(r, it.typ, stream.FormatID(h.epoch, it.seq), it.data)
					}
				}
				idle.Reset(keep)
			}
			if closed {
				return
			}
		}
	}
}

func (h *Hub) flush(bw *bufio.Writer, rc *http.ResponseController) error {
	_ = rc.SetWriteDeadline(h.o.Now().Add(h.o.WriteTimeout))
	if err := bw.Flush(); err != nil {
		return err
	}
	return rc.Flush()
}

// Poll is the long-poll fallback: it returns the events after lastID (or a
// full sync when lastID is unknown), waiting up to wait for new events. The
// returned id is the Last-Event-ID for the next poll.
func (h *Hub) Poll(ctx context.Context, lastID string, wait time.Duration) ([]json.RawMessage, string, bool) {
	t := time.NewTimer(wait)
	defer t.Stop()
	for {
		h.mu.Lock()
		items, full := h.backlogLocked(lastID)
		wake := h.wake
		cur := ""
		if h.seq > 0 {
			cur = stream.FormatID(h.epoch, h.seq)
		}
		h.mu.Unlock()
		if len(items) > 0 || full {
			out := make([]json.RawMessage, len(items))
			for i, it := range items {
				out[i] = it.data
			}
			next := cur
			if len(items) > 0 {
				next = stream.FormatID(h.epoch, items[len(items)-1].seq)
			}
			if full && next == "" {
				// Nothing known yet: hand out an id of this epoch so the next
				// poll waits instead of syncing again.
				next = stream.FormatID(h.epoch, 0)
			}
			return out, next, full
		}
		select {
		case <-ctx.Done():
			return nil, lastID, false
		case <-t.C:
			return nil, lastID, false
		case <-wake:
		}
	}
}

// Run sends heartbeats until ctx ends.
func (h *Hub) Run(ctx context.Context) {
	if h.o.Heartbeat < 0 {
		<-ctx.Done()
		h.Close()
		return
	}
	t := time.NewTicker(h.o.Heartbeat)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			h.Close()
			return
		case <-t.C:
			h.Heartbeat()
		}
	}
}

// Heartbeat publishes one heartbeat now (if a checkpoint is known).
func (h *Hub) Heartbeat() {
	if h.o.HeartbeatCheckpoint == nil {
		return
	}
	cp := h.o.HeartbeatCheckpoint()
	if cp == nil {
		return
	}
	_, _ = h.Publish(stream.Event{
		Type:       stream.TypeHeartbeat,
		Relay:      &stream.Relay{ID: h.o.ID, Time: msg.FormatTime(h.o.Now())},
		Checkpoint: cp,
	}, "heartbeat")
}

// Close disconnects every client and refuses new ones.
func (h *Hub) Close() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.closed = true
	for c := range h.clients {
		c.kill("shutdown")
		delete(h.clients, c)
	}
	close(h.wake)
	h.wake = make(chan struct{})
}
