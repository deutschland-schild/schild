package dashboard

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/deutschland-schild/schild/lab/internal/publog"
	"github.com/deutschland-schild/schild/lab/internal/scoring"
)

// Live updates (contracts v0.1): GET /api/v0/events/stream is one SSE stream
// per dashboard tab. The SSE event name is the topic:
//
//	health        full LabHealth, at once and every 5 s
//	signals       a ReceivedSignal (positive-list payload, never an IP)
//	log           a LogEntry of the public log
//	patterns, proposals, bundles, withdrawals, network, issuers, clients,
//	settings      a LiveNotice {topic, ref}: refresh the queries of the topic
//
// Nothing is replayed: after a reconnect the UI refetches.

// liveHub fans dashboard events out to SSE connections. It drops events
// for slow connections instead of buffering: the dashboard must never hold
// memory or time on behalf of a browser (and never touches ingest).
type liveHub struct {
	mu   sync.Mutex
	subs map[chan liveEvent]struct{}
}

type liveEvent struct {
	name string
	data []byte
}

// liveNotice is the API LiveNotice.
type liveNotice struct {
	Topic string `json:"topic"`
	Ref   string `json:"ref,omitempty"`
}

func newLiveHub() *liveHub { return &liveHub{subs: map[chan liveEvent]struct{}{}} }

func (h *liveHub) publish(name string, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for c := range h.subs {
		select {
		case c <- liveEvent{name, b}:
		default:
		}
	}
}

func (h *liveHub) sub() chan liveEvent {
	c := make(chan liveEvent, 64)
	h.mu.Lock()
	h.subs[c] = struct{}{}
	h.mu.Unlock()
	return c
}

func (h *liveHub) unsub(c chan liveEvent) {
	h.mu.Lock()
	delete(h.subs, c)
	h.mu.Unlock()
}

// topicOf maps an API path of a state change to its live topic.
func topicOf(path string) string {
	p := strings.TrimPrefix(path, "/api/v0/")
	first, _, _ := strings.Cut(p, "/")
	switch first {
	case "proposals":
		return "proposals"
	case "bundles":
		return "bundles"
	case "withdrawals", "emergency-stop":
		return "withdrawals"
	case "issuers":
		return "issuers"
	case "clients":
		return "clients"
	case "settings":
		return "settings"
	}
	return ""
}

// logTopic maps a public log entry kind to the topic it changes.
func logTopic(kind string) string {
	switch kind {
	case publog.KindProposal:
		return "proposals"
	case publog.KindBundle:
		return "bundles"
	case publog.KindWithdrawal:
		return "withdrawals"
	}
	return "network"
}

// PublishSignal sends a newly stored signal to live views (called by the
// scorer). Signals carry no IP: they are the positive-list payloads.
func (s *Server) PublishSignal(rs scoring.ReceivedSignal) { s.live.publish("signals", rs) }

// Run watches the public log, the scorer and co-signing state for live
// views until ctx ends.
func (s *Server) Run(ctx context.Context) {
	var size uint64
	_ = s.d.DB.View(func(tx *bolt.Tx) error { size = publog.HeadTx(tx).Size; return nil })
	fingerprint := s.d.Engine.Fingerprint()
	processed := s.d.Scorer.Status().ProcessedTotal
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		var entries []*publog.Entry
		_ = s.d.DB.View(func(tx *bolt.Tx) error {
			if h := publog.HeadTx(tx); h.Size > size {
				entries = publog.Range(tx, size, int(min(h.Size-size, 100)))
				size = h.Size
			}
			return nil
		})
		topics := map[string]bool{}
		for _, e := range entries {
			s.live.publish("log", logView(e))
			topics[logTopic(e.Kind)] = true
		}
		// Offers from peers and co-signatures change bundles and withdrawals
		// without a log entry.
		if fp := s.d.Engine.Fingerprint(); fp != fingerprint {
			fingerprint = fp
			topics["bundles"], topics["withdrawals"] = true, true
		}
		// New signals change patterns (at most one notice per tick).
		if p := s.d.Scorer.Status().ProcessedTotal; p != processed {
			processed = p
			topics["patterns"] = true
		}
		for topic := range topics {
			s.live.publish(topic, liveNotice{Topic: topic})
		}
	}
}

// liveStream serves GET /api/v0/events/stream (SSE, contracts v0.1).
func (s *Server) liveStream(w http.ResponseWriter, r *http.Request) {
	rc := http.NewResponseController(w)
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	c := s.live.sub()
	defer s.live.unsub(c)
	write := func(name string, data []byte) bool {
		_ = rc.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if _, err := w.Write([]byte("event: " + name + "\ndata: ")); err != nil {
			return false
		}
		if _, err := w.Write(data); err != nil {
			return false
		}
		if _, err := w.Write([]byte("\n\n")); err != nil {
			return false
		}
		return rc.Flush() == nil
	}
	w.Write([]byte("retry: 3000\n\n"))
	health := func() bool {
		b, _ := json.Marshal(s.healthView())
		return write("health", b)
	}
	if !health() {
		return
	}
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-t.C:
			if !health() {
				return
			}
		case ev := <-c:
			if !write(ev.name, ev.data) {
				return
			}
		}
	}
}
