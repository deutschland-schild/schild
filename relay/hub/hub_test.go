package hub

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/contract/stream"
	"github.com/deutschland-schild/schild/relay/upstream"
)

func env() json.RawMessage {
	return json.RawMessage(`{"payloadType":"application/vnd.schild.withdrawal.v0+json","payload":"e30=","signatures":[{"keyid":"test-lab-a","sig":"` + strings.Repeat("A", 86) + `=="}]}`)
}

type sseClient struct {
	cancel context.CancelFunc
	rd     *stream.Reader
	resp   *http.Response
}

func dial(t *testing.T, url, lastID string) *sseClient {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url+stream.Path, nil)
	if lastID != "" {
		req.Header.Set("Last-Event-ID", lastID)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		cancel()
		t.Fatalf("status %d", resp.StatusCode)
	}
	return &sseClient{cancel: cancel, rd: stream.NewReader(resp.Body), resp: resp}
}

func (c *sseClient) next(t *testing.T) (*stream.Event, string) {
	t.Helper()
	done := make(chan struct{})
	var f *stream.Frame
	var err error
	go func() { f, err = c.rd.Next(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for event")
	}
	if err != nil {
		t.Fatal(err)
	}
	ev, _, err := upstream.Parse(f.Data)
	if err != nil {
		t.Fatalf("event does not match stream schema: %v (%s)", err, f.Data)
	}
	if ev.ID != f.ID || ev.Type != f.Event {
		t.Fatalf("SSE id/event (%s/%s) differ from JSON (%s/%s)", f.ID, f.Event, ev.ID, ev.Type)
	}
	return ev, f.ID
}

func (c *sseClient) close() { c.cancel(); c.resp.Body.Close() }

func seqOf(t *testing.T, id string) uint64 {
	_, s, err := stream.ParseID(id)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestResumeWithoutGaps(t *testing.T) {
	state := []stream.Event{{Type: stream.TypeWithdrawal, Envelope: env()}}
	h := New(Options{ID: "relay-1", Heartbeat: -1, Snapshot: func() []stream.Event { return state }})
	srv := httptest.NewServer(h)
	defer srv.Close()

	c := dial(t, srv.URL, "")
	ev, id := c.next(t) // full sync: one withdrawal
	if ev.Type != stream.TypeWithdrawal {
		t.Fatalf("full sync starts with %s", ev.Type)
	}
	var published []string
	for i := 0; i < 50; i++ {
		pid, err := h.Publish(stream.Event{Type: stream.TypeWithdrawal, Envelope: env()}, "")
		if err != nil {
			t.Fatal(err)
		}
		published = append(published, pid)
	}
	last := seqOf(t, id)
	for i := 0; i < 20; i++ {
		_, id = c.next(t)
		if s := seqOf(t, id); s <= last {
			t.Fatalf("ids not increasing: %d after %d", s, last)
		}
		last = seqOf(t, id)
		if id != published[i] {
			t.Fatalf("event %d: got %s, want %s", i, id, published[i])
		}
	}
	c.close()
	// More events while the client is away.
	for i := 0; i < 30; i++ {
		pid, _ := h.Publish(stream.Event{Type: stream.TypeWithdrawal, Envelope: env()}, "")
		published = append(published, pid)
	}
	c2 := dial(t, srv.URL, id)
	defer c2.close()
	for i := 20; i < len(published); i++ {
		_, got := c2.next(t)
		if got != published[i] {
			t.Fatalf("resume: event %d: got %s, want %s (gap or reorder)", i, got, published[i])
		}
	}
}

func TestUnknownOrTooOldIDFullSync(t *testing.T) {
	state := []stream.Event{
		{Type: stream.TypeWithdrawal, Envelope: env()},
		{Type: stream.TypeBundle, Ref: &stream.Ref{BundleID: "schild-main", Version: 3, URLPath: "/v0/bundles/schild-main/3.json", SHA256: "sha256:" + strings.Repeat("ab", 32), Size: 10}},
	}
	h := New(Options{ID: "r", Heartbeat: -1, Ring: 8, Snapshot: func() []stream.Event { return state }})
	srv := httptest.NewServer(h)
	defer srv.Close()
	for i := 0; i < 20; i++ { // evicts early events from the ring
		h.Publish(stream.Event{Type: stream.TypeWithdrawal, Envelope: env()}, "")
	}
	for _, last := range []string{"otherepoch-5", h.Epoch() + "-2", "garbage", h.Epoch() + "-999"} {
		c := dial(t, srv.URL, last)
		ev1, id1 := c.next(t)
		ev2, id2 := c.next(t)
		c.close()
		if ev1.Type != stream.TypeWithdrawal || ev2.Type != stream.TypeBundle {
			t.Fatalf("%s: full sync not in priority order: %s, %s", last, ev1.Type, ev2.Type)
		}
		if seqOf(t, id2) <= seqOf(t, id1) || seqOf(t, id1) <= 20 {
			t.Fatalf("%s: full sync ids must be fresh and increasing: %s %s", last, id1, id2)
		}
	}
	// An id that is still covered resumes instead.
	c := dial(t, srv.URL, h.Epoch()+"-19")
	defer c.close()
	_, id := c.next(t)
	if id != h.Epoch()+"-20" {
		t.Fatalf("resume from 19 got %s", id)
	}
}

func TestOverflowDisconnectsAndCoalesces(t *testing.T) {
	h := New(Options{ID: "r", Heartbeat: -1, Buffer: 4})
	c := &client{notify: make(chan struct{}, 1)}
	h.clients[c] = struct{}{}
	// Checkpoints of one lab coalesce: the backlog stays at one.
	for i := 0; i < 10; i++ {
		h.Publish(stream.Event{Type: stream.TypeCheckpoint, Envelope: env()}, "checkpoint:lab-a")
	}
	if len(c.pending) != 1 || c.closed {
		t.Fatalf("coalescing: pending=%d closed=%v", len(c.pending), c.closed)
	}
	// Withdrawals never coalesce; heartbeats/checkpoints are shed first.
	for i := 0; i < 4; i++ {
		h.Publish(stream.Event{Type: stream.TypeWithdrawal, Envelope: env()}, "")
	}
	if c.closed || len(c.pending) != 4 {
		t.Fatalf("shedding: pending=%d closed=%v", len(c.pending), c.closed)
	}
	for _, p := range c.pending {
		if p.typ != stream.TypeWithdrawal {
			t.Fatalf("a checkpoint survived while withdrawals were pending")
		}
	}
	h.Publish(stream.Event{Type: stream.TypeWithdrawal, Envelope: env()}, "")
	if !c.closed || c.reason != "overflow" {
		t.Fatalf("client over the buffer must be disconnected")
	}
	if h.Clients() != 0 {
		t.Fatalf("overflowed client still registered")
	}
}

func TestPollFallback(t *testing.T) {
	state := []stream.Event{{Type: stream.TypeWithdrawal, Envelope: env()}}
	h := New(Options{ID: "r", Heartbeat: -1, Snapshot: func() []stream.Event { return state }})
	evs, next, full := h.Poll(context.Background(), "", 0)
	if !full || len(evs) != 1 {
		t.Fatalf("first poll must be a full sync")
	}
	go func() {
		time.Sleep(50 * time.Millisecond)
		h.Publish(stream.Event{Type: stream.TypeWithdrawal, Envelope: env()}, "")
	}()
	evs, next2, full := h.Poll(context.Background(), next, 3*time.Second)
	if full || len(evs) != 1 || next2 == next {
		t.Fatalf("long poll: full=%v n=%d next=%s", full, len(evs), next2)
	}
	evs, _, _ = h.Poll(context.Background(), next2, 10*time.Millisecond)
	if len(evs) != 0 {
		t.Fatalf("nothing new expected")
	}
}

func TestHeartbeatCarriesCheckpoint(t *testing.T) {
	cp := env()
	cp = json.RawMessage(strings.Replace(string(cp), "withdrawal", "checkpoint", 1))
	h := New(Options{ID: "relay-x", Heartbeat: -1, HeartbeatCheckpoint: func() json.RawMessage { return cp }})
	srv := httptest.NewServer(h)
	defer srv.Close()
	c := dial(t, srv.URL, "")
	defer c.close()
	h.Heartbeat()
	ev, _ := c.next(t)
	if ev.Type != stream.TypeHeartbeat || ev.Relay == nil || ev.Relay.ID != "relay-x" || string(ev.Checkpoint) != string(cp) {
		t.Fatalf("bad heartbeat %+v", ev)
	}
}

// Delivered reports every event after it was flushed to a client, with the
// request of that client (the lab uses it for its relay coverage view).
func TestDeliveredCallback(t *testing.T) {
	got := make(chan string, 16)
	h := New(Options{ID: "lab-a", Heartbeat: -1, Delivered: func(r *http.Request, typ, id string, data []byte) {
		if r.Header.Get("X-Test-Relay") == "relay-9" && strings.Contains(string(data), `"type":"`+typ+`"`) {
			got <- typ + " " + id
		}
	}})
	srv := httptest.NewServer(h)
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+stream.Path, nil)
	req.Header.Set("X-Test-Relay", "relay-9")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	rd := stream.NewReader(resp.Body)
	id, err := h.Publish(stream.Event{Type: stream.TypeWithdrawal, Envelope: env()}, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rd.Next(); err != nil {
		t.Fatal(err)
	}
	select {
	case v := <-got:
		if v != stream.TypeWithdrawal+" "+id {
			t.Fatalf("delivered %q, want %s %s", v, stream.TypeWithdrawal, id)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Delivered not called")
	}
}
