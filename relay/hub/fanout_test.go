package hub

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/contract/stream"
)

// memWriter is an in-memory SSE client: it records when a marker id arrives.
type memWriter struct {
	hdr    http.Header
	mu     sync.Mutex
	buf    bytes.Buffer
	marker []byte
	got    chan time.Time
	seen   bool
}

func (m *memWriter) Header() http.Header { return m.hdr }
func (m *memWriter) WriteHeader(int)     {}
func (m *memWriter) Write(p []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.seen && m.marker != nil && bytes.Contains(p, m.marker) {
		m.seen = true
		m.got <- time.Now()
	}
	return len(p), nil
}
func (m *memWriter) Flush() {}

// TestFanout10k connects 10,000 in-process clients and measures the time
// from Publish to the event being written to each client (B05 local; the
// target is 95 % < 10 s over the network, the hub itself must be far below).
func TestFanout10k(t *testing.T) {
	n := 10000
	if testing.Short() {
		n = 1000
	}
	if v := os.Getenv("SCHILD_FANOUT_CLIENTS"); v != "" {
		n, _ = strconv.Atoi(v)
	}
	h := New(Options{ID: "relay-bench", Heartbeat: -1})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	marker := []byte("id: " + h.Epoch() + "-1\n")
	ws := make([]*memWriter, n)
	var wg sync.WaitGroup
	for i := range ws {
		ws[i] = &memWriter{hdr: http.Header{}, marker: marker, got: make(chan time.Time, 1)}
		req := httptest.NewRequest(http.MethodGet, stream.Path, nil).WithContext(ctx)
		wg.Add(1)
		go func(w *memWriter) { defer wg.Done(); h.ServeHTTP(w, req) }(ws[i])
	}
	deadline := time.Now().Add(30 * time.Second)
	for h.Clients() < n {
		if time.Now().After(deadline) {
			t.Fatalf("only %d of %d clients connected", h.Clients(), n)
		}
		time.Sleep(5 * time.Millisecond)
	}
	start := time.Now()
	if _, err := h.Publish(stream.Event{Type: stream.TypeWithdrawal, Envelope: env()}, ""); err != nil {
		t.Fatal(err)
	}
	lat := make([]time.Duration, n)
	for i, w := range ws {
		select {
		case at := <-w.got:
			lat[i] = at.Sub(start)
		case <-time.After(30 * time.Second):
			t.Fatalf("client %d never got the event", i)
		}
	}
	sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
	p95, p99 := lat[n*95/100], lat[n*99/100]
	t.Logf("fan-out to %d clients: p50=%s p95=%s p99=%s max=%s", n, lat[n/2], p95, p99, lat[n-1])
	if p95 > 2*time.Second {
		t.Fatalf("in-process fan-out p95 %s too slow", p95)
	}
	cancel()
	wg.Wait()
}
