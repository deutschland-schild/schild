package reqring

import (
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/contract/msg"
)

// BenchmarkWriter measures the writer goroutine's work per record (visitor
// key, dictionaries, memory ring, segment append), off the request path.
func BenchmarkWriter(b *testing.B) {
	r, err := New(Config{StoragePath: b.TempDir()})
	if err != nil {
		b.Fatal(err)
	}
	defer r.Close()
	c := &clock{t: time.Date(2026, 10, 29, 10, 0, 1, 0, time.UTC)}
	r.cfg.Now = c.now
	es := make([]Entry, 1024)
	for i := range es {
		es[i] = entry(c, fmt.Sprintf("203.0.%d.%d", i/250, i%250), fmt.Sprintf("/p/%d", i%40))
		if i%10 == 0 {
			es[i].EventID = msg.NewID()
		}
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.handle(&es[i%len(es)])
	}
}

// TestRecordSize reports the bytes per record of a realistic mix, raw and
// compressed (the spec aims at about 40 B).
func TestRecordSize(t *testing.T) {
	r, c := newTestRing(t, Config{})
	const n = 20000
	for i := 0; i < n; i++ {
		e := entry(c, fmt.Sprintf("203.0.%d.%d", i%40, i%200), fmt.Sprintf("/p/%d", i%60))
		e.Referrer = []string{"_direct", "_intern", "google.com", "ai:chatgpt"}[i%4]
		if i%50 == 0 {
			e.EventID, e.Outcome, e.Rules, e.NRules, e.Score = msg.NewID(), OutWouldBlock, [3]string{"942100"}, 1, 5
		}
		e.Client = netip.MustParseAddr(fmt.Sprintf("203.0.%d.%d", i%40, i%200))
		e.Status = uint16([]int{200, 200, 200, 304, 404}[i%5])
		e.BytesOut = uint32(500 + i%20000)
		e.Dur = uint8(10 + i%30)
		r.Add(&e)
		if i%5000 == 0 {
			r.drain()
		}
		c.add(20 * time.Millisecond)
	}
	r.drain()
	r.mu.Lock()
	raw := r.seg.size
	r.mu.Unlock()
	r.finish()
	r.drainClosing()
	r.mu.Lock()
	z := r.files[len(r.files)-1].size
	r.mu.Unlock()
	t.Logf("%d records: raw %.1f B/record, compressed %.1f B/record", n, float64(raw)/n, float64(z)/n)
	if float64(raw)/n > 48 {
		t.Fatalf("raw record size %.1f B", float64(raw)/n)
	}
}
