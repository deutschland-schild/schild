package gate

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"

	"github.com/deutschland-schild/schild/contract/bodylimit"
	"github.com/deutschland-schild/schild/gateway/internal/metrics"
)

// A checked body waits for the backend outside its transaction (D44,
// contracts/body-limits.md section 2). The transaction keeps every transformed
// value of the evaluation and, for text, the whole body as a string, so it is
// closed first, at any size. Up to bodylimit.WaitingMemoryBodyBytes the body
// waits in memory, the rest in a temp file of its own. What memory it keeps, the
// overhead of the request included, counts in waiting bytes until the request
// ended, per client, per network and for the gateway. The limits apply when the
// next body is admitted: a body that passed its evaluation is never dropped.

// bodyWait is one request's count of waiting bytes. end is safe to call more
// than once.
type bodyWait struct {
	l               *bodyLimiter
	client, network string
	n               int64
	m               *metrics.Metrics
	ended           atomic.Bool
}

// wait counts a checked body of n bytes until end.
func (l *bodyLimiter) wait(ip netip.Addr, n int64, m *metrics.Metrics) *bodyWait {
	w := &bodyWait{l: l, n: bodylimit.Waiting(n), m: m}
	if ip.IsValid() {
		w.client, w.network = clientKey(ip), bodyNetKey(ip)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.waitClients == nil {
		l.waitClients, l.waitNetworks = map[string]int64{}, map[string]int64{}
	}
	if w.client != "" {
		l.waitClients[w.client] += w.n
		l.waitNetworks[w.network] += w.n
	}
	l.waiting += w.n
	if m != nil {
		m.BodiesWaiting.Inc()
		m.BodyWaitingBytes.Add(float64(w.n))
	}
	return w
}

// end gives the waiting bytes back.
func (w *bodyWait) end() {
	if !w.ended.CompareAndSwap(false, true) {
		return
	}
	l := w.l
	l.mu.Lock()
	defer l.mu.Unlock()
	if w.client != "" {
		if l.waitClients[w.client] -= w.n; l.waitClients[w.client] <= 0 {
			delete(l.waitClients, w.client)
		}
		if l.waitNetworks[w.network] -= w.n; l.waitNetworks[w.network] <= 0 {
			delete(l.waitNetworks, w.network)
		}
	}
	l.waiting -= w.n
	if w.m != nil {
		w.m.BodiesWaiting.Dec()
		w.m.BodyWaitingBytes.Add(-float64(w.n))
	}
}

// spoolBuffers keeps the copy into a temp file from allocating per request.
var spoolBuffers = sync.Pool{New: func() any { b := make([]byte, 32<<10); return &b }}

// waitingBody is a checked body after its transaction. The transport of the
// proxy may still read it after the handler returned, so a memory copy is never
// reused and reading a removed file ends the body instead of failing it.
type waitingBody struct {
	r    io.Reader
	file *os.File
}

// newWaitingBody moves n checked bytes out of the transaction. The temp file
// lies in TMPDIR, the temp space of bodies, whose name prefix is cleaned at start
// and measured by schild_body_spool_bytes.
func newWaitingBody(src io.Reader, n int64) (*waitingBody, error) {
	if bodylimit.WaitsInMemory(n) {
		b := make([]byte, n)
		if _, err := io.ReadFull(src, b); err != nil {
			return nil, err
		}
		return &waitingBody{r: bytes.NewReader(b)}, nil
	}
	f, err := os.CreateTemp("", bodylimit.TempFilePrefixes[0]+"-waiting*")
	if err != nil {
		return nil, err
	}
	b := &waitingBody{r: f, file: f}
	buf := spoolBuffers.Get().(*[]byte)
	defer spoolBuffers.Put(buf)
	// The wrappers hide ReadFrom and WriteTo: neither side has a faster way, and
	// the fallback of *os.File would allocate its own buffer.
	copied, err := io.CopyBuffer(struct{ io.Writer }{f}, struct{ io.Reader }{src}, *buf)
	if err == nil && copied != n {
		err = fmt.Errorf("body copy: %d of %d bytes", copied, n)
	}
	if err == nil {
		_, err = f.Seek(0, io.SeekStart)
	}
	if err != nil {
		b.remove()
		return nil, err
	}
	return b, nil
}

func (b *waitingBody) Read(p []byte) (int, error) {
	n, err := b.r.Read(p)
	if errors.Is(err, os.ErrClosed) {
		return n, io.EOF
	}
	return n, err
}

// remove deletes the temp file of the body, if it has one. A nil body has none.
func (b *waitingBody) remove() {
	if b != nil && b.file != nil {
		_ = b.file.Close()
		_ = os.Remove(b.file.Name())
	}
}
