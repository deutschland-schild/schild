package reqring

import (
	"encoding/binary"
	"math"
	"sync"
)

// memRing keeps every request of the last ContextRingWindow (10 min),
// unsampled, in at most ContextRingBytes (16 MiB) of encoded records with
// inline strings: chunks of chunkBytes, the oldest chunk goes first. At a
// high request rate it therefore covers less than 10 min.
type memRing struct {
	mu     sync.Mutex
	chunks []*memChunk // oldest first
	max    int
	buf    []byte
}

type memChunk struct {
	b           []byte
	first, last int64 // ms
	n           int
}

const chunkBytes = 256 << 10

func newMemRing(maxBytes int) *memRing {
	return &memRing{max: max(maxBytes/chunkBytes, 2)}
}

func (m *memRing) add(r *Rec) {
	m.buf = appendRec(m.buf[:0], r, 0, nil)
	var hdr [binary.MaxVarintLen64]byte
	hn := binary.PutUvarint(hdr[:], uint64(len(m.buf)))
	need := hn + len(m.buf)
	m.mu.Lock()
	defer m.mu.Unlock()
	var c *memChunk
	if n := len(m.chunks); n > 0 && len(m.chunks[n-1].b)+need <= chunkBytes {
		c = m.chunks[n-1]
	} else {
		if len(m.chunks) >= m.max {
			old := m.chunks[0]
			copy(m.chunks, m.chunks[1:])
			m.chunks = m.chunks[:len(m.chunks)-1]
			old.b, old.n = old.b[:0], 0
			c = old
		} else {
			c = &memChunk{b: make([]byte, 0, chunkBytes)}
		}
		c.first = r.T
		m.chunks = append(m.chunks, c)
	}
	c.b = append(c.b, hdr[:hn]...)
	c.b = append(c.b, m.buf...)
	if r.T < c.first {
		c.first = r.T
	}
	if r.T > c.last {
		c.last = r.T
	}
	c.n++
}

// expire drops chunks whose newest record is older than before.
func (m *memRing) expire(before int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	i := 0
	for i < len(m.chunks) && m.chunks[i].last < before {
		i++
	}
	if i > 0 {
		m.chunks = append(m.chunks[:0], m.chunks[i:]...)
	}
}

// clear empties the ring: it holds addresses, and a rare erasure is not worth
// rewriting its chunks for.
func (m *memRing) clear() { m.expire(math.MaxInt64) }

// oldest is the time from which the ring is complete (ms; 0 when empty).
func (m *memRing) oldest() int64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.chunks) == 0 {
		return 0
	}
	return m.chunks[0].first
}

// scan calls fn for every record with from <= t < to, oldest chunk first.
// fn must not keep r.
func (m *memRing) scan(from, to int64, fn func(r *Rec)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var r Rec
	for _, c := range m.chunks {
		if c.last < from || c.first >= to {
			continue
		}
		b := c.b
		for len(b) > 0 {
			n, k := binary.Uvarint(b)
			if k <= 0 || int(n) > len(b)-k {
				break
			}
			if decodeRec(b[k:k+int(n)], 0, nil, &r) == nil && r.T >= from && r.T < to {
				fn(&r)
			}
			b = b[k+int(n):]
		}
	}
}

func (m *memRing) bytes() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, c := range m.chunks {
		n += cap(c.b)
	}
	return n
}
