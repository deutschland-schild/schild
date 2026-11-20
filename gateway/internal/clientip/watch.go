package clientip

import (
	"sync/atomic"
	"time"
)

// Watch notices a proxy in front that is not trusted (D91): requests from a
// private or loopback peer outside ingress.trusted_proxies that carry a
// forwarding header (Result.Ignored). Behind nginx on the Docker host or a
// load balancer that is every request, and every visitor then counts as the
// proxy: statistics, scenarios and blocks see one private address, and
// private addresses are never blocked. The overview names it
// (trusted_proxies_missing) instead of failing silently.
//
// Two 10-minute slots of counters, lock free: a hint, not a measurement; a
// slot reset racing an add may lose a count.
type Watch struct {
	slots [2]watchSlot
}

type watchSlot struct {
	id, total, ignored atomic.Int64
}

const (
	watchSlotS     = 600
	watchMinHits   = 20
	watchMinShareN = 1 // ignored >= total * N / D
	watchMinShareD = 2
)

// Note counts one request.
func (w *Watch) Note(now time.Time, ignored bool) {
	id := now.Unix() / watchSlotS
	s := &w.slots[id%2]
	if s.id.Load() != id && s.id.Swap(id) != id {
		s.total.Store(0)
		s.ignored.Store(0)
	}
	s.total.Add(1)
	if ignored {
		s.ignored.Add(1)
	}
}

// Missing reports whether, over the current and the previous slot, at least
// 20 requests and at least half of all came from an untrusted proxy.
func (w *Watch) Missing(now time.Time) bool {
	id := now.Unix() / watchSlotS
	var total, ignored int64
	for i := range w.slots {
		s := &w.slots[i]
		if sid := s.id.Load(); sid == id || sid == id-1 {
			total += s.total.Load()
			ignored += s.ignored.Load()
		}
	}
	return ignored >= watchMinHits && ignored*watchMinShareD >= total*watchMinShareN
}
