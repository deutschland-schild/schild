package monitoring

import "net/netip"

// flushWrites writes the queued buckets synchronously (tests run without Start).
func (m *Monitor) flushWrites() {
	for {
		select {
		case j := <-m.writes:
			m.writeJob(j)
		default:
			return
		}
	}
}

// distinctRegisters reports whether the client keys of ips fall into
// different registers of the HyperLogLog sketches. The hash seed is random
// per process, so two of a handful of clients share a register now and then;
// the sketch then counts one client less, by design.
func (m *Monitor) distinctRegisters(ips ...string) bool {
	used := map[uint64]bool{}
	for _, ip := range ips {
		h, _ := m.rec.clientHash(netip.MustParseAddr(ip))
		i := h >> (64 - hllP)
		if used[i] {
			return false
		}
		used[i] = true
	}
	return true
}
