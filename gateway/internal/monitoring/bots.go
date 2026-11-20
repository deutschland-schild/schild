package monitoring

import (
	"net/netip"

	"github.com/deutschland-schild/schild/gateway/internal/bots"
)

// BotInfo is the bot classification of one request (MVP-22, D35), as
// record computes it for the counters and the request ring.
type BotInfo struct {
	// ID is the catalogue entry (bots.Engine.Bot), 0 for none.
	ID uint16
	// Category is an index into contract/monitoring BotCategories: the
	// entry's category, else likely_automated or likely_browser.
	Category uint8
	// Verification is bots.VerNone for no entry, else bots.VerVerified,
	// VerClaimed, VerMismatch or VerUnknownStale (index+1 into
	// contract/bots Verifications).
	Verification uint8
}

// UseBots sets the bot engine of the monitor (from schild.yaml bots; the
// default is bots.Default(): shipped catalogue, ranges on, FCrDNS off).
// Call it before the first request is recorded.
func (m *Monitor) UseBots(e *bots.Engine) {
	if m == nil || e == nil {
		return
	}
	m.rec.setBots(e)
}

// Bots returns the bot engine in use.
func (m *Monitor) Bots() *bots.Engine {
	if m == nil {
		return bots.Default()
	}
	return m.rec.bots
}

// ClassifyBot classifies one request the way record does (no counting).
// It does not allocate on a cache hit.
func (m *Monitor) ClassifyBot(ua string, client netip.Addr) BotInfo {
	rc := m.rec
	u := rc.ua.classify(ua)
	return BotInfo{ID: u.id, Category: uint8(u.bot), Verification: rc.bots.Verify(u.id, client)}
}

// BotID returns the catalogue entry a User-Agent names (0: none) from the
// monitor's UA cache (D57: the gate asks before the request goes on; the
// record afterwards hits the same cache slot). It does not allocate.
func (m *Monitor) BotID(ua string) uint16 {
	if m == nil {
		id, _ := bots.Default().MatchUA(ua)
		return id
	}
	return m.rec.ua.classify(ua).id
}

func (rc *recorder) setBots(e *bots.Engine) {
	rc.bots = e
	rc.ua = newUACache(e)
}
