package crawlers

import (
	"hash/maphash"
	"sync/atomic"

	"github.com/deutschland-schild/schild/gateway/internal/bots"
)

// uaCache remembers the bot id of recent user agents in a direct-mapped
// table keyed by a keyed hash of the first 512 bytes, like the monitor's
// UA cache: lock-free, one atomic word per slot holding a 40-bit tag of the
// hash, a valid bit and the bot id. A race only costs a new match. Used by
// the gate when monitoring is off (D57, measurement 1, finding 2).
type uaCache struct {
	seed  maphash.Seed
	eng   *bots.Engine
	slots [uaSlots]atomic.Uint64
}

const (
	uaSlots = 4096
	uaValid = 1 << 16
)

func newUACache(e *bots.Engine) *uaCache { return &uaCache{seed: maphash.MakeSeed(), eng: e} }

func (c *uaCache) id(ua string) uint16 {
	if len(ua) > bots.MaxUABytes {
		ua = ua[:bots.MaxUABytes]
	}
	if ua == "" {
		return 0
	}
	h := maphash.String(c.seed, ua)
	slot := &c.slots[h%uaSlots]
	tag := h >> 24 << 24
	if v := slot.Load(); v&uaValid != 0 && v>>24<<24 == tag {
		return uint16(v)
	}
	id, _ := c.eng.MatchUA(ua)
	slot.Store(tag | uaValid | uint64(id))
	return id
}
