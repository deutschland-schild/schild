// Package sites is the website model of the gateway (contracts v0.5, D36):
// the websites derived from the Caddyfile site blocks (ingress mode) or
// upstream.site_hosts (proxy mode) by contract/websites, and the mapping of
// a request Host to its website and to its monitoring slot (the first 32
// websites schild sees have their own series, the rest is _other).
//
// Resolve is on the request path: a Host seen before is answered from a
// bounded cache without allocation.
package sites

import (
	"strings"
	"sync"
	"sync/atomic"

	"github.com/deutschland-schild/schild/contract/websites"
)

// Slots of the monitoring rings: 0..MaxTracked-1 are the tracked websites,
// OtherSlot sums the untracked ones, NoSlot is a request of no website.
const (
	OtherSlot = websites.MaxTracked
	Slots     = websites.MaxTracked + 1
	NoSlot    = -1
)

// View is one derived website set. Immutable after New.
type View struct {
	Set    *websites.Set
	Source string // websites.SourceCaddyfile | websites.SourceProxy
	// Err is the derivation error; the view then has the one website
	// "default" so the gateway keeps counting.
	Err error
	// Protected is the number of websites schild sees (protected or
	// partial): the total of SitesAffected.
	Protected int

	index map[string]int // id -> index in Set.Websites
	slot  []int          // website index -> slot (NoSlot for unprotected)
	names [Slots]string  // slot -> id
	cache hostCache
	own   hostCache // OwnHost answers (1 own, 0 not)
}

// NewView derives the websites of in. On a derivation error the view has
// the one website DefaultID (and Err set).
func NewView(in websites.Input) *View {
	src := websites.SourceCaddyfile
	if in.Mode == websites.ModeProxy {
		src = websites.SourceProxy
	}
	set, err := websites.Derive(in)
	if err != nil && in.Mode == websites.ModeIngress {
		set = deriveWithoutBroken(in)
	}
	if set == nil {
		set, _ = websites.Derive(websites.Input{Mode: websites.ModeProxy})
	}
	v := &View{Set: set, Source: src, Err: err, index: map[string]int{}}
	v.names[OtherSlot] = websites.OtherSite
	n := 0
	for i, w := range set.Websites {
		v.index[w.ID] = i
		s := NoSlot
		switch {
		case w.Protection == websites.Unprotected:
		case w.Tracked:
			s = n
			v.names[n] = w.ID
			n++
		default:
			s = OtherSlot
		}
		if w.Protection != websites.Unprotected {
			v.Protected++
		}
		v.slot = append(v.slot, s)
	}
	v.cache.init()
	v.own.init()
	return v
}

// deriveWithoutBroken derives the websites of the blocks that derive on
// their own (D36 fix round 2): a block that alone is an error (an address
// that does not parse, a backend without schild that is not listed) is
// dropped, the other websites stay. Nil when no block is left or the rest
// still fails; the caller then falls back to the one website "default".
func deriveWithoutBroken(in websites.Input) *websites.Set {
	keep := in
	keep.Blocks = nil
	for _, b := range in.Blocks {
		one := in
		one.Blocks = []websites.Block{b}
		if _, err := websites.Derive(one); err == nil {
			keep.Blocks = append(keep.Blocks, b)
		}
	}
	if len(keep.Blocks) == 0 {
		return nil
	}
	set, err := websites.Derive(keep)
	if err != nil {
		return nil
	}
	return set
}

// Resolve maps the Host header of a request to its website id ("" for
// none) and its monitoring slot.
func (v *View) Resolve(host string) (id string, slot int) {
	i := v.cache.get(host, func(h string) int32 {
		id := v.Set.Resolve(h)
		if j, ok := v.index[id]; ok {
			return int32(j)
		}
		return -1
	})
	if i < 0 {
		return "", NoSlot
	}
	return v.Set.Websites[i].ID, v.slot[i]
}

// OwnHost reports whether host (a Referer host, optional port) is a host of
// any website of this gateway (websites.Set.OwnHost, D36 amendment: the
// referrer key _intern). Cached like Resolve: a hit does not allocate.
func (v *View) OwnHost(host string) bool {
	return v.own.get(host, func(h string) int32 {
		if v.Set.OwnHost(h) {
			return 1
		}
		return 0
	}) == 1
}

// ID is the website id of a Host header ("" for none).
func (v *View) ID(host string) string {
	id, _ := v.Resolve(host)
	return id
}

// SlotName returns the series name of a slot (website id or _other); ""
// for an unused slot.
func (v *View) SlotName(slot int) string {
	if slot < 0 || slot >= Slots {
		return ""
	}
	return v.names[slot]
}

// SlotOf returns the slot of a website id (NoSlot for unknown or
// unprotected ids).
func (v *View) SlotOf(id string) int {
	if id == websites.OtherSite {
		return OtherSlot
	}
	i, ok := v.index[id]
	if !ok {
		return NoSlot
	}
	return v.slot[i]
}

// Website returns a website by id.
func (v *View) Website(id string) (websites.Website, bool) {
	i, ok := v.index[id]
	if !ok {
		return websites.Website{}, false
	}
	return v.Set.Websites[i], true
}

// Websites returns every website in configuration order.
func (v *View) Websites() []websites.Website { return v.Set.Websites }

// Tracked returns the number of tracked websites.
func (v *View) Tracked() int {
	n := 0
	for _, s := range v.slot {
		if s >= 0 && s < OtherSlot {
			n++
		}
	}
	return n
}

// Untracked returns the number of protected websites counted in _other.
func (v *View) Untracked() int {
	n := 0
	for _, s := range v.slot {
		if s == OtherSlot {
			n++
		}
	}
	return n
}

// Registry holds the current view (swapped on a configuration change).
type Registry struct{ cur atomic.Pointer[View] }

// NewRegistry returns a registry with v.
func NewRegistry(v *View) *Registry {
	r := &Registry{}
	r.cur.Store(v)
	return r
}

// View returns the current view.
func (r *Registry) View() *View { return r.cur.Load() }

// Store swaps the view.
func (r *Registry) Store(v *View) { r.cur.Store(v) }

// Resolve is View().Resolve; a nil registry resolves nothing.
func (r *Registry) Resolve(host string) (string, int) {
	if r == nil {
		return "", NoSlot
	}
	return r.cur.Load().Resolve(host)
}

// OwnHost is View().OwnHost; false for a nil registry.
func (r *Registry) OwnHost(host string) bool {
	if r == nil {
		return false
	}
	return r.cur.Load().OwnHost(host)
}

// ID is View().ID; "" for a nil registry.
func (r *Registry) ID(host string) string {
	if r == nil {
		return ""
	}
	return r.cur.Load().ID(host)
}

// ---------------------------------------------------------------- cache

// hostCache maps Host headers to website indexes, bounded in entries:
// a stripe that is full starts over, and a key longer than 256 bytes is
// resolved without being stored. A hit takes a read lock and no allocation.
type hostCache struct {
	stripes [16]struct {
		mu sync.RWMutex
		m  map[string]int32
	}
}

const (
	cacheStripeMax = 1024
	cacheKeyMax    = 256
)

func (c *hostCache) init() {
	for i := range c.stripes {
		c.stripes[i].m = make(map[string]int32, 16)
	}
}

func (c *hostCache) get(k string, compute func(string) int32) int32 {
	if len(k) > cacheKeyMax || len(k) == 0 {
		return compute(k)
	}
	st := &c.stripes[(len(k)+int(k[len(k)-1]))%len(c.stripes)]
	st.mu.RLock()
	v, ok := st.m[k]
	st.mu.RUnlock()
	if ok {
		return v
	}
	v = compute(k)
	st.mu.Lock()
	if len(st.m) >= cacheStripeMax {
		clear(st.m)
	}
	st.m[strings.Clone(k)] = v
	st.mu.Unlock()
	return v
}
