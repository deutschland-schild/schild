//go:build !release

package behaviour

import "net/netip"

// EvictBlock drops the block of the client of ip from the block table as a
// full table drops one: nothing is reported and nothing else is touched. A
// test of the group fills no table of 16 384 blocks for it. A release
// build has no such hook.
func (e *Engine) EvictBlock(ip netip.Addr) {
	if key, _ := KeyOf(ip); key.IsValid() {
		e.blocks.delete(key)
	}
}

// SetBlockCapacity shrinks the block table to n entries (32 parts, at least
// one entry each), for tests of a full table. Called before any block.
func (e *Engine) SetBlockCapacity(n int) { e.blocks.per = max(n/shards, 1) }
