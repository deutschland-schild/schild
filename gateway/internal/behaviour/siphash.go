package behaviour

import (
	"encoding/binary"
	"math/bits"
	"sync"
)

// The keyed hashes of this package use the per-process random seed of
// hash/maphash: the same string hashes the same only inside one process. In
// a group of gateways (MVP-27) the nodes merge sketches and compare hashes
// of user names, so they need the same keyed hash: SipHash-2-4 (Aumasson,
// Bernstein 2012) under a key every node of the group holds and nobody
// else. Like the seed, the key keeps a client from choosing inputs that
// collide.

func sipRound(v0, v1, v2, v3 uint64) (uint64, uint64, uint64, uint64) {
	v0 += v1
	v1 = bits.RotateLeft64(v1, 13)
	v1 ^= v0
	v0 = bits.RotateLeft64(v0, 32)
	v2 += v3
	v3 = bits.RotateLeft64(v3, 16)
	v3 ^= v2
	v0 += v3
	v3 = bits.RotateLeft64(v3, 21)
	v3 ^= v0
	v2 += v1
	v1 = bits.RotateLeft64(v1, 17)
	v1 ^= v2
	v2 = bits.RotateLeft64(v2, 32)
	return v0, v1, v2, v3
}

// sipHash is SipHash-2-4 of b under the key (k0, k1).
func sipHash(k0, k1 uint64, b []byte) uint64 {
	v0 := k0 ^ 0x736f6d6570736575
	v1 := k1 ^ 0x646f72616e646f6d
	v2 := k0 ^ 0x6c7967656e657261
	v3 := k1 ^ 0x7465646279746573
	n := len(b)
	for len(b) >= 8 {
		m := binary.LittleEndian.Uint64(b)
		v3 ^= m
		v0, v1, v2, v3 = sipRound(v0, v1, v2, v3)
		v0, v1, v2, v3 = sipRound(v0, v1, v2, v3)
		v0 ^= m
		b = b[8:]
	}
	last := uint64(n) << 56
	for i, c := range b {
		last |= uint64(c) << (8 * uint(i))
	}
	v3 ^= last
	v0, v1, v2, v3 = sipRound(v0, v1, v2, v3)
	v0, v1, v2, v3 = sipRound(v0, v1, v2, v3)
	v0 ^= last
	v2 ^= 0xff
	for i := 0; i < 4; i++ {
		v0, v1, v2, v3 = sipRound(v0, v1, v2, v3)
	}
	return v0 ^ v1 ^ v2 ^ v3
}

var hashKeyMu sync.Mutex
var hashKeySet [16]byte
var hashKeyOn bool

// SetHashKey makes every keyed hash of this package SipHash-2-4 under key,
// for a node of a group. It has to be called before the first Engine of the
// process is made: the tables of an engine spread their entries by these
// hashes. The same key again changes nothing.
func SetHashKey(key [16]byte) {
	hashKeyMu.Lock()
	defer hashKeyMu.Unlock()
	if hashKeyOn && hashKeySet == key {
		return
	}
	k0, k1 := binary.LittleEndian.Uint64(key[:8]), binary.LittleEndian.Uint64(key[8:])
	keyedBytes = func(b []byte) uint64 { return sipHash(k0, k1, b) }
	keyedString = func(s string) uint64 { return sipHash(k0, k1, []byte(s)) }
	hashKeySet, hashKeyOn = key, true
}
