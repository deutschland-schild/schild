package behaviour

import "sync"

const shards = 32

// table is a fixed-capacity, sharded map. When a shard is full, inserting
// evicts an entry (Go's randomised map iteration order makes it a random
// eviction), so a flood of distinct addresses can never grow memory beyond
// the capacity and never takes a global lock.
type table[K comparable, V any] struct {
	shards [shards]shard[K, V]
	per    int
	hash   func(K) uint64
	// evictFirst, when set, returns a predicate for entries that a full
	// shard evicts before any other (D38: ended blocks before running
	// ones); it is called once per eviction. Without a matching entry the
	// eviction stays random.
	evictFirst func() func(*V) bool
}

type shard[K comparable, V any] struct {
	mu      sync.Mutex
	m       map[K]*V
	evicted uint64
}

func newTable[K comparable, V any](capacity int, hash func(K) uint64) *table[K, V] {
	t := &table[K, V]{per: max(capacity/shards, 1), hash: hash}
	for i := range t.shards {
		t.shards[i].m = make(map[K]*V, t.per)
	}
	return t
}

func (t *table[K, V]) shard(k K) *shard[K, V] { return &t.shards[t.hash(k)%shards] }

// with runs f on the entry of k under the shard lock. create: insert a zero
// entry when missing (evicting one when the shard is full); otherwise f gets
// nil for a missing key. f must not call back into the table.
func (t *table[K, V]) with(k K, create bool, f func(*V)) {
	s := t.shard(k)
	s.mu.Lock()
	defer s.mu.Unlock()
	v := s.m[k]
	if v == nil && create {
		if len(s.m) >= t.per {
			t.evict(s)
		}
		v = new(V)
		s.m[k] = v
	}
	f(v)
}

// evict removes one entry of a full shard (lock held): the first one
// evictFirst matches, else any.
func (t *table[K, V]) evict(s *shard[K, V]) {
	if t.evictFirst != nil {
		first := t.evictFirst()
		for ek, ev := range s.m {
			if first(ev) {
				delete(s.m, ek)
				s.evicted++
				return
			}
		}
	}
	for ek := range s.m {
		delete(s.m, ek)
		s.evicted++
		return
	}
}

// room reports whether an entry of k fits without dropping one that still
// counts: k has an entry, the shard is not full, or it holds an entry that
// spare reports (one a full shard drops first anyway).
func (t *table[K, V]) room(k K, spare func(*V) bool) bool {
	s := t.shard(k)
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.m[k]; ok || len(s.m) < t.per {
		return true
	}
	for _, v := range s.m {
		if spare(v) {
			return true
		}
	}
	return false
}

// delete removes k.
func (t *table[K, V]) delete(k K) {
	s := t.shard(k)
	s.mu.Lock()
	delete(s.m, k)
	s.mu.Unlock()
}

// sweep removes entries for which drop returns true and visits the rest.
func (t *table[K, V]) sweep(drop func(K, *V) bool) {
	for i := range t.shards {
		s := &t.shards[i]
		s.mu.Lock()
		for k, v := range s.m {
			if drop(k, v) {
				delete(s.m, k)
			}
		}
		s.mu.Unlock()
	}
}

// len returns the number of entries.
func (t *table[K, V]) len() int {
	n := 0
	for i := range t.shards {
		s := &t.shards[i]
		s.mu.Lock()
		n += len(s.m)
		s.mu.Unlock()
	}
	return n
}

// evictions returns how many entries were evicted because a shard was full.
func (t *table[K, V]) evictions() uint64 {
	var n uint64
	for i := range t.shards {
		s := &t.shards[i]
		s.mu.Lock()
		n += s.evicted
		s.mu.Unlock()
	}
	return n
}

// each visits the entries of shard i under its lock (0 <= i < shards). f
// must not call back into the table.
func (t *table[K, V]) each(i int, f func(K, *V)) {
	s := &t.shards[i]
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, v := range s.m {
		f(k, v)
	}
}
