package bots

import (
	"bytes"
	"strings"

	"github.com/deutschland-schild/schild/contract/bots"
)

// matcher finds every catalogue token and automation token in one pass over
// the lower-cased User-Agent: tokens are indexed by their first two bytes
// (a bitmap to skip most positions, then the candidate list of the pair),
// so a position compares only the few tokens that start with its two bytes. Semantics are exactly those of
// contract bots.Catalogue.Match: the longest token wins, on equal length
// the one the contract's loop meets first (catalogue order of bots, then
// the order of their ua_match tokens).
type matcher struct {
	toks  []mtok
	pairs [1 << 16 / 64]uint64 // bitmap of the first two bytes of every token
	// Candidates by their first two bytes (CSR): cand[start[p]:start[p+1]]
	// are the token indices starting with pair p, in token order.
	start []uint32
	cand  []uint16
}

type mtok struct {
	tok   []byte // lower case, at least 2 bytes (schema)
	bot   uint16 // bot id (index+1); 0 for an automation token
	order uint32 // position in the contract's loop
}

func pairOf(a, b byte) uint16 { return uint16(a)<<8 | uint16(b) }

func newMatcher(c *bots.Catalogue) *matcher {
	m := &matcher{}
	order := uint32(0)
	for i := range c.Bots {
		for _, t := range c.Bots[i].UAMatch {
			m.toks = append(m.toks, mtok{tok: []byte(strings.Map(lowerASCII, t)), bot: uint16(i + 1), order: order})
			order++
		}
	}
	for _, t := range c.AutomationTokens {
		m.toks = append(m.toks, mtok{tok: []byte(strings.Map(lowerASCII, t)), order: order})
		order++
	}
	if len(m.toks) > 1<<16 {
		panic("bots: too many tokens")
	}
	m.start = make([]uint32, 1<<16+1)
	for _, t := range m.toks {
		m.start[pairOf(t.tok[0], t.tok[1])+1]++
	}
	for p := 1; p < len(m.start); p++ {
		m.start[p] += m.start[p-1]
	}
	m.cand = make([]uint16, len(m.toks))
	fill := append([]uint32(nil), m.start[:1<<16]...)
	for i, t := range m.toks {
		p := pairOf(t.tok[0], t.tok[1])
		m.cand[fill[p]] = uint16(i)
		fill[p]++
		m.pairs[p/64] |= 1 << (p % 64)
	}
	return m
}

// lowerASCII lower-cases ASCII letters only (as the contract does).
func lowerASCII(r rune) rune {
	if r >= 'A' && r <= 'Z' {
		return r + 'a' - 'A'
	}
	return r
}

// scan returns the bot id of the best token (0: none) and whether an
// automation token occurs. b is lower case.
func (m *matcher) scan(b []byte) (id uint16, auto bool) {
	bestLen, bestOrder := 0, uint32(1<<32-1)
	for i := 0; i+1 < len(b); i++ {
		p := pairOf(b[i], b[i+1])
		if m.pairs[p/64]&(1<<(p%64)) == 0 {
			continue
		}
		rest := b[i:]
		for _, ti := range m.cand[m.start[p]:m.start[p+1]] {
			t := &m.toks[ti]
			n := len(t.tok)
			if n > len(rest) || !bytes.Equal(rest[2:n], t.tok[2:]) {
				continue
			}
			if t.bot == 0 {
				auto = true
				continue
			}
			if n > bestLen || n == bestLen && t.order < bestOrder {
				id, bestLen, bestOrder = t.bot, n, t.order
			}
		}
	}
	return id, auto
}

var mozilla = []byte("mozilla/")

// MatchLower is MatchUA for a User-Agent that is already cut to its first
// 512 bytes and ASCII lower-cased (the monitoring classifier lower-cases
// once for all its checks). It does not allocate.
func (e *Engine) MatchLower(b []byte) (id uint16, category int) {
	if len(b) > bots.MaxUABytes {
		b = b[:bots.MaxUABytes]
	}
	id, auto := e.m.scan(b)
	switch {
	case id != 0:
		return id, int(e.cats[id])
	case len(b) == 0 || !bytes.HasPrefix(b, mozilla) || auto:
		return 0, CategoryLikelyAutomated
	}
	return 0, CategoryLikelyBrowser
}

// MatchUA returns the catalogue entry a User-Agent names (id 0: none) and
// its category as an index into contract/monitoring BotCategories:
// the entry's category, else likely_automated or likely_browser
// (contract/bots Match). It does not allocate.
func (e *Engine) MatchUA(ua string) (id uint16, category int) {
	var buf [bots.MaxUABytes]byte
	n := copy(buf[:], ua)
	b := buf[:n]
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return e.MatchLower(b)
}
