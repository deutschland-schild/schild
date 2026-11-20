package gate

import (
	"context"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/semaphore"

	"github.com/deutschland-schild/schild/contract/config"
	"github.com/deutschland-schild/schild/gateway/internal/waf"
)

// EvalLimits bound the WAF work of the gate in every mode (ingress and proxy).
//
// MVP-19 measurement, finding 1: an evaluation that ran out of its budget kept
// running in the background, and nothing bounded how many evaluations ran at
// once. MVP-19 re-measurement, findings 2 and 3: requests just under the old
// 128 KiB "large body" line or with many arguments were as expensive and
// pushed ordinary requests out, and many-argument GETs exhausted the memory.
// Now:
//   - at most MaxConcurrent evaluations run at once; a request waits at most
//     QueueWait for a free slot and is otherwise answered 503 + Retry-After
//     (never passed uninspected);
//   - every phase is classified by its estimated cost (Estimate: arguments,
//     length of the request target and Host, body size and type; security
//     audit 2026-11-05: a long path counted as cheap and one client held
//     every slot). Expensive evaluations take at most
//     MaxHeavy of the slots, never more than config.ExpensiveEvalSlots
//     (about half), so cheap ordinary requests (typical GETs, small forms)
//     always keep MaxConcurrent-MaxHeavy slots of their own;
//   - one client may hold at most PerClient expensive evaluations at once
//     (clients on cgnat or mobile addresses, many people behind one address,
//     SharedFactor times as many, never more than MaxHeavy). A client is an
//     IPv4 address or an IPv6 /64; one IPv6 /48 together holds at most
//     config.NetEvalShare(MaxHeavy), half the expensive slots, so whoever
//     owns a /48 cannot collect a share per /64 and fill them (cgnat and
//     mobile addresses are exempt: carriers put many people under one /48);
//   - expensive evaluations together stay within MemBudget bytes of
//     estimated memory (a weighted semaphore), whatever the slot count;
//   - an evaluation over its budget is cancelled (it stops at the next rule)
//     and keeps its slot and its memory share until it has really stopped,
//     so abandoned work can never pile up beyond the limits.
type EvalLimits struct {
	MaxConcurrent int
	MaxHeavy      int
	QueueWait     time.Duration
	// A request is expensive above HeavyArgs arguments (query, body and
	// cookies), HeavyQuery bytes of request target (path and query) and
	// Host, or HeavyBody bytes of a body the rules read as text
	// (urlencoded, JSON, XML, plain text).
	HeavyBody  int64
	HeavyArgs  int
	HeavyQuery int
	// PerClient expensive evaluations of one client at once.
	PerClient int
	// MemBudget is the estimated memory of all expensive evaluations at
	// once, in bytes.
	MemBudget int64
	// BodyAllowance is added to the phase 2 budget per KiB of body the
	// rules read as text, up to MaxBudget (see Gate.bodyBudget).
	BodyAllowance time.Duration
	MaxBudget     time.Duration
}

// Defaults of EvalLimits.
const (
	DefaultQueueWait = 100 * time.Millisecond
	// DefaultHeavyBody: CRS costs about 3 ms per KiB of text on the
	// measurement machine, so 32 KiB is about 0.1 s of CPU.
	DefaultHeavyBody = 32 << 10
	// DefaultHeavyArgs: each argument is run through every CRS rule that
	// reads ARGS; 64 arguments are about 20 ms and 4 MiB.
	DefaultHeavyArgs     = 64
	DefaultHeavyQuery    = 4 << 10
	DefaultMemBudget     = 1 << 30
	DefaultBodyAllowance = 4 * time.Millisecond
	DefaultMaxBudget     = 10 * time.Second // the schema maximum of waf.eval_timeout_ms
	// SharedFactor multiplies PerClient for a cgnat or mobile address.
	SharedFactor = 4
)

// Cost model of one evaluation (measured with Coraza 3.8.1 and CRS 4 at
// paranoia level 1, rounded up): Coraza caches every transformed argument
// value per rule for the phase, about 40-110 KiB per argument; text bodies
// cost a few dozen bytes per byte.
const (
	memBase    = 256 << 10
	memPerArg  = 96 << 10
	memPerByte = 32
)

// DefaultEvalLimits derives the slots from GOMAXPROCS.
func DefaultEvalLimits() EvalLimits { return EvalLimits{}.norm() }

func (l EvalLimits) norm() EvalLimits {
	if l.MaxConcurrent <= 0 {
		l.MaxConcurrent = max(2, runtime.GOMAXPROCS(0))
	}
	// Reserved slots (D31 amendment 2026-10-29, contract/config
	// ExpensiveEvalSlots): expensive evaluations never use more than
	// ExpensiveEvalSlots(MaxConcurrent), whatever MaxHeavy asks for (also
	// through an environment override); the other slots stay free for cheap
	// ones. MaxConcurrent 1 exists only in tests (config and environment
	// raise it to MinEvalSlots); the cap never exceeds the slots.
	exp := min(config.ExpensiveEvalSlots(l.MaxConcurrent), l.MaxConcurrent)
	if l.MaxHeavy <= 0 || l.MaxHeavy > exp {
		l.MaxHeavy = exp
	}
	if l.QueueWait <= 0 {
		l.QueueWait = DefaultQueueWait
	}
	if l.HeavyBody <= 0 {
		l.HeavyBody = DefaultHeavyBody
	}
	if l.HeavyArgs <= 0 {
		l.HeavyArgs = DefaultHeavyArgs
	}
	if l.HeavyQuery <= 0 {
		l.HeavyQuery = DefaultHeavyQuery
	}
	if l.PerClient <= 0 {
		l.PerClient = max(2, l.MaxHeavy/3)
	}
	if l.MemBudget <= 0 {
		l.MemBudget = DefaultMemBudget
	}
	if l.BodyAllowance <= 0 {
		l.BodyAllowance = DefaultBodyAllowance
	}
	if l.MaxBudget <= 0 {
		l.MaxBudget = DefaultMaxBudget
	}
	return l
}

// Shape is what the gate knows about a request before an evaluation phase.
type Shape struct {
	QueryArgs  int
	QueryBytes int
	// TargetBytes is the request target as sent (path and query) plus the
	// Host: phase 1 runs the URI and header rules over both, so their length
	// costs like a long query does.
	TargetBytes int
	Cookies     int
	Body        waf.BodyInfo // zero before the body is read
}

// textBytes are the body bytes the rules read as text: a whole body, or the
// text fields of a multipart form, never its file content.
func (s Shape) textBytes() int64 {
	if s.Body.Files {
		return s.Body.Text
	}
	return s.Body.Bytes
}

// Cost is the estimated cost of one evaluation phase.
type Cost struct {
	Heavy bool
	// Mem is the estimated memory in bytes (counted against MemBudget for
	// expensive evaluations).
	Mem int64
	// Net keys the share of an IPv6 /48 ("" for none, see EvalLimits).
	Net string
	// Client keys the per-client share ("" for none); Shared marks a cgnat
	// or mobile address.
	Client string
	Shared bool
}

// Estimate classifies one evaluation phase by its expected cost.
func (l EvalLimits) Estimate(s Shape) Cost {
	l = l.norm()
	args := s.QueryArgs + s.Cookies + s.Body.Args
	text := s.textBytes()
	line := max(s.TargetBytes, s.QueryBytes)
	mem := int64(memBase) + int64(args)*memPerArg + (int64(line)+text)*memPerByte
	heavy := args > l.HeavyArgs || line > l.HeavyQuery || text > l.HeavyBody
	return Cost{Heavy: heavy, Mem: mem}
}

type evalPool struct {
	lim   EvalLimits
	slots chan struct{}
	heavy chan struct{}
	mem   *semaphore.Weighted

	mu      sync.Mutex
	clients map[string]int // expensive evaluations per client and per IPv6 /48

	inFlight      atomic.Int64
	heavyInFlight atomic.Int64
	memInUse      atomic.Int64
	waiting       atomic.Int64
	busy          atomic.Int64 // requests answered 503 because no slot was free
	clientBusy    atomic.Int64 // of busy: the client had its share of expensive slots
	cancelled     atomic.Int64 // evaluations stopped after their budget
}

func newEvalPool(l EvalLimits) *evalPool {
	l = l.norm()
	return &evalPool{lim: l, slots: make(chan struct{}, l.MaxConcurrent), heavy: make(chan struct{}, l.MaxHeavy),
		mem: semaphore.NewWeighted(l.MemBudget), clients: map[string]int{}}
}

// share is the number of expensive evaluations one client may run at once.
func (p *evalPool) share(c Cost) int {
	if c.Shared {
		return min(p.lim.MaxHeavy, p.lim.PerClient*SharedFactor)
	}
	return min(p.lim.MaxHeavy, p.lim.PerClient)
}

// hold counts one expensive evaluation under key unless limit are running,
// and returns how to give it back.
func (p *evalPool) hold(key string, limit int) (func(), bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.clients[key] >= limit {
		return nil, false
	}
	p.clients[key]++
	return func() {
		p.mu.Lock()
		if p.clients[key]--; p.clients[key] <= 0 {
			delete(p.clients, key)
		}
		p.mu.Unlock()
	}, true
}

// takeShares holds the client's share and the share of its IPv6 /48.
func (p *evalPool) takeShares(c Cost, undo *[]func()) bool {
	if c.Client != "" {
		give, ok := p.hold(c.Client, p.share(c))
		if !ok {
			return false
		}
		*undo = append(*undo, give)
	}
	if c.Net != "" && !c.Shared {
		give, ok := p.hold(c.Net, config.NetEvalShare(p.lim.MaxHeavy))
		if !ok {
			return false
		}
		*undo = append(*undo, give)
	}
	return true
}

// acquire takes what the evaluation needs within the queue wait: for an
// expensive one the client's share, a heavy slot and its memory, then a
// slot. The returned release must be called exactly once.
func (p *evalPool) acquire(c Cost) (release func(), ok bool) {
	var undo []func()
	fail := func() (func(), bool) {
		for i := len(undo) - 1; i >= 0; i-- {
			undo[i]()
		}
		p.busy.Add(1)
		return nil, false
	}
	deadline := time.Now().Add(p.lim.QueueWait)
	var timer *time.Timer
	waitStarted := false
	startWait := func() {
		if !waitStarted {
			waitStarted = true
			p.waiting.Add(1)
		}
	}
	defer func() {
		if waitStarted {
			p.waiting.Add(-1)
		}
		if timer != nil {
			timer.Stop()
		}
	}()
	take := func(ch chan struct{}) bool {
		select {
		case ch <- struct{}{}:
			return true
		default:
		}
		startWait()
		if timer == nil {
			timer = time.NewTimer(time.Until(deadline))
		}
		select {
		case ch <- struct{}{}:
			return true
		case <-timer.C:
			return false
		}
	}
	if c.Heavy {
		if !p.takeShares(c, &undo) {
			p.clientBusy.Add(1)
			return fail()
		}
		if !take(p.heavy) {
			return fail()
		}
		undo = append(undo, func() { <-p.heavy })
		mem := min(max(c.Mem, 1), p.lim.MemBudget) // a single evaluation larger than the budget runs alone
		if !p.mem.TryAcquire(mem) {
			startWait()
			ctx, cancel := context.WithDeadline(context.Background(), deadline)
			err := p.mem.Acquire(ctx, mem)
			cancel()
			if err != nil {
				return fail()
			}
		}
		p.memInUse.Add(mem)
		undo = append(undo, func() { p.memInUse.Add(-mem); p.mem.Release(mem) })
	}
	if !take(p.slots) {
		return fail()
	}
	undo = append(undo, func() { <-p.slots })
	p.inFlight.Add(1)
	if c.Heavy {
		p.heavyInFlight.Add(1)
	}
	var once atomic.Bool
	return func() {
		if !once.CompareAndSwap(false, true) {
			return
		}
		p.inFlight.Add(-1)
		if c.Heavy {
			p.heavyInFlight.Add(-1)
		}
		for i := len(undo) - 1; i >= 0; i-- {
			undo[i]()
		}
	}, true
}

// SetEvalLimits replaces the evaluation limits. Evaluations in flight finish
// on the slots they hold.
func (g *Gate) SetEvalLimits(l EvalLimits) { g.evals.Store(newEvalPool(l)) }

// EvalLimits returns the active evaluation limits.
func (g *Gate) EvalLimits() EvalLimits { return g.evals.Load().lim }

// EvalStats are counters of the evaluation slots (tests and status).
type EvalStats struct {
	InFlight      int64 // evaluations holding a slot, including cancelled ones still stopping
	HeavyInFlight int64 // of InFlight: expensive evaluations
	MemInUse      int64 // estimated memory of the expensive evaluations in flight
	Waiting       int64 // requests waiting for a slot
	Busy          int64 // requests answered 503 because every slot was taken
	ClientBusy    int64 // of Busy: the client already ran its share of expensive evaluations
	Cancelled     int64 // evaluations stopped after their budget ran out
}

// EvalStats returns the counters of the active pool.
func (g *Gate) EvalStats() EvalStats {
	p := g.evals.Load()
	return EvalStats{InFlight: p.inFlight.Load(), HeavyInFlight: p.heavyInFlight.Load(), MemInUse: p.memInUse.Load(), Waiting: p.waiting.Load(),
		Busy: p.busy.Load(), ClientBusy: p.clientBusy.Load(), Cancelled: p.cancelled.Load()}
}

type evalResult int

const (
	evalDone evalResult = iota
	evalTimedOut
	evalPanicked
	evalBusy
)

// runEval runs f (one WAF phase on the transaction tx belongs to) on a slot
// and waits at most budget. On timeout the evaluation is cancelled and the
// request answered at once; a background goroutine waits until f has
// stopped, then calls closeTx and frees the slot. f never outlives its slot.
func (g *Gate) runEval(cost Cost, budget time.Duration, c *waf.Cancel, f func(), closeTx func()) evalResult {
	p := g.evals.Load()
	release, ok := p.acquire(cost)
	if !ok {
		return evalBusy
	}
	type outcome struct{ panicked, cancelled bool }
	done := make(chan outcome, 1)
	go func() {
		var o outcome
		defer func() {
			if v := recover(); v != nil {
				if waf.IsCancelled(v) {
					o.cancelled = true
				} else {
					o.panicked = true
				}
			}
			done <- o
		}()
		f()
	}()
	if budget <= 0 {
		budget = time.Millisecond
	}
	t := time.NewTimer(budget)
	defer t.Stop()
	select {
	case o := <-done:
		release()
		if o.panicked || o.cancelled {
			return evalPanicked
		}
		return evalDone
	case <-t.C:
		c.Cancel()
		go func() {
			o := <-done
			c.Finish()
			if o.cancelled {
				p.cancelled.Add(1)
			}
			closeTx()
			release()
		}()
		return evalTimedOut
	}
}
