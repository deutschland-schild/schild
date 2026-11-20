// Package memlimit sets the Go memory limit of `schild run` (MVP-19
// re-measurement, finding 2). Without a limit the Go runtime lets the heap
// grow to twice the live data before collecting; under a flood of expensive
// evaluations that went past a 4 GiB container limit and the kernel killed
// the ingress. With a soft limit the collector works harder as the heap
// approaches it, and the gate's memory budget for evaluations is derived
// from the same number.
package memlimit

import (
	"bufio"
	"bytes"
	"math"
	"os"
	"runtime/debug"
	"strconv"
	"strings"

	"github.com/deutschland-schild/schild/contract/bodylimit"
)

// Share of the container or machine memory used as the Go memory limit.
const Share = 0.8

// Headroom is the memory always left between the Go memory limit and the
// container or machine memory (MVP-19 measurement 3, finding 2: the heap
// sits at the Go limit after a flood, and 20 % of 1 GiB left only about
// 0.2 GiB for stacks, Caddy buffers and the rest of the process).
const Headroom = 256 << 20

// FloorShare is the lowest share of a tiny limit used as the Go limit:
// below about 512 MiB the headroom would leave too little for the heap.
const FloorShare = 0.5

// Rules that set the limit (logged).
const (
	RuleShare    = "share"    // Share of the total
	RuleHeadroom = "headroom" // total minus Headroom (smaller than Share)
	RuleFloor    = "floor"    // FloorShare of a tiny total
)

// Of returns the Go memory limit for total bytes of container or machine
// memory: min(Share * total, total - Headroom), at least FloorShare * total.
func Of(total int64) (int64, string) {
	share := int64(float64(total) * Share)
	floor := int64(float64(total) * FloorShare)
	switch head := total - Headroom; {
	case share <= head:
		return share, RuleShare
	case head >= floor:
		return head, RuleHeadroom
	default:
		return floor, RuleFloor
	}
}

// Sources of the limit.
const (
	SourceEnv    = "GOMEMLIMIT" // set by the operator, applied by the Go runtime
	SourceCgroup = "cgroup"     // the container's cgroup memory limit
	SourceRAM    = "ram"        // the machine's memory (no container limit)
	SourceNone   = "none"       // nothing readable: no limit
)

// Result is the effective limit in bytes (0 with SourceNone).
type Result struct {
	Limit  int64
	Source string
	// Total is the memory the limit was derived from. With SourceEnv it is the
	// limit of the cgroup, 0 without one: the kernel kills on that limit, whatever
	// the operator told the Go runtime (D46).
	Total int64
	// Rule is how the limit follows from Total (RuleShare, RuleHeadroom,
	// RuleFloor; empty for SourceEnv and SourceNone).
	Rule string
}

// Brake reports whether the memory pressure of D45 can run: it needs the limit of
// a cgroup, because that is where the kernel kills.
func (r Result) Brake() bool {
	return r.Source == SourceCgroup || (r.Source == SourceEnv && r.Total > 0)
}

// cgroupLimit reads the cgroup v2 or v1 memory limit, 0 without one.
func cgroupLimit(readFile func(string) ([]byte, error)) int64 {
	if b, err := readFile("/sys/fs/cgroup/memory.max"); err == nil {
		if n, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64); err == nil && n > 0 {
			return n
		}
	}
	if b, err := readFile("/sys/fs/cgroup/memory/memory.limit_in_bytes"); err == nil {
		if n, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64); err == nil && n > 0 && n < 1<<60 {
			return n
		}
	}
	return 0
}

// Derive finds the limit: GOMEMLIMIT wins (the runtime has applied it
// already, current is its value), then the cgroup v2 or v1 memory limit,
// then MemTotal of /proc/meminfo; Of it.
func Derive(getenv func(string) string, readFile func(string) ([]byte, error), current int64) Result {
	if strings.TrimSpace(getenv("GOMEMLIMIT")) != "" {
		return Result{Limit: current, Source: SourceEnv, Total: cgroupLimit(readFile)}
	}
	share := func(total int64, src string) Result {
		l, rule := Of(total)
		return Result{Limit: l, Source: src, Total: total, Rule: rule}
	}
	if n := cgroupLimit(readFile); n > 0 {
		return share(n, SourceCgroup)
	}
	if b, err := readFile("/proc/meminfo"); err == nil {
		sc := bufio.NewScanner(bytes.NewReader(b))
		for sc.Scan() {
			f := strings.Fields(sc.Text())
			if len(f) >= 2 && f[0] == "MemTotal:" {
				if kb, err := strconv.ParseInt(f[1], 10, 64); err == nil && kb > 0 {
					return share(kb<<10, SourceRAM)
				}
			}
		}
	}
	return Result{Source: SourceNone}
}

// Apply derives the limit from the process environment and sets it.
func Apply() Result {
	cur := debug.SetMemoryLimit(-1)
	if cur == math.MaxInt64 {
		cur = 0
	}
	r := Derive(os.Getenv, os.ReadFile, cur)
	if r.Source == SourceCgroup || r.Source == SourceRAM {
		debug.SetMemoryLimit(r.Limit)
	}
	return r
}

// memoryStat is the file with the kernel's account of the container (cgroup v2;
// cgroup v1 has no such lines and the limit stays as it is).
const memoryStat = "/sys/fs/cgroup/memory.stat"

// Stat holds the lines of memory.stat the kernel cannot drop at once.
type Stat = bodylimit.MemoryStat

// WithoutOutside is the Go limit left when the kernel holds outside bytes for
// the container, at least half of limit. The kernel charges socket buffers and
// dirty pages to the container, and the Go runtime knows nothing of them: full
// buffers on a thousand connections and the temp files of their bodies took more
// than the headroom, while the collector saw no reason to run, and the container
// was killed (D44, D45).
func WithoutOutside(limit, outside int64) int64 { return max(limit-outside, limit/2) }

// readStat reads the lines of Stat from a memory.stat file.
func readStat(readFile func(string) ([]byte, error)) (Stat, bool) {
	b, err := readFile(memoryStat)
	if err != nil {
		return Stat{}, false
	}
	var s Stat
	found := false
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) != 2 {
			continue
		}
		var into *int64
		switch f[0] {
		case "anon":
			into = &s.Anon
		case "sock":
			into = &s.Sock
		case "slab_reclaimable", "slab_unreclaimable":
			into = &s.Slab
		case "kernel_stack":
			into = &s.KernelStack
		case "pagetables":
			into = &s.PageTables
		case "shmem":
			into = &s.Shmem
		case "file_dirty":
			into = &s.Dirty
		case "file_writeback":
			into = &s.Writeback
		default:
			continue
		}
		n, err := strconv.ParseInt(f[1], 10, 64)
		if err != nil {
			return Stat{}, false
		}
		*into, found = *into+n, true
	}
	return s, found
}

// followStep is the smallest move of the Go limit worth a stop of the world.
const followStep = 8 << 20

// Follower sets the Go limit for what the kernel holds now and reports it. An
// operator's GOMEMLIMIT is the ceiling of that move, as the derived limit is, so
// it no longer switches the brake off (D46). A limit from the machine has no cgroup
// to read.
type Follower struct {
	Result Result
	// read and set are os.ReadFile and debug.SetMemoryLimit, for tests.
	read func(string) ([]byte, error)
	set  func(int64)
	last int64
}

// Follow reads memory.stat and moves the Go limit. Call it several times per
// second: the memory of a flood of uploads moves by hundreds of MiB in one
// second. ok is false when no brake can run.
func (f *Follower) Follow() (s Stat, ok bool) {
	if !f.Result.Brake() {
		return Stat{}, false
	}
	if f.read == nil {
		f.read = os.ReadFile
		f.set = func(n int64) { debug.SetMemoryLimit(n) }
	}
	if s, ok = readStat(f.read); !ok {
		return Stat{}, false
	}
	// With GOMEMLIMIT=off the limit is 0 and next stays 0, so nothing moves.
	if next := WithoutOutside(f.Result.Limit, s.Outside()); next-f.last >= followStep || f.last-next >= followStep {
		f.set(next)
		f.last = next
	}
	return s, true
}

// EvalBudget is the memory budget for expensive WAF evaluations: half of the
// limit, at least 64 MiB; def without a limit.
func EvalBudget(r Result, def int64) int64 {
	if r.Limit <= 0 {
		return def
	}
	return max(r.Limit/2, 64<<20)
}
