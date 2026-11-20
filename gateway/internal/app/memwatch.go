package app

import (
	"context"
	"runtime"
	"runtime/debug"
	"time"

	"github.com/deutschland-schild/schild/contract/bodylimit"
	"github.com/deutschland-schild/schild/gateway/internal/memlimit"
)

const (
	// memWatchEvery: a flood of uploads moves the container by hundreds of MiB in
	// a second, faster than a watch once per second can answer.
	memWatchEvery = 200 * time.Millisecond
	// memFreeEvery is the most often the Go heap is given back under pressure.
	memFreeEvery = 2 * time.Second
)

// watchMemory follows the account of the kernel: it moves the Go limit and sets
// the level of bodylimit.Pressure for the admissions (D45). Under pressure the Go
// heap is given back at once: after a burst most of it is free but not returned,
// the kernel counts it as used, and the level would never fall again. Without a
// brake the gauge says so (D46): 0 would look like calm.
func (a *App) watchMemory(ctx context.Context) {
	f := memlimit.Follower{Result: a.mem}
	var freed time.Time
	warned := false
	step := func() {
		st, ok := f.Follow()
		if !ok {
			a.Gate.SetMemoryPressure(bodylimit.PressureNone)
			a.Metrics.MemoryPressure.Set(bodylimit.PressureUnknown)
			if !warned {
				warned = true
				if runtime.GOOS != "linux" {
					// A trial on a laptop: nothing to fix, so a note.
					a.log.Info("memory pressure brake not available on this system: it reads the memory limit of a Linux cgroup v2. Fine for a local trial; run schild for real traffic on Linux",
						"os", runtime.GOOS, "source", a.mem.Source, "total_mib", a.mem.Total>>20)
				} else {
					a.log.Warn("no memory pressure brake: no memory limit of a cgroup v2 can be read, so nothing slows the gateway down before the kernel kills it",
						"source", a.mem.Source, "total_mib", a.mem.Total>>20)
				}
			}
			return
		}
		level := bodylimit.Pressure(a.mem.Total, st.Held())
		a.Gate.SetMemoryPressure(level)
		if level != bodylimit.PressureNone && time.Since(freed) >= memFreeEvery {
			debug.FreeOSMemory()
			freed = time.Now()
		}
	}
	step()
	every(ctx, memWatchEvery, step)
}
