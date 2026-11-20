package app

import (
	"context"
	"encoding/json"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/deutschland-schild/schild/contract/config"
	"github.com/deutschland-schild/schild/gateway/internal/buildinfo"
	"github.com/deutschland-schild/schild/gateway/internal/monitoring"
	"github.com/deutschland-schild/schild/gateway/internal/reqring"
)

// newMonitor opens the MVP-21 monitoring (metrics.db next to schild.db); nil
// with monitoring.enabled false or when metrics.db cannot be opened (request
// handling never depends on it).
func (a *App) newMonitor(cfg *config.Site) *monitoring.Monitor {
	if !cfg.Monitoring.On() {
		a.log.Info("monitoring.enabled false: no counters, no host sampler, no metrics.db")
		return nil
	}
	a.botEngine = a.newBots(cfg)
	a.robots = a.newRobots(cfg)
	a.botDir = botDir{e: a.botEngine, r: a.robots}
	a.Requests = a.newRequestRing(cfg)
	var storeBytes atomic.Int64
	storeBytes.Store(a.Store.SizeBytes())
	m, err := monitoring.New(monitoring.Config{
		StoragePath: a.dataDir,
		Sites:       a.Sites,
		Requests:    a.Requests,
		Keep:        cfg.Monitoring.Keep,
		Log:         a.log,
		Sampler: monitoring.SamplerConfig{Linux: runtime.GOOS == "linux", Host: cfg.Monitoring.HostOn(), Mounts: cfg.Monitoring.Mounts,
			Interfaces: cfg.Monitoring.Interfaces, Started: a.started, Version: "schild " + buildinfo.Version, OS: a.hostOS()},
		Internals: func(full bool) monitoring.Internals {
			var in monitoring.Internals
			used, capacity := a.Events.Queue()
			in.EventQueueUsed, in.EventQueueCapacity = int64(used), int64(capacity)
			in.EventsDroppedTotal = a.Events.Dropped()
			st := a.Gate.EvalStats()
			in.EvalSlotsUsed, in.EvalSlotsMax = st.InFlight, int64(a.Gate.EvalLimits().MaxConcurrent)
			if full {
				storeBytes.Store(a.Store.SizeBytes())
			}
			in.StoreBytes = storeBytes.Load()
			in.StoreMaxBytes = int64(a.Config().Retention.MaxSizeMB) << 20
			in.StoreCapUnreachable = a.capUnreachable.Load()
			return in
		},
	}, time.Now())
	if err != nil {
		a.log.Error("monitoring not started (request handling is not affected)", "err", err)
		if a.Requests != nil {
			_ = a.Requests.Close()
			a.Requests = nil
		}
		return nil
	}
	m.UseBots(a.botEngine)
	m.SetBotVerification(cfg.Bots.RangesOn() || cfg.Bots.FCrDNSOn())
	if err := a.Metrics.Reg.Register(m.Collector()); err != nil {
		a.log.Warn("monitoring: prometheus collector not registered", "err", err)
	}
	return m
}

// newRequestRing opens the MVP-22 request ring below storage.path (nil with
// monitoring.requests off or when the directory cannot be used; request
// handling never depends on it).
func (a *App) newRequestRing(cfg *config.Site) *reqring.Ring {
	if !cfg.Monitoring.RequestsOn() {
		a.log.Info("monitoring.requests off: no single requests kept")
		return nil
	}
	rq := cfg.Monitoring.Requests
	// The ring holds addresses (D49): raw_ip_days bounds it like the events.
	keep := min(rq.KeepHours, cfg.Retention.RawIPDays*24)
	r, err := reqring.New(reqring.Config{StoragePath: a.dataDir, KeepHours: keep, PinKeepHours: min(cfg.Retention.EventsDays, cfg.Retention.RawIPDays) * 24, MaxBytes: int64(rq.MaxSizeMB) << 20, Log: a.log,
		Robots: a.botDir.robotsDisallowed,
		// D63: every record keeps the real (redacted) path.
		RawPath: func(string) bool { return true }})
	if err != nil {
		a.log.Error("request ring not started (request handling is not affected)", "err", err)
		return nil
	}
	r.SetBots(a.botDir)
	return r
}

// hostOS returns the OS of the latest local MVP-11 host report (cached for
// ten minutes); nil without host_check or a report.
func (a *App) hostOS() func() *monitoring.HostOS {
	var mu sync.Mutex
	var cached *monitoring.HostOS
	var at time.Time
	return func() *monitoring.HostOS {
		if a.Hosts == nil {
			return nil
		}
		mu.Lock()
		defer mu.Unlock()
		if time.Since(at) < 10*time.Minute {
			return cached
		}
		at = time.Now()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		d, err := a.Hosts.Host(ctx, "local")
		if err != nil || d == nil || len(d.Report) == 0 || string(d.Report) == "null" {
			cached = nil
			return nil
		}
		var r struct {
			Host struct {
				OS struct {
					Name   string  `json:"name"`
					Kernel string  `json:"kernel"`
					Arch   string  `json:"arch"`
					EOL    *string `json:"eol"`
				} `json:"os"`
			} `json:"host"`
			Run struct {
				StartedAt string `json:"started_at"`
			} `json:"run"`
		}
		if json.Unmarshal(d.Report, &r) != nil || r.Host.OS.Name == "" {
			cached = nil
			return nil
		}
		o := r.Host.OS
		h := &monitoring.HostOS{Source: "host_report", Name: trunc(o.Name, 128), Kernel: trunc(o.Kernel, 64), Arch: trunc(o.Arch, 16), EOL: o.EOL}
		if r.Run.StartedAt != "" {
			s := r.Run.StartedAt
			h.ReportAt = &s
		}
		cached = h
		return h
	}
}

func trunc(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
