package app

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/deutschland-schild/schild/contract/config"
	"github.com/deutschland-schild/schild/gateway/internal/behaviour"
)

// behaviourConfig builds the MVP-17 engine configuration.
func (a *App) behaviourConfig(c *config.Site) behaviour.Config {
	dash := map[string]bool{}
	for _, l := range a.dashLimits {
		dash[l.ID] = true
	}
	return behaviour.Config{Behaviour: c.Behaviour, Dashboard: dash, GatewayObserve: c.Mode == "observe",
		InstalledAt: a.InstalledAt(context.Background())}
}

// knownSiteHost reports whether h belongs to a configured website. When any
// website is a catch-all without explicit hosts (proxy mode without
// site_hosts), every host is accepted; otherwise arbitrary Host headers are
// ignored so they cannot evict real sites from behaviour's per-site tables.
func (a *App) knownSiteHost(h string) bool {
	if a.Sites == nil {
		return true
	}
	v := a.Sites.View()
	if v == nil {
		return true
	}
	for _, w := range v.Websites() {
		if len(w.Hosts) == 0 {
			return true
		}
	}
	return v.OwnHost(h)
}

// SetInstalledAt moves the first-start date (tests, migrations) and
// re-applies the behaviour configuration (MVP-18 learning period).
func (a *App) SetInstalledAt(ctx context.Context, t time.Time) error {
	if err := a.Store.Put(ctx, installedAtKey, []byte(t.UTC().Format(time.RFC3339))); err != nil {
		return err
	}
	a.Behaviour.SetConfig(a.behaviourConfig(a.Config()))
	return nil
}

// ApplyDistributed switches MVP-18 detectors from the dashboard (settings
// overlay, validated like schild.yaml).
func (a *App) ApplyDistributed(ctx context.Context, detectors map[string]string, thresholds map[string]config.DetectorThresholds) (*config.Site, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	ov := cloneMap(a.overlay)
	dets := sub(sub(sub(ov, "behaviour"), "distributed"), "detectors")
	for id, mode := range detectors {
		if (&config.DistributedDetectors{}).Get(id) == nil {
			return nil, fmt.Errorf("unknown detector %q", id)
		}
		sub(dets, id)["mode"] = mode
	}
	// D97: the thresholds of a detector replace what the dashboard set before.
	for id, t := range thresholds {
		if (&config.DistributedDetectors{}).Get(id) == nil {
			return nil, fmt.Errorf("unknown detector %q", id)
		}
		if t == (config.DetectorThresholds{}) {
			delete(sub(dets, id), "thresholds")
			continue
		}
		b, _ := json.Marshal(t)
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		sub(dets, id)["thresholds"] = m
	}
	return a.commit(ctx, ov, a.dashLimits, false)
}

// DashboardLimits returns the rate limits created in the dashboard.
func (a *App) DashboardLimits() []config.RateLimit {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]config.RateLimit(nil), a.dashLimits...)
}

// InstalledAt is the first start of this data directory.
func (a *App) InstalledAt(ctx context.Context) time.Time {
	raw, err := a.Store.Get(ctx, installedAtKey)
	if err != nil {
		return time.Time{}
	}
	t, _ := time.Parse(time.RFC3339, string(raw))
	return t
}

// ApplyBehaviour changes scenario modes, scenario thresholds and the modes of
// preset limits (by id, D95) from the dashboard (settings overlay, validated like
// schild.yaml). The thresholds of a scenario replace what the dashboard set
// before (D93): zero fields fall back to schild.yaml or the built-in default.
func (a *App) ApplyBehaviour(ctx context.Context, scenarios map[string]string, thresholds map[string]config.Thresholds, presetLimitModes map[string]string) (*config.Site, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	ov := cloneMap(a.overlay)
	beh := sub(ov, "behaviour")
	for id, mode := range scenarios {
		if (&config.BehaviourScenarios{}).Get(id) == nil {
			return nil, fmt.Errorf("unknown scenario %q", id)
		}
		sub(sub(beh, "scenarios"), id)["mode"] = mode
	}
	for id, t := range thresholds {
		if (&config.BehaviourScenarios{}).Get(id) == nil {
			return nil, fmt.Errorf("unknown scenario %q", id)
		}
		sc := sub(sub(beh, "scenarios"), id)
		if t == (config.Thresholds{}) {
			delete(sc, "thresholds")
			continue
		}
		b, _ := json.Marshal(t)
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		sc["thresholds"] = m
	}
	for id, mode := range presetLimitModes {
		sub(beh, "preset_limit_modes")[id] = mode
	}
	return a.commit(ctx, ov, a.dashLimits, false)
}

// SetDashboardLimits replaces the rate limits created in the dashboard after
// validating them together with schild.yaml.
func (a *App) SetDashboardLimits(ctx context.Context, limits []config.RateLimit) (*config.Site, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.commit(ctx, a.overlay, limits, true)
}

// commit validates overlay and dashboard limits, persists and applies them.
// Caller holds a.mu.
func (a *App) commit(ctx context.Context, ov map[string]any, dash []config.RateLimit, limitsChanged bool) (*config.Site, error) {
	next, err := a.mergedWith(ov, dash)
	if err != nil {
		return nil, err
	}
	if limitsChanged {
		b, _ := json.Marshal(dash)
		if err := a.Store.Put(ctx, dashLimitsKey, b); err != nil {
			return nil, err
		}
		a.dashLimits = append([]config.RateLimit(nil), dash...)
		a.droppedLimits.Store(false)
	} else {
		b, _ := json.Marshal(ov)
		if err := a.Store.Put(ctx, overlayKey, b); err != nil {
			return nil, err
		}
		a.overlay = ov
		a.droppedOverlay.Store(false)
	}
	prev := a.Config()
	a.cfg.Store(next)
	a.applyRuntime(ctx, prev, next)
	a.log.Info("behaviour settings changed in the dashboard", "rate_limits", len(next.Behaviour.RateLimits), "preset_limit_modes", len(next.Behaviour.PresetLimitModes))
	return next, nil
}
