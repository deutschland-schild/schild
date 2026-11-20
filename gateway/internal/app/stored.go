package app

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/deutschland-schild/schild/contract/config"
	"github.com/deutschland-schild/schild/gateway/internal/store"
)

// Settings stored by the dashboard that no longer fit schild.yaml are not
// applied at start: the file wins and the gateway starts (D78). That must
// not happen silently, so the start log, `schild status`, `schild preflight`
// and the dashboard (baseline reason dashboard_settings_dropped) say it
// until the settings are saved again or schild.yaml fits again.
const (
	droppedOverlayMsg = "settings saved in the dashboard no longer fit schild.yaml and are NOT applied (retention, rule states, behaviour detectors): schild.yaml counts. " +
		"Check the settings in the dashboard and save them again, or correct schild.yaml and restart"
	droppedLimitsMsg = "rate limits created in the dashboard no longer fit schild.yaml and are NOT applied. " +
		"Create them again in the dashboard, or correct schild.yaml and restart"
)

// mergeConfig merges the settings overlay into the config of the file,
// appends the dashboard rate limits to behaviour.rate_limits and validates
// the result like schild.yaml.
func mergeConfig(base, ov map[string]any, dash []config.RateLimit) (*config.Site, error) {
	// D89: a mode the dashboard saved before means nothing any more.
	ov = cloneMap(ov)
	delete(ov, "mode")
	m := cloneMap(deepMerge(base, ov))
	if len(dash) > 0 {
		beh := sub(m, "behaviour")
		list, _ := beh["rate_limits"].([]any)
		for _, l := range dash {
			b, _ := json.Marshal(l)
			var lm map[string]any
			_ = json.Unmarshal(b, &lm)
			list = append(list, lm)
		}
		beh["rate_limits"] = list
	}
	b, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	return config.ParseSiteJSON(b)
}

// DroppedSettings checks, without a running gateway, what New would not
// apply of the settings stored by the dashboard: one line per finding, with
// the validation error. base is the config of the file (LoadConfig). The
// order is the one of New: rate limits first, then the overlay.
func DroppedSettings(ctx context.Context, st *store.Store, base map[string]any) []string {
	var out []string
	var dash []config.RateLimit
	if raw, err := st.Get(ctx, dashLimitsKey); err == nil && json.Unmarshal(raw, &dash) == nil && len(dash) > 0 {
		if _, err := mergeConfig(base, map[string]any{}, dash); err != nil {
			out = append(out, fmt.Sprintf("%s (%v)", droppedLimitsMsg, err))
			dash = nil
		}
	}
	if raw, err := st.Get(ctx, overlayKey); err == nil {
		var ov map[string]any
		if json.Unmarshal(raw, &ov) == nil {
			if _, err := mergeConfig(base, ov, dash); err != nil {
				out = append(out, fmt.Sprintf("%s (%v)", droppedOverlayMsg, err))
			}
		}
	}
	return out
}

// SettingsDropped reports whether settings stored by the dashboard were not
// applied at start and have not been saved again since.
func (a *App) SettingsDropped() bool {
	return a.droppedOverlay.Load() || a.droppedLimits.Load()
}
