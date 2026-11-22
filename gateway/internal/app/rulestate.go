package app

import (
	"context"
	"encoding/json"
	"time"

	"github.com/deutschland-schild/schild/contract/rules"
	"github.com/deutschland-schild/schild/gateway/internal/ruleset"
)

// ownersKey is the store row of who set the state of each rule repository in
// the settings overlay (D73): repository -> owner. It goes with the overlay.
const ownersKey = "rules_state_by_v1"

func ruleStateOf(m map[string]any, repository string) string {
	sec, _ := m["rules"].(map[string]any)
	repo, _ := sec[repository].(map[string]any)
	v, _ := repo["state"].(string)
	return v
}

func (a *App) owners(ctx context.Context) map[string]ruleset.Owner {
	o := map[string]ruleset.Owner{}
	if raw, err := a.Store.Get(ctx, ownersKey); err == nil {
		_ = json.Unmarshal(raw, &o)
	}
	return o
}

// RuleState returns the state of a repository in schild.yaml, the overlay
// value and who set it (ruleset.Settings).
func (a *App) RuleState(repository string) (base, overlay string, owner ruleset.Owner) {
	a.mu.Lock()
	base, overlay = ruleStateOf(a.base, repository), ruleStateOf(a.overlay, repository)
	a.mu.Unlock()
	return base, overlay, a.owners(context.Background())[repository]
}

// SetRuleState is the one write of a repository state into the settings
// overlay, for the dashboard and the agent API alike (ruleset.Settings): it
// sets the value or drops it with reset, validates the result like
// schild.yaml, records who did it and makes it effective at once.
func (a *App) SetRuleState(ctx context.Context, repository, state string, reset bool, owner ruleset.Owner) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	ov := cloneMap(a.overlay)
	if reset {
		if sec, ok := ov["rules"].(map[string]any); ok {
			if repo, ok := sec[repository].(map[string]any); ok {
				delete(repo, "state")
				if len(repo) == 0 {
					delete(sec, repository)
				}
			}
			if len(sec) == 0 {
				delete(ov, "rules")
			}
		}
	} else {
		sub(sub(ov, "rules"), repository)["state"] = state
	}
	next, err := a.merged(ov)
	if err != nil {
		return err
	}
	b, err := json.Marshal(ov)
	if err != nil {
		return err
	}
	owners := a.owners(ctx)
	if reset {
		delete(owners, repository)
	} else {
		owners[repository] = owner
	}
	ob, err := json.Marshal(owners)
	if err != nil {
		return err
	}
	if err := a.Store.Put(ctx, overlayKey, b); err != nil {
		return err
	}
	if err := a.Store.Put(ctx, ownersKey, ob); err != nil {
		return err
	}
	a.overlay = ov
	a.droppedOverlay.Store(false)
	a.cfg.Store(next)
	a.logConfigChange(ctx, time.Now().UTC(), next.Mode, next)
	if repository == rules.RepoCRS {
		a.Metrics.BaselineProtection.Set(boolf(next.Rules.CRS.State != rules.StateOff))
	}
	return nil
}

// crsNumber reads a whole number of rules.crs from a config map, whatever
// number type the YAML or JSON decoder left there.
func crsNumber(m map[string]any, key string) int {
	sec, _ := m["rules"].(map[string]any)
	crs, _ := sec[rules.RepoCRS].(map[string]any)
	switch v := crs[key].(type) {
	case int:
		return v
	case int64:
		return int(v)
	case uint64:
		return int(v)
	case float64:
		return int(v)
	case json.Number:
		n, _ := v.Int64()
		return int(n)
	}
	return 0
}

// CRSSettings returns the paranoia level and the blocking threshold of
// schild.yaml, zero where the file leaves one open (ruleset.Settings).
func (a *App) CRSSettings() ruleset.CRSSettings {
	a.mu.Lock()
	defer a.mu.Unlock()
	return ruleset.CRSSettings{ParanoiaLevel: crsNumber(a.base, "paranoia_level"), InboundAnomalyThreshold: crsNumber(a.base, "inbound_anomaly_threshold")}
}

// SetCRSSettings replaces the overlay values of rules.crs set in the
// dashboard (D101, ruleset.Settings): a zero drops the value, so schild.yaml
// or the built-in default holds again. The result is validated like
// schild.yaml and effective at once; the repository state in the overlay
// stays.
func (a *App) SetCRSSettings(ctx context.Context, s ruleset.CRSSettings) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	ov := cloneMap(a.overlay)
	sec := sub(ov, "rules")
	crs := sub(sec, rules.RepoCRS)
	for key, v := range map[string]int{"paranoia_level": s.ParanoiaLevel, "inbound_anomaly_threshold": s.InboundAnomalyThreshold} {
		if v == 0 {
			delete(crs, key)
		} else {
			crs[key] = v
		}
	}
	if len(crs) == 0 {
		delete(sec, rules.RepoCRS)
	}
	if len(sec) == 0 {
		delete(ov, "rules")
	}
	next, err := a.merged(ov)
	if err != nil {
		return err
	}
	b, err := json.Marshal(ov)
	if err != nil {
		return err
	}
	if err := a.Store.Put(ctx, overlayKey, b); err != nil {
		return err
	}
	a.overlay = ov
	a.droppedOverlay.Store(false)
	a.cfg.Store(next)
	a.logConfigChange(ctx, time.Now().UTC(), next.Mode, next)
	return nil
}
