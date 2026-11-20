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
