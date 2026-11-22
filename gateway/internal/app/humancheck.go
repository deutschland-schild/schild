package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	hc "github.com/deutschland-schild/schild/contract/humancheck"
	"github.com/deutschland-schild/schild/gateway/internal/dashboard"
	"github.com/deutschland-schild/schild/gateway/internal/humancheck"
	"github.com/deutschland-schild/schild/gateway/internal/store"
)

// newHumanCheck loads the browser verification state from schild.db, rotates
// keys if older than 24 h, and wires it into the gate.
func (a *App) newHumanCheck(ctx context.Context) error {
	a.HumanCheck = humancheck.New()
	now := time.Now().UTC()
	st := humancheck.NewState(now)
	dirty := false
	raw, err := a.Store.Get(ctx, humancheck.StoreKey)
	switch {
	case errors.Is(err, store.ErrNotFound):
		dirty = true
	case err != nil:
		return fmt.Errorf("human check: %w", err)
	default:
		if err := json.Unmarshal(raw, st); err != nil {
			return fmt.Errorf("human check: %w", err)
		}
		if st.Entries == nil {
			st.Entries = map[string]*humancheck.Entry{}
		}
		if !hc.ValidPrefix(st.Prefix) || len(st.ChallengeKey) == 0 || len(st.ClearanceKey) == 0 {
			fresh := humancheck.NewState(now)
			if !hc.ValidPrefix(st.Prefix) {
				st.Prefix = fresh.Prefix
			}
			if len(st.ChallengeKey) == 0 {
				st.ChallengeKey = fresh.ChallengeKey
			}
			if len(st.ClearanceKey) == 0 {
				st.ClearanceKey = fresh.ClearanceKey
			}
			st.KeysRotatedAt = now
			dirty = true
		} else if now.Sub(st.KeysRotatedAt) >= humancheck.KeyRotationInterval && a.groupNodeID == "" {
			// A node of a group does not rotate at its start: the group
			// rotates once for all (rotateHumanCheckKeys), or every node
			// that restarts would put the visitors of the others through
			// the check again.
			st.RotateKeys(now)
			dirty = true
		}
	}
	if dirty {
		if err := a.storeHumanCheck(ctx, st); err != nil {
			return fmt.Errorf("human check: %w", err)
		}
	}
	a.HumanCheck.Store(st)
	a.Gate.HumanCheck = a.HumanCheck
	return nil
}

func (a *App) storeHumanCheck(ctx context.Context, st *humancheck.State) error {
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	return a.Store.Put(ctx, humancheck.StoreKey, b)
}

// HumanCheckEntry returns the browser verification entry for website, or nil.
func (a *App) HumanCheckEntry(website string) *humancheck.Entry {
	return a.HumanCheck.Lookup(website)
}

// SetHumanCheck validates and stores the browser verification policy of website.
func (a *App) SetHumanCheck(ctx context.Context, website string, p hc.Policy, actor, user string) (*humancheck.Entry, error) {
	a.humanCheckMu.Lock()
	defer a.humanCheckMu.Unlock()
	if _, ok := a.Sites.View().Website(website); !ok {
		return nil, ErrAccessWebsite
	}
	now := time.Now().UTC()
	p.Website = website
	if p.Mode == "" {
		p.Mode = hc.ModeOff
	}
	if err := p.CheckShape(now); err != nil {
		return nil, err
	}
	next := a.HumanCheck.State().Clone()
	e := &humancheck.Entry{
		Policy:    p,
		UpdatedAt: now,
		Actor:     actor,
		User:      user,
	}
	next.Entries[website] = e
	if err := a.storeHumanCheck(ctx, next); err != nil {
		return nil, err
	}
	a.HumanCheck.Store(next)
	return e, nil
}

// RemoveHumanCheck resets the browser verification policy of website to off.
func (a *App) RemoveHumanCheck(ctx context.Context, website string) error {
	a.humanCheckMu.Lock()
	defer a.humanCheckMu.Unlock()
	next := a.HumanCheck.State().Clone()
	delete(next.Entries, website)
	if err := a.storeHumanCheck(ctx, next); err != nil {
		return err
	}
	a.HumanCheck.Store(next)
	return nil
}

func (a *App) dashboardHumanCheck() dashboard.HumanCheckFuncs {
	return dashboard.HumanCheckFuncs{
		Entry:  a.HumanCheckEntry,
		Counts: func() humancheck.Counters { return a.HumanCheck.Counts() },
		Set: func(ctx context.Context, website string, in dashboard.HumanCheckInput, user string) (*humancheck.Entry, error) {
			p := hc.Policy{
				Website:       website,
				Mode:          in.Mode,
				UnderAttack:   in.UnderAttack,
				Except:        in.Except,
				ClearanceTTLS: in.ClearanceTTLS,
				Difficulty:    in.Difficulty,
			}
			return a.SetHumanCheck(ctx, website, p, AccessByDashboard, user)
		},
		Remove: func(ctx context.Context, website, _ string) error {
			return a.RemoveHumanCheck(ctx, website)
		},
	}
}

// jobHumanCheckKeys is the group's task of rotating the keys of the browser
// check (cluster/jobs.go).
const jobHumanCheckKeys = "human_check_keys"

// rotateHumanCheckKeys gives the browser check new keys when the ones in
// use are older than a day. In a group one node does it for all: the keys
// travel with the settings, the keys before stay valid next to the new
// ones, so no visitor is asked again because of a rotation.
func (a *App) rotateHumanCheckKeys(ctx context.Context) error {
	a.humanCheckMu.Lock()
	defer a.humanCheckMu.Unlock()
	now := time.Now().UTC()
	cur := a.HumanCheck.State()
	if cur == nil || now.Sub(cur.KeysRotatedAt) < humancheck.KeyRotationInterval {
		return nil
	}
	next := cur.Clone()
	next.RotateKeys(now)
	if err := a.storeHumanCheck(ctx, next); err != nil {
		return err
	}
	a.HumanCheck.Store(next)
	a.log.Info("browser check: keys rotated for the group")
	return nil
}
