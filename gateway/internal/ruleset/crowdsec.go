package ruleset

import (
	"context"
	"strconv"

	"github.com/deutschland-schild/schild/contract/rules"
	"github.com/deutschland-schild/schild/gateway/internal/hub"
	"github.com/deutschland-schild/schild/gateway/internal/waf"
)

// crowdsecRepo is the repository crowdsec: the CrowdSec Hub virtual patches
// of internal/hub, an image snapshot plus updates fetched while the gateway
// runs. Its rules reach the WAF through the composer's hub builder.
type crowdsecRepo struct {
	reg *Registry
	src *hub.Source
}

func (c *crowdsecRepo) ID() string { return rules.RepoCrowdsec }

func (c *crowdsecRepo) Rules() []Entry {
	list := c.src.Rules()
	out := make([]Entry, 0, len(list))
	for i := range list {
		r := &list[i]
		v := r.View
		text := ""
		for j, g := range r.SecLang {
			if j > 0 {
				text += "\n"
			}
			text += g
		}
		out = append(out, Entry{ID: strconv.Itoa(r.BaseID), Name: v.Name, Msg: r.Msg, Version: v.Version, SecLang: text, Input: r.Input, Crowdsec: &v})
	}
	return out
}

func (c *crowdsecRepo) Describe(v *RepositoryView, state string) {
	sum := c.src.Summary(state)
	v.Name, v.Origin, v.Licence = "CrowdSec Hub", "remote", "MIT"
	v.Counts.Skipped, v.LastChangeAt = sum.Skipped, sum.LastChangeAt
	info := sum.Info
	v.Crowdsec = &info
}

// Apply leaves the crowdsec rules to internal/hub: they load, update and
// unload through the composer's hub builder.
func (c *crowdsecRepo) Apply(*waf.Config, string, []int) {}

// Sync checks the hub now; the outcome is in the status.
func (c *crowdsecRepo) Sync(ctx context.Context) (SyncResult, error) {
	c.src.Check(ctx)
	return SyncResult{Rules: len(c.src.Rules())}, nil
}

// Reset goes back to the image snapshot (D43).
func (c *crowdsecRepo) Reset(ctx context.Context) error { return c.src.Reset(ctx) }
