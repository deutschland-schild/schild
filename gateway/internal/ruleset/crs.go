package ruleset

import (
	"context"
	"strconv"

	"github.com/deutschland-schild/schild/contract/config"
	"github.com/deutschland-schild/schild/contract/rules"
	"github.com/deutschland-schild/schild/gateway/internal/waf"
)

// crsRepo is the repository crs: the OWASP CRS embedded in the binary. It
// blocks by anomaly score; a rule's effect is that of the repository.
type crsRepo struct {
	reg     *Registry
	version string
}

func (c *crsRepo) ID() string { return rules.RepoCRS }

// Rules lists the detection rules up to the paranoia level (D48): flow
// control, the setup check and the correlation report are no findings.
func (c *crsRepo) Rules() []Entry {
	pl := c.reg.cfg().Rules.CRS.ParanoiaLevel
	list := waf.CRSRules(pl)
	out := make([]Entry, 0, len(list))
	for _, r := range list {
		out = append(out, Entry{ID: strconv.Itoa(r.ID), Msg: r.Msg, Version: c.version, Paranoia: r.Paranoia, SecLang: r.Text, File: r.File,
			Input: rules.Input{Origin: rules.OriginRelease}})
	}
	return out
}

func (c *crsRepo) Describe(v *RepositoryView, _ string) {
	crs := c.reg.cfg().Rules.CRS
	v.Name, v.Origin, v.Licence = "OWASP CRS", "built_in", "Apache-2.0"
	base := c.reg.o.Settings.CRSSettings()
	if base.ParanoiaLevel == 0 {
		base.ParanoiaLevel = config.DefaultParanoiaLevel
	}
	if base.InboundAnomalyThreshold == 0 {
		base.InboundAnomalyThreshold = config.DefaultInboundAnomalyThreshold
	}
	v.CRS = &CRSInfo{ParanoiaLevel: crs.ParanoiaLevel, InboundAnomalyThreshold: crs.InboundAnomalyThreshold,
		ConfigParanoiaLevel: base.ParanoiaLevel, ConfigInboundAnomalyThreshold: base.InboundAnomalyThreshold,
		LivewireException: *crs.LivewireException, Version: c.version}
}

// Apply sets the CRS of the WAF: off leaves it out, detect and block build
// the same rules, the gate decides by the state. Disabled rules leave with
// SecRuleRemoveById after the CRS include.
func (c *crsRepo) Apply(cfg *waf.Config, state string, disabled []int) {
	crs := c.reg.cfg().Rules.CRS
	cfg.CRS = state != rules.StateOff
	cfg.ParanoiaLevel, cfg.AnomalyThreshold, cfg.Livewire = crs.ParanoiaLevel, crs.InboundAnomalyThreshold, *crs.LivewireException
	cfg.CRSRemove = disabled
}

func (c *crsRepo) Sync(context.Context) (SyncResult, error) { return SyncResult{}, ErrNotSupported }
func (c *crsRepo) Reset(context.Context) error              { return ErrNotSupported }
