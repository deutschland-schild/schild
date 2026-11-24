package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/deutschland-schild/schild/contract/config"
	"github.com/deutschland-schild/schild/contract/websites"
	"github.com/deutschland-schild/schild/gateway/internal/caddymod"
	"github.com/deutschland-schild/schild/gateway/internal/sites"
	"github.com/deutschland-schild/schild/gateway/internal/store"
)

// websitesView derives the websites of cfg (v0.5, D36): the Caddyfile site
// blocks in ingress mode, upstream.site_hosts in proxy mode. A Caddyfile
// that cannot be read gives the one website "default" (the start fails on
// it anyway, see startCaddy).
func (a *App) websitesView(cfg *config.Site) *sites.View {
	v := deriveWebsites(cfg, a.dataDir, nil)
	if !cfg.CaddyIngress() {
		return v
	}
	switch {
	case notDerived(v):
		a.log.Warn("websites not derived from the Caddyfile, counting everything as one website", "err", v.Err)
	case v.Err != nil:
		a.log.Warn("a Caddyfile block is no website (dropped), the other websites stay", "err", v.Err, "count", len(v.Websites()))
	default:
		a.log.Info("websites", "count", len(v.Websites()), "tracked", v.Tracked(), "other", v.Untracked())
	}
	return v
}

// notDerived: the Caddyfile gave no websites, everything counts as one.
func notDerived(v *sites.View) bool {
	return v.Err != nil && len(v.Websites()) == 1 && v.Websites()[0].ID == websites.DefaultID
}

// deriveWebsites is websitesView without the log lines; prev is the view a
// running gateway has (sites.NewViewAfter), nil at a start.
func deriveWebsites(cfg *config.Site, dataDir string, prev *sites.View) *sites.View {
	if !cfg.CaddyIngress() {
		return sites.NewView(websites.Input{Mode: websites.ModeProxy, SiteHosts: cfg.Upstream.SiteHosts})
	}
	in := websites.Input{Mode: websites.ModeIngress, UnprotectedSites: cfg.Ingress.UnprotectedSites}
	ing, err := IngressFor(cfg, dataDir)
	if ing != nil {
		in.Blocks, err = caddymod.SiteBlocks(cfg.Ingress.Caddyfile, ing.Check)
	}
	v := sites.NewViewAfter(prev, in)
	if err != nil && v.Err == nil {
		v = sites.NewView(websites.Input{Mode: websites.ModeProxy})
		v.Source = websites.SourceCaddyfile
		v.Err = err
	}
	return v
}

// WebsiteCount is the number of websites of cfg (the metrics.db bound of
// the disk budget grows with it; preflight runs before the app exists).
func WebsiteCount(cfg *config.Site, dataDir string) int {
	return len(deriveWebsites(cfg, dataDir, nil).Websites())
}

// configSHA is the hash of the effective configuration (annotations).
func configSHA(c *config.Site) string {
	raw, _ := json.Marshal(c)
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}

// logConfigChange appends to the configuration change log when the hash
// or the mode differs from the last entry (start and dashboard changes).
func (a *App) logConfigChange(ctx context.Context, at time.Time, prevMode string, c *config.Site) {
	sha := configSHA(c)
	last, err := a.Store.LastConfigChange(ctx)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return
	}
	if last != nil {
		if last.SHA256 == sha {
			return
		}
		if prevMode == "" {
			prevMode = last.ModeTo
		}
	}
	if err := a.Store.AddConfigChange(ctx, store.ConfigChange{Time: at, ModeFrom: prevMode, ModeTo: c.Mode, SHA256: sha}); err != nil {
		a.log.Warn("configuration change log", "err", err)
	}
}
