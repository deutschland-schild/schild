package app

import (
	"context"
	"time"

	contractbots "github.com/deutschland-schild/schild/contract/bots"
	"github.com/deutschland-schild/schild/contract/config"
	cr "github.com/deutschland-schild/schild/contract/requests"
	"github.com/deutschland-schild/schild/gateway/internal/bots"
)

// MVP-22 (D35): the bot catalogue and verification engine and the
// robots.txt observation. Everything works offline; the engine fetches
// ranges with bots.ranges_fetch (on by default, D67: only the operators'
// lists, no client data) and asks the resolver only with
// bots.verify.fcrdns (off by default).

// newBots returns the engine of schild.yaml bots (the shipped catalogue
// with default switches when the section cannot be used).
func (a *App) newBots(cfg *config.Site) *bots.Engine {
	now := a.opts.BotsNow
	if now == nil {
		now = time.Now
	}
	e, err := bots.New(cfg.Bots, now)
	if err != nil {
		a.log.Warn("bots: shipped catalogue with default switches", "err", err)
		return bots.Default()
	}
	if cfg.Bots.FCrDNSOn() {
		a.log.Info("bots.verify.fcrdns on: claimed bot addresses are sent to the resolver for reverse lookups")
	}
	if !cfg.Bots.FetchOn() {
		a.log.Info("bots.ranges_fetch off: range lists only come with a release; after 30 days no bot is checked against them")
	}
	return e
}

// newRobots returns the robots.txt observation: in proxy mode the gateway
// fetches each website's robots.txt from the upstream once an hour. In
// ingress mode there is no single upstream to ask (backends may be file
// servers or FastCGI); the websites stay "unklar" there (nil).
func (a *App) newRobots(cfg *config.Site) *bots.Robots {
	if cfg.CaddyIngress() || cfg.Upstream.URL == "" {
		return nil
	}
	fetch, err := bots.ProxyFetch(cfg.Upstream.URL, 10*time.Second)
	if err != nil {
		a.log.Warn("robots.txt observation off", "err", err)
		return nil
	}
	var sites []bots.RobotsSite
	if a.Sites != nil {
		if v := a.Sites.View(); v != nil {
			sites = bots.RobotsSitesOf(v.Websites())
		}
	}
	return bots.NewRobots(sites, fetch)
}

// robotsLoop follows website changes of the robots.txt observation.
func (a *App) robotsLoop(ctx context.Context) {
	if a.robots == nil || a.Sites == nil {
		return
	}
	every(ctx, 10*time.Minute, func() {
		if v := a.Sites.View(); v != nil {
			a.robots.SetSites(bots.RobotsSitesOf(v.Websites()))
		}
	})
}

// botDir adapts the engine and the robots.txt observation to the request
// ring and the dashboard.
type botDir struct {
	e *bots.Engine
	r *bots.Robots
}

func (d botDir) BotID(name string) (uint16, bool) {
	id := d.e.ID(name)
	return id, id != 0
}

func (d botDir) BotName(id uint16) string {
	if b := d.e.Bot(id); b != nil {
		return b.ID
	}
	return ""
}

func (d botDir) Bot(id uint16) *contractbots.Bot   { return d.e.Bot(id) }
func (d botDir) CatalogueVersion() string          { return d.e.CatalogueVersion() }
func (d botDir) Ranges() []cr.RangeInfo            { return d.e.Ranges() }
func (d botDir) Settings() cr.VerificationSettings { return d.e.Settings() }
func (d botDir) RobotsFetched(site string) bool    { return d.r != nil && !d.r.FetchedAt(site).IsZero() }
func (d botDir) robotsDisallowed(site string, bot uint16, path string) bool {
	if d.r == nil {
		return false
	}
	b := d.e.Bot(bot)
	if b == nil || b.RobotsToken == "" {
		return false
	}
	dis, _ := d.r.Disallowed(site, b.RobotsToken, path)
	return dis
}
