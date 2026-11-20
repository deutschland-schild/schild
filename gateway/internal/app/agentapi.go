package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"maps"
	"net"
	"net/http"
	"net/netip"
	"os"
	"time"

	contractapi "github.com/deutschland-schild/schild/contract/agentapi"
	"github.com/deutschland-schild/schild/contract/config"
	cc "github.com/deutschland-schild/schild/contract/crawlers"
	"github.com/deutschland-schild/schild/contract/rules"
	"github.com/deutschland-schild/schild/gateway/internal/agentapi"
	"github.com/deutschland-schild/schild/gateway/internal/eventlog"
	"github.com/deutschland-schild/schild/gateway/internal/store"
)

// newAgentAPI returns the read-only agent API (MVP-21, D33) when
// agent_api.enabled is set; its own loopback listener starts in Run.
func (a *App) newAgentAPI(cfg *config.Site) *agentapi.Server {
	if !cfg.AgentAPI.On() {
		return nil
	}
	blocks := &agentapi.BlockDeps{Engine: a.Behaviour, Mode: func() string { return a.Gate.Settings().Mode }, Own: a.ownAddress,
		Released: func(ip netip.Addr) bool { return a.Gate.Exceptions.Running(ip, time.Now()) },
		NetClass: func(ip netip.Addr) string {
			if a.Geo == nil {
				return ""
			}
			return a.Geo.Lookup(ip).NetClass
		},
		Emit: func(id, typ string, t time.Time, data any, idx eventlog.Index) {
			a.Events.EmitWithID(id, typ, t, data, idx)
		}, Incident: a.Gate.QueueIncident, FlushIncidents: a.Gate.FlushIncidents}
	s := &agentapi.Server{St: a.Store, Monitor: a.Monitor, Blocks: blocks, IncidentBlock: a.agentIncidentBlock, Requests: a.Requests, Config: a.Config, Log: a.log, Sites: a.Sites,
		Websites: a.Dashboard.WebsiteList, Website: a.Dashboard.WebsiteDetail, SitesAffected: a.Dashboard.SitesAffected,
		Repos:      a.Repos,
		Exceptions: &agentapi.ExceptionDeps{List: a.listRuleExceptions, Create: a.createRuleException, Remove: a.removeRuleException},
		Firewall:   &agentapi.FirewallDeps{Blocks: a.firewallBlocks},
		Crawlers: &agentapi.CrawlerDeps{List: a.agentCrawlers, Set: func(ctx context.Context, req cc.SetRequest, tokenID, label string) (cc.AgentPolicy, error) {
			out, err := a.agentSetCrawlers(ctx, req, tokenID, label)
			if errors.Is(err, ErrCrawlerWebsite) {
				err = agentapi.ErrUnknownWebsite
			}
			return out, err
		}, Known: func(id string) bool { _, ok := a.Sites.View().Website(id); return ok }},
		Rules: &agentapi.RuleDeps{WAF: a.Engine.Current, Mode: func() string { return a.Gate.Settings().Mode },
			Hosts: func(id string) ([]string, bool) {
				w, ok := a.Sites.View().Website(id)
				return w.Hosts, ok
			},
			Effect: func(repository string, id int) rules.Rule {
				return a.Repos.Effect(repository, id, a.Gate.Settings().Mode, time.Now())
			}},
		Hints: func(ctx context.Context, site string, from, to time.Time) (any, error) {
			return a.Dashboard.FalsePositiveHints(ctx, site, from, to)
		},
		Overview: func(ctx context.Context) any { return a.Dashboard.Overview(ctx) },
		Settings: func(ctx context.Context) agentapi.Settings { return a.agentSettings(ctx, *a.configHash.Load()) }}
	if a.botEngine != nil {
		s.Bots = a.botDir
	}
	return s
}

// ownAddress: an agent never blocks the allowlist, this host or a trusted
// proxy: blocking a proxy would block everyone behind it (D42).
func (a *App) ownAddress(ip netip.Addr) bool {
	if lvl, _ := a.Allow.Match(ip, time.Now()); lvl != "" {
		return true
	}
	if a.Gate.Settings().Resolver.Trusted(ip) {
		return true
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, x := range addrs {
		if p, err := netip.ParsePrefix(x.String()); err == nil && p.Addr().Unmap() == ip.Unmap() {
			return true
		}
	}
	return false
}

// agentIncidentBlock is the block behind an incident for the agent API.
func (a *App) agentIncidentBlock(ctx context.Context, in *store.Incident) *contractapi.IncidentBlock {
	b := a.Dashboard.IncidentBlock(ctx, in)
	if b == nil {
		return nil
	}
	out := &contractapi.IncidentBlock{Source: b.Source, Until: b.Until, Level: b.Level, NetClass: b.NetClass, DurationS: b.DurationS, Persisted: b.Persisted,
		EndedAt: b.EndedAt, Incident: b.Incident, AgentReason: b.AgentReason}
	if b.SetBy != nil {
		out.SetBy = &contractapi.BlockSetBy{TokenID: b.SetBy.TokenID, TokenLabel: b.SetBy.TokenLabel}
	}
	return out
}

// setConfigHash sets the config version of the agent API: schild.yaml and rules.d
// as loaded.
func (a *App) setConfigHash(localRules string) {
	raw, _ := os.ReadFile(a.opts.ConfigPath)
	h := sha256.New()
	h.Write(raw)
	h.Write([]byte{0})
	h.Write([]byte(localRules))
	hash := hex.EncodeToString(h.Sum(nil))
	a.configHash.Store(&hash)
}

func (a *App) agentSettings(ctx context.Context, hash string) agentapi.Settings {
	c := a.Config()
	lim := a.Gate.EvalLimits()
	allow, _ := a.Store.ListAllow(ctx)
	sc := c.Behaviour.Scenarios
	limits := len(c.Behaviour.RateLimits)
	return agentapi.Settings{
		Profile: profileOf(c), ConfigSHA256: hash,
		Retention: agentapi.RetentionSettings{RawIPDays: c.Retention.RawIPDays, EventsDays: c.Retention.EventsDays, MaxSizeMB: c.Retention.MaxSizeMB, SummariesDays: c.Retention.SummariesDays},
		WAF: agentapi.WAFSettings{CRSEnabled: c.Rules.CRS.State != rules.StateOff, ParanoiaLevel: c.Rules.CRS.ParanoiaLevel, InboundAnomalyThreshold: c.Rules.CRS.InboundAnomalyThreshold,
			EvalTimeoutMS: c.WAF.EvalTimeoutMS, MaxConcurrentEvals: max(1, lim.MaxConcurrent), QueueWaitMS: max(1, int(lim.QueueWait/time.Millisecond))},
		Behaviour: agentapi.BehaviourSettings{Scenarios: scenarioModes(map[string]string{"login_bruteforce": sc.LoginBruteforce.Mode, "credential_stuffing": sc.CredentialStuffing.Mode,
			"path_probing": sc.PathProbing.Mode, "aggressive_crawl": sc.AggressiveCrawl.Mode, "waf_repeat": sc.WAFRepeat.Mode}), ScenariosRecommended: maps.Clone(config.ScenarioRecommended),
			RateLimits: limits},
		Monitoring:       agentapi.MonitorSettings{Enabled: c.Monitoring.On(), Host: c.Monitoring.HostOn(), Keep: c.Monitoring.Keep},
		AllowlistEntries: len(allow),
	}
}

func scenarioModes(m map[string]string) map[string]string {
	for k, v := range m {
		if v != config.BehaviourOff && v != config.BehaviourObserve && v != config.BehaviourBlock {
			delete(m, k)
		}
	}
	return m
}

func profileOf(c *config.Site) string {
	if c.Profile == "test" {
		return "test"
	}
	return "production"
}

// startAgentAPI starts the agent API listener (loopback only, checked by the
// config) and its call log writer.
func (a *App) startAgentAPI(ctx context.Context, servers *[]*http.Server) {
	if a.AgentAPI == nil {
		return
	}
	addr := a.Config().AgentAPI.Listen
	srv := &http.Server{Addr: addr, Handler: a.AgentAPI.Handler(addr), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 2 * time.Minute}
	*servers = append(*servers, srv)
	a.goLoop(ctx, "agent-api-log", a.AgentAPI.Run)
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			a.log.Error("agent API listener stopped (request handling is not affected)", "addr", addr, "err", err)
		}
	}()
	a.log.Info("agent API listening (bearer tokens from `schild token add`)", "addr", addr, "openapi", "http://"+addr+"/agent/v0/openapi.json")
}
