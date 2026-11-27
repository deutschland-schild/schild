package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/deutschland-schild/schild/gateway/internal/auditlog"
	"sort"
	"time"

	cc "github.com/deutschland-schild/schild/contract/crawlers"
	"github.com/deutschland-schild/schild/contract/events"
	"github.com/deutschland-schild/schild/contract/websites"
	"github.com/deutschland-schild/schild/gateway/internal/crawlers"
	"github.com/deutschland-schild/schild/gateway/internal/dashboard"
	"github.com/deutschland-schild/schild/gateway/internal/eventlog"
	"github.com/deutschland-schild/schild/gateway/internal/store"
)

// Crawler control (D57, MVP-29): the crawler policy of each website, set
// from the dashboard or the agent API, kept in schild.db and compiled into
// the gate.

// ErrCrawlerWebsite: the website is unknown here.
var ErrCrawlerWebsite = errors.New("unknown website")

// CrawlerChange is who changes a policy and why.
type CrawlerChange struct {
	Preset                           string
	Actor, User, TokenID, TokenLabel string
	Reason                           string
}

// newCrawlers loads the policies from schild.db and wires them into the
// gate. Without a policy that blocks something the gate pays one map
// lookup per request.
func (a *App) newCrawlers(ctx context.Context) error {
	// The engine of schild.yaml bots, also with monitoring off, so
	// bots.verify holds for crawler control too (measurement 1, finding 2).
	if a.botEngine == nil {
		a.botEngine = a.newBots(a.Config())
	}
	a.Crawlers = crawlers.New(a.botEngine, time.Now())
	st := crawlers.NewState()
	raw, err := a.Store.Get(ctx, crawlers.StoreKey)
	switch {
	case errors.Is(err, store.ErrNotFound):
	case err != nil:
		return fmt.Errorf("crawler policies: %w", err)
	default:
		if err := json.Unmarshal(raw, st); err != nil {
			return fmt.Errorf("crawler policies: %w", err)
		}
		if st.Entries == nil {
			st.Entries = map[string]*crawlers.Entry{}
		}
	}
	if unknown := a.Crawlers.Set(st); len(unknown) > 0 {
		a.log.Warn("crawler policy: rules for bots the catalogue no longer knows are dropped; the next change stores the policy without them", "bots", unknown)
	}
	a.Gate.Crawlers = a.Crawlers
	if err := a.Metrics.Reg.Register(crawlers.Collector(a.Crawlers)); err != nil {
		a.log.Warn("crawler policy: prometheus collector not registered", "err", err)
	}
	return nil
}

// SetCrawlers changes the policy of a website with next (called with the
// stored policy). It is in force before it returns. A validation error is
// a *cc.FieldError; Field "website" means not every request of the website
// runs through schild.
func (a *App) SetCrawlers(ctx context.Context, website string, next func(cur cc.Policy) (cc.Policy, error), c CrawlerChange) (*crawlers.Entry, error) {
	a.crawlersMu.Lock()
	defer a.crawlersMu.Unlock()
	w, ok := a.Sites.View().Website(website)
	if !ok {
		return nil, ErrCrawlerWebsite
	}
	if w.Protection != websites.Protected {
		return nil, &cc.FieldError{Field: "website", Msg: "not every request of this website runs through schild"}
	}
	cur := a.Crawlers.State()
	var old cc.Policy
	if e := cur.Entries[website]; e != nil {
		old = e.Policy.Clone()
	}
	p, err := next(old)
	if err != nil {
		return nil, err
	}
	if err := p.Check(a.Crawlers.Known); err != nil {
		return nil, err
	}
	p = p.Normalize()
	now := time.Now().UTC()
	st := cur.Clone()
	e := &crawlers.Entry{Policy: p, UpdatedAt: now, Actor: c.Actor, User: c.User, TokenID: c.TokenID, TokenLabel: c.TokenLabel}
	st.Entries[website] = e
	raw, err := json.Marshal(st)
	if err == nil {
		// What crawlers.set records: the policy as the API shows it, and
		// the preset it came from.
		before, after := asMap(old.Wire()), asMap(p.Wire())
		if c.Preset != "" {
			after["preset"] = c.Preset
		}
		err = a.putAudited(ctx, crawlers.StoreKey, raw, func(o auditlog.Origin) []auditlog.Entry {
			if o.Reason == "" {
				o.Reason = c.Reason
			}
			return one("crawlers.set", website, website, before, after)(o)
		})
	}
	if err != nil {
		return nil, fmt.Errorf("crawler policy not stored: %w", err)
	}
	a.Crawlers.Set(st)
	wp := p.Wire()
	a.Events.Emit(events.CrawlerPolicySet, now, events.CrawlerPolicyChange{Website: website, Categories: wp.Categories, Bots: wp.Bots,
		Impersonators: wp.Impersonators, Preset: c.Preset, Actor: c.Actor, User: c.User, TokenID: c.TokenID, TokenLabel: c.TokenLabel, Reason: c.Reason},
		eventlog.Index{Site: website, Summary: "crawler policy of " + website + " set"})
	a.log.Info("crawler policy set", "website", website, "actor", c.Actor, "blocks", p.Blocks(), "preset", c.Preset)
	return e, nil
}

// crawlerState is getCrawlerPolicy and setCrawlerPolicy.
func (a *App) crawlerState(website string) cc.State {
	e := a.Crawlers.Engine()
	st := cc.State{Website: website, Policy: cc.Policy{}.Wire(), CatalogueVersion: e.CatalogueVersion(), Presets: cc.PresetNames}
	if x := a.Crawlers.Entry(website); x != nil {
		st.Policy = x.Policy.Wire()
		u, actor := x.UpdatedAt.UTC().Format("2006-01-02T15:04:05.000Z"), x.Actor
		st.UpdatedAt, st.Actor = &u, &actor
	}
	for _, b := range e.Catalogue().Bots {
		st.Crawlers = append(st.Crawlers, cc.CatalogueEntry{ID: b.ID, Name: b.Name, Operator: b.Operator, Category: b.Category, Verifiable: b.Verify.Ranges != ""})
	}
	return st
}

// dashboardCrawlers connects the dashboard with crawler control.
func (a *App) dashboardCrawlers() dashboard.CrawlerFuncs {
	return dashboard.CrawlerFuncs{
		Get: func(website string) (cc.State, error) {
			if _, ok := a.Sites.View().Website(website); !ok {
				return cc.State{}, ErrCrawlerWebsite
			}
			return a.crawlerState(website), nil
		},
		Set: func(ctx context.Context, website string, in cc.Input, user string) (cc.State, error) {
			_, err := a.SetCrawlers(ctx, website, in.Next, CrawlerChange{Preset: in.Preset, Actor: cc.ActorDashboard, User: user})
			if err != nil {
				return cc.State{}, err
			}
			return a.crawlerState(website), nil
		},
	}
}

// agentCrawlerPolicy is one website of getAgentCrawlers.
func (a *App) agentCrawlerPolicy(website string) cc.AgentPolicy {
	e := a.Crawlers.Engine()
	out := cc.AgentPolicy{Website: website, Policy: cc.Policy{}.Wire(), Crawlers: []cc.BotCount{}}
	var p cc.Policy
	if x := a.Crawlers.Entry(website); x != nil {
		p = x.Policy
		out.Policy = p.Wire()
		u, actor := x.UpdatedAt.UTC().Format("2006-01-02T15:04:05.000Z"), x.Actor
		out.UpdatedAt, out.Actor = &u, &actor
	}
	counts := map[uint16]crawlers.Count{}
	for _, c := range a.Crawlers.Counts(website) {
		counts[c.Bot] = c
	}
	named := map[uint16]bool{}
	for id := range p.Bots {
		if n := e.ID(id); n != 0 {
			named[n] = true
		}
	}
	for id := 1; id <= e.NumBots(); id++ {
		b := e.Bot(uint16(id))
		c, hit := counts[uint16(id)]
		rule := cc.RuleFor(p, b.ID, b.Category, "")
		if !hit && !named[uint16(id)] {
			continue
		}
		action := cc.Allow
		if rule != cc.RuleNone {
			action = cc.Block
		}
		out.Crawlers = append(out.Crawlers, cc.BotCount{Bot: b.ID, Name: b.Name, Category: b.Category, Rule: action, Blocked: int64(c.Blocked), WouldBlock: int64(c.WouldBlock)})
	}
	sort.SliceStable(out.Crawlers, func(i, j int) bool {
		x, y := out.Crawlers[i], out.Crawlers[j]
		if x.Blocked+x.WouldBlock != y.Blocked+y.WouldBlock {
			return x.Blocked+x.WouldBlock > y.Blocked+y.WouldBlock
		}
		return x.Bot < y.Bot
	})
	return out
}

// agentCrawlers is getAgentCrawlers: every website of this gateway, or one.
func (a *App) agentCrawlers(site string) cc.AgentList {
	out := cc.AgentList{Since: a.Crawlers.Since().Format("2006-01-02T15:04:05.000Z"), Items: []cc.AgentPolicy{}}
	var ids []string
	if site != "" {
		ids = []string{site}
	} else {
		for _, w := range a.Sites.View().Websites() {
			ids = append(ids, w.ID)
		}
		sort.Strings(ids)
	}
	for _, id := range ids {
		out.Items = append(out.Items, a.agentCrawlerPolicy(id))
	}
	return out
}

// agentSetCrawlers is setAgentCrawlers.
func (a *App) agentSetCrawlers(ctx context.Context, req cc.SetRequest, tokenID, label string) (cc.AgentPolicy, error) {
	_, err := a.SetCrawlers(ctx, req.Website, func(cur cc.Policy) (cc.Policy, error) { return req.Apply(cur, a.Crawlers.Known) },
		CrawlerChange{Preset: req.Preset, Actor: cc.ActorAgent, TokenID: tokenID, TokenLabel: label, Reason: req.Reason})
	if err != nil {
		return cc.AgentPolicy{}, err
	}
	return a.agentCrawlerPolicy(req.Website), nil
}
