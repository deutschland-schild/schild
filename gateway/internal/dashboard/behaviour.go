package dashboard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/deutschland-schild/schild/contract/config"
	"github.com/deutschland-schild/schild/contract/events"
	"github.com/deutschland-schild/schild/gateway/internal/allowlist"
	"github.com/deutschland-schild/schild/gateway/internal/behaviour"
	"github.com/deutschland-schild/schild/gateway/internal/store"
)

// v0.4 (MVP-17): behaviour across requests and rate limits. Everything here
// is local: hits are local events, blocks and counters live in memory.

// BehaviourHit is one scenario hit or rate-limit record.
type BehaviourHit struct {
	ID          string  `json:"id"`
	Time        string  `json:"time"`
	Kind        string  `json:"kind"`
	Scenario    string  `json:"scenario,omitempty"`
	Scope       string  `json:"scope,omitempty"`
	LimitID     string  `json:"limit_id,omitempty"`
	LimitLabel  string  `json:"limit_label,omitempty"`
	IP          string  `json:"ip,omitempty"`
	KeyBits     int     `json:"key_bits,omitempty"`
	Geo         *Geo    `json:"geo,omitempty"`
	Host        string  `json:"host,omitempty"`
	Route       string  `json:"route,omitempty"`
	Preset      string  `json:"preset,omitempty"`
	Count       int     `json:"count"`
	Threshold   int     `json:"threshold"`
	WindowS     int     `json:"window_s"`
	PerS        int     `json:"per_s,omitempty"`
	Mode        string  `json:"mode"`
	Action      string  `json:"action"`
	WouldAction string  `json:"would_action,omitempty"`
	Reason      string  `json:"reason,omitempty"`
	Level       int     `json:"level,omitempty"`
	DurationS   int     `json:"duration_s,omitempty"`
	Until       *string `json:"until,omitempty"`
	Incident    string  `json:"incident,omitempty"`
	Active      bool    `json:"active"`
	Released    bool    `json:"released"`
}

// BehaviourHitPage is a page of hits.
type BehaviourHitPage struct {
	Items      []BehaviourHit `json:"items"`
	NextCursor *string        `json:"next_cursor"`
}

// BehaviourBlock is a running block of a client key.
// D29 amendment: the duration comes from the ladder of NetClass; Persisted
// blocks (over 24 h) survive a restart.
type BehaviourBlock struct {
	Source    string `json:"source"`
	Until     string `json:"until"`
	Level     int    `json:"level"`
	Incident  string `json:"incident,omitempty"`
	NetClass  string `json:"net_class,omitempty"`
	DurationS int    `json:"duration_s,omitempty"`
	Persisted bool   `json:"persisted,omitempty"`
	// EndedAt (contracts v0.5): set once the block is no longer in force
	// (ran out, lifted, or ended by a restart); absent while it runs.
	EndedAt string `json:"ended_at,omitempty"`
	// SetBy and AgentReason (D42): only on a block an agent set. The reason is
	// the agent's text: render it as text.
	SetBy       *BlockSetBy `json:"set_by,omitempty"`
	AgentReason string      `json:"agent_reason,omitempty"`
}

// BlockSetBy names the agent token that set a block. It comes from the event
// of the block, so the name stays after the token is revoked.
type BlockSetBy struct {
	TokenID    string `json:"token_id"`
	TokenLabel string `json:"token_label"`
}

func blockView(b behaviour.BlockInfo) BehaviourBlock {
	out := BehaviourBlock{Source: behaviour.BlockSource(b.Scenario), Until: ts(b.Until), Level: b.Level, Incident: b.Incident, NetClass: b.NetClass, Persisted: b.Persisted}
	if d := int(b.Duration / time.Second); d >= 1 {
		out.DurationS = min(d, events.MaxBlockHostingS)
	}
	return out
}

// BehaviourHitDetail is one hit with context.
type BehaviourHitDetail struct {
	Hit         BehaviourHit     `json:"hit"`
	Requests    []EventSummary   `json:"requests"`
	Blocks      []BehaviourBlock `json:"blocks"`
	Allowlisted bool             `json:"allowlisted"`
}

// ScenarioThresholds in the API.
type ScenarioThresholds struct {
	Count          int     `json:"count"`
	WindowS        int     `json:"window_s"`
	SlowCount      int     `json:"slow_count,omitempty"`
	SlowWindowS    int     `json:"slow_window_s,omitempty"`
	BaselineFactor float64 `json:"baseline_factor,omitempty"`
}

// ScenarioSetting is one scenario in the settings.
type ScenarioSetting struct {
	ID            string             `json:"id"`
	Mode          string             `json:"mode"`
	EffectiveMode string             `json:"effective_mode"`
	Recommended   string             `json:"recommended"`
	Thresholds    ScenarioThresholds `json:"thresholds"`
	Defaults      ScenarioThresholds `json:"defaults"`
	Hits24h       int                `json:"hits_24h"`
	WouldBlock24h int                `json:"would_block_24h"`
	BlocksActive  int                `json:"blocks_active"`
}

// BehaviourSettings is GET /behaviour/settings.
type BehaviourSettings struct {
	Scenarios          []ScenarioSetting `json:"scenarios"`
	Presets            []string          `json:"presets"`
	BlockStepsS        []int             `json:"block_steps_s"`
	BlockCapS          int               `json:"block_cap_s"`
	HostingBlockStepsS []int             `json:"hosting_block_steps_s,omitempty"`
	HostingBlockCapS   int               `json:"hosting_block_cap_s,omitempty"`
	InstalledAt        *string           `json:"installed_at,omitempty"`
	// LearningUntil is the end of the learning period; before it no scenario
	// blocks. Nil when the first start is unknown (keeps learning).
	LearningUntil *string `json:"learning_until"`
}

// ScenarioModes is the scenarios part of a settings patch.
type ScenarioModes struct {
	LoginBruteforce    *string `json:"login_bruteforce,omitempty"`
	CredentialStuffing *string `json:"credential_stuffing,omitempty"`
	PathProbing        *string `json:"path_probing,omitempty"`
	AggressiveCrawl    *string `json:"aggressive_crawl,omitempty"`
	WAFRepeat          *string `json:"waf_repeat,omitempty"`
}

func (m *ScenarioModes) asMap() map[string]string {
	out := map[string]string{}
	for id, v := range map[string]*string{config.ScenarioLoginBruteforce: m.LoginBruteforce, config.ScenarioCredentialStuffing: m.CredentialStuffing,
		config.ScenarioPathProbing: m.PathProbing, config.ScenarioAggressiveCrawl: m.AggressiveCrawl, config.ScenarioWAFRepeat: m.WAFRepeat} {
		if v != nil {
			out[id] = *v
		}
	}
	return out
}

// ScenarioThresholdsPatch sets the thresholds of one scenario (D93). It
// replaces what the dashboard set before; a field left out falls back to
// schild.yaml or the built-in default, an empty object to all of them.
type ScenarioThresholdsPatch struct {
	Count          *int     `json:"count,omitempty"`
	WindowS        *int     `json:"window_s,omitempty"`
	SlowCount      *int     `json:"slow_count,omitempty"`
	SlowWindowS    *int     `json:"slow_window_s,omitempty"`
	BaselineFactor *float64 `json:"baseline_factor,omitempty"`
}

// ScenarioThresholdPatches is the thresholds part of a settings patch.
type ScenarioThresholdPatches struct {
	LoginBruteforce    *ScenarioThresholdsPatch `json:"login_bruteforce,omitempty"`
	CredentialStuffing *ScenarioThresholdsPatch `json:"credential_stuffing,omitempty"`
	PathProbing        *ScenarioThresholdsPatch `json:"path_probing,omitempty"`
	AggressiveCrawl    *ScenarioThresholdsPatch `json:"aggressive_crawl,omitempty"`
	WAFRepeat          *ScenarioThresholdsPatch `json:"waf_repeat,omitempty"`
}

// thresholdBounds mirrors schild.schema.json (thresholds, crawlScenario), so
// a refused value names its field. The config validation of the commit stays
// the authority.
type thresholdBounds struct{ minCount, minWindowS, maxWindowS int }

var scenarioBounds = map[string]thresholdBounds{
	config.ScenarioLoginBruteforce:    {2, 1, 86400},
	config.ScenarioCredentialStuffing: {2, 1, 86400},
	config.ScenarioPathProbing:        {2, 1, 86400},
	config.ScenarioAggressiveCrawl:    {10, 10, 3600},
	config.ScenarioWAFRepeat:          {2, 1, 86400},
}

// asMap returns the patched thresholds by scenario (zero fields: not set)
// and what the bounds refuse.
func (m *ScenarioThresholdPatches) asMap() (map[string]config.Thresholds, []FieldError) {
	out := map[string]config.Thresholds{}
	var errs []FieldError
	for id, p := range map[string]*ScenarioThresholdsPatch{config.ScenarioLoginBruteforce: m.LoginBruteforce, config.ScenarioCredentialStuffing: m.CredentialStuffing,
		config.ScenarioPathProbing: m.PathProbing, config.ScenarioAggressiveCrawl: m.AggressiveCrawl, config.ScenarioWAFRepeat: m.WAFRepeat} {
		if p == nil {
			continue
		}
		b, at := scenarioBounds[id], "/thresholds/"+id
		bad := func(field, detail string) { errs = append(errs, FieldError{Pointer: at + "/" + field, Detail: detail}) }
		var t config.Thresholds
		if v := p.Count; v != nil {
			if t.Count = *v; *v < b.minCount || *v > 100000 {
				bad("count", fmt.Sprintf("%d bis 100000", b.minCount))
			}
		}
		if v := p.WindowS; v != nil {
			if t.WindowS = *v; *v < b.minWindowS || *v > b.maxWindowS {
				bad("window_s", fmt.Sprintf("%d bis %d Sekunden", b.minWindowS, b.maxWindowS))
			}
		}
		slow := id == config.ScenarioLoginBruteforce
		if v := p.SlowCount; v != nil {
			if t.SlowCount = *v; !slow || *v < 2 || *v > 100000 {
				bad("slow_count", "nur bei login_bruteforce, 2 bis 100000")
			}
		}
		if v := p.SlowWindowS; v != nil {
			if t.SlowWindowS = *v; !slow || *v < 60 || *v > 86400 {
				bad("slow_window_s", "nur bei login_bruteforce, 60 bis 86400 Sekunden")
			}
		}
		if v := p.BaselineFactor; v != nil {
			if t.BaselineFactor = *v; id != config.ScenarioAggressiveCrawl || *v < 2 || *v > 1000 {
				bad("baseline_factor", "nur bei aggressive_crawl, 2 bis 1000")
			}
		}
		out[id] = t
	}
	sort.Slice(errs, func(i, j int) bool { return errs[i].Pointer < errs[j].Pointer })
	return out, errs
}

// BehaviourSettingsPatch is PATCH /behaviour/settings.
type BehaviourSettingsPatch struct {
	Scenarios  *ScenarioModes            `json:"scenarios,omitempty"`
	Thresholds *ScenarioThresholdPatches `json:"thresholds,omitempty"`
	// PresetLimitModes switches preset limits by id (D95).
	PresetLimitModes map[string]string `json:"preset_limit_modes,omitempty"`
}

// RateLimitDraft is a limit for the dry run.
type RateLimitDraft struct {
	Route   string   `json:"route"`
	Methods []string `json:"methods,omitempty"`
	Limit   int      `json:"limit"`
	Per     string   `json:"per"`
	Burst   int      `json:"burst,omitempty"`
	Site    string   `json:"site,omitempty"`
}

// RateLimitInput creates or replaces an own limit.
type RateLimitInput struct {
	Route           string   `json:"route"`
	Methods         []string `json:"methods,omitempty"`
	Limit           int      `json:"limit"`
	Per             string   `json:"per"`
	Burst           int      `json:"burst,omitempty"`
	Mode            string   `json:"mode,omitempty"`
	Site            string   `json:"site,omitempty"`
	Label           string   `json:"label,omitempty"`
	ConfirmSiteWide bool     `json:"confirm_site_wide,omitempty"`
}

// RateLimitDryRun is the Probelauf result.
type RateLimitDryRun struct {
	WindowH    int  `json:"window_h"`
	Requests   int  `json:"requests"`
	WouldLimit int  `json:"would_limit"`
	Clients    int  `json:"clients"`
	Sampled    bool `json:"sampled"`
}

// RateLimit in the API.
type RateLimit struct {
	ID              string   `json:"id"`
	Label           string   `json:"label,omitempty"`
	Route           string   `json:"route"`
	Methods         []string `json:"methods,omitempty"`
	Limit           int      `json:"limit"`
	Per             string   `json:"per"`
	Burst           int      `json:"burst"`
	Mode            string   `json:"mode"`
	Site            string   `json:"site,omitempty"`
	Preset          string   `json:"preset,omitempty"`
	Recommended     string   `json:"recommended,omitempty"`
	ConfirmSiteWide bool     `json:"confirm_site_wide,omitempty"`
	Source          string   `json:"source"`
	Matched24h      int      `json:"matched_24h"`
	Exceeded24h     int      `json:"exceeded_24h"`
	Clients24h      int      `json:"clients_24h"`
}

// RateLimitPage is a page of limits.
type RateLimitPage struct {
	Items      []RateLimit `json:"items"`
	NextCursor *string     `json:"next_cursor"`
}

// ReleaseRequest releases a client.
type ReleaseRequest struct {
	IP       string `json:"ip"`
	Scenario string `json:"scenario,omitempty"`
	LimitID  string `json:"limit_id,omitempty"`
	Allow    string `json:"allow,omitempty"`
	TTL      string `json:"ttl,omitempty"`
	Label    string `json:"label,omitempty"`
}

// ReleaseResult is what a release did.
type ReleaseResult struct {
	IP               string   `json:"ip"`
	BlocksEnded      int      `json:"blocks_ended"`
	ExceptionUntil   *string  `json:"exception_until,omitempty"`
	ExceptionSources []string `json:"exception_sources,omitempty"`
	AllowlistEntry   *string  `json:"allowlist_entry"`
}

func (s *Server) behaviourRoutes(a func(string, http.HandlerFunc)) {
	a("GET "+apiPrefix+"/behaviour/hits", s.listBehaviourHits)
	a("GET "+apiPrefix+"/behaviour/hits/{id}", s.getBehaviourHit)
	a("GET "+apiPrefix+"/behaviour/settings", s.getBehaviourSettings)
	a("PATCH "+apiPrefix+"/behaviour/settings", s.updateBehaviourSettings)
	a("GET "+apiPrefix+"/behaviour/rate-limits", s.listRateLimits)
	a("POST "+apiPrefix+"/behaviour/rate-limits", s.createRateLimit)
	a("POST "+apiPrefix+"/behaviour/rate-limits/dry-run", s.dryRunRateLimit)
	a("PATCH "+apiPrefix+"/behaviour/rate-limits/{limit_id}", s.updateRateLimit)
	a("DELETE "+apiPrefix+"/behaviour/rate-limits/{limit_id}", s.deleteRateLimit)
	a("POST "+apiPrefix+"/behaviour/release", s.releaseClient)
	a("GET "+apiPrefix+"/blocks", s.listBlocks)
	a("POST "+apiPrefix+"/blocks", s.createBlock)
}

func (s *Server) behaviourAvailable(w http.ResponseWriter) bool {
	if s.Behaviour == nil {
		problem(w, http.StatusServiceUnavailable, "unavailable", "Verhalten und Limits sind auf diesem Gateway nicht aktiv.", nil)
		return false
	}
	return true
}

// ---------------------------------------------------------------- hits

var scenarioIDs = config.ScenarioIDs

// dropChallenge shows a hit of an event written before D92 without the old
// mode challenge: it only ever observed, there was no browser check.
func dropChallenge(h *BehaviourHit) {
	const challenge, unavailable = "challenge", "challenge_unavailable"
	if h.Mode == challenge {
		h.Mode = behaviour.ActionObserve
	}
	if h.Action == challenge {
		h.Action = behaviour.ActionObserve
	}
	if h.WouldAction == challenge {
		h.WouldAction = behaviour.ActionObserve
	}
	if h.Reason == unavailable {
		h.Reason = ""
	}
}

func (s *Server) hitOf(e *store.EventRow, now time.Time) (BehaviourHit, bool) {
	var ev struct {
		Data json.RawMessage `json:"data"`
	}
	if json.Unmarshal(e.Body, &ev) != nil {
		return BehaviourHit{}, false
	}
	h := BehaviourHit{ID: e.ID, Time: ts(e.Time)}
	var client *events.Client
	switch e.Type {
	case events.BehaviourTriggered:
		var d events.BehaviourTriggeredData
		if json.Unmarshal(ev.Data, &d) != nil {
			return h, false
		}
		h.Kind, h.Scenario, h.Scope = "scenario", d.Scenario, d.Scope
		h.KeyBits, h.Host, h.Route, h.Preset = d.KeyBits, d.Host, d.Route, d.Preset
		h.Count, h.Threshold, h.WindowS = d.Count, d.Threshold, d.WindowS
		h.Mode, h.Action, h.WouldAction, h.Reason, h.Level, h.Incident = d.Mode, d.Action, d.WouldAction, d.Reason, d.Level, d.Incident
		dropChallenge(&h)
		h.DurationS = d.DurationS
		if d.Until != "" {
			u := d.Until
			h.Until = &u
		}
		client = d.Client
	case events.RateLimitExceeded:
		var d events.RateLimitExceededData
		if json.Unmarshal(ev.Data, &d) != nil {
			return h, false
		}
		h.Kind, h.LimitID, h.Scope = "rate_limit", d.LimitID, ""
		h.KeyBits, h.Host, h.Route = d.KeyBits, d.Host, d.Route
		h.Count, h.Threshold, h.WindowS, h.PerS = d.Count, d.Limit, d.PerS, d.PerS
		h.Mode, h.Action, h.Reason = d.Mode, d.Action, d.Reason
		if d.Action == behaviour.ActionObserve && d.Reason == "" {
			h.WouldAction = behaviour.ActionBlock
		}
		c := d.Client
		client = &c
		if s.Behaviour != nil {
			for _, l := range s.Behaviour.Limits() {
				if l.ID == d.LimitID {
					h.LimitLabel, h.Preset = l.Label, l.Preset
				}
			}
		}
	default:
		return h, false
	}
	if client != nil {
		h.IP = client.IP
		g := client.Geo
		h.Geo = &Geo{Country: g.Country, City: g.City, ASN: g.ASN, ASOrg: g.ASOrg, NetClass: g.NetClass}
		if ip, err := netip.ParseAddr(client.IP); err == nil && s.Behaviour != nil {
			if h.Kind == "scenario" && h.Action == behaviour.ActionBlock {
				// A block restored at start (D29 amendment, kept in
				// schild.db) does not know its event id; its incident
				// number names the hit (D36 measurement C: restored
				// blocks showed active false while still blocking).
				if b, ok := s.Behaviour.ActiveBlock(ip); ok && (b.EventID == e.ID || b.EventID == "" && b.Incident != "" && b.Incident == h.Incident) {
					h.Active = true
				}
			}
			h.Released = s.Behaviour.ReleasedSince(ip, e.Time)
			if !h.Released && h.Scenario != "" && s.Gate != nil && s.Gate.Exceptions.Has(ip, "behaviour:"+h.Scenario, now) {
				h.Released = true
				h.Active = false
			}
		}
	}
	return h, true
}

func (s *Server) listBehaviourHits(w http.ResponseWriter, r *http.Request) {
	q := &query{r: r}
	f := store.EventFilter{IP: q.str("ip", 64, nil)}
	f.Site = s.siteParam(q)
	f.From, f.To = q.time("from"), q.time("to")
	kind := q.enum("kind", "scenario", "rate_limit")
	scenario := q.enum("scenario", scenarioIDs...)
	active := q.enum("active", "true", "false")
	limit, cursor := q.limit(), q.cursor()
	if q.failed(w) {
		return
	}
	switch {
	case scenario != "":
		f.Type, f.SummaryPrefix = events.BehaviourTriggered, "behaviour "+scenario+" "
	case kind == "scenario":
		f.Type = events.BehaviourTriggered
	case kind == "rate_limit":
		f.Type = events.RateLimitExceeded
	default:
		f.Types = []string{events.BehaviourTriggered, events.RateLimitExceeded}
	}
	if active == "true" {
		f.Type, f.Types, f.Outcome = events.BehaviourTriggered, nil, behaviour.ActionBlock
		if f.From.IsZero() {
			f.From = s.now().Add(-behaviour.MaxBlock)
		}
	}
	rows, next, err := s.St.ListEvents(r.Context(), f, cursor, limit)
	if err != nil {
		s.internal(w, err)
		return
	}
	now := s.now()
	page := BehaviourHitPage{Items: []BehaviourHit{}, NextCursor: nextCursor(next)}
	for _, e := range rows {
		h, ok := s.hitOf(e, now)
		if !ok || (active == "true" && !h.Active) || (active == "false" && h.Active) {
			continue
		}
		page.Items = append(page.Items, h)
	}
	writeJSON(w, 200, page)
}

func (s *Server) getBehaviourHit(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	notFound := func() { problem(w, 404, "not_found", "Diesen Treffer gibt es nicht (mehr).", nil) }
	if !uuidRe.MatchString(id) {
		notFound()
		return
	}
	e, err := s.St.GetEvent(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		notFound()
		return
	}
	if err != nil {
		s.internal(w, err)
		return
	}
	now := s.now()
	h, ok := s.hitOf(e, now)
	if !ok {
		notFound()
		return
	}
	d := BehaviourHitDetail{Hit: h, Requests: []EventSummary{}, Blocks: []BehaviourBlock{}}
	if ip, err := netip.ParseAddr(h.IP); err == nil {
		win := time.Duration(max(h.WindowS, 60)) * time.Second
		rows, _, err := s.St.ListEvents(r.Context(), store.EventFilter{IP: ip.String(), From: e.Time.Add(-win), To: e.Time.Add(5 * time.Minute),
			Types: []string{events.RequestEvaluated, events.RequestBlocked}}, 0, 100)
		if err == nil {
			for _, x := range rows {
				d.Requests = append(d.Requests, summarize(x))
			}
		}
		if s.Behaviour != nil {
			if b, ok := s.Behaviour.ActiveBlock(ip); ok {
				d.Blocks = append(d.Blocks, blockView(b))
			}
		}
		if s.Allow != nil {
			lvl, _ := s.Allow.Match(ip, now)
			d.Allowlisted = lvl != ""
		}
	}
	writeJSON(w, 200, d)
}

// ---------------------------------------------------------------- settings

func thresholdsView(t config.Thresholds) ScenarioThresholds {
	return ScenarioThresholds{Count: t.Count, WindowS: t.WindowS, SlowCount: t.SlowCount, SlowWindowS: t.SlowWindowS, BaselineFactor: t.BaselineFactor}
}

func (s *Server) behaviourSettings(ctx context.Context) BehaviourSettings {
	b := s.Config().Behaviour
	e := s.Behaviour
	out := BehaviourSettings{Presets: append([]string{}, b.Presets...), LearningUntil: tsp(e.LearnUntil()),
		BlockCapS: events.MaxBlockDefaultS, BlockStepsS: append([]int{}, events.LadderDefault...),
		HostingBlockStepsS: append([]int{}, events.LadderHosting...), HostingBlockCapS: events.MaxBlockHostingS}
	active := e.ActiveBlocks()
	for _, id := range config.ScenarioIDs {
		hits, would := e.Counts24h(id)
		out.Scenarios = append(out.Scenarios, ScenarioSetting{ID: id, Mode: e.Mode(id), EffectiveMode: e.EffectiveMode(id), Recommended: config.ScenarioRecommended[id],
			Thresholds: thresholdsView(e.Thresholds(id)), Defaults: thresholdsView(behaviour.Defaults[id]), Hits24h: hits, WouldBlock24h: would, BlocksActive: active[id]})
	}
	if s.InstalledAt != nil {
		out.InstalledAt = tsp(s.InstalledAt(ctx))
	}
	return out
}

func (s *Server) getBehaviourSettings(w http.ResponseWriter, r *http.Request) {
	if !s.behaviourAvailable(w) {
		return
	}
	writeJSON(w, 200, s.behaviourSettings(r.Context()))
}

var behaviourModes = map[string]bool{config.BehaviourOff: true, config.BehaviourObserve: true, config.BehaviourBlock: true}

func (s *Server) updateBehaviourSettings(w http.ResponseWriter, r *http.Request) {
	if !s.behaviourAvailable(w) {
		return
	}
	var p BehaviourSettingsPatch
	if !decode(w, r, &p) {
		return
	}
	modes := map[string]string{}
	if p.Scenarios != nil {
		modes = p.Scenarios.asMap()
	}
	for id, m := range modes {
		if !behaviourModes[m] {
			invalid(w, "Unbekannter Modus.", FieldError{Pointer: "/scenarios/" + id, Detail: "off, observe oder block"})
			return
		}
	}
	var thresholds map[string]config.Thresholds
	if p.Thresholds != nil {
		var errs []FieldError
		if thresholds, errs = p.Thresholds.asMap(); len(errs) > 0 {
			invalid(w, "Diese Schwelle ist nicht möglich.", errs...)
			return
		}
	}
	if len(p.PresetLimitModes) > 0 {
		preset := map[string]bool{}
		for _, l := range s.Behaviour.Limits() {
			preset[l.ID] = l.Source == "preset"
		}
		var errs []FieldError
		for id, m := range p.PresetLimitModes {
			switch {
			case !preset[id]:
				errs = append(errs, FieldError{Pointer: "/preset_limit_modes/" + id, Detail: "kein voreingestelltes Limit"})
			case !behaviourModes[m]:
				errs = append(errs, FieldError{Pointer: "/preset_limit_modes/" + id, Detail: "off, observe oder block"})
			}
		}
		if len(errs) > 0 {
			sort.Slice(errs, func(i, j int) bool { return errs[i].Pointer < errs[j].Pointer })
			invalid(w, "Dieses Limit lässt sich so nicht schalten.", errs...)
			return
		}
	}
	if s.ApplyBehaviour == nil {
		problem(w, http.StatusServiceUnavailable, "unavailable", "Diese Einstellung lässt sich hier nicht ändern.", nil)
		return
	}
	if _, err := s.ApplyBehaviour(r.Context(), modes, thresholds, p.PresetLimitModes); err != nil {
		invalid(w, "Diese Einstellung ist nicht möglich: "+err.Error())
		return
	}
	writeJSON(w, 200, s.behaviourSettings(r.Context()))
}

// ---------------------------------------------------------------- rate limits

func (s *Server) limitView(l *behaviour.Limit) RateLimit {
	ex, cl := s.Behaviour.LimitCounts24h(l.ID)
	return RateLimit{ID: l.ID, Label: l.Label, Route: l.Route, Methods: l.Methods, Limit: l.Limit, Per: l.Per, Burst: l.Burst, Mode: l.Mode, Site: l.Site,
		Preset: l.Preset, Recommended: l.Recommended, ConfirmSiteWide: l.ConfirmSiteWide, Source: l.Source, Matched24h: s.Behaviour.LimitMatched24h(l.ID), Exceeded24h: ex, Clients24h: cl}
}

func (s *Server) listRateLimits(w http.ResponseWriter, r *http.Request) {
	if !s.behaviourAvailable(w) {
		return
	}
	q := &query{r: r}
	limit := q.limit()
	off := 0
	if c := r.URL.Query().Get("cursor"); c != "" {
		n, err := strconv.Atoi(strings.TrimPrefix(c, "o"))
		if err != nil || n < 0 || !strings.HasPrefix(c, "o") {
			q.errs = append(q.errs, FieldError{Pointer: "#/query/cursor", Detail: "ungültig"})
		}
		off = n
	}
	if q.failed(w) {
		return
	}
	all := s.Behaviour.Limits()
	page := RateLimitPage{Items: []RateLimit{}}
	for i := off; i < len(all) && len(page.Items) < limit; i++ {
		page.Items = append(page.Items, s.limitView(all[i]))
	}
	if off+limit < len(all) {
		c := "o" + strconv.Itoa(off+limit)
		page.NextCursor = &c
	}
	writeJSON(w, 200, page)
}

var (
	routeInputRe = regexp.MustCompile(`^/[A-Za-z0-9._~!&'()+,;=:@%/*-]{0,255}$`)
	siteInputRe  = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,62}\.)*[A-Za-z0-9-]{1,63}$`)
	limitMethods = map[string]bool{"GET": true, "HEAD": true, "POST": true, "PUT": true, "PATCH": true, "DELETE": true, "OPTIONS": true}
)

// checkDraft validates the fields a draft and an input share.
func checkDraft(d RateLimitDraft) []FieldError {
	var fe []FieldError
	if !routeInputRe.MatchString(d.Route) {
		fe = append(fe, FieldError{Pointer: "/route", Detail: "Pfad mit / am Anfang; * für einen Abschnitt, ** für beliebig viele"})
	}
	if d.Limit < 1 || d.Limit > 100000 {
		fe = append(fe, FieldError{Pointer: "/limit", Detail: "1 bis 100000"})
	}
	if _, err := config.ParsePer(d.Per); err != nil {
		fe = append(fe, FieldError{Pointer: "/per", Detail: "z. B. 10s, 1m, 1h (höchstens 24h)"})
	}
	if d.Burst < 0 || d.Burst > 100000 {
		fe = append(fe, FieldError{Pointer: "/burst", Detail: "1 bis 100000"})
	}
	for i, m := range d.Methods {
		if !limitMethods[m] {
			fe = append(fe, FieldError{Pointer: "/methods/" + strconv.Itoa(i), Detail: "GET, HEAD, POST, PUT, PATCH, DELETE oder OPTIONS"})
		}
	}
	if d.Site != "" && (!siteInputRe.MatchString(d.Site) || len(d.Site) > 253) {
		fe = append(fe, FieldError{Pointer: "/site", Detail: "Hostname, z. B. verein.example"})
	}
	return fe
}

func (s *Server) limitFromInput(w http.ResponseWriter, in RateLimitInput, id string) (config.RateLimit, bool) {
	fe := checkDraft(RateLimitDraft{Route: in.Route, Methods: in.Methods, Limit: in.Limit, Per: in.Per, Burst: in.Burst, Site: in.Site})
	if in.Mode != "" && in.Mode != config.BehaviourOff && in.Mode != config.BehaviourObserve && in.Mode != config.BehaviourBlock {
		fe = append(fe, FieldError{Pointer: "/mode", Detail: "off, observe oder block"})
	}
	if len(in.Label) > 64 {
		fe = append(fe, FieldError{Pointer: "/label", Detail: "höchstens 64 Zeichen"})
	}
	if config.SiteWideRoute(in.Route) && !in.ConfirmSiteWide {
		fe = append(fe, FieldError{Pointer: "/confirm_site_wide", Detail: "Dieses Limit gilt für die ganze Website. Bestätige das ausdrücklich."})
	}
	if len(fe) > 0 {
		invalid(w, "Dieses Limit ist so nicht möglich.", fe...)
		return config.RateLimit{}, false
	}
	l := config.RateLimit{ID: id, Label: in.Label, Route: in.Route, Methods: in.Methods, Limit: in.Limit, Per: in.Per, Burst: in.Burst, Mode: in.Mode,
		Site: in.Site, ConfirmSiteWide: in.ConfirmSiteWide}
	if l.Burst == 0 {
		l.Burst = l.Limit
	}
	if l.Mode == "" {
		l.Mode = config.BehaviourObserve
	}
	return l, true
}

func (s *Server) saveLimits(w http.ResponseWriter, r *http.Request, limits []config.RateLimit) bool {
	if s.SetDashboardLimits == nil {
		problem(w, http.StatusServiceUnavailable, "unavailable", "Limits lassen sich hier nicht ändern.", nil)
		return false
	}
	if _, err := s.SetDashboardLimits(r.Context(), limits); err != nil {
		invalid(w, "Dieses Limit ist so nicht möglich: "+err.Error())
		return false
	}
	return true
}

func (s *Server) findLimit(id string) *behaviour.Limit {
	for _, l := range s.Behaviour.Limits() {
		if l.ID == id {
			return l
		}
	}
	return nil
}

func (s *Server) dashLimits() []config.RateLimit {
	if s.DashboardLimits == nil {
		return nil
	}
	return s.DashboardLimits()
}

func (s *Server) createRateLimit(w http.ResponseWriter, r *http.Request) {
	if !s.behaviourAvailable(w) {
		return
	}
	var in RateLimitInput
	if !decode(w, r, &in) {
		return
	}
	l, ok := s.limitFromInput(w, in, "rl-"+randHex(4))
	if !ok {
		return
	}
	if !s.saveLimits(w, r, append(s.dashLimits(), l)) {
		return
	}
	if cl := s.findLimit(l.ID); cl != nil {
		writeJSON(w, http.StatusCreated, s.limitView(cl))
		return
	}
	s.internal(w, errors.New("rate limit not applied"))
}

// ownLimit finds a dashboard limit; answers 404 or 409 otherwise.
func (s *Server) ownLimit(w http.ResponseWriter, id string) (int, bool) {
	for i, l := range s.dashLimits() {
		if l.ID == id {
			return i, true
		}
	}
	if s.findLimit(id) != nil {
		problem(w, http.StatusConflict, "config_limit", "Dieses Limit kommt aus einer Voreinstellung oder aus schild.yaml und lässt sich nur dort ändern.", nil)
		return 0, false
	}
	problem(w, http.StatusNotFound, "not_found", "Dieses Limit gibt es nicht.", nil)
	return 0, false
}

func (s *Server) updateRateLimit(w http.ResponseWriter, r *http.Request) {
	if !s.behaviourAvailable(w) {
		return
	}
	var in RateLimitInput
	if !decode(w, r, &in) {
		return
	}
	id := r.PathValue("limit_id")
	i, ok := s.ownLimit(w, id)
	if !ok {
		return
	}
	l, ok := s.limitFromInput(w, in, id)
	if !ok {
		return
	}
	ls := s.dashLimits()
	ls[i] = l
	if !s.saveLimits(w, r, ls) {
		return
	}
	writeJSON(w, 200, s.limitView(s.findLimit(id)))
}

func (s *Server) deleteRateLimit(w http.ResponseWriter, r *http.Request) {
	if !s.behaviourAvailable(w) {
		return
	}
	i, ok := s.ownLimit(w, r.PathValue("limit_id"))
	if !ok {
		return
	}
	ls := s.dashLimits()
	ls = append(ls[:i], ls[i+1:]...)
	if !s.saveLimits(w, r, ls) {
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// dryRunScan bounds the rows a Probelauf reads.
const dryRunScan = 200000

func (s *Server) dryRunRateLimit(w http.ResponseWriter, r *http.Request) {
	var d RateLimitDraft
	if !decode(w, r, &d) {
		return
	}
	if fe := checkDraft(d); len(fe) > 0 {
		invalid(w, "Dieses Limit ist so nicht möglich.", fe...)
		return
	}
	l, err := behaviour.CompileLimit(config.RateLimit{Route: d.Route, Methods: d.Methods, Limit: d.Limit, Per: d.Per, Burst: d.Burst, Site: d.Site})
	if err != nil {
		invalid(w, "Dieses Limit ist so nicht möglich: "+err.Error())
		return
	}
	prefix := d.Route
	if i := strings.IndexByte(prefix, '*'); i >= 0 {
		prefix = prefix[:i]
	}
	rows, err := s.St.RequestsSince(r.Context(), s.now().Add(-24*time.Hour), prefix, dryRunScan)
	if err != nil {
		s.internal(w, err)
		return
	}
	matching, over, clients := l.DryRun(func(yield func(time.Time, netip.Addr, string, string, string) bool) {
		for _, x := range rows {
			ip, err := netip.ParseAddr(x.IP)
			if err != nil {
				continue
			}
			if !yield(x.Time, ip, x.Method, x.Host, x.Path) {
				return
			}
		}
	})
	// Unremarkable requests are stored as a sample (gate: EventsPerSecond,
	// SampleRate), so the result is a lower bound.
	writeJSON(w, 200, RateLimitDryRun{WindowH: 24, Requests: matching, WouldLimit: over, Clients: clients, Sampled: true})
}

// ---------------------------------------------------------------- release

func (s *Server) releaseClient(w http.ResponseWriter, r *http.Request) {
	if !s.behaviourAvailable(w) {
		return
	}
	var req ReleaseRequest
	if !decode(w, r, &req) {
		return
	}
	ip, ok := parseIP(w, req.IP, "/ip")
	if !ok {
		return
	}
	if req.Allow == "" {
		req.Allow = "none"
	}
	if req.TTL == "" {
		req.TTL = "7d"
	}
	var fe []FieldError
	if req.Allow != "none" && req.Allow != "exception" && req.Allow != "permanent" {
		fe = append(fe, FieldError{Pointer: "/allow", Detail: "none, exception oder permanent"})
	}
	if req.TTL != "24h" && req.TTL != "7d" && req.TTL != "30d" {
		fe = append(fe, FieldError{Pointer: "/ttl", Detail: "24h, 7d oder 30d"})
	}
	if req.Scenario != "" && (&config.BehaviourScenarios{}).Get(req.Scenario) == nil {
		fe = append(fe, FieldError{Pointer: "/scenario", Detail: "unbekanntes Szenario"})
	}
	if req.LimitID != "" && s.findLimit(req.LimitID) == nil {
		fe = append(fe, FieldError{Pointer: "/limit_id", Detail: "unbekanntes Limit"})
	}
	if len(req.Label) > 64 {
		fe = append(fe, FieldError{Pointer: "/label", Detail: "höchstens 64 Zeichen"})
	}
	if len(fe) > 0 {
		invalid(w, "Diese Freigabe ist so nicht möglich.", fe...)
		return
	}
	ctx := r.Context()
	now := s.now()
	// On a node of a group a release ends every block the group holds of
	// this client, also one that does not run on this node: the incidents
	// the group holds and the incidents of the blocks that ended here are
	// the lifts, one step with the end of the blocks. A single gateway
	// notes none.
	res := ReleaseResult{IP: ip.String()}
	release := func(held []string) error {
		ended, incidents := s.Behaviour.ReleaseIncidents(ip)
		res.BlocksEnded = ended
		return s.St.NoteLifts(ctx, now, append(held, incidents...)...)
	}
	var err error
	if s.ClientBlocks != nil {
		err = s.ClientBlocks(ip, release)
	} else {
		err = release(nil)
	}
	if err != nil {
		s.internal(w, err)
		return
	}
	switch req.Allow {
	case "exception":
		srcs := []string{"behaviour", "ratelimit"}
		switch {
		case req.Scenario != "":
			srcs = []string{"behaviour:" + req.Scenario}
		case req.LimitID != "":
			srcs = []string{"ratelimit:" + req.LimitID}
		}
		days := map[string]time.Duration{"24h": 24 * time.Hour, "7d": 7 * 24 * time.Hour, "30d": 30 * 24 * time.Hour}[req.TTL]
		until := now.Add(days)
		if err := s.St.AddException(ctx, store.Exception{IP: ip.String(), Sources: srcs, Expires: until}); err != nil {
			s.internal(w, err)
			return
		}
		if s.Gate != nil {
			s.Gate.Exceptions.Add(ip, srcs, until)
		}
		res.ExceptionUntil, res.ExceptionSources = tsp(until), srcs
	case "permanent":
		label := req.Label
		if label == "" {
			label = "Freigabe Verhalten"
		}
		e, errs := allowlist.Validate(allowlist.Input{IP: ip.String(), Label: label, Level: allowlist.NoBlock, TTL: "never"}, now)
		if len(errs) > 0 {
			invalid(w, "Diese Adresse lässt sich nicht dauerhaft erlauben.")
			return
		}
		e.Source = "dashboard"
		if err := s.St.AddAllow(ctx, e); err != nil {
			s.internal(w, err)
			return
		}
		s.reloadAllow(ctx)
		res.AllowlistEntry = &e.ID
	}
	if s.Log != nil {
		s.Log.Info("client released in the dashboard", "ip", ip.String(), "blocks_ended", res.BlocksEnded, "allow", req.Allow)
	}
	writeJSON(w, 200, res)
}
