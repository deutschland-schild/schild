package crawlers

import "fmt"

// Wire types of crawler control (client dashboard tag websites, agent API
// tag crawlers). Field names and optionality follow the OpenAPI schemas of
// the same name.

// Actors of a change.
const (
	ActorDashboard = "dashboard"
	ActorAgent     = "agent"
)

// ActionInherit (agent writes only) drops the rule of a bot, so its
// category decides again.
const ActionInherit = "inherit"

// WirePolicy is OpenAPI CrawlerPolicy: every key present, maps never null.
type WirePolicy struct {
	Categories    map[string]string `json:"categories"`
	Bots          map[string]string `json:"bots"`
	Impersonators string            `json:"impersonators"`
}

// Wire returns the policy as answered.
func (p Policy) Wire() WirePolicy {
	n := p.Normalize()
	w := WirePolicy{Categories: map[string]string{}, Bots: map[string]string{}, Impersonators: Allow}
	for k, v := range n.Categories {
		w.Categories[k] = v
	}
	for k, v := range n.Bots {
		w.Bots[k] = v
	}
	if n.Impersonators != "" {
		w.Impersonators = n.Impersonators
	}
	return w
}

// CatalogueEntry is OpenAPI CrawlerCatalogueEntry: one crawler a policy can
// name.
type CatalogueEntry struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Operator string `json:"operator"`
	Category string `json:"category"`
	// Verifiable: the operator publishes address ranges, so an
	// impersonator of it can be told apart.
	Verifiable bool `json:"verifiable"`
}

// State is OpenAPI CrawlerPolicyState (getCrawlerPolicy, setCrawlerPolicy).
type State struct {
	Website          string           `json:"website"`
	Policy           WirePolicy       `json:"policy"`
	UpdatedAt        *string          `json:"updated_at"`
	Actor            *string          `json:"actor"`
	CatalogueVersion string           `json:"catalogue_version"`
	Crawlers         []CatalogueEntry `json:"crawlers"`
	Presets          []string         `json:"presets"`
}

// Input is OpenAPI CrawlerPolicyInput (setCrawlerPolicy): the whole policy,
// or a preset applied to the stored one.
type Input struct {
	Categories    map[string]string `json:"categories,omitempty"`
	Bots          map[string]string `json:"bots,omitempty"`
	Impersonators string            `json:"impersonators,omitempty"`
	Preset        string            `json:"preset,omitempty"`
}

// Next returns the policy an Input sets, given the stored one.
func (in Input) Next(cur Policy) (Policy, error) {
	p := Policy{Categories: in.Categories, Bots: in.Bots, Impersonators: in.Impersonators}
	if in.Preset == "" {
		return p, nil
	}
	if len(in.Categories) > 0 || len(in.Bots) > 0 {
		return cur, &FieldError{Field: "preset", Msg: "a preset replaces categories and bots; send it alone"}
	}
	if in.Impersonators != "" {
		cur.Impersonators = in.Impersonators
	}
	return ApplyPreset(cur, in.Preset)
}

// SetRequest is OpenAPI AgentCrawlerSet (setAgentCrawlers): exactly one of
// category (with action allow or block), bot (with action allow, block or
// inherit), impersonators or preset, plus a reason.
type SetRequest struct {
	Website       string `json:"website"`
	Category      string `json:"category,omitempty"`
	Bot           string `json:"bot,omitempty"`
	Action        string `json:"action,omitempty"`
	Impersonators string `json:"impersonators,omitempty"`
	Preset        string `json:"preset,omitempty"`
	Reason        string `json:"reason"`
}

// Apply returns the policy after the request; known reports catalogue bot
// ids. The error is a *FieldError.
func (r SetRequest) Apply(cur Policy, known func(string) bool) (Policy, error) {
	n := 0
	for _, s := range []string{r.Category, r.Bot, r.Impersonators, r.Preset} {
		if s != "" {
			n++
		}
	}
	if n != 1 {
		return cur, &FieldError{Field: "body", Msg: "name exactly one of category, bot, impersonators or preset"}
	}
	next := cur.Clone()
	switch {
	case r.Category != "":
		if !IsCategory(r.Category) {
			return cur, &FieldError{Field: "category", Key: r.Category, Msg: "unknown category"}
		}
		if !validAction(r.Action) {
			return cur, &FieldError{Field: "action", Msg: "allow or block"}
		}
		if next.Categories == nil {
			next.Categories = map[string]string{}
		}
		next.Categories[r.Category] = r.Action
	case r.Bot != "":
		// inherit drops a rule, also one for a bot a later catalogue no
		// longer knows; a new rule needs a bot the catalogue knows.
		if r.Action != ActionInherit && (known == nil || !known(r.Bot)) {
			return cur, &FieldError{Field: "bot", Key: r.Bot, Msg: "unknown bot"}
		}
		switch r.Action {
		case Allow, Block:
			if next.Bots == nil {
				next.Bots = map[string]string{}
			}
			next.Bots[r.Bot] = r.Action
		case ActionInherit:
			delete(next.Bots, r.Bot)
		default:
			return cur, &FieldError{Field: "action", Msg: "allow, block or inherit"}
		}
	case r.Impersonators != "":
		if r.Action != "" {
			return cur, &FieldError{Field: "action", Msg: "not with impersonators"}
		}
		if !validAction(r.Impersonators) {
			return cur, &FieldError{Field: "impersonators", Msg: "allow or block"}
		}
		next.Impersonators = r.Impersonators
	default:
		if r.Action != "" {
			return cur, &FieldError{Field: "action", Msg: "not with a preset"}
		}
		p, err := ApplyPreset(next, r.Preset)
		if err != nil {
			return cur, err
		}
		next = p
	}
	if err := next.Check(known); err != nil {
		return cur, err
	}
	return next.Normalize(), nil
}

// BotCount is OpenAPI AgentCrawlerCount: what one crawler did on a website
// since the gateway started.
type BotCount struct {
	Bot        string `json:"bot"`
	Name       string `json:"name"`
	Category   string `json:"category"`
	Rule       string `json:"rule"` // allow | block: what the policy says for a request that is no impersonator
	Blocked    int64  `json:"blocked"`
	WouldBlock int64  `json:"would_block"`
}

// AgentPolicy is OpenAPI AgentCrawlerPolicy: the policy of one website and
// the counts of the crawlers it names or that a rule hit.
type AgentPolicy struct {
	Website   string     `json:"website"`
	Policy    WirePolicy `json:"policy"`
	UpdatedAt *string    `json:"updated_at"`
	Actor     *string    `json:"actor"`
	Crawlers  []BotCount `json:"crawlers"`
}

// AgentList is OpenAPI AgentCrawlerList (getAgentCrawlers).
type AgentList struct {
	// Since: the counts start here (the gateway's start).
	Since string        `json:"since"`
	Items []AgentPolicy `json:"items"`
}

// String describes a request (logs).
func (r SetRequest) String() string {
	switch {
	case r.Category != "":
		return fmt.Sprintf("category %s %s", r.Category, r.Action)
	case r.Bot != "":
		return fmt.Sprintf("bot %s %s", r.Bot, r.Action)
	case r.Impersonators != "":
		return "impersonators " + r.Impersonators
	}
	return "preset " + r.Preset
}
