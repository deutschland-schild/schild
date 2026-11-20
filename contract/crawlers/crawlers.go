// Package crawlers is the v0.5 (D57, MVP-29) contract of crawler control:
// per website, which crawlers of the bot catalogue may fetch it. A policy
// names categories and single bots with allow or block, and whether
// requests that name a crawler from outside its published ranges
// (impersonators) are blocked. Absent keys allow, so an empty policy changes
// nothing. contracts/crawler-policy.schema.json is the shape;
// contracts/tools/crosscheck.py implements Decide independently and the
// crawler-policy vectors keep both in step.
//
// Only user agents that name a catalogue entry can be blocked: the feature
// covers crawlers that identify themselves. likely_automated and
// likely_browser are no crawlers and are never blocked here.
package crawlers

import (
	"fmt"
	"net/netip"
	"sort"
	"time"

	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/bots"
	"github.com/deutschland-schild/schild/contract/jsonx"
	"github.com/deutschland-schild/schild/contract/schema"
)

// SchemaName is the vector input schema (crawler-policy.schema.json).
const SchemaName = "crawler-policy"

// Actions of a rule.
const (
	Allow = "allow"
	Block = "block"
)

// Presets (one action in the dashboard and the agent API).
const (
	// PresetBlockAITraining blocks the category ai_training and allows every
	// other category.
	PresetBlockAITraining = "block_ai_training"
)

// PresetNames in the order of the schema enum.
var PresetNames = []string{PresetBlockAITraining}

// Rules: which part of a policy decided.
const (
	RuleNone         = "none"
	RuleBot          = "bot"
	RuleCategory     = "category"
	RuleImpersonator = "impersonator"
)

// Outcomes of the decision (contract/requests outcomes).
const (
	OutcomePassed     = "passed"
	OutcomeWouldBlock = "would_block"
	OutcomeBlocked    = "blocked_crawler"
)

// Why a would_block was passed (events.WouldBlockReasons).
const (
	ReasonGatewayObserve = "gateway_observe"
	ReasonAllowlist      = "allowlist"
)

// StatusBlocked is the answer of a blocked crawler request.
const StatusBlocked = 403

// The two values of the mode input (D89): observe is the dry run of the test
// profile, autoblock every other gateway.
const (
	ModeObserve   = "observe"
	ModeAutoblock = "autoblock"
)

// Limits.
const (
	// MaxBots: bot rules in one policy.
	MaxBots = 512
	// MaxInputBytes of one vector input (it carries a catalogue).
	MaxInputBytes = bots.MaxCatalogueBytes
)

// Policy is the crawler policy of one website (crawler-policy.schema.json
// $defs/policy).
type Policy struct {
	Categories    map[string]string `json:"categories,omitempty"`
	Bots          map[string]string `json:"bots,omitempty"`
	Impersonators string            `json:"impersonators,omitempty"`
}

// FieldError names the part of a policy that is wrong.
type FieldError struct {
	Field string // categories, bots, impersonators, preset
	Key   string // the category or bot id ("" for the field itself)
	Msg   string
}

func (e *FieldError) Error() string {
	if e.Key != "" {
		return e.Field + "." + e.Key + ": " + e.Msg
	}
	return e.Field + ": " + e.Msg
}

func validAction(a string) bool { return a == Allow || a == Block }

// IsCategory reports whether c is a catalogue category a policy may name.
func IsCategory(c string) bool {
	for _, x := range bots.Categories {
		if x == c {
			return true
		}
	}
	return false
}

// Check checks a policy against the catalogue ids known (known(id) reports
// whether a bot id exists). Every category must be a catalogue category,
// every bot a catalogue entry, every value allow or block.
func (p Policy) Check(known func(id string) bool) error {
	for _, c := range sortedKeys(p.Categories) {
		if !IsCategory(c) {
			return &FieldError{Field: "categories", Key: c, Msg: "unknown category"}
		}
		if !validAction(p.Categories[c]) {
			return &FieldError{Field: "categories", Key: c, Msg: "allow or block"}
		}
	}
	if len(p.Bots) > MaxBots {
		return &FieldError{Field: "bots", Msg: fmt.Sprintf("at most %d", MaxBots)}
	}
	for _, id := range sortedKeys(p.Bots) {
		if known == nil || !known(id) {
			return &FieldError{Field: "bots", Key: id, Msg: "unknown bot"}
		}
		if !validAction(p.Bots[id]) {
			return &FieldError{Field: "bots", Key: id, Msg: "allow or block"}
		}
	}
	if p.Impersonators != "" && !validAction(p.Impersonators) {
		return &FieldError{Field: "impersonators", Msg: "allow or block"}
	}
	return nil
}

// Blocks reports whether the policy blocks anything. A policy that blocks
// nothing behaves exactly like no policy.
func (p Policy) Blocks() bool {
	if p.Impersonators == Block {
		return true
	}
	for _, a := range p.Categories {
		if a == Block {
			return true
		}
	}
	for _, a := range p.Bots {
		if a == Block {
			return true
		}
	}
	return false
}

// Clone copies p.
func (p Policy) Clone() Policy {
	c := Policy{Impersonators: p.Impersonators}
	if p.Categories != nil {
		c.Categories = make(map[string]string, len(p.Categories))
		for k, v := range p.Categories {
			c.Categories[k] = v
		}
	}
	if p.Bots != nil {
		c.Bots = make(map[string]string, len(p.Bots))
		for k, v := range p.Bots {
			c.Bots[k] = v
		}
	}
	return c
}

// Normalize drops category rules that allow (allow is the default) and
// empty maps, so equal policies have equal JSON. Bot rules that allow stay:
// they override a blocked category.
func (p Policy) Normalize() Policy {
	c := p.Clone()
	for k, v := range c.Categories {
		if v == Allow {
			delete(c.Categories, k)
		}
	}
	if len(c.Categories) == 0 {
		c.Categories = nil
	}
	if len(c.Bots) == 0 {
		c.Bots = nil
	}
	if c.Impersonators == Allow {
		c.Impersonators = ""
	}
	return c
}

// Preset returns the categories of a preset.
func Preset(name string) (map[string]string, bool) {
	switch name {
	case PresetBlockAITraining:
		return map[string]string{"ai_training": Block}, true
	}
	return nil, false
}

// ApplyPreset returns cur with a preset applied: the preset's categories
// replace the categories, the bot rules are dropped, impersonators stays.
func ApplyPreset(cur Policy, name string) (Policy, error) {
	cats, ok := Preset(name)
	if !ok {
		return cur, &FieldError{Field: "preset", Key: name, Msg: "unknown preset"}
	}
	return Policy{Categories: cats, Impersonators: cur.Impersonators}, nil
}

// RuleFor returns which rule of p blocks a request that named bot id of
// category cat with verification state ver, or RuleNone. Order: an
// impersonator (verification mismatch) with impersonators block; a rule
// for the bot (allow or block, it overrides the category); the rule of the
// category. A request that names no catalogue entry (id "") is never
// blocked.
func RuleFor(p Policy, id, cat, ver string) string {
	if id == "" {
		return RuleNone
	}
	if p.Impersonators == Block && ver == bots.Mismatch {
		return RuleImpersonator
	}
	if a, ok := p.Bots[id]; ok {
		if a == Block {
			return RuleBot
		}
		return RuleNone
	}
	if p.Categories[cat] == Block {
		return RuleCategory
	}
	return RuleNone
}

// Result of the decision for one request.
type Result struct {
	Bot          *string `json:"bot"`
	Category     string  `json:"category"`
	Verification *string `json:"verification"`
	Rule         string  `json:"rule"`
	Outcome      string  `json:"outcome"`
	// Reason of a would_block (gateway_observe, allowlist), else "".
	Reason string `json:"reason"`
	// Status is 403 for blocked_crawler, else 0 (the request goes on).
	Status int `json:"status"`
}

// Apply turns a rule into the outcome: no rule passes; with a rule, the
// gateway in observe and an allowlisted client record would_block (observe
// wins), else the request is blocked with 403.
func Apply(rule, mode string, allowlisted bool) (outcome, reason string, status int) {
	switch {
	case rule == RuleNone:
		return OutcomePassed, "", 0
	case mode == ModeObserve:
		return OutcomeWouldBlock, ReasonGatewayObserve, 0
	case allowlisted:
		return OutcomeWouldBlock, ReasonAllowlist, 0
	}
	return OutcomeBlocked, "", StatusBlocked
}

// Decide classifies a request (contract/bots) and applies the policy.
func Decide(p Policy, c *bots.Catalogue, ua string, a netip.Addr, mode string, allowlisted bool, now time.Time) Result {
	cl := c.Classify(ua, a, "", bots.DefaultOptions, now)
	r := Result{Bot: cl.Bot, Category: cl.Category, Verification: cl.Verification, Rule: RuleNone}
	id, ver := "", ""
	if cl.Bot != nil {
		id = *cl.Bot
	}
	if cl.Verification != nil {
		ver = *cl.Verification
	}
	r.Rule = RuleFor(p, id, cl.Category, ver)
	r.Outcome, r.Reason, r.Status = Apply(r.Rule, mode, allowlisted)
	return r
}

// RunVector runs one crawler-policy input at now: schema, catalogue,
// policy check against the catalogue, preset, Decide.
func RunVector(raw []byte, now time.Time) (Result, error) {
	if len(raw) > MaxInputBytes {
		return Result{}, contract.Errf(contract.CodeOversize, "%d bytes > %d", len(raw), MaxInputBytes)
	}
	v, err := jsonx.ParseObject(raw)
	if err != nil {
		return Result{}, contract.Errf(contract.CodeMalformed, "%v", err)
	}
	if err := schema.Validate(SchemaName, v); err != nil {
		return Result{}, err
	}
	cv, err := jsonx.Marshal(v["catalogue"])
	if err != nil {
		return Result{}, contract.Errf(contract.CodeSchema, "catalogue: %v", err)
	}
	cat, err := bots.Parse(cv)
	if err != nil {
		return Result{}, err
	}
	var in struct {
		Catalogue any    `json:"catalogue"`
		Policy    Policy `json:"policy"`
		Preset    string `json:"preset"`
		Request   struct {
			UserAgent string `json:"user_agent"`
			IP        string `json:"ip"`
		} `json:"request"`
		Mode        string `json:"mode"`
		Allowlisted bool   `json:"allowlisted"`
	}
	if err := jsonx.Decode(v, &in); err != nil {
		return Result{}, contract.Errf(contract.CodeSchema, "%v", err)
	}
	ids := map[string]bool{}
	for _, b := range cat.Bots {
		ids[b.ID] = true
	}
	if err := in.Policy.Check(func(id string) bool { return ids[id] }); err != nil {
		return Result{}, contract.Errf(contract.CodeSchema, "%v", err)
	}
	p := in.Policy
	if in.Preset != "" {
		if p, err = ApplyPreset(p, in.Preset); err != nil {
			return Result{}, contract.Errf(contract.CodeSchema, "%v", err)
		}
	}
	a, err := netip.ParseAddr(in.Request.IP)
	if err != nil || a.Zone() != "" {
		return Result{}, contract.Errf(contract.CodeSchema, "request.ip: not an address")
	}
	return Decide(p, cat, in.Request.UserAgent, a, in.Mode, in.Allowlisted, now), nil
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
