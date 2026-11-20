// Package bots is the v0.5 (MVP-22, D35) contract of the bot catalogue
// (contracts/bot-catalogue.schema.json): loading and checking a catalogue,
// matching a User-Agent to a bot and verifying the client address against
// the operator's published ranges (and, when switched on, a forward-confirmed
// reverse name). Everything works offline. contracts/tools/crosscheck.py
// implements the same rules independently; the bot-catalogue and bot-match
// vectors keep both in step. MVP-12 reuses the same verification.
package bots

import (
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/jsonx"
	"github.com/deutschland-schild/schild/contract/msg"
	"github.com/deutschland-schild/schild/contract/schema"
)

// Schema names (contracts/*.schema.json).
const (
	SchemaCatalogue = "bot-catalogue"
	SchemaMatch     = "bot-match"
	// SchemaVersion is the value of the catalogue's "schema" field.
	SchemaVersion = "schild.bot_catalogue/0.1"
)

// Limits.
const (
	// MaxCatalogueBytes of a catalogue (and of a bot-match input).
	MaxCatalogueBytes = 4 << 20
	// MaxUABytes: only this prefix of a User-Agent is matched.
	MaxUABytes = 512
	// StaleAfter: a range set fetched longer ago is unknown_stale.
	StaleAfter = 30 * 24 * time.Hour
)

// Categories of catalogue entries (bot-catalogue.schema.json $defs/category).
var Categories = []string{"search_engine", "ai_training", "ai_search", "ai_assistant", "preview_social", "feed_reader",
	"monitoring", "seo_tool", "archive_research", "security_scanner", "tool_library"}

// Categories of user agents no entry matches (BotCategory in the client
// dashboard API).
const (
	LikelyAutomated = "likely_automated"
	LikelyBrowser   = "likely_browser"
)

// Verification states of a matched bot.
const (
	Verified     = "verified"      // address in a fresh published range, or FCrDNS match
	Claimed      = "claimed"       // the operator publishes nothing, or the check is off
	Mismatch     = "mismatch"      // ranges published (fresh), address not in them: "gibt sich als ... aus"
	UnknownStale = "unknown_stale" // the range snapshot is older than StaleAfter
)

// Verifications in the order of the OpenAPI enum BotVerification.
var Verifications = []string{Verified, Claimed, Mismatch, UnknownStale}

// Source is an attribution entry.
type Source struct {
	ID      string `json:"id"`
	License string `json:"license"`
	URL     string `json:"url"`
}

// Verify says how an address of a bot is checked.
type Verify struct {
	Ranges       string   `json:"ranges,omitempty"`
	RDNSSuffixes []string `json:"rdns_suffixes,omitempty"`
}

// Bot is one catalogue entry.
type Bot struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Operator    string   `json:"operator"`
	Category    string   `json:"category"`
	RobotsToken string   `json:"robots_token,omitempty"`
	UAMatch     []string `json:"ua_match"`
	Verify      Verify   `json:"verify"`
	Source      string   `json:"source,omitempty"`
	URL         string   `json:"url,omitempty"`
}

// RangeSet is a snapshot of an operator's published address ranges.
type RangeSet struct {
	ID        string   `json:"id"`
	Operator  string   `json:"operator"`
	URL       string   `json:"url"`
	FetchedAt string   `json:"fetched_at"`
	Prefixes  []string `json:"prefixes"`

	fetched  time.Time
	prefixes []netip.Prefix
}

// Catalogue is a checked bot catalogue.
type Catalogue struct {
	Schema           string     `json:"schema"`
	Version          string     `json:"version"`
	GeneratedAt      string     `json:"generated_at"`
	Sources          []Source   `json:"sources"`
	AutomationTokens []string   `json:"automation_tokens"`
	Bots             []Bot      `json:"bots"`
	Ranges           []RangeSet `json:"ranges"`

	ranges map[string]*RangeSet
}

// Parse checks size, strict JSON, schema and the semantic rules of a
// catalogue file. Errors are *contract.Error (oversize, malformed, schema).
func Parse(raw []byte) (*Catalogue, error) {
	if len(raw) > MaxCatalogueBytes {
		return nil, contract.Errf(contract.CodeOversize, "%d bytes > %d", len(raw), MaxCatalogueBytes)
	}
	v, err := jsonx.ParseObject(raw)
	if err != nil {
		return nil, contract.Errf(contract.CodeMalformed, "%v", err)
	}
	if err := schema.Validate(SchemaCatalogue, v); err != nil {
		return nil, err
	}
	return fromValue(v)
}

// fromValue decodes a schema-valid catalogue value and runs the semantic
// checks.
func fromValue(v any) (*Catalogue, error) {
	var c Catalogue
	if err := jsonx.Decode(v, &c); err != nil {
		return nil, contract.Errf(contract.CodeSchema, "catalogue: %v", err)
	}
	return &c, c.check()
}

func schemaErr(format string, args ...any) error {
	return contract.Errf(contract.CodeSchema, format, args...)
}

// asciiLower lower-cases ASCII letters only (the same in every language).
func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}

// parsePrefix accepts a canonical prefix: no host bits, no IPv4-mapped
// IPv6 address.
func parsePrefix(s string) (netip.Prefix, bool) {
	p, err := netip.ParsePrefix(s)
	if err != nil || p.Addr().Zone() != "" || p.Addr().Is4In6() || p.Masked() != p {
		return netip.Prefix{}, false
	}
	return p, true
}

func (c *Catalogue) check() error {
	sources := map[string]bool{}
	for _, s := range c.Sources {
		if sources[s.ID] {
			return schemaErr("duplicate source %s", s.ID)
		}
		sources[s.ID] = true
	}
	c.ranges = map[string]*RangeSet{}
	for i := range c.Ranges {
		r := &c.Ranges[i]
		if c.ranges[r.ID] != nil {
			return schemaErr("duplicate range set %s", r.ID)
		}
		t, err := msg.ParseTime(r.FetchedAt)
		if err != nil {
			return schemaErr("range set %s: fetched_at: %v", r.ID, err)
		}
		r.fetched = t
		r.prefixes = r.prefixes[:0]
		for _, s := range r.Prefixes {
			p, ok := parsePrefix(s)
			if !ok {
				return schemaErr("range set %s: prefix %q is not canonical", r.ID, s)
			}
			r.prefixes = append(r.prefixes, p)
		}
		c.ranges[r.ID] = r
	}
	tokens := map[string]string{}
	for _, t := range c.AutomationTokens {
		k := asciiLower(t)
		if tokens[k] != "" {
			return schemaErr("duplicate automation token %q", t)
		}
		tokens[k] = "automation_tokens"
	}
	ids := map[string]bool{}
	for _, b := range c.Bots {
		if ids[b.ID] {
			return schemaErr("duplicate bot %s", b.ID)
		}
		ids[b.ID] = true
		if b.Verify.Ranges != "" && c.ranges[b.Verify.Ranges] == nil {
			return schemaErr("bot %s: unknown range set %s", b.ID, b.Verify.Ranges)
		}
		if b.Source != "" && !sources[b.Source] {
			return schemaErr("bot %s: unknown source %s", b.ID, b.Source)
		}
		for _, t := range b.UAMatch {
			k := asciiLower(t)
			if tokens[k] != "" {
				return schemaErr("bot %s: ua_match %q already used by %s", b.ID, t, tokens[k])
			}
			tokens[k] = b.ID
		}
	}
	return nil
}

// Options are the bots.verify switches of schild.yaml.
type Options struct {
	Ranges bool // default true
	FCrDNS bool // default false: sends client addresses to the resolver
}

// DefaultOptions of schild.yaml.
var DefaultOptions = Options{Ranges: true}

// Result of the classification of one request. Bot and Verification are
// nil when no catalogue entry matched.
type Result struct {
	Bot          *string `json:"bot"`
	Category     string  `json:"category"`
	Verification *string `json:"verification"`
}

// Match returns the catalogue entry a User-Agent names (nil for none) and
// the category: the entry's, or likely_automated / likely_browser.
func (c *Catalogue) Match(ua string) (*Bot, string) {
	if len(ua) > MaxUABytes {
		ua = ua[:MaxUABytes]
	}
	l := asciiLower(ua)
	var best *Bot
	bestLen := 0
	for i := range c.Bots {
		b := &c.Bots[i]
		for _, t := range b.UAMatch {
			if len(t) > bestLen && strings.Contains(l, asciiLower(t)) {
				best, bestLen = b, len(t)
			}
		}
	}
	if best != nil {
		return best, best.Category
	}
	if l == "" || !strings.HasPrefix(l, "mozilla/") {
		return nil, LikelyAutomated
	}
	for _, t := range c.AutomationTokens {
		if strings.Contains(l, asciiLower(t)) {
			return nil, LikelyAutomated
		}
	}
	return nil, LikelyBrowser
}

// VerifyAddr checks the client address of a request that claims bot b.
// fcrdnsName is the forward-confirmed reverse name ("" when none); it is
// used only with opt.FCrDNS.
func (c *Catalogue) VerifyAddr(b *Bot, a netip.Addr, fcrdnsName string, opt Options, now time.Time) string {
	a = a.Unmap()
	fc := "" // match | nomatch
	if opt.FCrDNS && len(b.Verify.RDNSSuffixes) > 0 && fcrdnsName != "" {
		n := strings.TrimSuffix(asciiLower(fcrdnsName), ".")
		fc = "nomatch"
		for _, s := range b.Verify.RDNSSuffixes {
			if n == s || strings.HasSuffix(n, "."+s) {
				fc = "match"
				break
			}
		}
	}
	rg := "" // in | out | stale
	if r := c.ranges[b.Verify.Ranges]; opt.Ranges && r != nil {
		switch {
		case now.Sub(r.fetched) > StaleAfter:
			rg = "stale"
		case r.contains(a):
			rg = "in"
		default:
			rg = "out"
		}
	}
	switch {
	case fc == "match" || rg == "in":
		return Verified
	case fc == "nomatch" || rg == "out":
		return Mismatch
	case rg == "stale":
		return UnknownStale
	}
	return Claimed
}

func (r *RangeSet) contains(a netip.Addr) bool {
	for _, p := range r.prefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// Classify matches and, for a matched bot, verifies one request.
func (c *Catalogue) Classify(ua string, a netip.Addr, fcrdnsName string, opt Options, now time.Time) Result {
	b, cat := c.Match(ua)
	if b == nil {
		return Result{Category: cat}
	}
	id, v := b.ID, c.VerifyAddr(b, a, fcrdnsName, opt, now)
	return Result{Bot: &id, Category: cat, Verification: &v}
}

// RunVector runs one bot-match input (bot-match.schema.json) at now.
func RunVector(raw []byte, now time.Time) (Result, error) {
	if len(raw) > MaxCatalogueBytes {
		return Result{}, contract.Errf(contract.CodeOversize, "%d bytes > %d", len(raw), MaxCatalogueBytes)
	}
	v, err := jsonx.ParseObject(raw)
	if err != nil {
		return Result{}, contract.Errf(contract.CodeMalformed, "%v", err)
	}
	if err := schema.Validate(SchemaMatch, v); err != nil {
		return Result{}, err
	}
	c, err := fromValue(v["catalogue"])
	if err != nil {
		return Result{}, err
	}
	req := v["request"].(map[string]any)
	a, err := netip.ParseAddr(req["ip"].(string))
	if err != nil || a.Zone() != "" {
		return Result{}, schemaErr("request.ip: not an address")
	}
	name, _ := req["fcrdns_name"].(string)
	opt := DefaultOptions
	if o, ok := v["options"].(map[string]any); ok {
		if x, ok := o["ranges"].(bool); ok {
			opt.Ranges = x
		}
		if x, ok := o["fcrdns"].(bool); ok {
			opt.FCrDNS = x
		}
	}
	return c.Classify(req["user_agent"].(string), a, name, opt, now), nil
}

// String describes a result (tests).
func (r Result) String() string {
	s := func(p *string) string {
		if p == nil {
			return "-"
		}
		return *p
	}
	return fmt.Sprintf("%s/%s/%s", s(r.Bot), r.Category, s(r.Verification))
}
