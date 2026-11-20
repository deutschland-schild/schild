// Command gen builds the bot catalogue shipped in the schild binary
// (internal/bots/catalogue.json, schema schild.bot_catalogue/0.1) at build
// time: the entries of ai.robots.txt (robots.json, MIT) mapped to the
// catalogue categories, schild's own entries (entries.go), and snapshots of
// the address ranges the operators publish (internal/bots/rangesrc Sources).
// The result is checked with contract/bots.Parse before it is written.
//
//	make bot-snapshot            (from the repository root)
//	go run ./internal/bots/gen   (from gateway)
//
// A range source that cannot be fetched keeps its previous snapshot from
// the existing catalogue (-keep-old, default) or, without one, its bots are
// written without ranges (claimed); every failure is printed.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/deutschland-schild/schild/contract/bots"
	"github.com/deutschland-schild/schild/contract/msg"
	"github.com/deutschland-schild/schild/gateway/internal/bots/rangesrc"
)

const (
	robotsJSONURL = "https://raw.githubusercontent.com/ai-robots-txt/ai.robots.txt/main/robots.json"
	aiRobotsRepo  = "https://github.com/ai-robots-txt/ai.robots.txt"
	ownRepo       = "https://github.com/deutschland-schild/schild"
	userAgent     = "schild-bot-snapshot/0.1 (+" + ownRepo + ")"
	sourceAI      = "ai-robots-txt"
	sourceOwn     = "schild"
)

func main() {
	out := flag.String("out", "internal/bots/catalogue.json", "catalogue file to write")
	robots := flag.String("robots-json", robotsJSONURL, "ai.robots.txt robots.json (URL or file)")
	keepOld := flag.Bool("keep-old", true, "keep the previous snapshot of a range source that cannot be fetched")
	flag.Parse()
	if err := run(*out, *robots, *keepOld); err != nil {
		fmt.Fprintln(os.Stderr, "gen:", err)
		os.Exit(1)
	}
}

func run(out, robotsSrc string, keepOld bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	now := time.Now().UTC().Truncate(time.Second)
	client := rangesrc.HTTPClient(60 * time.Second)

	var prev *bots.Catalogue
	if raw, err := os.ReadFile(out); err == nil {
		if prev, err = bots.Parse(raw); err != nil {
			fmt.Fprintf(os.Stderr, "gen: previous catalogue %s does not parse (%v); not reused\n", out, err)
			prev = nil
		}
	}

	rawRobots, err := readSource(ctx, client, robotsSrc)
	if err != nil {
		return fmt.Errorf("ai.robots.txt: %w", err)
	}

	c := &bots.Catalogue{
		Schema:           bots.SchemaVersion,
		Version:          nextVersion(prev, now),
		GeneratedAt:      msg.FormatTime(now),
		Sources:          []bots.Source{{ID: sourceAI, License: "MIT", URL: aiRobotsRepo}, {ID: sourceOwn, License: "MIT", URL: ownRepo}},
		AutomationTokens: automationTokens,
	}

	// Range snapshots.
	have := map[string]bool{}
	var failed []string
	for _, src := range rangesrc.Sources {
		prefixes, err := rangesrc.FetchSource(ctx, client, src, userAgent)
		fetched := msg.FormatTime(now)
		if err != nil {
			failed = append(failed, fmt.Sprintf("%s: %v", src.ID, err))
			old := prevRange(prev, src.ID)
			if !keepOld || old == nil {
				continue
			}
			prefixes, fetched = old.Prefixes, old.FetchedAt
			fmt.Fprintf(os.Stderr, "gen: %s: kept the snapshot of %s\n", src.ID, fetched)
		}
		c.Ranges = append(c.Ranges, bots.RangeSet{ID: src.ID, Operator: src.Operator, URL: src.URLs[0], FetchedAt: fetched, Prefixes: prefixes})
		have[src.ID] = true
	}

	tokens := map[string]string{}
	for _, t := range automationTokens {
		tokens[strings.ToLower(t)] = "automation_tokens"
	}
	ids := map[string]bool{}
	add := func(b bots.Bot) {
		if b.Verify.Ranges != "" && !have[b.Verify.Ranges] {
			fmt.Fprintf(os.Stderr, "gen: %s: no range snapshot %s, written as claimed\n", b.ID, b.Verify.Ranges)
			b.Verify.Ranges = ""
		}
		var keep []string
		for _, t := range b.UAMatch {
			k := strings.ToLower(t)
			if tokens[k] != "" {
				fmt.Fprintf(os.Stderr, "gen: %s: token %q already used by %s, dropped\n", b.ID, t, tokens[k])
				continue
			}
			tokens[k] = b.ID
			keep = append(keep, t)
		}
		if len(keep) == 0 {
			return
		}
		b.UAMatch = keep
		for ids[b.ID] {
			b.ID += "-x"
		}
		ids[b.ID] = true
		c.Bots = append(c.Bots, b)
	}

	for _, o := range ownBots {
		add(bots.Bot{ID: o.id, Name: o.name, Operator: o.operator, Category: o.category, RobotsToken: o.robots, UAMatch: o.ua,
			Verify: bots.Verify{Ranges: o.ranges, RDNSSuffixes: o.rdns}, Source: sourceOwn, URL: o.url})
	}
	ai, err := aiEntries(rawRobots, tokens)
	if err != nil {
		return err
	}
	for _, b := range ai {
		add(b)
	}

	raw, err := marshal(c)
	if err != nil {
		return err
	}
	if _, err := bots.Parse(raw); err != nil {
		return fmt.Errorf("generated catalogue does not pass contract/bots.Parse: %w", err)
	}
	if err := os.WriteFile(out, raw, 0o644); err != nil {
		return err
	}
	fmt.Printf("gen: wrote %s: version %s, %d bots, %d range sets\n", out, c.Version, len(c.Bots), len(c.Ranges))
	for _, r := range c.Ranges {
		fmt.Printf("gen:   %-16s %5d prefixes, fetched %s\n", r.ID, len(r.Prefixes), r.FetchedAt)
	}
	for _, f := range failed {
		fmt.Printf("gen: FAILED %s\n", f)
	}
	return nil
}

func readSource(ctx context.Context, c *http.Client, src string) ([]byte, error) {
	if !strings.HasPrefix(src, "https://") {
		return os.ReadFile(src)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, src, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, bots.MaxCatalogueBytes))
}

func prevRange(prev *bots.Catalogue, id string) *bots.RangeSet {
	if prev == nil {
		return nil
	}
	for i := range prev.Ranges {
		if prev.Ranges[i].ID == id {
			return &prev.Ranges[i]
		}
	}
	return nil
}

// nextVersion: date of today and a counter that grows within one day.
func nextVersion(prev *bots.Catalogue, now time.Time) string {
	day := now.Format("2006-01-02")
	n := 1
	if prev != nil && strings.HasPrefix(prev.Version, day+".") {
		fmt.Sscanf(strings.TrimPrefix(prev.Version, day+"."), "%d", &n)
		n++
	}
	return fmt.Sprintf("%s.%d", day, n)
}

func marshal(c *bots.Catalogue) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", " ")
	if err := enc.Encode(c); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// ---------------------------------------------------------------- ai.robots.txt

type aiEntry struct {
	Operator    string `json:"operator"`
	Respect     string `json:"respect"`
	Function    string `json:"function"`
	Frequency   string `json:"frequency"`
	Description string `json:"description"`
}

var (
	robotsTokenRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
	tokenRe       = regexp.MustCompile(`^[!-~]([ -~]*[!-~])?$`)
	mdLinkRe      = regexp.MustCompile(`^\[([^\]]{1,64})\]\((https://[!-~]{1,248})\)`)
	idCleanRe     = regexp.MustCompile(`[^a-z0-9]+`)
	searchWordRe  = regexp.MustCompile(`\bsearch`)
)

// aiEntries maps robots.json (an object, keys in file order) to catalogue
// entries. Names already used as a token (own entries come first) are
// skipped; a name that is another name plus a version ("iaskspider/2.0",
// "Brightbot 1.0") is skipped too, the shorter name matches it.
func aiEntries(raw []byte, used map[string]string) ([]bots.Bot, error) {
	keys, err := objectKeys(raw)
	if err != nil {
		return nil, fmt.Errorf("robots.json: %w", err)
	}
	var m map[string]aiEntry
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("robots.json: %w", err)
	}
	lower := map[string]bool{}
	for _, k := range keys {
		lower[strings.ToLower(k)] = true
	}
	var out []bots.Bot
	seen := map[string]bool{}
	for _, k := range keys {
		e := m[k]
		lk := strings.ToLower(k)
		o := overrides[k]
		switch {
		case o.skip:
			fmt.Fprintf(os.Stderr, "gen: ai.robots.txt %q skipped (too generic as a User-Agent substring)\n", k)
			continue
		case seen[lk] || used[lk] != "":
			continue
		case !tokenRe.MatchString(k) || len(k) < 2 || len(k) > 64:
			fmt.Fprintf(os.Stderr, "gen: ai.robots.txt %q skipped (not a token)\n", k)
			continue
		case versionOf(lk, lower):
			continue
		}
		seen[lk] = true
		b := bots.Bot{ID: idOf(k), Name: k, Category: o.category, Source: sourceAI, UAMatch: []string{k},
			Verify: bots.Verify{Ranges: o.ranges, RDNSSuffixes: o.rdns}}
		if b.Category == "" {
			b.Category = categoryOf(e.Function)
		}
		b.Operator, b.URL = operatorOf(e.Operator)
		if o.operator != "" {
			b.Operator = o.operator
		}
		if robotsTokenRe.MatchString(k) {
			b.RobotsToken = k
		}
		out = append(out, b)
	}
	return out, nil
}

// versionOf: lk is "<other name>/<version>" or "<other name> <version>".
func versionOf(lk string, names map[string]bool) bool {
	for i := 1; i < len(lk); i++ {
		if (lk[i] == '/' || lk[i] == ' ') && names[lk[:i]] && i+1 < len(lk) && lk[i+1] >= '0' && lk[i+1] <= '9' {
			return true
		}
	}
	return false
}

func idOf(k string) string {
	id := strings.Trim(idCleanRe.ReplaceAllString(strings.ToLower(k), "-"), "-")
	if len(id) > 48 {
		id = strings.TrimRight(id[:48], "-")
	}
	if len(id) < 2 {
		id = "bot-" + id
	}
	return id
}

// categoryOf maps the ai.robots.txt function text to a catalogue category.
func categoryOf(fn string) string {
	f := strings.ToLower(strings.TrimSpace(fn))
	switch f {
	case "ai assistants", "ai agents", "ai coding agents", "undocumented ai agents", "ai learning companion":
		return "ai_assistant"
	case "ai search crawlers":
		return "ai_search"
	case "ai data scrapers", "ai data scraper", "ai data providers":
		return "ai_training"
	}
	switch {
	case searchWordRe.MatchString(f): // "search", not "research"
		return "ai_search"
	case strings.Contains(f, "user-initiated"), strings.Contains(f, "user prompts"), strings.Contains(f, "on behalf"),
		strings.Contains(f, "assistant"):
		return "ai_assistant"
	}
	return "ai_training"
}

// operatorOf: "[Name](https://...)" gives name and URL; free text is cut
// at the first clause; unknown operators are "Unknown".
func operatorOf(s string) (string, string) {
	s = strings.TrimSpace(s)
	if m := mdLinkRe.FindStringSubmatch(s); m != nil {
		return clean(m[1]), m[2]
	}
	l := strings.ToLower(s)
	if s == "" || strings.HasPrefix(l, "unclear") || strings.HasPrefix(l, "unknown") || strings.HasPrefix(l, "http") ||
		strings.HasPrefix(l, "anyone") {
		return "Unknown", ""
	}
	for _, sep := range []string{" that ", ", ", " (", ". ", " to ", " used "} {
		if i := strings.Index(s, sep); i > 0 {
			s = s[:i]
		}
	}
	s = strings.TrimSuffix(strings.TrimPrefix(s, "the "), ".")
	if len(s) > 40 {
		return "Unknown", ""
	}
	return clean(s), ""
}

func clean(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if s == "" {
		return "Unknown"
	}
	return s
}

// objectKeys returns the keys of a JSON object in file order.
func objectKeys(raw []byte) ([]string, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	t, err := dec.Token()
	if err != nil || t != json.Delim('{') {
		return nil, fmt.Errorf("not an object")
	}
	var keys []string
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return nil, err
		}
		k, _ := t.(string)
		keys = append(keys, k)
		var skip json.RawMessage
		if err := dec.Decode(&skip); err != nil {
			return nil, err
		}
	}
	return keys, nil
}
