//go:build !release

package dashboard_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	cc "github.com/deutschland-schild/schild/contract/crawlers"
	"github.com/deutschland-schild/schild/contract/events"
	"github.com/deutschland-schild/schild/gateway/internal/app"
	"github.com/deutschland-schild/schild/gateway/internal/apptest"
	"github.com/deutschland-schild/schild/gateway/internal/crawlers"
	"github.com/deutschland-schild/schild/gateway/internal/store"
)

// crawlerVisit sends GET / to shop.example with a user agent from ip.
func crawlerVisit(t *testing.T, h *apptest.Harness, ua, ip string) int {
	t.Helper()
	req, _ := http.NewRequest("GET", h.Proxy.URL+"/", nil)
	req.Host = "shop.example"
	req.Header.Set("X-Forwarded-For", ip)
	req.Header.Set("User-Agent", ua)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.StatusCode
}

const (
	uaClaudeBot = "Mozilla/5.0 (compatible; ClaudeBot/1.0; +claudebot@anthropic.com)"
	uaGooglebot = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
)

// Measurement 1, finding 1: a catalogue update drops a bot that has a
// stored rule. The gateway drops the rule when it loads the policy, so the
// policy can be changed again: a dashboard round trip and inherit for the
// dropped id succeed; a new rule for an unknown id stays refused.
func TestCrawlerStaleBotID(t *testing.T) {
	h := apptest.New(t, apptest.Options{})
	h.Login()
	id := websiteID(t, h)
	raw := fmt.Sprintf(`{"entries":{%q:{"policy":{"bots":{"claudebot":"block","dropped-bot":"block"}},"updated_at":"2026-11-02T10:00:00Z","actor":"dashboard"}}}`, id)
	if err := h.App.Store.Put(context.Background(), crawlers.StoreKey, []byte(raw)); err != nil {
		t.Fatal(err)
	}
	dir := h.Dir
	if err := h.Stop(); err != nil {
		t.Fatal(err)
	}
	h2 := apptest.New(t, apptest.Options{Dir: dir})
	h2.Login()
	path := "/websites/" + id + "/crawlers"
	if c := crawlerVisit(t, h2, uaClaudeBot, "198.51.100.61"); c != 403 {
		t.Fatalf("the rest of the policy holds: %d", c)
	}
	code, body := h2.API("GET", path, nil)
	var st cc.State
	if code != 200 || json.Unmarshal(body, &st) != nil || st.Policy.Bots["claudebot"] != cc.Block {
		t.Fatalf("get: %d %s", code, body)
	}
	if _, ok := st.Policy.Bots["dropped-bot"]; ok {
		t.Fatalf("the dropped id is still answered: %s", body)
	}
	// The dashboard sends the policy it got back, with one change.
	st.Policy.Categories["seo_tool"] = cc.Block
	if code, body := h2.API("PUT", path, st.Policy); code != 200 {
		t.Fatalf("dashboard round trip: %d %s", code, body)
	}
	// inherit for the dropped id, as the agent API runs it.
	req := cc.SetRequest{Website: id, Bot: "dropped-bot", Action: cc.ActionInherit, Reason: "the catalogue dropped it"}
	if _, err := h2.App.SetCrawlers(context.Background(), id, func(cur cc.Policy) (cc.Policy, error) { return req.Apply(cur, h2.App.Crawlers.Known) },
		app.CrawlerChange{Actor: cc.ActorAgent, TokenID: "tok_000000000003", TokenLabel: "agent", Reason: req.Reason}); err != nil {
		t.Fatalf("inherit for the dropped id: %v", err)
	}
	// New rules for unknown ids stay refused.
	if code, body := h2.API("PUT", path, map[string]any{"bots": map[string]string{"dropped-bot": "block"}}); code != 400 {
		t.Fatalf("new unknown id: %d %s", code, body)
	}
	req = cc.SetRequest{Website: id, Bot: "dropped-bot", Action: cc.Block, Reason: "x"}
	if _, err := h2.App.SetCrawlers(context.Background(), id, func(cur cc.Policy) (cc.Policy, error) { return req.Apply(cur, h2.App.Crawlers.Known) },
		app.CrawlerChange{Actor: cc.ActorAgent, TokenID: "tok_000000000003", TokenLabel: "agent", Reason: req.Reason}); err == nil {
		t.Fatal("block for an unknown id accepted")
	}
	if c := crawlerVisit(t, h2, uaClaudeBot, "198.51.100.62"); c != 403 {
		t.Fatalf("claudebot after the changes: %d", c)
	}
}

// Measurement 1, finding 2: crawler control uses the bots settings of
// schild.yaml with monitoring on and off. bots.verify.ranges false: no
// impersonators; true: a Googlebot from outside Google's ranges is one.
func TestCrawlerEngineFromConfig(t *testing.T) {
	for _, tc := range []struct {
		monitoring, ranges bool
	}{{true, true}, {true, false}, {false, true}, {false, false}} {
		t.Run(fmt.Sprintf("monitoring-%v-ranges-%v", tc.monitoring, tc.ranges), func(t *testing.T) {
			extra := fmt.Sprintf("monitoring:\n  enabled: %v\nbots:\n  verify:\n    ranges: %v\n", tc.monitoring, tc.ranges)
			h := apptest.New(t, apptest.Options{Extra: extra})
			if (h.App.Monitor != nil) != tc.monitoring {
				t.Fatalf("monitor %v", h.App.Monitor != nil)
			}
			h.Login()
			id := websiteID(t, h)
			if code, body := h.API("PUT", "/websites/"+id+"/crawlers", map[string]any{"categories": map[string]string{"ai_training": "block"}, "impersonators": "block"}); code != 200 {
				t.Fatalf("set: %d %s", code, body)
			}
			want := 200
			if tc.ranges {
				want = 403
			}
			if c := crawlerVisit(t, h, uaGooglebot, "203.0.113.5"); c != want {
				t.Fatalf("googlebot from elsewhere: %d, want %d", c, want)
			}
			if c := crawlerVisit(t, h, uaGooglebot, "66.249.66.1"); c != 200 {
				t.Fatalf("googlebot from its range: %d", c)
			}
			if c := crawlerVisit(t, h, uaClaudeBot, "203.0.113.6"); c != 403 {
				t.Fatalf("claudebot: %d", c)
			}
			if c := crawlerVisit(t, h, "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0", "203.0.113.7"); c != 200 {
				t.Fatalf("browser: %d", c)
			}
		})
	}
}

// D57 (MVP-29): crawler control from the dashboard.
func TestCrawlerPolicyDashboard(t *testing.T) {
	h := apptest.New(t, apptest.Options{})
	h.Login()
	id := websiteID(t, h)
	path := "/websites/" + id + "/crawlers"
	visit := func(h *apptest.Harness, ua string) int {
		req, _ := http.NewRequest("GET", h.Proxy.URL+"/", nil)
		req.Host = "shop.example"
		req.Header.Set("X-Forwarded-For", "198.51.100.60")
		req.Header.Set("User-Agent", ua)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return resp.StatusCode
	}
	const gptbot = "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.2; +https://openai.com/gptbot)"

	code, body := h.API("GET", path, nil)
	if code != 200 || !strings.Contains(string(body), `"policy":{"categories":{},"bots":{},"impersonators":"allow"}`) || !strings.Contains(string(body), `"actor":null`) {
		t.Fatalf("get empty: %d %.300s", code, body)
	}
	validate(t, "CrawlerPolicyState", body)
	var st cc.State
	_ = json.Unmarshal(body, &st)
	if len(st.Crawlers) < 300 || st.Presets[0] != cc.PresetBlockAITraining {
		t.Fatalf("catalogue: %d crawlers, presets %v", len(st.Crawlers), st.Presets)
	}
	for _, c := range st.Crawlers {
		if c.Category == "likely_automated" || c.Category == "likely_browser" {
			t.Fatalf("%+v is no crawler", c)
		}
	}
	if c := visit(h, gptbot); c != 200 {
		t.Fatalf("before: %d", c)
	}

	// Refused: unknown bot, unknown category, a preset with categories.
	for _, in := range []map[string]any{
		{"bots": map[string]string{"nosuchbot": "block"}},
		{"categories": map[string]string{"likely_browser": "block"}},
		{"preset": "block_ai_training", "categories": map[string]string{"seo_tool": "block"}},
		{"impersonators": "maybe"},
	} {
		code, body := h.API("PUT", path, in)
		if code != 400 || !strings.Contains(string(body), `"pointer"`) {
			t.Fatalf("%v: %d %s", in, code, body)
		}
	}
	// Unknown fields are refused too (no charging).
	if code, body := h.API("PUT", path, map[string]any{"charge": "1 EUR"}); code != 400 {
		t.Fatalf("unknown field: %d %s", code, body)
	}

	// The preset, then GPTBot back in by its own rule.
	code, body = h.API("PUT", path, map[string]any{"preset": "block_ai_training", "impersonators": "block"})
	if code != 200 || !strings.Contains(string(body), `"categories":{"ai_training":"block"}`) || !strings.Contains(string(body), `"actor":"dashboard"`) {
		t.Fatalf("preset: %d %.300s", code, body)
	}
	validate(t, "CrawlerPolicyState", body)
	if c := visit(h, gptbot); c != 403 {
		t.Fatalf("after preset: %d", c)
	}
	// With impersonators block, GPTBot from an address outside OpenAI's
	// ranges stays blocked even when allowed: an allow is for the real one.
	code, body = h.API("PUT", path, map[string]any{"categories": map[string]string{"ai_training": "block"}, "bots": map[string]string{"gptbot": "allow"}, "impersonators": "block"})
	if code != 200 {
		t.Fatalf("override: %d %s", code, body)
	}
	if c := visit(h, gptbot); c != 403 {
		t.Fatalf("gptbot impersonator: %d", c)
	}
	code, body = h.API("PUT", path, map[string]any{"categories": map[string]string{"ai_training": "block"}, "bots": map[string]string{"gptbot": "allow"}})
	if code != 200 {
		t.Fatalf("override: %d %s", code, body)
	}
	if c := visit(h, gptbot); c != 200 {
		t.Fatalf("gptbot by its own rule: %d", c)
	}
	if c := visit(h, "Mozilla/5.0 (compatible; ClaudeBot/1.0; +claudebot@anthropic.com)"); c != 403 {
		t.Fatalf("claudebot by its category: %d", c)
	}

	// Every change is an event with the dashboard user.
	h.Flush()
	rows, _, err := h.App.Store.ListEvents(t.Context(), store.EventFilter{Type: events.CrawlerPolicySet}, 0, 10)
	if err != nil || len(rows) != 3 {
		t.Fatalf("events: %d %v", len(rows), err)
	}
	ev, _ := h.App.Store.GetEvent(t.Context(), rows[0].ID)
	if !strings.Contains(string(ev.Body), `"actor":"dashboard"`) || !strings.Contains(string(ev.Body), `"bots":{"gptbot":"allow"}`) {
		t.Fatalf("event %s", ev.Body)
	}

	if code, _ := h.API("GET", "/websites/nope.example/crawlers", nil); code != 404 {
		t.Fatalf("unknown website: %d", code)
	}

	// A restart keeps the policy.
	dir := h.Dir
	if err := h.Stop(); err != nil {
		t.Fatal(err)
	}
	h2 := apptest.New(t, apptest.Options{Dir: dir})
	if c := visit(h2, "Mozilla/5.0 (compatible; ClaudeBot/1.0; +claudebot@anthropic.com)"); c != 403 {
		t.Fatalf("after restart: %d", c)
	}
	if c := visit(h2, gptbot); c != 200 {
		t.Fatalf("gptbot after restart: %d", c)
	}
}
