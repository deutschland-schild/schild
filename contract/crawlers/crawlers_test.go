package crawlers

import (
	"errors"
	"reflect"
	"testing"

	"github.com/deutschland-schild/schild/contract/bots"
)

func known(id string) bool { return id == "gptbot" || id == "ccbot" || id == "googlebot" }

func TestRuleForPrecedence(t *testing.T) {
	p := Policy{Categories: map[string]string{"ai_training": Block}, Bots: map[string]string{"ccbot": Allow, "googlebot": Block}, Impersonators: Block}
	for _, tc := range []struct {
		id, cat, ver, want string
	}{
		{"gptbot", "ai_training", bots.Verified, RuleCategory},
		{"ccbot", "ai_training", bots.Claimed, RuleNone},                  // bot allow overrides the category
		{"googlebot", "search_engine", bots.Verified, RuleBot},            // bot block overrides the category
		{"ccbot", "ai_training", bots.Mismatch, RuleImpersonator},         // an allow is for the real one
		{"bingbot", "search_engine", bots.UnknownStale, RuleNone},         // stale ranges prove nothing
		{"", "likely_automated", "", RuleNone},                            // no crawler
		{"", "likely_browser", "", RuleNone},                              // no crawler
		{"applebot", "search_engine", bots.Mismatch, RuleImpersonator},    // any named crawler
		{"gptbot", "ai_training", bots.Mismatch, RuleImpersonator},        // impersonator first
		{"chatgpt-user", "ai_assistant", bots.Claimed, RuleNone},          // other category
		{"claudebot", "ai_training", "", RuleCategory},                    // category without verification
		{"examplebot", "seo_tool", bots.Verified, RuleNone},               // nothing for it
		{"googlebot", "search_engine", bots.Mismatch, RuleImpersonator},   // impersonator over bot rule
		{"perplexitybot", "ai_search", bots.Verified, RuleNone},           // other category
		{"curl", "tool_library", bots.Claimed, RuleNone},                  // other category
		{"ccbot", "ai_training", bots.UnknownStale, RuleNone},             // allow
		{"ai2bot", "ai_training", bots.Claimed, RuleCategory},             // the category
		{"bytespider", "ai_training", bots.Claimed, RuleCategory},         // the category
		{"googlebot-image", "search_engine", bots.Verified, RuleNone},     // its own entry
		{"googlebot", "search_engine", bots.UnknownStale, RuleBot},        // the bot rule
		{"gptbot", "ai_training", bots.UnknownStale, RuleCategory},        // stale: no impersonator
		{"meta-externalagent", "ai_training", bots.Claimed, RuleCategory}, // the category
	} {
		if got := RuleFor(p, tc.id, tc.cat, tc.ver); got != tc.want {
			t.Errorf("%s/%s/%s: %s, want %s", tc.id, tc.cat, tc.ver, got, tc.want)
		}
	}
	if got := RuleFor(Policy{}, "gptbot", "ai_training", bots.Mismatch); got != RuleNone {
		t.Errorf("empty policy: %s", got)
	}
}

func TestApply(t *testing.T) {
	for _, tc := range []struct {
		rule, mode string
		allow      bool
		out, why   string
		status     int
	}{
		{RuleNone, ModeAutoblock, false, OutcomePassed, "", 0},
		{RuleCategory, ModeAutoblock, false, OutcomeBlocked, "", 403},
		{RuleCategory, ModeObserve, false, OutcomeWouldBlock, ReasonGatewayObserve, 0},
		{RuleImpersonator, ModeAutoblock, true, OutcomeWouldBlock, ReasonAllowlist, 0},
		{RuleCategory, ModeObserve, true, OutcomeWouldBlock, ReasonGatewayObserve, 0},
		{RuleNone, ModeObserve, true, OutcomePassed, "", 0},
	} {
		o, r, s := Apply(tc.rule, tc.mode, tc.allow)
		if o != tc.out || r != tc.why || s != tc.status {
			t.Errorf("%+v: %s %s %d", tc, o, r, s)
		}
	}
}

func TestCheck(t *testing.T) {
	var fe *FieldError
	for _, p := range []Policy{
		{Categories: map[string]string{"likely_browser": Block}},
		{Categories: map[string]string{"ai_training": "charge"}},
		{Bots: map[string]string{"nosuchbot": Block}},
		{Bots: map[string]string{"gptbot": "deny"}},
		{Impersonators: "yes"},
	} {
		if err := p.Check(known); !errors.As(err, &fe) {
			t.Errorf("%+v accepted (%v)", p, err)
		}
	}
	if err := (Policy{Categories: map[string]string{"ai_training": Block}, Bots: map[string]string{"gptbot": Allow}, Impersonators: Block}).Check(known); err != nil {
		t.Error(err)
	}
	if (Policy{Categories: map[string]string{"ai_training": Allow}, Bots: map[string]string{"gptbot": Allow}}).Blocks() {
		t.Error("allow only blocks nothing")
	}
}

func TestSetRequest(t *testing.T) {
	cur := Policy{Categories: map[string]string{"ai_training": Block}, Bots: map[string]string{"gptbot": Allow}, Impersonators: Block}
	for _, tc := range []struct {
		r    SetRequest
		want Policy
	}{
		{SetRequest{Category: "search_engine", Action: Block}, Policy{Categories: map[string]string{"ai_training": Block, "search_engine": Block}, Bots: map[string]string{"gptbot": Allow}, Impersonators: Block}},
		{SetRequest{Category: "ai_training", Action: Allow}, Policy{Bots: map[string]string{"gptbot": Allow}, Impersonators: Block}},
		{SetRequest{Bot: "gptbot", Action: ActionInherit}, Policy{Categories: map[string]string{"ai_training": Block}, Impersonators: Block}},
		{SetRequest{Bot: "ccbot", Action: Block}, Policy{Categories: map[string]string{"ai_training": Block}, Bots: map[string]string{"gptbot": Allow, "ccbot": Block}, Impersonators: Block}},
		{SetRequest{Impersonators: Allow}, Policy{Categories: map[string]string{"ai_training": Block}, Bots: map[string]string{"gptbot": Allow}}},
		{SetRequest{Preset: PresetBlockAITraining}, Policy{Categories: map[string]string{"ai_training": Block}, Impersonators: Block}},
		// inherit for a bot the catalogue no longer knows drops nothing and
		// is no error (measurement 1, finding 1).
		{SetRequest{Bot: "gone-bot", Action: ActionInherit}, Policy{Categories: map[string]string{"ai_training": Block}, Bots: map[string]string{"gptbot": Allow}, Impersonators: Block}},
	} {
		got, err := tc.r.Apply(cur, known)
		if err != nil || !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: %+v %v, want %+v", tc.r, got, err, tc.want)
		}
	}
	for _, r := range []SetRequest{
		{},
		{Category: "ai_training", Bot: "gptbot", Action: Block},
		{Category: "ai_training", Action: ActionInherit},
		{Category: "likely_automated", Action: Block},
		{Bot: "nosuchbot", Action: Block},
		{Bot: "gptbot"},
		{Impersonators: Block, Action: Block},
		{Preset: "block_all"},
		{Preset: PresetBlockAITraining, Action: Block},
	} {
		if _, err := r.Apply(cur, known); err == nil {
			t.Errorf("%+v accepted", r)
		}
	}
	if !reflect.DeepEqual(cur.Bots, map[string]string{"gptbot": Allow}) {
		t.Error("Apply changed the stored policy")
	}
}

func TestInputNext(t *testing.T) {
	cur := Policy{Bots: map[string]string{"gptbot": Allow}, Impersonators: Block}
	got, err := Input{Preset: PresetBlockAITraining}.Next(cur)
	if err != nil || !reflect.DeepEqual(got, Policy{Categories: map[string]string{"ai_training": Block}, Impersonators: Block}) {
		t.Errorf("preset: %+v %v", got, err)
	}
	got, err = Input{Preset: PresetBlockAITraining, Impersonators: Allow}.Next(cur)
	if err != nil || got.Impersonators != Allow {
		t.Errorf("preset with impersonators: %+v %v", got, err)
	}
	if _, err := (Input{Preset: PresetBlockAITraining, Bots: map[string]string{"ccbot": Block}}).Next(cur); err == nil {
		t.Error("preset with bots accepted")
	}
	got, _ = Input{Categories: map[string]string{"seo_tool": Block}}.Next(cur)
	if !reflect.DeepEqual(got, Policy{Categories: map[string]string{"seo_tool": Block}}) {
		t.Errorf("replace: %+v", got)
	}
	w := Policy{Categories: map[string]string{"seo_tool": Allow}}.Wire()
	if len(w.Categories) != 0 || w.Bots == nil || w.Impersonators != Allow {
		t.Errorf("wire: %+v", w)
	}
}
