package decide

import (
	"reflect"
	"testing"

	"github.com/deutschland-schild/schild/contract/events"
	"github.com/deutschland-schild/schild/contract/rules"
)

// hit is what the gate hands in for one repository or rule: the action of
// contract/rules for mode, state and origin, after allowlist and exceptions.
func hit(src, mode, state, origin, allow string, excepted bool) []Hit {
	r := rules.Compute(rules.Input{Mode: mode, State: state, Origin: origin, Now: 1})
	a := rules.Apply(r, rules.Request{Allow: allow, Excepted: excepted})
	if a.Action == rules.ActionNone {
		return nil
	}
	return []Hit{{Source: src, Action: a.Action, WouldBlockReason: a.WouldBlockReason}}
}

func crs(mode string) []Hit {
	return hit("crs", mode, rules.StateBlock, rules.OriginRelease, "", false)
}

// TestWouldBlockReason: the reason is set exactly with outcome would_block,
// and the first in precedence order wins when several apply (D36 open items).
func TestWouldBlockReason(t *testing.T) {
	siteObserve := []Hit{{Source: "crowdsec:60000000", Action: rules.ActionWouldBlock, WouldBlockReason: ReasonSiteObserve}}
	cases := []struct {
		name string
		in   Input
		want string
	}{
		{"gateway observe", Input{Hits: crs(ModeObserve)}, ReasonGatewayObserve},
		{"gateway observe wins over allowlist", Input{Allow: AllowNoBlock, Hits: hit("crs", ModeObserve, "block", "release", AllowNoBlock, false)}, ReasonGatewayObserve},
		{"allowlist no_block", Input{Allow: AllowNoBlock, Hits: hit("local", ModeAutoblock, "block", "operator", AllowNoBlock, false)}, ReasonAllowlist},
		{"site observe of a crowdsec rule wins over allowlist", Input{Allow: AllowNoBlock,
			Hits: append(hit("crs", ModeAutoblock, "block", "release", AllowNoBlock, false), siteObserve...)}, ReasonSiteObserve},
		{"blocked has none", Input{Hits: crs(ModeAutoblock)}, ""},
		{"logged has none", Input{AnyMatch: true}, ""},
		{"excepted has none", Input{Hits: hit("crs", ModeObserve, "block", "release", "", true)}, ""},
		{"passed has none", Input{}, ""},
	}
	for _, c := range cases {
		got := Decide(c.in)
		if got.WouldBlockReason != c.want {
			t.Errorf("%s: reason %q want %q (%+v)", c.name, got.WouldBlockReason, c.want, got)
		}
		if (got.Outcome == WouldBlock) != (got.WouldBlockReason != "") {
			t.Errorf("%s: reason %q with outcome %s", c.name, got.WouldBlockReason, got.Outcome)
		}
	}
	if FirstReason("allowlist", "shared_address", "learning", "bogus") != ReasonLearning || FirstReason() != "" || FirstReason("bogus") != "" {
		t.Fatal("FirstReason precedence")
	}
}

// TestReasonsMatchContract: the precedence order equals the contract's.
func TestReasonsMatchContract(t *testing.T) {
	for i, r := range events.WouldBlockReasons {
		if reasonRank[r] != i+1 {
			t.Fatalf("%s rank %d want %d", r, reasonRank[r], i+1)
		}
	}
	if len(reasonRank) != len(events.WouldBlockReasons) {
		t.Fatal("reason count")
	}
}

func TestDecide(t *testing.T) {
	cs := func(mode, origin string) []Hit {
		return hit("crowdsec:60000000", mode, rules.StateBlock, origin, "", false)
	}
	cases := []struct {
		name string
		in   Input
		out  string
		st   int
	}{
		{"clean", Input{}, Passed, 0},
		{"match below threshold", Input{AnyMatch: true}, Logged, 0},
		{"crs blocks in autoblock", Input{Hits: crs(ModeAutoblock)}, Blocked, 403},
		{"crs only would block in observe", Input{Hits: crs(ModeObserve)}, WouldBlock, 0},
		{"crs in detect is Erkannt (D90)", Input{AnyMatch: true, Hits: hit("crs", ModeAutoblock, "detect", "release", "", false)}, WouldBlock, 0},
		{"local blocks", Input{Hits: hit("local", ModeAutoblock, "block", "operator", "", false)}, Blocked, 403},
		{"no_block allowlist", Input{Allow: AllowNoBlock, Hits: hit("crs", ModeAutoblock, "block", "release", AllowNoBlock, false)}, WouldBlock, 0},
		{"bypass allowlist", Input{HardStatus: 413, Allow: AllowBypassWAF, Hits: crs(ModeAutoblock)}, Passed, 0},
		{"hard limit in observe", Input{HardStatus: 413}, Blocked, 413},
		{"hard limit with no_block", Input{HardStatus: 503, Allow: AllowNoBlock}, Blocked, 503},
		{"crowdsec release blocks", Input{Hits: cs(ModeAutoblock, rules.OriginRelease)}, Blocked, 403},
		{"crowdsec would block", Input{Hits: cs(ModeObserve, rules.OriginRelease)}, WouldBlock, 0},
		{"crowdsec excepted", Input{Hits: hit("crowdsec:60000000", ModeAutoblock, "block", "release", "", true)}, Logged, 0},
		{"exception for crs does not cover local", Input{Hits: append(hit("crs", ModeAutoblock, "block", "release", "", true),
			hit("local", ModeAutoblock, "block", "operator", "", false)...)}, Blocked, 403},
	}
	for _, c := range cases {
		got := Decide(c.in)
		if got.Outcome != c.out || got.Status != c.st {
			t.Errorf("%s: got %s/%d want %s/%d (%+v)", c.name, got.Outcome, got.Status, c.out, c.st, got)
		}
	}
	got := Decide(Input{Hits: append(hit("local", ModeAutoblock, "block", "operator", "", false), crs(ModeAutoblock)...)})
	if !reflect.DeepEqual(got.Sources, []string{"crs", "local"}) {
		t.Fatal(got.Sources)
	}
}

// TestObserveNeverBlocks: in observe nothing but a hard limit blocks.
func TestObserveNeverBlocks(t *testing.T) {
	for _, allow := range []string{AllowNone, AllowNoBlock} {
		for _, origin := range []string{rules.OriginRelease, rules.OriginUpdate, rules.OriginOperator} {
			got := Decide(Input{Allow: allow, Hits: hit("x", ModeObserve, rules.StateBlock, origin, allow, false)})
			if got.Outcome == Blocked {
				t.Fatalf("observe blocked: %s %s", origin, allow)
			}
		}
	}
}
