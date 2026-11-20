package gate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/contract/config"
	"github.com/deutschland-schild/schild/contract/crowdsec"
	"github.com/deutschland-schild/schild/contract/events"
	"github.com/deutschland-schild/schild/contract/rules"
	"github.com/deutschland-schild/schild/gateway/internal/allowlist"
	"github.com/deutschland-schild/schild/gateway/internal/behaviour"
	"github.com/deutschland-schild/schild/gateway/internal/decide"
	"github.com/deutschland-schild/schild/gateway/internal/eventlog"
	"github.com/deutschland-schild/schild/gateway/internal/store"
	"github.com/deutschland-schild/schild/gateway/internal/waf"
)

const hubRuleName = "crowdsecurity/vpatch-CVE-2026-0001"

const hubYAML = `name: crowdsecurity/vpatch-CVE-2026-0001
description: test rule
rules:
  - and:
      - zones: [URI]
        transform: [lowercase]
        match: { type: contains, value: /vulnerable/one }
      - zones: [ARGS]
        variables: [cmd]
        match: { type: contains, value: pwn }
labels:
  label: Test rule
  classification:
    - cve.CVE-2026-0001
`

const hubAttack = "/vulnerable/one?cmd=pwn"

// fakeRules are the repositories of a test: the facts of contract/rules per
// repository; a repository not named blocks with origin release.
type fakeRules struct{ in map[string]rules.Input }

func (f *fakeRules) Effect(repository string, _ int, mode string, now time.Time) rules.Rule {
	in, ok := f.in[repository]
	if !ok {
		in = rules.Input{State: rules.StateBlock, Origin: rules.OriginRelease}
	}
	in.Mode, in.Now = mode, now.Unix()
	return rules.Compute(in)
}

// hubEnv is a gate with the CRS and one crowdsec rule with the given facts.
func hubEnv(t *testing.T, mode string, h rules.Input) (*tenv, *fakeRules) {
	t.Helper()
	sum := sha256.Sum256([]byte(hubYAML))
	r, sk := crowdsec.Convert(hubRuleName, "0.1", hex.EncodeToString(sum[:]), []byte(hubYAML), "")
	if sk != nil {
		t.Fatal(sk)
	}
	inst, err := waf.Build(waf.Config{CRS: true, ParanoiaLevel: 1, AnomalyThreshold: 5,
		Hub: []waf.HubRule{{Name: r.Name, Version: r.Version, Label: r.Label, CVEs: r.CVEs, BaseID: r.BaseID, Groups: r.SecLang}}})
	if err != nil {
		t.Fatal(err)
	}
	e := newEnv(t, mode)
	e.g.Engine = &waf.Engine{}
	e.g.Engine.Swap(inst)
	f := &fakeRules{in: map[string]rules.Input{rules.RepoCrowdsec: h}}
	e.g.Rules = f
	return e, f
}

func hubHit(state string) rules.Input { return rules.Input{State: state, Origin: rules.OriginRelease} }

// The core promise of the default: detect never blocks, in any mode, with any
// allowlist level, however often it matches.
func TestHubDetectNeverBlocks(t *testing.T) {
	for _, mode := range []string{decide.ModeObserve, decide.ModeAutoblock} {
		t.Run(mode, func(t *testing.T) {
			e, _ := hubEnv(t, mode, hubHit(crowdsec.StateDetect))
			for range 30 {
				if c := e.sendFrom("203.0.113.5", "GET", hubAttack, "", "", nil); c != 200 {
					t.Fatalf("detect answered %d", c)
				}
			}
			if e.hits.Load() != 30 {
				t.Fatalf("backend saw %d", e.hits.Load())
			}
			// D90: a source on detect shows its matches as "Erkannt".
			rows := e.events(t, store.EventFilter{Outcome: decide.WouldBlock})
			if len(rows) != 30 || !strings.Contains(string(rows[0].Body), `"would_block_reason":"source_detect"`) {
				t.Fatalf("%d would_block events", len(rows))
			}
			var body struct {
				Data events.Request `json:"data"`
			}
			if err := json.Unmarshal(rows[0].Body, &body); err != nil {
				t.Fatal(err)
			}
			d := body.Data
			if d.Score != 0 || len(d.Rules) != 1 || d.Rules[0].Repository != rules.RepoCrowdsec || d.Rules[0].Crowdsec == nil ||
				d.Rules[0].Crowdsec.Name != hubRuleName || d.Rules[0].Crowdsec.CVEs[0] != "CVE-2026-0001" {
				t.Fatalf("event %+v", d)
			}
		})
	}
}

// Nothing of a match in detect may feed a counter that later blocks.
func TestHubDetectFeedsNoBehaviourCounter(t *testing.T) {
	ri := &reqInfo{analysis: &waf.Analysis{Matches: []waf.Match{{ID: 60000000, Source: waf.SourceCrowdsec, Hub: &waf.HubRule{BaseID: 60000000}}}}}
	if got := wafRuleIDs(ri); len(got) != 0 {
		t.Fatalf("waf_repeat input: %v", got)
	}
	ri.analysis.Matches[0].Counts = true
	if got := wafRuleIDs(ri); len(got) != 1 {
		t.Fatalf("a real block must count: %v", got)
	}
}

func TestHubEffectTable(t *testing.T) {
	cases := []struct {
		name    string
		mode    string
		hit     rules.Input
		allow   string
		except  bool
		status  int
		outcome string
		reason  string
	}{
		{name: "block in autoblock", mode: decide.ModeAutoblock, hit: hubHit(crowdsec.StateBlock), status: 403, outcome: decide.Blocked},
		{name: "a settled update blocks", mode: decide.ModeAutoblock, hit: rules.Input{State: crowdsec.StateBlock, Origin: rules.OriginUpdate}, status: 403, outcome: decide.Blocked},
		{name: "block in observe", mode: decide.ModeObserve, hit: hubHit(crowdsec.StateBlock), status: 200, outcome: decide.WouldBlock, reason: decide.ReasonGatewayObserve},
		{name: "settling", mode: decide.ModeAutoblock, hit: rules.Input{State: crowdsec.StateBlock, Origin: rules.OriginUpdate, SettlingUntil: time.Now().Unix() + 86400}, status: 200, outcome: decide.WouldBlock, reason: decide.ReasonSettling},
		{name: "disabled", mode: decide.ModeAutoblock, hit: rules.Input{State: crowdsec.StateBlock, Origin: rules.OriginRelease, Disabled: true, DisabledBy: rules.ByDashboard}, status: 200, outcome: decide.Passed},
		{name: "state off", mode: decide.ModeAutoblock, hit: hubHit(crowdsec.StateOff), status: 200, outcome: decide.Passed},
		{name: "excepted", mode: decide.ModeAutoblock, hit: hubHit(crowdsec.StateBlock), except: true, status: 200, outcome: decide.Logged},
		{name: "allowlist no_block", mode: decide.ModeAutoblock, hit: hubHit(crowdsec.StateBlock), allow: allowlist.NoBlock, status: 200, outcome: decide.WouldBlock, reason: decide.ReasonAllowlist},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e, _ := hubEnv(t, c.mode, c.hit)
			ip := "203.0.113.5"
			if c.allow != "" {
				e.g.Allow.Set([]store.AllowEntry{{ID: "a", IP: ip, Label: "me", Level: c.allow, Expires: "never"}})
			}
			if c.except {
				e.g.Exceptions.Add(netip.MustParseAddr(ip), []string{CrowdsecSource(crowdsec.BaseID(hubRuleName))}, time.Now().Add(time.Hour))
			}
			if got := e.sendFrom(ip, "GET", hubAttack, "", "", nil); got != c.status {
				t.Fatalf("status %d, want %d", got, c.status)
			}
			rows := e.events(t, store.EventFilter{Outcome: c.outcome})
			if c.outcome == decide.Passed {
				for _, r := range rows {
					if strings.Contains(string(r.Body), `"repository":"crowdsec"`) {
						t.Fatalf("a rule without effect in an event: %s", r.Body)
					}
				}
				return
			}
			if len(rows) != 1 {
				t.Fatalf("%d events with outcome %s", len(rows), c.outcome)
			}
			var body struct {
				Data events.Request `json:"data"`
			}
			_ = json.Unmarshal(rows[0].Body, &body)
			if body.Data.WouldBlockReason != c.reason {
				t.Fatalf("reason %q, want %q", body.Data.WouldBlockReason, c.reason)
			}
		})
	}
}

func TestHubBlockMakesAnIncidentWithItsSource(t *testing.T) {
	e, _ := hubEnv(t, decide.ModeAutoblock, hubHit(crowdsec.StateBlock))
	if c := e.sendFrom("203.0.113.5", "GET", hubAttack, "", "", nil); c != 403 {
		t.Fatalf("%d", c)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	e.g.FlushIncidents(ctx)
	rows := e.events(t, store.EventFilter{Outcome: decide.Blocked})
	if len(rows) != 1 || rows[0].Incident == "" {
		t.Fatalf("%+v", rows)
	}
	in, err := e.st.GetIncident(context.Background(), rows[0].Incident)
	if err != nil {
		t.Fatal(err)
	}
	want := "crowdsec:" + strconv.Itoa(crowdsec.BaseID(hubRuleName))
	if len(in.Sources) != 1 || in.Sources[0] != want {
		t.Fatalf("incident %+v", in)
	}
}

// A hub rule in detect next to a real CRS block stays out of the incident.
func TestHubDetectIsNoCauseOfAnotherBlock(t *testing.T) {
	e, _ := hubEnv(t, decide.ModeAutoblock, hubHit(crowdsec.StateDetect))
	if c := e.sendFrom("203.0.113.5", "GET", hubAttack+"&q=%3Cscript%3Ealert(1)%3C%2Fscript%3E", "", "", nil); c != 403 {
		t.Fatalf("%d", c)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	e.g.FlushIncidents(ctx)
	rows := e.events(t, store.EventFilter{Outcome: decide.Blocked})
	if len(rows) != 1 {
		t.Fatalf("%d", len(rows))
	}
	in, err := e.st.GetIncident(context.Background(), rows[0].Incident)
	if err != nil {
		t.Fatal(err)
	}
	if len(in.Sources) != 1 || in.Sources[0] != "crs" || strings.Contains(in.Reason, strconv.Itoa(crowdsec.BaseID(hubRuleName))) {
		t.Fatalf("incident %+v", in)
	}
}

// waf_repeat counts distinct rules over several requests. The same traffic
// with two hub rules triggers it when the rules really block (the control) and
// leaves the behaviour engine untouched in detect.
func TestHubOnlyARealBlockFeedsWAFRepeat(t *testing.T) {
	run := func(state string) int {
		e, _ := hubEnv(t, decide.ModeAutoblock, hubHit(state))
		const second = "crowdsecurity/vpatch-CVE-2026-0002"
		y := strings.ReplaceAll(strings.ReplaceAll(hubYAML, hubRuleName, second), "CVE-2026-0001", "CVE-2026-0002")
		sum := sha256.Sum256([]byte(y))
		r2, sk := crowdsec.Convert(second, "0.1", hex.EncodeToString(sum[:]), []byte(y), "")
		if sk != nil {
			t.Fatal(sk)
		}
		cur := e.g.Engine.Current()
		cfg := cur.Config
		cfg.Hub = append(append([]waf.HubRule{}, cfg.Hub...), waf.HubRule{Name: r2.Name, Version: r2.Version, BaseID: r2.BaseID, Groups: r2.SecLang})
		inst, err := waf.Build(cfg)
		if err != nil {
			t.Fatal(err)
		}
		e.g.Engine.Swap(inst)
		b := config.Behaviour{PresetLimits: config.BehaviourOff}
		for _, id := range config.ScenarioIDs {
			b.Scenarios.Get(id).Mode = config.BehaviourObserve
		}
		b.Scenarios.Get(config.ScenarioWAFRepeat).Mode = config.BehaviourBlock
		e.g.Behaviour = behaviour.New(behaviour.Config{Behaviour: b, InstalledAt: time.Now().Add(-365 * 24 * time.Hour)})
		var triggered atomic.Int64
		e.g.Behaviour.Sink = behaviour.Sink{
			Emit: func(_, typ string, _ time.Time, _ any, _ eventlog.Index) {
				if typ == events.BehaviourTriggered {
					triggered.Add(1)
				}
			},
			Incident: func(*store.Incident) {},
		}
		for range 10 {
			c := e.sendFrom("203.0.113.5", "GET", hubAttack, "", "", nil)
			if state == crowdsec.StateDetect && c != 200 {
				t.Fatalf("blocked indirectly: %d", c)
			}
		}
		return int(triggered.Load())
	}
	if n := run(crowdsec.StateBlock); n == 0 {
		t.Fatal("control: real hub blocks did not reach waf_repeat, so this test proves nothing")
	}
	if n := run(crowdsec.StateDetect); n != 0 {
		t.Fatalf("detect fed waf_repeat %d times", n)
	}
}

// Repository crs in detect (D73): CRS matches are logged and never block, in
// any mode, and feed no behaviour counter; off is not built at all.
func TestCRSDetectNeverBlocks(t *testing.T) {
	const xss = "/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"
	for _, mode := range []string{decide.ModeObserve, decide.ModeAutoblock} {
		t.Run(mode, func(t *testing.T) {
			e, f := hubEnv(t, mode, hubHit(crowdsec.StateDetect))
			f.in[rules.RepoCRS] = rules.Input{State: rules.StateDetect, Origin: rules.OriginRelease}
			if c := e.sendFrom("203.0.113.5", "GET", xss, "", "", nil); c != 200 {
				t.Fatalf("crs in detect answered %d", c)
			}
			rows := e.events(t, store.EventFilter{Outcome: decide.WouldBlock})
			if len(rows) != 1 || !strings.Contains(string(rows[0].Body), `"repository":"crs"`) || !strings.Contains(string(rows[0].Body), `"would_block_reason":"source_detect"`) {
				t.Fatalf("%d would_block events", len(rows))
			}
			if n := len(e.events(t, store.EventFilter{Outcome: decide.Blocked})); n != 0 {
				t.Fatalf("%d blocked events", n)
			}
		})
	}
	ri := &reqInfo{analysis: &waf.Analysis{CRSBlock: true, Matches: []waf.Match{{ID: 941100, Source: waf.SourceCRS, Points: 5}}}, start: time.Now()}
	g := &Gate{Rules: &fakeRules{in: map[string]rules.Input{rules.RepoCRS: {State: rules.StateDetect, Origin: rules.OriginRelease}}}, Exceptions: NewExceptions()}
	g.applyRules(ri, &Settings{Mode: decide.ModeAutoblock})
	if got := wafRuleIDs(ri); len(got) != 0 || len(ri.hits) != 1 || ri.hits[0].Action != rules.ActionWouldBlock || ri.hits[0].WouldBlockReason != rules.WouldBlockSourceDetect {
		t.Fatalf("crs in detect: ids %v, hits %+v", got, ri.hits)
	}
}
