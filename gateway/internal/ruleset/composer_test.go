package ruleset

import (
	"errors"
	"io"
	"log/slog"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/gateway/internal/waf"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

func newComposer(t *testing.T) (*Composer, *waf.Engine) {
	t.Helper()
	engine := &waf.Engine{}
	c := NewComposer(engine, waf.Config{}, quiet, nil)
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	return c, engine
}

func setLocal(text string) func(*waf.Config) { return func(cfg *waf.Config) { cfg.LocalRules = text } }

var hubRules = []waf.HubRule{{Name: "x/y", Version: "1", BaseID: 60000000, Groups: []string{`SecRule REQUEST_URI "@beginsWith /hub" "id:60000000,phase:1,pass,log"`}}}

// A crowdsec set that does not build is left out at the start (D39).
func TestStartWithoutABrokenHub(t *testing.T) {
	engine := &waf.Engine{}
	c := NewComposer(engine, waf.Config{}, quiet, nil)
	b := c.HubBuilder()
	b.SetHub([]waf.HubRule{{Name: "x/y", Version: "1", BaseID: 60000000, Groups: []string{`SecRule ARGS "@nope" "id:60000000,phase:2,pass"`}}})
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	if b.HubLoaded() != 0 || engine.Current() == nil {
		t.Fatal("a broken hub set held up the start")
	}
}

const localBlock = `SecRule REQUEST_URI "@beginsWith /stop" "id:1000001,phase:1,deny,status:403,log"`

// A swap of another repository between build and commit must not be undone:
// the build runs again with what that swap brought (D46).
func TestRebuildAfterAnotherSwap(t *testing.T) {
	c, engine := newComposer(t)
	b := c.HubBuilder()
	builds := 0
	c.afterBuild = func() {
		builds++
		if builds == 1 {
			inst, gen, err := b.PrepareHub(hubRules)
			if err != nil {
				t.Error(err)
				return
			}
			if !b.CommitHub(inst, gen, hubRules) {
				t.Error("hub commit refused")
			}
		}
	}
	inst, err := c.Rebuild(setLocal(localBlock))
	if err != nil {
		t.Fatal(err)
	}
	if builds != 2 {
		t.Fatalf("%d builds", builds)
	}
	if len(inst.Hub) != 1 || inst.Config.LocalRules != localBlock || c.Config().LocalRules != localBlock || b.HubLoaded() != 1 {
		t.Fatalf("hub %d local %q", len(inst.Hub), inst.Config.LocalRules)
	}
	if engine.Current() != inst {
		t.Fatal("not swapped in")
	}
}

// A crowdsec update builds on the rebuilt local rules, not on the ones it
// started with.
func TestHubAfterRebuild(t *testing.T) {
	c, _ := newComposer(t)
	b := c.HubBuilder()
	inst, gen, err := b.PrepareHub(hubRules)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Rebuild(setLocal(localBlock)); err != nil {
		t.Fatal(err)
	}
	if b.CommitHub(inst, gen, hubRules) {
		t.Fatal("a stale hub build took the local rules away")
	}
	if c.Config().LocalRules != localBlock {
		t.Fatal("local rules lost")
	}
}

// Every repository keeps to its id range (D73): a local rule in the range of
// crs, crowdsec, agent exceptions or the network is refused and changes
// nothing.
func TestLocalRuleIDRanges(t *testing.T) {
	c, engine := newComposer(t)
	before := engine.Current()
	for _, id := range []string{"942100", "200005", "60000000", "1900001", "7700001"} {
		_, err := c.Rebuild(setLocal(`SecRule REQUEST_URI "@beginsWith /x" "id:` + id + `,phase:1,deny"`))
		if !errors.Is(err, ErrIDRange) {
			t.Errorf("id %s: %v", id, err)
		}
	}
	if engine.Current() != before || c.Config().LocalRules != "" {
		t.Fatal("a refused build changed something")
	}
	for _, id := range []string{"1", "10001", "1000001", "199999", "2000000", "59999999"} {
		if _, err := c.Rebuild(setLocal(`SecRule REQUEST_URI "@beginsWith /x" "id:` + id + `,phase:1,deny"`)); err != nil {
			t.Errorf("id %s refused: %v", id, err)
		}
	}
	if _, err := c.SetExceptions(`SecRule REQUEST_URI "@beginsWith /x" "id:10002,phase:1,pass,nolog,ctl:ruleRemoveById=942100"`); !errors.Is(err, ErrIDRange) {
		t.Fatalf("an agent exception outside its range: %v", err)
	}
}

// matched lists the rule ids a request to path matches.
func matched(t *testing.T, inst *waf.Instance, path string) map[int]bool {
	t.Helper()
	a, _, err := inst.Probe(httptest.NewRequest("GET", path, nil), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	out := map[int]bool{}
	for _, m := range a.Matches {
		out[m.ID] = true
	}
	return out
}

// Disabled rules leave with SecRuleRemoveById after their repository.
func TestRemoveDisabledRules(t *testing.T) {
	c, _ := newComposer(t)
	inst, err := c.Rebuild(func(cfg *waf.Config) {
		cfg.LocalRules = localBlock + "\n" + `SecRule REQUEST_URI "@beginsWith /also" "id:1000002,phase:1,deny,status:403,log"`
		cfg.LocalRemove = []int{1000001}
	})
	if err != nil {
		t.Fatal(err)
	}
	if matched(t, inst, "/stop")[1000001] || !matched(t, inst, "/also")[1000002] {
		t.Fatal("the disabled local rule still runs, or the other one does not")
	}
	inst, err = c.Rebuild(func(cfg *waf.Config) { cfg.CRS, cfg.ParanoiaLevel, cfg.AnomalyThreshold = true, 1, 5 })
	if err != nil {
		t.Fatal(err)
	}
	const attack = "/?q=%3Cscript%3Ealert(1)%3C/script%3E"
	if !matched(t, inst, attack)[941100] {
		t.Fatal("941100 does not match the probe")
	}
	inst, err = c.Rebuild(func(cfg *waf.Config) { cfg.CRSRemove = []int{941100} })
	if err != nil {
		t.Fatal(err)
	}
	if got := matched(t, inst, attack); got[941100] || !got[941110] && !got[941160] {
		t.Fatalf("after disabling 941100: %v", got)
	}
}
