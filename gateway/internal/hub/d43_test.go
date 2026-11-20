package hub_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/contract/crowdsec"
	"github.com/deutschland-schild/schild/gateway/internal/hub"
	"github.com/deutschland-schild/schild/gateway/internal/store"
	"github.com/deutschland-schild/schild/gateway/internal/waf"
)

// noCost is a cost check that always passes: these tests are about the rest.
func noCost(context.Context, []waf.HubRule, []waf.HubRule) (crowdsec.CostSample, error) {
	return crowdsec.CostSample{BaselineNS: 20000, ReferenceNS: 20000, CandidateNS: 20000, Rounds: crowdsec.CostRounds}, nil
}

func ruleNames(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("r%d", i)
	}
	return out
}

// bigAlternation is one regex of the hostile shape of the MVP-26 measurement
// (testlab/measure/crowdsec-hub/hub/mkindex.py): about 960 characters, far below the program
// bound of one regex.
func bigAlternation(rng *rand.Rand, i int) string {
	var parts []string
	for n := 0; n < 960; n += 6 {
		var b strings.Builder
		for range 5 {
			b.WriteByte("bcdfghjkmpqtvwxz"[rng.Intn(16)])
		}
		parts = append(parts, b.String())
	}
	return "(?:" + strings.Join(parts, "|") + fmt.Sprintf(")/m%d", i)
}

// hostileRule has six groups with one such regex each.
func hostileRule(rng *rand.Rand, name, zones string, i int) string {
	var y strings.Builder
	fmt.Fprintf(&y, "name: crowdsecurity/vpatch-%s\ndescription: TEST ONLY\nrules:\n", name)
	for g := range 6 {
		fmt.Fprintf(&y, "  - zones: [%s]\n    match:\n      type: regex\n      value: '%s'\n", zones, bigAlternation(rng, i*10+g))
	}
	y.WriteString("labels:\n  label: TEST ONLY\n")
	return y.String()
}

// shippedRules converts the snapshot of the image into YAML by name.
func shippedRules(t *testing.T) (raw []byte, rules map[string]string) {
	t.Helper()
	raw, err := os.ReadFile("snapshot.json")
	if err != nil {
		t.Fatal(err)
	}
	set, err := crowdsec.ParseSet(raw)
	if err != nil {
		t.Fatal(err)
	}
	rules = map[string]string{}
	for _, it := range set.Rules {
		b, err := base64.StdEncoding.DecodeString(it.Content)
		if err != nil {
			t.Fatal(err)
		}
		rules[strings.TrimPrefix(it.Name, "crowdsecurity/vpatch-")] = string(b)
	}
	return raw, rules
}

// D43, finding 1: a hostile set inside every static bound is refused by the
// measured check, with the real measurement on the real snapshot. The hostile
// rules read the URI in one run and every argument in the other, as the two
// sets of the measurement did.
func TestHostileSetIsRefusedByItsMeasuredCost(t *testing.T) {
	for _, zones := range []string{"URI", "URI,ARGS,BODY_ARGS"} {
		t.Run(zones, func(t *testing.T) {
			image, _ := shippedRules(t)
			e := newEnv(t, setup{auto: true, image: image})
			before := e.status2()
			inst := e.engine.Current()
			rng := rand.New(rand.NewSource(26))
			names, bodies := make([]string, 110), map[string]string{}
			for i := range names {
				names[i] = fmt.Sprintf("heavy-%d", i)
				bodies[names[i]] = hostileRule(rng, names[i], zones, i)
			}
			raw := indexOf(names, func(n string) string { return bodies[n] })
			// Inside every static bound of the contract, as the measured shape.
			u := crowdsec.CheckIndex(raw, nil, crowdsec.DefaultLimits, "2026-10-30T12:00:00Z")
			if u.Outcome != "accepted" || len(u.Rules) != 110 {
				t.Fatalf("not inside the static bounds: %s, %d rules", u.Code, len(u.Rules))
			}
			e.serve(raw)
			t0 := time.Now()
			e.src.Check(context.Background())
			t.Logf("check took %s", time.Since(t0).Round(time.Millisecond))
			st := e.status2()
			if st.LastRefusal == nil || st.LastRefusal.Code != crowdsec.RefuseCost {
				t.Fatalf("want %s, got %+v", crowdsec.RefuseCost, st.LastRefusal)
			}
			if e.engine.Current() != inst || st.RulesLoaded != before.RulesLoaded || st.SetSource != crowdsec.SetImage || st.UpdateState != "refused" {
				t.Fatalf("running set touched: %+v", st)
			}
			if _, err := e.st.Get(context.Background(), crowdsec.StoreKey); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("a refused set was stored: %v", err)
			}
			if ev := e.events(t); len(ev) != 1 || ev[0].Outcome != "refused" || ev[0].Code != crowdsec.RefuseCost {
				t.Fatalf("events %+v", ev)
			}
		})
	}
}

// D43, finding 1: the static bounds alone stop the shape as measured, 995
// rules of six groups, before anything compiles.
func TestStaticBoundsStopTheMeasuredShape(t *testing.T) {
	names := ruleNames(995)
	raw := indexOf(names, func(n string) string { return "x" })
	if u := crowdsec.CheckIndex(raw, nil, crowdsec.DefaultLimits, "2026-10-30T12:00:00Z"); u.Code != crowdsec.RefuseTooManyRules {
		t.Fatalf("%+v", u.Code)
	}
	rng := rand.New(rand.NewSource(26))
	bodies := map[string]string{}
	names = ruleNames(400)
	for i, n := range names {
		bodies[n] = hostileRule(rng, n, "URI", i)
	}
	u := crowdsec.CheckIndex(indexOf(names, func(n string) string { return bodies[n] }), nil, crowdsec.DefaultLimits, "2026-10-30T12:00:00Z")
	if u.Code != crowdsec.RefuseSetTooLarge {
		t.Fatalf("%+v", u.Code)
	}
}

// D43, finding 1: a normal update passes the real measurement on a machine
// with every core busy: the sample is relative.
func TestNormalSetPassesOnABusyMachine(t *testing.T) {
	image, shipped := shippedRules(t)
	e := newEnv(t, setup{auto: true, image: image})
	before := e.status2().RulesLoaded
	names, bodies := []string{}, map[string]string{}
	for n, y := range shipped {
		names = append(names, n)
		bodies[n] = y
	}
	for i := range 40 {
		n := fmt.Sprintf("new-%d", i)
		names = append(names, n)
		bodies[n] = yamlRule("crowdsecurity/vpatch-"+n, "a"+strings.ReplaceAll(n, "-", ""), "evil")
	}
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for range runtime.GOMAXPROCS(0) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			x := 0
			for {
				select {
				case <-stop:
					return
				default:
					x++
				}
			}
		}()
	}
	e.serve(indexOf(names, func(n string) string { return bodies[n] }))
	e.src.Check(context.Background())
	close(stop)
	wg.Wait()
	st := e.status2()
	if st.LastRefusal != nil || st.SetSource != crowdsec.SetStored || st.RulesLoaded != before+40 {
		t.Fatalf("refused: %+v, %d rules", st.LastRefusal, st.RulesLoaded)
	}
}

// The check runs only when something would go live, and a failed measurement
// keeps the running set.
func TestCostCheckRunsOnlyOnAChange(t *testing.T) {
	var runs atomic.Int64
	var fail atomic.Bool
	e := newEnv(t, setup{auto: true, cost: func(ctx context.Context, r, c []waf.HubRule) (crowdsec.CostSample, error) {
		runs.Add(1)
		if len(r) != 4 {
			t.Errorf("reference has %d rules, want the 4 of the image", len(r))
		}
		if fail.Load() {
			return crowdsec.CostSample{}, errors.New("no")
		}
		return noCost(ctx, r, c)
	}})
	e.serve(index("one", "two", "three", "four"))
	e.src.Check(context.Background())
	if runs.Load() != 0 {
		t.Fatal("the same rules were measured")
	}
	e.serve(index("one", "two", "three", "four", "five"))
	e.src.Check(context.Background())
	if st := e.status2(); runs.Load() != 1 || st.RulesLoaded != 5 {
		t.Fatalf("runs %d, %+v", runs.Load(), st)
	}
	fail.Store(true)
	e.serve(index("one", "two", "three", "four", "five", "six"))
	e.src.Check(context.Background())
	if st := e.status2(); st.LastRefusal == nil || st.LastRefusal.Code != crowdsec.RefuseCost || st.RulesLoaded != 5 {
		t.Fatalf("%+v", st)
	}
}

// Finding 6: the first check after the image with the same rules builds
// nothing and writes no event, whatever commit the rules came from.
func TestFirstCheckWithTheSameRulesIsQuiet(t *testing.T) {
	e := newEnv(t, setup{auto: true})
	builds := e.b.prepared.Load()
	e.serve(index("one", "two", "three", "four"))
	e.src.Check(context.Background())
	if e.b.prepared.Load() != builds || len(e.events(t)) != 0 {
		t.Fatalf("builds %d events %+v", e.b.prepared.Load()-builds, e.events(t))
	}
	if st := e.status2(); st.LastChange != nil || st.UpdateState != "current" {
		t.Fatalf("%+v", st)
	}
}

// bigSetDB leaves a running set of n rules in a stopped gateway's database,
// the state of the measurement before finding 2.
func bigSetDB(t *testing.T, n int) string {
	t.Helper()
	e := newEnv(t, setup{auto: true, cost: noCost})
	e.serve(index(ruleNames(n)...))
	e.src.Check(context.Background())
	if st := e.status2(); st.SetSource != crowdsec.SetStored || st.RulesLoaded != n {
		t.Fatalf("%+v", st)
	}
	e.close()
	return e.path
}

// D43, finding 2: the path of the report. A set that ran too large never
// blocks a normal index: not after an update, not after off and on, not after
// a restart.
func TestShrinkDoesNotBlockTheWayBack(t *testing.T) {
	normal := index("one", "two", "three", "four")
	t.Run("update", func(t *testing.T) {
		e := newEnv(t, setup{auto: true, path: bigSetDB(t, 40), cost: noCost})
		if st := e.status2(); st.RulesLoaded != 40 {
			t.Fatalf("%+v", st)
		}
		e.serve(normal)
		e.src.Check(context.Background())
		if st := e.status2(); st.LastRefusal != nil || st.RulesLoaded != 4 || st.SetSource != crowdsec.SetStored {
			t.Fatalf("%+v", st)
		}
	})
	t.Run("off and on", func(t *testing.T) {
		e := newEnv(t, setup{auto: true, path: bigSetDB(t, 40), cost: noCost})
		e.setState(t, crowdsec.StateOff)
		if st := e.status2(); st.SetSource != crowdsec.SetNone || st.RulesLoaded != 0 {
			t.Fatalf("off: %+v", st)
		}
		if _, err := e.st.Get(context.Background(), crowdsec.StoreKey); err != nil {
			t.Fatalf("off dropped the stored set: %v", err)
		}
		e.setState(t, crowdsec.StateDetect)
		if st := e.status2(); st.SetSource != crowdsec.SetStored || st.RulesLoaded != 40 {
			t.Fatalf("on: %+v", st)
		}
		e.serve(normal)
		e.src.Check(context.Background())
		if st := e.status2(); st.LastRefusal != nil || st.RulesLoaded != 4 {
			t.Fatalf("%+v", st)
		}
	})
	t.Run("hollow index stays refused", func(t *testing.T) {
		e := newEnv(t, setup{auto: true, path: bigSetDB(t, 40), cost: noCost})
		e.serve(index("one"))
		e.src.Check(context.Background())
		if st := e.status2(); st.LastRefusal == nil || st.LastRefusal.Code != crowdsec.RefuseShrink || st.RulesLoaded != 40 {
			t.Fatalf("%+v", st)
		}
	})
	t.Run("no walk down", func(t *testing.T) {
		e := newEnv(t, setup{auto: true, cost: noCost})
		e.serve(index("one", "two"))
		e.src.Check(context.Background())
		if st := e.status2(); st.RulesLoaded != 2 {
			t.Fatalf("half of the image: %+v", st)
		}
		e.serve(index("one"))
		e.src.Check(context.Background())
		if st := e.status2(); st.LastRefusal == nil || st.LastRefusal.Code != crowdsec.RefuseShrink || st.RulesLoaded != 2 {
			t.Fatalf("a smaller set lowered the mark: %+v", st)
		}
	})
}

// (setState stands in for App.SwitchHub: the configuration changed, then the
// rebuild.)
func (e *env) setState(t *testing.T, state string) {
	t.Helper()
	c := *e.cfg.Load()
	c.Rules.Crowdsec.State = state
	e.cfg.Store(&c)
	if err := e.src.SetState(context.Background(), true); err != nil {
		t.Fatal(err)
	}
}

// D43, finding 2: a pin wins over shrink. The operator named the commit.
func TestPinWinsOverShrink(t *testing.T) {
	pin := strings.Repeat("b", 40)
	e := newEnv(t, setup{auto: false, pin: pin, path: bigSetDB(t, 40), cost: noCost})
	e.serve(index("one"))
	e.src.Check(context.Background())
	if st := e.status2(); st.LastRefusal != nil || st.UpdateState != "pinned" || st.RulesLoaded != 1 {
		t.Fatalf("%+v", st)
	}
}

// D43, finding 2: the operator's way back works with updates off, without the
// network and across a restart, and is on the record.
func TestResetGoesBackToTheImage(t *testing.T) {
	e := newEnv(t, setup{auto: false, path: bigSetDB(t, 40), cost: noCost})
	if st := e.status2(); st.SetSource != crowdsec.SetStored || st.RulesLoaded != 40 {
		t.Fatalf("%+v", st)
	}
	if err := e.src.Reset(context.Background()); err != nil {
		t.Fatal(err)
	}
	st := e.status2()
	if st.SetSource != crowdsec.SetImage || st.RulesLoaded != 4 || loadedCount(e) != 4 {
		t.Fatalf("%+v", st)
	}
	if _, err := e.st.Get(context.Background(), crowdsec.StoreKey); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("stored set still there: %v", err)
	}
	ev := e.events(t)
	if len(ev) == 0 || ev[0].Outcome != "reset" || ev[0].SetSource != crowdsec.SetImage || ev[0].RulesLoaded != 4 {
		t.Fatalf("events %+v", ev)
	}
	path := e.path
	e.close()
	r := newEnv(t, setup{auto: false, path: path})
	if st := r.status2(); st.SetSource != crowdsec.SetImage || st.RulesLoaded != 4 {
		t.Fatalf("after restart: %+v", st)
	}
}

// Off keeps nothing running; a reset in off drops the stored set only.
func TestResetInStateOff(t *testing.T) {
	e := newEnv(t, setup{auto: false, state: crowdsec.StateOff, path: bigSetDB(t, 40)})
	if err := e.src.Reset(context.Background()); err != nil {
		t.Fatal(err)
	}
	if st := e.status2(); st.SetSource != crowdsec.SetNone || st.RulesLoaded != 0 {
		t.Fatalf("%+v", st)
	}
	if _, err := e.st.Get(context.Background(), crowdsec.StoreKey); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("stored set still there: %v", err)
	}
	e.setState(t, crowdsec.StateDetect)
	if st := e.status2(); st.SetSource != crowdsec.SetImage {
		t.Fatalf("%+v", st)
	}
}

func TestResetWithoutASnapshot(t *testing.T) {
	e := newEnv(t, setup{auto: false, noImage: true})
	if err := e.src.Reset(context.Background()); !errors.Is(err, hub.ErrNoSnapshot) {
		t.Fatalf("%v", err)
	}
}

// editStoredRow changes the row of a stopped gateway.
func editStoredRow(t *testing.T, path string, f func(row map[string]any)) {
	t.Helper()
	st, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	raw, err := st.Get(context.Background(), crowdsec.StoreKey)
	if err != nil {
		t.Fatal(err)
	}
	row := map[string]any{}
	if err := json.Unmarshal(raw, &row); err != nil {
		t.Fatal(err)
	}
	f(row)
	b, _ := json.Marshal(row)
	if err := st.Put(context.Background(), crowdsec.StoreKey, b); err != nil {
		t.Fatal(err)
	}
}

// D43: a row from before the cost check does not load, so an upgrade heals a
// gateway that holds a hostile set.
func TestStoredSetWithoutCostCheckFallsBackToTheImage(t *testing.T) {
	path := storedDB(t)
	editStoredRow(t, path, func(row map[string]any) { delete(row, "cost_checked") })
	e := newEnv(t, setup{auto: false, path: path})
	if st := e.status2(); st.SetSource != crowdsec.SetImage || st.RulesLoaded != 4 {
		t.Fatalf("%+v", st)
	}
}

// D43: a stored set above the bounds of this contract does not load.
func TestStoredSetAboveTheBoundsFallsBackToTheImage(t *testing.T) {
	e := newEnv(t, setup{auto: true, cost: noCost})
	e.serve(index(ruleNames(crowdsec.MaxRules)...))
	e.src.Check(context.Background())
	if st := e.status2(); st.RulesLoaded != crowdsec.MaxRules {
		t.Fatalf("%+v", st)
	}
	e.close()
	raw := index(ruleNames(crowdsec.MaxRules + 1)...)
	u := crowdsec.CheckIndex(raw, nil, crowdsec.Limits{IndexBytes: crowdsec.MaxIndexBytes, Rules: 1000, SetBytes: crowdsec.MaxSetBytes, SetLines: crowdsec.MaxSetLines}, "2026-10-30T12:00:00Z")
	set, _, err := hub.BuildSet(raw, u, u.Rules, "", "2026-10-30T12:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(set)
	editStoredRow(t, e.path, func(row map[string]any) { row["set"] = json.RawMessage(b) })
	r := newEnv(t, setup{auto: false, path: e.path})
	if st := r.status2(); st.SetSource != crowdsec.SetImage || st.RulesLoaded != 4 {
		t.Fatalf("%+v", st)
	}
}
