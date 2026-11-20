package hub_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/deutschland-schild/schild/contract/keys"
	"time"

	"github.com/deutschland-schild/schild/contract/config"
	"github.com/deutschland-schild/schild/contract/crowdsec"
	"github.com/deutschland-schild/schild/contract/events"
	"github.com/deutschland-schild/schild/contract/rules"
	"github.com/deutschland-schild/schild/gateway/internal/eventlog"
	"github.com/deutschland-schild/schild/gateway/internal/hub"
	"github.com/deutschland-schild/schild/gateway/internal/ruleset"
	"github.com/deutschland-schild/schild/gateway/internal/store"
	"github.com/deutschland-schild/schild/gateway/internal/waf"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

// yamlRule is a hub rule on ?<arg>=<value>.
func yamlRule(name, arg, value string) string {
	return fmt.Sprintf(`name: %s
description: Detects a test exploit
rules:
  - and:
      - zones: [URI]
        transform: [lowercase]
        match: { type: contains, value: /vulnerable/%s }
      - zones: [ARGS]
        variables: [%s]
        match: { type: contains, value: %s }
labels:
  label: Test rule
  classification:
    - cve.CVE-2026-0001
`, name, arg, arg, value)
}

// index builds a .index.json; rules maps a short name to its YAML (name is
// filled in for %s). A value of "!digest" breaks the digest of that rule.
func index(names ...string) []byte {
	return indexOf(names, func(n string) string {
		return yamlRule("crowdsecurity/vpatch-"+n, "a"+strings.ReplaceAll(n, "-", ""), "evil")
	})
}

func indexOf(names []string, content func(string) string) []byte {
	items := map[string]any{}
	var members []string
	for _, n := range names {
		full := "crowdsecurity/vpatch-" + n
		y := content(n)
		sum := sha256.Sum256([]byte(y))
		items[full] = map[string]any{"path": "appsec-rules/" + full + ".yaml", "version": "0.1", "content": base64.StdEncoding.EncodeToString([]byte(y)),
			"versions": map[string]any{"0.1": map[string]any{"digest": hex.EncodeToString(sum[:])}}}
		members = append(members, full)
	}
	doc := map[string]any{"appsec-rules": items, "collections": map[string]any{crowdsec.Collection: map[string]any{"appsec-rules": members}}}
	b, _ := json.Marshal(doc)
	return b
}

// imageOf makes a snapshot of an index.
func imageOf(t *testing.T, raw []byte, commit, at string) []byte {
	t.Helper()
	u := crowdsec.CheckIndex(raw, nil, crowdsec.DefaultLimits, at)
	if u.Outcome != "accepted" {
		t.Fatalf("image index refused: %s", u.Code)
	}
	set, _, err := hub.BuildSet(raw, u, u.Rules, commit, at)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(set)
	return b
}

// countingBuilder counts the builds that reach the WAF.
type countingBuilder struct {
	hub.Builder
	prepared atomic.Int64
	delay    time.Duration
}

func (c *countingBuilder) PrepareHub(h []waf.HubRule) (*waf.Instance, uint64, error) {
	c.prepared.Add(1)
	if c.delay > 0 {
		time.Sleep(c.delay)
	}
	return c.Builder.PrepareHub(h)
}

// decisions are the decisions of people and agents in a test.
type decisions struct {
	mu       sync.Mutex
	disabled map[string]string
}

func (d *decisions) Disabled(rule string) (string, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	by, ok := d.disabled[rule]
	return by, ok
}

type env struct {
	t      *testing.T
	st     *store.Store
	engine *waf.Engine
	mgr    *ruleset.Composer
	b      *countingBuilder
	dec    *decisions
	src    *hub.Source
	ev     *eventlog.Log
	cfg    atomic.Pointer[config.Site]
	now    atomic.Pointer[time.Time]
	srv    *httptest.Server
	body   atomic.Pointer[[]byte]
	status atomic.Int32
	reqs   atomic.Int64
	etags  atomic.Int64 // requests with If-None-Match
	lastUA atomic.Value
	cancel context.CancelFunc
	path   string
}

type setup struct {
	state    string
	auto     bool
	pin      string
	image    []byte
	noImage  bool
	check    func([]waf.HubRule) error
	cost     func(context.Context, []waf.HubRule, []waf.HubRule) (crowdsec.CostSample, error)
	timeout  time.Duration
	disabled []string
	path     string
}

func newEnv(t *testing.T, o setup) *env {
	if keys.Release {
		// The fake hub is reached through SCHILD_CROWDSEC_HUB_URL, which a
		// release build ignores (D77): the test would ask the real hub.
		t.Skip("needs the test hub URL, which release builds ignore")
	}
	t.Helper()
	e := &env{t: t, path: o.path}
	if e.path == "" {
		e.path = filepath.Join(t.TempDir(), "schild.db")
	}
	var err error
	e.st, err = store.Open(e.path)
	if err != nil {
		t.Fatal(err)
	}
	if o.state == "" {
		o.state = crowdsec.StateDetect
	}
	settling := 86400
	e.cfg.Store(&config.Site{Rules: config.Rules{Crowdsec: config.CrowdsecRules{State: o.state, AutoUpdate: &o.auto, IntervalS: 3600, Pin: o.pin, SettlingS: &settling, DisabledRules: o.disabled}}})
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	e.now.Store(&now)
	e.engine = &waf.Engine{}
	e.mgr = ruleset.NewComposer(e.engine, waf.Config{}, quiet, nil)
	e.b = &countingBuilder{Builder: e.mgr.HubBuilder()}
	e.dec = &decisions{disabled: map[string]string{}}
	ctx, cancel := context.WithCancel(context.Background())
	e.cancel = cancel
	e.ev = eventlog.New(e.st, "test", nil, quiet)
	e.ev.Validate = true
	go e.ev.Run(ctx)
	e.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e.reqs.Add(1)
		e.lastUA.Store(r.UserAgent())
		if r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" {
			t.Errorf("credentials sent to the hub")
		}
		if s := e.status.Load(); s != 0 {
			w.WriteHeader(int(s))
			return
		}
		b := e.body.Load()
		sum := sha256.Sum256(*b)
		tag := `"` + hex.EncodeToString(sum[:8]) + `"`
		if r.Header.Get("If-None-Match") != "" {
			e.etags.Add(1)
			if r.Header.Get("If-None-Match") == tag {
				w.WriteHeader(http.StatusNotModified)
				return
			}
		}
		w.Header().Set("ETag", tag)
		_, _ = w.Write(*b)
	}))
	t.Setenv(crowdsec.TestURLEnv, e.srv.URL)
	image := o.image
	if image == nil && !o.noImage {
		image = imageOf(t, index("one", "two", "three", "four"), strings.Repeat("a", 40), "2026-10-01T00:00:00Z")
	}
	if o.noImage {
		image = []byte{}
	}
	e.src = hub.New(hub.Options{Store: e.st, Builder: e.b, Config: e.cfg.Load, Events: e.ev, Log: quiet, Now: func() time.Time { return *e.now.Load() },
		Decisions: e.dec, Image: image, Client: e.srv.Client(), Check: o.check, Cost: o.cost, CompileTimeout: o.timeout})
	e.src.Prepare(ctx)
	if err := e.mgr.Start(); err != nil {
		t.Fatal(err)
	}
	e.src.AfterStart()
	t.Cleanup(e.close)
	return e
}

var closed sync.Map

func (e *env) close() {
	if _, dup := closed.LoadOrStore(e, true); dup {
		return
	}
	e.cancel()
	e.srv.Close()
	time.Sleep(10 * time.Millisecond)
	_ = e.st.Close()
}

func (e *env) serve(raw []byte) { e.body.Store(&raw) }

// stat is the status of the source with the counts of its rules in mode
// autoblock.
type stat struct {
	hub.Info
	RulesLoaded, RulesSkipped, RulesDisabled, RulesSettling int
}

func statusOf(src *hub.Source, state string, now time.Time) stat {
	sum := src.Summary(state)
	st := stat{Info: sum.Info, RulesLoaded: sum.Loaded, RulesSkipped: sum.Skipped}
	for _, r := range src.Rules() {
		in := r.Input
		in.Mode, in.State, in.Now = rules.ModeAutoblock, state, now.Unix()
		switch rules.Compute(in).Status {
		case rules.StatusDisabled:
			st.RulesDisabled++
		case rules.StatusSettling:
			st.RulesSettling++
		}
	}
	return st
}

func (e *env) status2() stat {
	return statusOf(e.src, e.cfg.Load().Rules.Crowdsec.State, *e.now.Load())
}

func (e *env) events(t *testing.T) []events.RepositoryUpdated {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	e.ev.Flush(ctx)
	rows, _, err := e.st.ListEvents(context.Background(), store.EventFilter{Type: events.RuleRepositoryUpdated}, 0, 50)
	if err != nil {
		t.Fatal(err)
	}
	var out []events.RepositoryUpdated
	for _, r := range rows {
		var b struct {
			Data events.RepositoryUpdated `json:"data"`
		}
		if json.Unmarshal(r.Body, &b) != nil {
			t.Fatal("event body")
		}
		out = append(out, b.Data)
	}
	return out
}

func loadedCount(e *env) int { return len(e.engine.Current().Hub) }

func TestImageRunsWithoutNetwork(t *testing.T) {
	e := newEnv(t, setup{auto: true})
	e.status.Store(http.StatusBadGateway)
	st := e.status2()
	if st.SetSource != crowdsec.SetImage || st.RulesLoaded != 4 || loadedCount(e) != 4 {
		t.Fatalf("status %+v, %d rules in the WAF", st, loadedCount(e))
	}
	e.srv.Close() // no network at all
	e.src.Check(context.Background())
	st = e.status2()
	if st.UpdateState != "unreachable" || st.LastRefusal == nil || st.LastRefusal.Code != crowdsec.RefuseFetchFailed {
		t.Fatalf("status %+v", st)
	}
	if st.SetSource != crowdsec.SetImage || loadedCount(e) != 4 {
		t.Fatalf("rules gone: %+v", st)
	}
	// The second identical failure writes nothing new.
	e.src.Check(context.Background())
	if ev := e.events(t); len(ev) != 1 || ev[0].Outcome != "refused" || ev[0].Code != crowdsec.RefuseFetchFailed {
		t.Fatalf("events %+v", ev)
	}
}

func TestNoSetAtAllIsNoError(t *testing.T) {
	e := newEnv(t, setup{auto: false, noImage: true})
	if st := e.status2(); st.SetSource != crowdsec.SetNone || st.RulesLoaded != 0 || loadedCount(e) != 0 {
		t.Fatalf("%+v", st)
	}
}

func TestBrokenImageIsSkipped(t *testing.T) {
	e := newEnv(t, setup{auto: false, image: []byte(`{"schema":"nonsense"}`)})
	if st := e.status2(); st.SetSource != crowdsec.SetNone {
		t.Fatalf("%+v", st)
	}
}

func TestUpdateSwapsAndRestartKeepsTheSet(t *testing.T) {
	e := newEnv(t, setup{auto: true})
	e.serve(index("one", "two", "three", "four", "five"))
	e.src.Check(context.Background())
	st := e.status2()
	if st.SetSource != crowdsec.SetStored || st.RulesLoaded != 5 || loadedCount(e) != 5 || st.UpdateState != "current" {
		t.Fatalf("%+v, %d", st, loadedCount(e))
	}
	if st.LastChange == nil || st.LastChange.Added != 1 || st.LastChange.Changed != 0 || st.LastChange.Removed != 0 {
		t.Fatalf("change %+v", st.LastChange)
	}
	if ev := e.events(t); len(ev) != 1 || ev[0].Outcome != "accepted" || len(ev[0].Added) != 1 || ev[0].RulesLoaded != 5 {
		t.Fatalf("events %+v", ev)
	}
	if got, _ := e.lastUA.Load().(string); got != crowdsec.UserAgent {
		t.Fatalf("user agent %q", got)
	}
	// Nothing new: an ETag, no build, no event.
	builds := e.b.prepared.Load()
	e.src.Check(context.Background())
	if e.etags.Load() != 1 || e.b.prepared.Load() != builds || len(e.events(t)) != 1 {
		t.Fatalf("etags %d builds %d events %d", e.etags.Load(), e.b.prepared.Load()-builds, len(e.events(t)))
	}
	// Restart on the same database, the hub unreachable.
	path := e.path
	e.close()
	r := newEnv(t, setup{auto: true, path: path})
	if st := r.status2(); st.SetSource != crowdsec.SetStored || st.RulesLoaded != 5 || loadedCount(r) != 5 || st.LastChange == nil {
		t.Fatalf("after restart: %+v", st)
	}
}

func TestChangedRuleKeepsFirstSeen(t *testing.T) {
	e := newEnv(t, setup{auto: true})
	base := func(n string) string { return yamlRule("crowdsecurity/vpatch-"+n, "a"+n, "evil") }
	e.serve(indexOf([]string{"one", "two", "three", "four"}, func(n string) string {
		if n == "two" {
			return yamlRule("crowdsecurity/vpatch-two", "atwo", "worse")
		}
		return base(n)
	}))
	later := e.now.Load().Add(time.Hour)
	e.now.Store(&later)
	e.src.Check(context.Background())
	byName := map[string]hub.Rule{}
	for _, r := range e.src.Rules() {
		byName[r.View.Name] = r
	}
	two, one := byName["crowdsecurity/vpatch-two"], byName["crowdsecurity/vpatch-one"]
	if two.View.FirstSeen != "2026-10-01T00:00:00Z" || two.View.ChangedAt != "2026-10-30T13:00:00Z" {
		t.Fatalf("two %+v", two.View)
	}
	if one.View.ChangedAt != "2026-10-01T00:00:00Z" {
		t.Fatalf("one moved: %+v", one.View)
	}
}

// Every update-level refusal keeps the running set.
func TestRefusalsKeepTheRunningSet(t *testing.T) {
	names := func(n int) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = fmt.Sprintf("r%d", i)
		}
		return out
	}
	bad := func(string) string { return "not: [a rule" }
	cases := []struct {
		name   string
		code   string
		body   []byte
		status int
	}{
		{name: "status", code: crowdsec.RefuseFetchStatus, status: 500},
		{name: "not found", code: crowdsec.RefuseFetchStatus, status: 404},
		{name: "not json", code: crowdsec.RefuseMalformed, body: []byte("<html>")},
		{name: "truncated", code: crowdsec.RefuseMalformed, body: index("one", "two")[:60]},
		{name: "no collection", code: crowdsec.RefuseMalformed, body: []byte(`{"appsec-rules":{}}`)},
		{name: "too many", code: crowdsec.RefuseTooManyRules, body: indexOf(names(crowdsec.MaxRules+1), func(n string) string { return "x" })},
		{name: "nothing loads", code: crowdsec.RefuseEmpty, body: indexOf([]string{"a", "b", "c", "d", "e"}, bad)},
		{name: "hollow index", code: crowdsec.RefuseShrink, body: index("one")},
		{name: "oversize", code: crowdsec.RefuseIndexSize, body: bytes.Repeat([]byte("x"), crowdsec.MaxIndexBytes+1)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t, setup{auto: true})
			e.status.Store(int32(c.status))
			e.serve(c.body)
			before := e.engine.Current()
			e.src.Check(context.Background())
			st := e.status2()
			if st.LastRefusal == nil || st.LastRefusal.Code != c.code {
				t.Fatalf("want %s, got %+v", c.code, st.LastRefusal)
			}
			if e.engine.Current() != before || st.RulesLoaded != 4 || st.SetSource != crowdsec.SetImage {
				t.Fatalf("running set touched: %+v", st)
			}
			want := "refused"
			if c.code == crowdsec.RefuseFetchStatus {
				want = "unreachable"
			}
			if st.UpdateState != want {
				t.Fatalf("update_state %s", st.UpdateState)
			}
		})
	}
}

func TestSetTooLarge(t *testing.T) {
	e := newEnv(t, setup{auto: true})
	pad := "# " + strings.Repeat("x", 40000) + "\n"
	names := make([]string, 300)
	for i := range names {
		names[i] = fmt.Sprintf("r%d", i)
	}
	e.serve(indexOf(names, func(n string) string { return pad + yamlRule("crowdsecurity/vpatch-"+n, "a"+n, "evil") }))
	e.src.Check(context.Background())
	if st := e.status2(); st.LastRefusal == nil || st.LastRefusal.Code != crowdsec.RefuseSetTooLarge || st.RulesLoaded != 4 {
		t.Fatalf("%+v", st)
	}
}

func TestGzipBombIsCutOff(t *testing.T) {
	e := newEnv(t, setup{auto: true})
	var z bytes.Buffer
	w := gzip.NewWriter(&z)
	chunk := make([]byte, 1<<20)
	for range 40 {
		_, _ = w.Write(chunk)
	}
	_ = w.Close()
	e.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = w.Write(z.Bytes())
	})
	e.src.Check(context.Background())
	if st := e.status2(); st.LastRefusal == nil || st.LastRefusal.Code != crowdsec.RefuseIndexSize {
		t.Fatalf("%+v", st.LastRefusal)
	}
}

func TestSlowHubIsAbandoned(t *testing.T) {
	e := newEnv(t, setup{auto: true})
	release := make(chan struct{})
	e.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		<-release
	})
	defer close(release)
	client := *e.srv.Client()
	client.Timeout = 100 * time.Millisecond
	src := hub.New(hub.Options{Store: e.st, Builder: e.b, Config: e.cfg.Load, Log: quiet, Client: &client, Image: []byte{}})
	src.Check(context.Background())
	if st := statusOf(src, crowdsec.StateDetect, *e.now.Load()); st.LastRefusal == nil || st.LastRefusal.Code != crowdsec.RefuseFetchFailed {
		t.Fatalf("%+v", st.LastRefusal)
	}
}

func TestRedirectAwayIsRefused(t *testing.T) {
	var foreign atomic.Int64
	other := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { foreign.Add(1) }))
	defer other.Close()
	e := newEnv(t, setup{auto: true})
	e.srv.Config.Handler = http.RedirectHandler(other.URL, http.StatusFound)
	src := hub.New(hub.Options{Store: e.st, Builder: e.b, Config: e.cfg.Load, Log: quiet, Image: []byte{}})
	src.Check(context.Background())
	if foreign.Load() != 0 {
		t.Fatal("redirect followed")
	}
	if st := statusOf(src, crowdsec.StateDetect, *e.now.Load()); st.LastRefusal == nil || st.LastRefusal.Code != crowdsec.RefuseFetchFailed {
		t.Fatalf("%+v", st.LastRefusal)
	}
}

func TestExpensiveRegexIsSkipped(t *testing.T) {
	e := newEnv(t, setup{auto: true})
	e.serve(indexOf([]string{"one", "two", "three", "four"}, func(n string) string {
		if n == "two" {
			return strings.Replace(yamlRule("crowdsecurity/vpatch-two", "atwo", "x"), "type: contains, value: x", "type: regex, value: '(?:abcdefghij){500}'", 1)
		}
		return yamlRule("crowdsecurity/vpatch-"+n, "a"+n, "evil")
	}))
	e.src.Check(context.Background())
	st := e.status2()
	if st.RulesLoaded != 3 || st.RulesSkipped != 1 || st.Skipped[0].Code != crowdsec.SkipRegexCost {
		t.Fatalf("%+v", st)
	}
	if st.LastChange == nil || st.LastChange.Removed != 1 {
		t.Fatalf("change %+v", st.LastChange)
	}
}

func TestOneRuleThatDoesNotCompileIsSkipped(t *testing.T) {
	check := func(rs []waf.HubRule) error {
		for _, r := range rs {
			if strings.HasSuffix(r.Name, "-five") {
				return errors.New("refused")
			}
		}
		return waf.CheckHub(rs)
	}
	e := newEnv(t, setup{auto: true, check: check})
	e.serve(index("one", "two", "three", "four", "five"))
	e.src.Check(context.Background())
	st := e.status2()
	if st.RulesLoaded != 4 || st.RulesSkipped != 1 || st.Skipped[0].Code != crowdsec.SkipCompileFailed || st.UpdateState != "current" {
		t.Fatalf("%+v", st)
	}
}

func TestSetThatNeverCompilesIsRefused(t *testing.T) {
	var fail atomic.Bool
	check := func(rs []waf.HubRule) error {
		if fail.Load() && len(rs) > 1 {
			return errors.New("refused")
		}
		return nil
	}
	e := newEnv(t, setup{auto: true, check: check})
	fail.Store(true)
	before := e.engine.Current()
	e.serve(index("one", "two", "three", "four", "five"))
	e.src.Check(context.Background())
	if st := e.status2(); st.LastRefusal == nil || st.LastRefusal.Code != crowdsec.RefuseCompile || st.RulesLoaded != 4 || e.engine.Current() != before {
		t.Fatalf("%+v", st)
	}
}

func TestSlowBuildIsAbandoned(t *testing.T) {
	e := newEnv(t, setup{auto: true, timeout: 30 * time.Millisecond})
	e.b.delay = 200 * time.Millisecond
	before := e.engine.Current()
	e.serve(index("one", "two", "three", "four", "five"))
	e.src.Check(context.Background())
	if st := e.status2(); st.LastRefusal == nil || st.LastRefusal.Code != crowdsec.RefuseCompileTime || st.RulesLoaded != 4 {
		t.Fatalf("%+v", st)
	}
	time.Sleep(300 * time.Millisecond) // the abandoned build ends
	if e.engine.Current() != before {
		t.Fatal("an abandoned build went live")
	}
}

func TestHostileUpdateNeverStopsRequests(t *testing.T) {
	e := newEnv(t, setup{auto: true})
	stop := make(chan struct{})
	var bad atomic.Int64
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				inst := e.engine.Current()
				if inst == nil || len(inst.Hub) < 4 {
					bad.Add(1)
				}
				tx := inst.WAF.NewTransaction()
				tx.ProcessURI("/vulnerable/aone?aone=evil", "GET", "HTTP/1.1")
				tx.ProcessRequestHeaders()
				_, _ = tx.ProcessRequestBody()
				_ = tx.Close()
			}
		}()
	}
	for i := range 6 {
		if i%2 == 0 {
			e.serve(index("one", "two", "three", "four", "five"))
		} else {
			e.serve([]byte("hostile"))
		}
		e.src.Check(context.Background())
	}
	close(stop)
	wg.Wait()
	if bad.Load() != 0 {
		t.Fatalf("%d requests without the rules", bad.Load())
	}
}

func TestSwitch(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, setup{state: crowdsec.StateOff, auto: true})
	e.serve(index("one", "two", "three", "four"))
	if st := e.status2(); st.UpdateState != "off" || st.RulesLoaded != 0 || loadedCount(e) != 0 {
		t.Fatalf("off: %+v", st)
	}
	e.src.Check(ctx)
	if e.reqs.Load() != 0 {
		t.Fatal("off fetched")
	}
	set := func(s string) {
		c := *e.cfg.Load()
		before := c.Rules.Crowdsec.State
		c.Rules.Crowdsec.State = s
		e.cfg.Store(&c)
		if err := e.src.SetState(ctx, (before == crowdsec.StateOff) != (s == crowdsec.StateOff)); err != nil {
			t.Fatal(err)
		}
	}
	set(crowdsec.StateDetect)
	if loadedCount(e) != 4 || e.status2().SetSource != crowdsec.SetImage {
		t.Fatalf("on: %d", loadedCount(e))
	}
	builds := e.b.prepared.Load()
	set(crowdsec.StateBlock)
	if e.b.prepared.Load() != builds {
		t.Fatal("detect to block rebuilt")
	}
	if h := e.src.Lookup(crowdsec.BaseID("crowdsecurity/vpatch-one")); h.Origin != rules.OriginRelease || h.Disabled {
		t.Fatalf("%+v", h)
	}
	set(crowdsec.StateOff)
	if loadedCount(e) != 0 || e.b.prepared.Load() != builds+1 {
		t.Fatalf("off: %d", loadedCount(e))
	}
}

// Only updates settle (D73): the rules of the image snapshot are release and
// act at once, a rule the hub brought later waits settling_s from changed_at
// in mode autoblock, and an approval of its version ends that at once.
func TestSettlingCountsFromChangedAt(t *testing.T) {
	e := newEnv(t, setup{state: crowdsec.StateBlock, auto: true})
	if st := e.status2(); st.RulesSettling != 0 {
		t.Fatalf("%+v", st)
	}
	e.serve(index("one", "two", "three", "four", "five"))
	e.src.Check(context.Background())
	st := e.status2()
	if st.RulesSettling != 1 {
		t.Fatalf("%+v", st)
	}
	id := crowdsec.BaseID("crowdsecurity/vpatch-five")
	r, ok := e.src.Rule(id)
	if !ok || r.View.SettlingUntil == nil || *r.View.SettlingUntil != "2026-10-31T12:00:00Z" || r.Input.Origin != rules.OriginUpdate {
		t.Fatalf("%+v", r)
	}
	if one, _ := e.src.Rule(crowdsec.BaseID("crowdsecurity/vpatch-one")); one.Input.Origin != rules.OriginRelease || one.View.SettlingUntil != nil {
		t.Fatalf("a rule of the image settles: %+v", one)
	}
	later := e.now.Load().Add(25 * time.Hour)
	e.now.Store(&later)
	if st := e.status2(); st.RulesSettling != 0 {
		t.Fatalf("%+v", st)
	}
}

// Disabling: the config by name, people and agents by base id (D73); the
// request path sees it at once after a refresh.
func TestDisableOneRule(t *testing.T) {
	cfgRule := "crowdsecurity/vpatch-three"
	e := newEnv(t, setup{auto: false, disabled: []string{cfgRule, "crowdsecurity/vpatch-gone"}})
	id := crowdsec.BaseID("crowdsecurity/vpatch-one")
	e.dec.mu.Lock()
	e.dec.disabled[strconv.Itoa(id)] = rules.ByAgent
	e.dec.mu.Unlock()
	e.src.Refresh()
	if h := e.src.Lookup(id); !h.Disabled || h.DisabledBy != rules.ByAgent {
		t.Fatalf("not disabled: %+v", h)
	}
	if h := e.src.Lookup(crowdsec.BaseID(cfgRule)); !h.Disabled || h.DisabledBy != rules.ByConfig {
		t.Fatalf("config: %+v", h)
	}
	if st := e.status2(); st.RulesDisabled != 2 {
		t.Fatalf("%+v", st)
	}
	if h := e.src.Lookup(12345); h.Origin != rules.OriginUpdate || h.SettlingUntil == 0 {
		t.Fatalf("an unknown rule may act: %+v", h)
	}
}

func TestPin(t *testing.T) {
	pin := strings.Repeat("b", 40)
	e := newEnv(t, setup{auto: false, pin: pin})
	if st := e.status2(); st.UpdateState != "pin_pending" {
		t.Fatalf("%+v", st)
	}
	e.serve(index("one", "two", "three", "four"))
	e.src.Check(context.Background())
	st := e.status2()
	if st.UpdateState != "pinned" || st.HubCommit != pin || st.SetSource != crowdsec.SetStored {
		t.Fatalf("%+v", st)
	}
	n := e.reqs.Load()
	e.src.Check(context.Background())
	if e.reqs.Load() != n {
		t.Fatal("fetched again")
	}
}

func TestUpdatesOff(t *testing.T) {
	e := newEnv(t, setup{auto: false})
	e.src.Check(context.Background())
	if st := e.status2(); e.reqs.Load() != 0 || st.UpdateState != "updates_off" {
		t.Fatalf("%d %+v", e.reqs.Load(), st)
	}
}

func TestShippedSnapshot(t *testing.T) {
	e := newEnv(t, setup{auto: false})
	src := hub.New(hub.Options{Store: e.st, Builder: e.b, Config: e.cfg.Load, Log: quiet, Now: func() time.Time { return *e.now.Load() }})
	src.Prepare(context.Background())
	st := statusOf(src, crowdsec.StateDetect, *e.now.Load())
	if st.SetSource != crowdsec.SetImage || st.RulesLoaded < 150 || st.HubCommit == "" || st.SnapshotAt == nil {
		t.Fatalf("%+v", st)
	}
}

// storeSet leaves a stored set in the database of a stopped gateway.
func storedDB(t *testing.T) string {
	t.Helper()
	e := newEnv(t, setup{auto: true})
	e.serve(index("one", "two", "three", "four", "five"))
	e.src.Check(context.Background())
	if st := e.status2(); st.SetSource != crowdsec.SetStored {
		t.Fatalf("%+v", st)
	}
	e.close()
	return e.path
}

// imageAt is a six-rule snapshot with a commit date.
func imageAt(t *testing.T, at string) []byte {
	t.Helper()
	raw := index("one", "two", "three", "four", "five", "six")
	u := crowdsec.CheckIndex(raw, nil, crowdsec.DefaultLimits, "2026-10-01T00:00:00Z")
	set, _, err := hub.BuildSet(raw, u, u.Rules, strings.Repeat("c", 40), "2026-10-01T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	set.HubCommitAt = at
	b, _ := json.Marshal(set)
	return b
}

// D39 amendment: the newer set runs, whatever auto_update says. The stored set
// of storedDB dates from 2026-10-30T12:00:00Z.
func TestNewerSetWinsAtStart(t *testing.T) {
	cases := []struct {
		name  string
		at    string
		auto  bool
		want  string
		rules int
	}{
		{"image newer", "2026-10-30T12:00:01Z", true, crowdsec.SetImage, 6},
		{"image newer, updates off", "2026-10-30T12:00:01Z", false, crowdsec.SetImage, 6},
		{"tie keeps the stored set", "2026-10-30T12:00:00Z", true, crowdsec.SetStored, 5},
		{"image older", "2026-10-29T12:00:00Z", true, crowdsec.SetStored, 5},
		{"a date far ahead of the clock is no date", "2027-10-30T12:00:00Z", true, crowdsec.SetStored, 5},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := storedDB(t)
			e := newEnv(t, setup{auto: c.auto, path: path, image: imageAt(t, c.at)})
			if st := e.status2(); st.SetSource != c.want || st.RulesLoaded != c.rules {
				t.Fatalf("%+v", st)
			}
		})
	}
}

// When the image wins, the row stays until an accepted update, and the ETag of
// that row is not sent for the image.
func TestImageWinsSendsNoForeignETag(t *testing.T) {
	path := storedDB(t)
	e := newEnv(t, setup{auto: true, path: path, image: imageAt(t, "2026-10-30T12:00:01Z")})
	e.serve(index("one", "two", "three", "four", "five", "six"))
	e.src.Check(context.Background())
	if e.etags.Load() != 0 {
		t.Fatal("an ETag of another set was sent")
	}
	if st := e.status2(); st.SetSource != crowdsec.SetStored || st.RulesLoaded != 6 {
		t.Fatalf("%+v", st)
	}
}

func TestBrokenStoredSetFallsBackToTheImage(t *testing.T) {
	path := storedDB(t)
	st, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Put(context.Background(), crowdsec.StoreKey, []byte(`{"set":{"schema":"tampered"}}`)); err != nil {
		t.Fatal(err)
	}
	_ = st.Close()
	e := newEnv(t, setup{auto: false, path: path})
	if s := e.status2(); s.SetSource != crowdsec.SetImage || s.RulesLoaded != 4 {
		t.Fatalf("%+v", s)
	}
}

func TestPinWinsOverTheNewerSet(t *testing.T) {
	path := storedDB(t)
	pin := strings.Repeat("c", 40)
	e := newEnv(t, setup{auto: true, path: path, pin: pin, image: imageAt(t, "2026-01-01T00:00:00Z")})
	if st := e.status2(); st.SetSource != crowdsec.SetImage || st.UpdateState != "pinned" {
		t.Fatalf("%+v", st)
	}
}

func TestSwitchChangesCoalesce(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, setup{state: crowdsec.StateOff, auto: false})
	e.b.delay = 20 * time.Millisecond
	set := func(s string) {
		c := *e.cfg.Load()
		c.Rules.Crowdsec.State = s
		e.cfg.Store(&c)
	}
	var wg sync.WaitGroup
	for _, s := range []string{crowdsec.StateDetect, crowdsec.StateOff, crowdsec.StateDetect, crowdsec.StateOff, crowdsec.StateDetect} {
		set(s)
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := e.src.SetState(ctx, true); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if loadedCount(e) != 4 || e.status2().RulesLoaded != 4 {
		t.Fatalf("the last state lost: %d", loadedCount(e))
	}
	if n := e.b.prepared.Load(); n != 1 {
		t.Fatalf("%d builds for one result", n)
	}
}
