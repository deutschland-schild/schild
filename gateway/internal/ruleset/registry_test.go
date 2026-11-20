package ruleset

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/deutschland-schild/schild/contract/keys"
	"time"

	"github.com/deutschland-schild/schild/contract/config"
	"github.com/deutschland-schild/schild/contract/crowdsec"
	"github.com/deutschland-schild/schild/contract/rules"
	"github.com/deutschland-schild/schild/gateway/internal/hub"
	"github.com/deutschland-schild/schild/gateway/internal/store"
	"github.com/deutschland-schild/schild/gateway/internal/waf"
)

// settings is the overlay of the app in a test.
type settings struct {
	mu      sync.Mutex
	cfg     atomic.Pointer[config.Site]
	overlay map[string]string
	owners  map[string]Owner
}

func (s *settings) Config() *config.Site { return s.cfg.Load() }

func (s *settings) RuleState(repo string) (string, string, Owner) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return "", s.overlay[repo], s.owners[repo]
}

func (s *settings) SetRuleState(_ context.Context, repo, state string, reset bool, o Owner) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := *s.cfg.Load()
	if reset {
		delete(s.overlay, repo)
		delete(s.owners, repo)
		state = rules.DefaultState(repo)
	} else {
		s.overlay[repo], s.owners[repo] = state, o
	}
	switch repo {
	case rules.RepoCRS:
		c.Rules.CRS.State = state
	case rules.RepoCrowdsec:
		c.Rules.Crowdsec.State = state
	case rules.RepoLocal:
		c.Rules.Local.State = state
	}
	s.cfg.Store(&c)
	return nil
}

func hubYAML(name, value string) string {
	return fmt.Sprintf(`name: %s
description: Detects a test exploit
rules:
  - and:
      - zones: [URI]
        transform: [lowercase]
        match: { type: contains, value: /vulnerable/x }
      - zones: [ARGS]
        variables: [a]
        match: { type: contains, value: %s }
labels:
  label: Test rule
`, name, value)
}

type item struct{ name, version, value string }

// index builds a .index.json of the hub.
func index(items ...item) []byte {
	all := map[string]any{}
	var members []string
	for _, it := range items {
		full := "crowdsecurity/vpatch-" + it.name
		y := hubYAML(full, it.value)
		sum := sha256.Sum256([]byte(y))
		all[full] = map[string]any{"path": "appsec-rules/" + full + ".yaml", "version": it.version, "content": base64.StdEncoding.EncodeToString([]byte(y)),
			"versions": map[string]any{it.version: map[string]any{"digest": hex.EncodeToString(sum[:])}}}
		members = append(members, full)
	}
	b, _ := json.Marshal(map[string]any{"appsec-rules": all, "collections": map[string]any{crowdsec.Collection: map[string]any{"appsec-rules": members}}})
	return b
}

type renv struct {
	t    *testing.T
	reg  *Registry
	set  *settings
	body atomic.Pointer[[]byte]
	now  atomic.Pointer[time.Time]
	dir  string
}

func newRegistry(t *testing.T, mode string, rs config.Rules) *renv {
	if keys.Release {
		// The fake hub is reached through SCHILD_CROWDSEC_HUB_URL, which a
		// release build ignores (D77): the test would ask the real hub.
		t.Skip("needs the test hub URL, which release builds ignore")
	}
	t.Helper()
	e := &renv{t: t, set: &settings{overlay: map[string]string{}, owners: map[string]Owner{}}, dir: filepath.Join(t.TempDir(), "rules.d")}
	cfg, err := config.ParseSite([]byte("config_version: 0\nnode_name: test\nmode: " + mode + "\nupstream: {url: \"http://127.0.0.1:1\"}\n"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Rules.Crowdsec.State = rules.StateBlock
	if rs.CRS.DisabledRules != nil {
		cfg.Rules.CRS.DisabledRules = rs.CRS.DisabledRules
	}
	cfg.Rules.Local.Dir = e.dir
	e.set.cfg.Store(cfg)
	st, err := store.Open(filepath.Join(t.TempDir(), "schild.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	now := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	e.now.Store(&now)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(*e.body.Load()) }))
	t.Cleanup(srv.Close)
	t.Setenv(crowdsec.TestURLEnv, srv.URL)
	raw := index(item{"one", "0.1", "evil1"}, item{"two", "0.1", "evil2"})
	u := crowdsec.CheckIndex(raw, nil, crowdsec.DefaultLimits, "2026-10-01T00:00:00Z")
	set, _, err := hub.BuildSet(raw, u, u.Rules, "", "2026-10-01T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	image, _ := json.Marshal(set)
	c := NewComposer(&waf.Engine{}, waf.Config{}, quiet, nil)
	e.reg, err = New(context.Background(), Options{Store: st, Composer: c, Settings: e.set, Log: quiet, Now: func() time.Time { return *e.now.Load() },
		Hub: hub.Options{Image: image, Client: srv.Client(),
			Cost: func(context.Context, []waf.HubRule, []waf.HubRule) (crowdsec.CostSample, error) {
				return crowdsec.CostSample{BaselineNS: 1, ReferenceNS: 2, CandidateNS: 2, Rounds: 1}, nil
			}}})
	if err != nil {
		t.Fatal(err)
	}
	e.reg.Prepare(context.Background())
	if err := e.reg.Start(); err != nil {
		t.Fatal(err)
	}
	return e
}

func (e *renv) serve(items ...item) {
	b := index(items...)
	e.body.Store(&b)
	if _, err := e.reg.Sync(context.Background(), rules.RepoCrowdsec); err != nil {
		e.t.Fatal(err)
	}
}

func (e *renv) effect(name string) rules.Rule {
	return e.reg.Effect(rules.RepoCrowdsec, crowdsec.BaseID("crowdsecurity/vpatch-"+name), e.set.Config().Mode, *e.now.Load())
}

var dashboardActor = Actor{Kind: rules.ByDashboard}

// D89: no approvals. A rule of the image blocks; an update only detects while
// it settles, is counted and listed as settling, and then blocks on its own.
func TestUpdatesSettle(t *testing.T) {
	e := newRegistry(t, rules.ModeAutoblock, config.Rules{})
	if r := e.effect("one"); r.Status != rules.StatusActive || r.Effect != rules.EffectBlock {
		t.Fatalf("a rule of the image: %+v", r)
	}
	e.serve(item{"one", "0.1", "evil1"}, item{"two", "0.1", "evil2"}, item{"four", "0.1", "evil4"})
	if r := e.effect("four"); r.Status != rules.StatusSettling || r.Effect != rules.EffectDetect || r.LimitedBy != rules.LimitSettling {
		t.Fatalf("an update: %+v", r)
	}
	if v, _ := e.reg.Repository(rules.RepoCrowdsec); v.Counts.Settling != 1 {
		t.Fatalf("counts %+v", v.Counts)
	}
	if got := e.reg.Rules(Filter{Status: rules.StatusSettling}); len(got) != 1 || got[0].Name != "crowdsecurity/vpatch-four" {
		t.Fatalf("settling: %+v", got)
	}
	later := e.now.Load().Add(48 * time.Hour)
	e.now.Store(&later)
	if r := e.effect("four"); r.Status != rules.StatusActive || r.Effect != rules.EffectBlock {
		t.Fatalf("settled: %+v", r)
	}
}

func matches(t *testing.T, inst *waf.Instance, path string, id int) bool {
	t.Helper()
	a, _, err := inst.Probe(httptest.NewRequest("GET", path, nil), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range a.Matches {
		if m.ID == id {
			return true
		}
	}
	return false
}

// Disabling a crs or local rule rebuilds the WAF without it; a rule disabled
// in schild.yaml cannot be enabled; repository detect and off.
func TestDisableCRSAndLocal(t *testing.T) {
	e := newRegistry(t, rules.ModeAutoblock, config.Rules{CRS: config.CRS{DisabledRules: []string{"942100"}}})
	ctx := context.Background()
	engine := func() *waf.Instance { return e.reg.o.Composer.engine.Current() }
	const xss = "/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"
	if !matches(t, engine(), xss, 941100) {
		t.Fatal("941100 does not match")
	}
	d, err := e.reg.SetDisabled(ctx, rules.RepoCRS, "941100", true, "note", Actor{Kind: rules.ByAgent, TokenID: "tok_000000000001", Label: "x"})
	if err != nil || d.Status != rules.StatusDisabled || d.DisabledBy != rules.ByAgent {
		t.Fatalf("%v %+v", err, d)
	}
	if matches(t, engine(), xss, 941100) {
		t.Fatal("the disabled crs rule still runs")
	}
	if _, err := e.reg.SetDisabled(ctx, rules.RepoCRS, "941100", false, "", dashboardActor); err != nil || !matches(t, engine(), xss, 941100) {
		t.Fatalf("enable: %v", err)
	}
	if _, err := e.reg.SetDisabled(ctx, rules.RepoCRS, "942100", false, "", dashboardActor); !errors.Is(err, ErrConfigLimit) {
		t.Fatalf("a rule disabled in schild.yaml: %v", err)
	}
	if d, _ := e.reg.Rule(rules.RepoCRS, "942100"); d.DisabledBy != rules.ByConfig || len(d.Decisions) != 1 || d.Decisions[0].By != rules.ByConfig {
		t.Fatalf("%+v", d)
	}
	if _, err := e.reg.SetDisabled(ctx, rules.RepoCRS, "1", true, "", dashboardActor); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown: %v", err)
	}

	// Local: a sync loads the files, a disabled rule leaves the WAF.
	if err := os.MkdirAll(e.dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(e.dir, "a.conf"), []byte(`SecRule REQUEST_URI "@beginsWith /stop" "id:1000001,phase:1,deny,msg:'stop'"`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if res, err := e.reg.Sync(ctx, rules.RepoLocal); err != nil || res.Rules != 1 {
		t.Fatalf("%v %+v", err, res)
	}
	if !matches(t, engine(), "/stop", 1000001) {
		t.Fatal("the local rule does not run")
	}
	if _, err := e.reg.SetDisabled(ctx, rules.RepoLocal, "1000001", true, "", dashboardActor); err != nil || matches(t, engine(), "/stop", 1000001) {
		t.Fatalf("disable local: %v", err)
	}
	if _, err := e.reg.SetDisabled(ctx, rules.RepoLocal, "1000001", false, "", dashboardActor); err != nil || !matches(t, engine(), "/stop", 1000001) {
		t.Fatalf("enable local: %v", err)
	}
	// A rule in another repository's range is refused, the running rules stay.
	if err := os.WriteFile(filepath.Join(e.dir, "b.conf"), []byte(`SecRule REQUEST_URI "@beginsWith /x" "id:60000000,phase:1,deny"`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var se *SyncError
	if _, err := e.reg.Sync(ctx, rules.RepoLocal); !errors.As(err, &se) || se.Code != CodeIDRange || !matches(t, engine(), "/stop", 1000001) {
		t.Fatalf("id range: %v", err)
	}
	if _, err := e.reg.Sync(ctx, rules.RepoCRS); !errors.Is(err, ErrNotSupported) {
		t.Fatalf("crs sync: %v", err)
	}

	// Repository crs in detect: same WAF, no block; off: not built.
	if _, err := e.reg.SetState(ctx, rules.RepoCRS, rules.StateDetect, false, dashboardActor); err != nil {
		t.Fatal(err)
	}
	if r := e.reg.Effect(rules.RepoCRS, 941100, rules.ModeAutoblock, time.Now()); r.Effect != rules.EffectDetect || r.LimitedBy != rules.LimitRepositoryDetect {
		t.Fatalf("crs detect: %+v", r)
	}
	if !engine().Config.CRS {
		t.Fatal("detect unloaded the CRS")
	}
	if _, err := e.reg.SetState(ctx, rules.RepoCRS, rules.StateOff, false, dashboardActor); err != nil || engine().Config.CRS {
		t.Fatalf("crs off: %v", err)
	}
	if v, _ := e.reg.Repository(rules.RepoCRS); v.State != rules.StateOff || v.StateSource != rules.ByDashboard || v.Effect != rules.EffectOff {
		t.Fatalf("%+v", v)
	}
}
