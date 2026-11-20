package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/keys"
)

const examples = "../../contracts/config/examples/"

func TestSiteExampleT0(t *testing.T) {
	s, err := LoadSite(examples + "schild.t0.yaml")
	if keys.Release {
		if !errors.Is(err, ErrTestProfileInRelease) {
			t.Fatalf("release build accepted the test profile: %v", err)
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	if s.Profile != "test" || s.Mode != "observe" {
		t.Fatal("test profile")
	}
	if s.Retention.RawIPDays != 7 || s.Listen.Proxy != "0.0.0.0:8080" {
		t.Fatal("values")
	}
}

func TestSiteExampleProduction(t *testing.T) {
	s, err := LoadSite(examples + "schild.production.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if s.Profile != "production" {
		t.Fatal("defaults")
	}
	if s.WAF.EvalTimeoutMS != 1000 || s.WAF.RequestBodyLimitBytes != 13107200 || s.Listen.Dashboard != "127.0.0.1:8788" {
		t.Fatal("defaults not applied")
	}
}

func TestSiteExampleStandalone(t *testing.T) {
	s, err := LoadSite(examples + "schild.standalone.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if !s.CaddyIngress() || s.Profile != "production" || s.Mode != "autoblock" {
		t.Fatal("standalone ingress not recognised")
	}
	if s.Listen.Proxy != "" || !s.Upstream.IsZero() || s.Listen.Dashboard != "127.0.0.1:8788" {
		t.Fatalf("plain proxy defaults applied with a Caddyfile: %+v %+v", s.Listen, s.Upstream)
	}
	if s.Ingress.CaddyStorage != "/data/caddy" || len(s.Ingress.UnprotectedSites) != 1 {
		t.Fatal("ingress values")
	}
}

// D72: the keys of the lab network are unknown keys now.
func TestNetworkKeysRefused(t *testing.T) {
	base := "config_version: 0\nmode: observe\nnode_name: web-1\nupstream: {url: \"http://app:80\"}\n"
	if _, err := ParseSite([]byte(base)); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"network: {enabled: false}", "channel: schild-main", "labs: []", "min_independent_operators: 3", "test_profile: {simulated_operators: []}",
		"relays: []", "remote_rules: {enabled: false}", "signals: {enabled: false}", "site_key: {keyid: a, private_key_file: /k}"} {
		if _, err := ParseSite([]byte(base + k + "\n")); contract.CodeOf(err) != contract.CodeSchema {
			t.Errorf("%s: want schema error, got %v", k, err)
		}
	}
	if _, err := ParseSite([]byte(base + "behaviour: {distributed: {wave_hint: {enabled: false}}}\n")); contract.CodeOf(err) != contract.CodeSchema {
		t.Errorf("wave_hint: want schema error, got %v", err)
	}
}

// D73: crs and local block, crowdsec detects; the old keys are refused.
func TestRulesDefaults(t *testing.T) {
	s, err := LoadSite(examples + "schild.production.yaml")
	if err != nil {
		t.Fatal(err)
	}
	h := s.Rules.Crowdsec
	if h.State != "detect" || !*h.AutoUpdate || h.IntervalS != 3600 || *h.SettlingS != 86400 || h.Pin != "" || len(h.DisabledRules) != 0 {
		t.Fatalf("crowdsec defaults: %+v", h)
	}
	c := s.Rules.CRS
	if c.State != "block" || c.ParanoiaLevel != 1 || c.InboundAnomalyThreshold != 5 || !*c.LivewireException {
		t.Fatalf("crs defaults: %+v", c)
	}
	if s.Rules.Local.State != "block" || s.Rules.Local.Dir != LocalRulesDirDefault {
		t.Fatalf("local defaults: %+v", s.Rules.Local)
	}
	s, err = LoadSite(examples + "schild.standalone.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if s.Rules.Crowdsec.State != "detect" {
		t.Fatalf("standalone: state %q", s.Rules.Crowdsec.State)
	}
	base, err := os.ReadFile(examples + "schild.standalone.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for _, old := range []string{"crowdsec_hub: {state: block}\n", "waf: {crs: {paranoia_level: 2}}\n"} {
		if _, err := ParseSite(append(append([]byte{}, base...), old...)); contract.CodeOf(err) != contract.CodeSchema {
			t.Errorf("%q: want schema error, got %v", old, err)
		}
	}
}

func TestBackendInCode(t *testing.T) {
	s := &Site{Upstream: Upstream{URL: "http://app:80"}}
	s.defaults()
	if err := s.check(); err != nil {
		t.Fatalf("plain proxy rejected: %v", err)
	}
	s = &Site{Upstream: Upstream{URL: "http://app:80"}, Ingress: Ingress{Caddyfile: "/etc/caddy/Caddyfile"}}
	s.defaults()
	if err := s.check(); contract.CodeOf(err) != contract.CodeConfig {
		t.Fatalf("caddyfile with upstream accepted: %v", err)
	}
	s = &Site{}
	s.defaults()
	if err := s.check(); contract.CodeOf(err) != contract.CodeConfig {
		t.Fatalf("no backend accepted: %v", err)
	}
}

func TestLabExample(t *testing.T) {
	l, err := LoadLab(examples + "lab.t0.yaml")
	if keys.Release {
		if !errors.Is(err, ErrTestProfileInRelease) {
			t.Fatal("release build accepted lab test profile")
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	ts, err := l.ClientTrustStore()
	if err != nil || ts.Len() != 3 {
		t.Fatalf("client trust: %v", err)
	}
	k, _ := ts.Lookup("test-site-c")
	if k.Issuer != "issuer-test-2" || !k.Allows(contract.PurposeSignal) || k.Allows(contract.PurposeRules) {
		t.Fatal("client key")
	}
	if !*l.Publish.RequireHumanApproval || l.Scoring.MinIssuers != 3 {
		t.Fatal("defaults")
	}
}

// D89: the mode is gone. The test profile observes whatever schild.yaml says,
// an old mode observe sets the repositories rules leaves open to detect, and
// every old mode is named in a warning.
func TestModeIsGone(t *testing.T) {
	for _, c := range []struct {
		profile, mode, want, crs, crowdsec string
		warn                               bool
	}{
		{"production", "", ModeAutoblock, "", "", false},
		{"production", "autoblock", ModeAutoblock, "", "", true},
		{"production", "review", ModeAutoblock, "", "", true},
		{"production", "observe", ModeAutoblock, "detect", "detect", true},
		{"test", "autoblock", ModeObserve, "", "", true},
		{"test", "", ModeObserve, "", "", false},
	} {
		s := &Site{Profile: c.profile, Mode: c.mode, Upstream: Upstream{URL: "http://app:80"}}
		s.dropMode()
		if s.Mode != c.want || s.Rules.CRS.State != c.crs || s.Rules.Crowdsec.State != c.crowdsec || (s.ModeWarning() != "") != c.warn {
			t.Fatalf("%+v: mode %s, crs %q, crowdsec %q, warning %q", c, s.Mode, s.Rules.CRS.State, s.Rules.Crowdsec.State, s.ModeWarning())
		}
	}
	s, err := ParseSite([]byte("config_version: 0\nmode: observe\nnode_name: web-1\nupstream:\n  url: http://app:80\nrules:\n  crs:\n    state: block\n"))
	if err != nil || s.Rules.CRS.State != "block" || s.Rules.Local.State != "detect" || s.Rules.Crowdsec.State != "detect" || s.Mode != ModeAutoblock {
		t.Fatalf("a state set in rules stays, the others detect: %v %+v", err, s)
	}
	if s, err := ParseSite([]byte("config_version: 0\nnode_name: web-1\nupstream:\n  url: http://app:80\n")); err != nil || s.Rules.CRS.State != "block" || s.ModeWarning() != "" {
		t.Fatalf("without mode the defaults hold: %v %+v", err, s)
	}
}

func TestYAMLStrict(t *testing.T) {
	bad := map[string]string{
		"duplicate": "a: 1\na: 2\n",
		"alias":     "a: &x 1\nb: *x\n",
		"merge":     "a: {x: 1}\nb:\n  <<: {x: 2}\n",
		"two docs":  "a: 1\n---\nb: 2\n",
		"int key":   "1: a\n",
		"inf":       "a: .inf\n",
		"empty":     "",
	}
	for name, in := range bad {
		if _, err := YAMLToJSON([]byte(in)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	j, err := YAMLToJSON([]byte("a: yes\nb: true\nc: 0x10\nd: 2026-11-30T00:00:00Z\ne: 1.5\nf: ~\n"))
	if err != nil {
		t.Fatal(err)
	}
	if string(j) != `{"a":"yes","b":true,"c":16,"d":"2026-11-30T00:00:00Z","e":1.5,"f":null}` {
		t.Fatalf("got %s", j)
	}
}

func TestSchemaErrors(t *testing.T) {
	b, _ := os.ReadFile(examples + "schild.production.yaml")
	in := strings.Replace(string(b), "node_name: web-1", "node_name: web-1\nmode: block", 1)
	if _, err := ParseSite([]byte(in)); contract.CodeOf(err) != contract.CodeSchema {
		t.Fatalf("want schema error, got %v", err)
	}
	in = strings.Replace(string(b), "node_name: web-1", "node_name: web-1\nnode_name: web-2", 1)
	if _, err := ParseSite([]byte(in)); contract.CodeOf(err) != contract.CodeMalformed {
		t.Fatalf("duplicate YAML key: %v", err)
	}
	p := filepath.Join(t.TempDir(), "s.yaml")
	_ = os.WriteFile(p, b, 0o600)
	t.Setenv(SitePathEnv, p)
	if _, err := LoadSite(""); err != nil {
		t.Fatalf("env path: %v", err)
	}
}

// v0.4 (MVP-21): monitoring is on by default; the ring order is checked in
// code too. v0.4 addendum: WAF evaluation keys default as documented.
func TestMonitoringAndEvalDefaults(t *testing.T) {
	s, err := LoadSite(examples + "schild.production.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if s.Retention.RawIPDays != 14 || s.Retention.EventsDays != 14 { // D51
		t.Fatalf("retention defaults: %+v", s.Retention)
	}
	m := s.Monitoring
	if !m.On() || !m.HostOn() || m.Keep != (MonitoringKeep{6, 48, 14}) || m.Mounts != nil || m.Interfaces != nil {
		t.Fatalf("monitoring defaults: %+v", m)
	}
	if s.WAF.QueueWaitMS != 100 || s.WAF.MaxConcurrentEvals != 0 {
		t.Fatalf("waf eval defaults: %+v", s.WAF)
	}
	off := false
	s = &Site{Upstream: Upstream{URL: "http://app:80"}, Monitoring: Monitoring{Enabled: &off}}
	s.defaults()
	if err := s.check(); err != nil || s.Monitoring.On() || s.Monitoring.HostOn() {
		t.Fatalf("monitoring off: %v", err)
	}
	s = &Site{Upstream: Upstream{URL: "http://app:80"}, Monitoring: Monitoring{Keep: MonitoringKeep{TenMinuteDays: 1}}}
	s.defaults()
	if err := s.check(); contract.CodeOf(err) != contract.CodeConfig {
		t.Fatalf("minute_hours 48 above one day of 10 min accepted: %v", err)
	}
}

// v0.5 (MVP-22): request ring, bots and geo defaults; the ring needs
// monitoring; raw paths per site.
func TestRequestsBotsGeoDefaults(t *testing.T) {
	s, err := LoadSite(examples + "schild.production.yaml")
	if err != nil {
		t.Fatal(err)
	}
	r := s.Monitoring.Requests
	if !s.Monitoring.RequestsOn() || r.KeepHours != 720 || r.MaxSizeMB != 512 {
		t.Fatalf("requests defaults: %+v", r)
	}
	if !s.Bots.RangesOn() || s.Bots.FCrDNSOn() || !s.Bots.FetchOn() { // fetch on since D67
		t.Fatalf("bots defaults: %+v", s.Bots)
	}
	if s.Geo.Provider != GeoDBIP || s.Geo.Downloads() || s.Geo.RefreshHours != 0 || s.Geo.Database != nil {
		t.Fatalf("geo defaults: %+v", s.Geo)
	}
	g := Geo{Provider: GeoMaxMind}
	g.defaults()
	if !g.Downloads() || g.RefreshHours != 24 || len(g.Database) != 2 {
		t.Fatalf("maxmind defaults: %+v", g)
	}
	on, off := true, false
	s = &Site{Upstream: Upstream{URL: "http://app:80"}, Monitoring: Monitoring{Enabled: &off, Requests: Requests{Enabled: &on}}}
	s.defaults()
	if err := s.check(); contract.CodeOf(err) != contract.CodeConfig {
		t.Fatalf("request ring without monitoring accepted: %v", err)
	}
	s = &Site{Upstream: Upstream{URL: "http://app:80"}, Monitoring: Monitoring{Enabled: &off}}
	s.defaults()
	if err := s.check(); err != nil || s.Monitoring.RequestsOn() {
		t.Fatalf("monitoring off turns the ring off: %v", err)
	}
}

// TestWaitingPageDefault: D37, the waiting page is on unless switched off.
func TestWaitingPageDefault(t *testing.T) {
	s, err := LoadSite(examples + "schild.production.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if !s.WaitingPage.On() || s.WaitingPage.Enabled == nil || !*s.WaitingPage.Enabled {
		t.Fatalf("waiting page default: %+v", s.WaitingPage)
	}
	off := false
	if (&WaitingPage{Enabled: &off}).On() || !(&WaitingPage{}).On() {
		t.Fatal("WaitingPage.On")
	}
}
