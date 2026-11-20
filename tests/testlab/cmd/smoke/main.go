// Command smoke proves the schild gateway end to end in a running test lab
// (make smoke PROFILE=t0|t1). It runs inside the stack (networks inet and
// federation) and only talks to the test lab's own containers:
//
//  1. legit and attack traffic through the label strippers to the sites
//     behind schild (X-Forwarded-For with documentation addresses);
//  2. local events with full IP and geo in the gateway dashboard API;
//  3. the NDJSON event log is there for the evaluator.
//
// D72: the first gateway version has no network features. It sends no
// signals, receives no rule bundles or withdrawals and talks to no lab or
// relay, so the gateway steps of the old loop (signals delivered to the labs,
// bundle applied by the clients, network rule matching, emergency stop
// reaching the clients, egress check of the transparency log) are gone. The
// labs and relays still run in the stack as planned parts: the smoke checks
// that they are up, that their users log in and that the feed's collecting
// endpoint needs a peer signature. The lab chain (pattern, proposal, approval,
// co-signed bundle, relays, RFC 6962 log root, emergency stop) needs signals
// as input; until a signal source for the labs exists (lab later) those steps
// are reported as skipped, not run.
//
// The report goes to -out (JSON) and stdout; the exit code is 0 only if every
// step that ran passed.
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/deutschland-schild/schild/contract/logtree"
	"github.com/deutschland-schild/schild/testlab/internal/label"
)

type site struct {
	Name, Stripper, Dashboard, SetupCode, Export, Mode string
	api                                                *apiClient
}

type labNode struct {
	Name, Dashboard, Feed string
	users                 map[string]*apiClient
}

type stepResult struct {
	Name     string  `json:"name"`
	OK       bool    `json:"ok"`
	Seconds  float64 `json:"seconds"`
	Detail   string  `json:"detail"`
	Evidence any     `json:"evidence,omitempty"`
	// Skipped names why a step did not run (e.g. "lab later (D72)"); a
	// skipped step neither passes nor fails the run.
	Skipped string `json:"skipped,omitempty"`
}

type report struct {
	Profile  string             `json:"profile"`
	Started  string             `json:"started"`
	Finished string             `json:"finished"`
	OK       bool               `json:"ok"`
	Steps    []stepResult       `json:"steps"`
	Timings  map[string]float64 `json:"timings"`
}

type smoke struct {
	ctx       context.Context
	profile   string
	password  string
	approvers int
	cosigners int
	sites     []*site
	labs      []*labNode
	relays    map[string]string
	gen       *trafficGen
	feed      *http.Client
	rep       report
	sentAll   []sent
	// state between steps
	patternID   string
	proposalID  string
	ruleID      string
	secRuleID   string
	bundle      int
	withdrawal  int
	publishedAt time.Time
	effectiveAt time.Time
}

func main() {
	var (
		profile   = flag.String("profile", "t0", "test-lab profile (report only)")
		sitesF    = flag.String("sites", "", "name=stripperURL|dashboardURL|exportDir|mode,...")
		labsF     = flag.String("labs", "", "name=dashboardURL|feedURL,... (first = the lab that proposes)")
		relaysF   = flag.String("relays", "", "name=URL,...")
		approvers = flag.Int("approvers", 1, "people (organisations) approving the proposal")
		cosigners = flag.Int("cosigners", 2, "other labs that co-sign (threshold - 1)")
		out       = flag.String("out", "", "write the JSON report here")
	)
	if len(os.Args) > 1 && os.Args[1] == "agents" { // MVP-11 agent phases (agents.go)
		os.Exit(agentsMain(os.Args[2:]))
	}
	flag.Parse()
	log.SetFlags(0)
	s := &smoke{ctx: context.Background(), profile: *profile, password: os.Getenv("SMOKE_PASSWORD"), approvers: *approvers, cosigners: *cosigners, relays: map[string]string{}}
	s.rep = report{Profile: *profile, Started: time.Now().UTC().Format(time.RFC3339), Timings: map[string]float64{}}
	if s.password == "" {
		log.Fatal("smoke: SMOKE_PASSWORD is not set")
	}
	secret := os.Getenv(label.EnvSecret)
	if secret == "" {
		log.Fatal("smoke: SCHILD_LABEL_SECRET is not set")
	}
	s.gen = &trafficGen{secret: []byte(secret), hc: &http.Client{Timeout: 30 * time.Second}}
	for _, kv := range splitList(*sitesF) {
		name, v, _ := strings.Cut(kv, "=")
		p := strings.Split(v, "|")
		if len(p) != 4 {
			log.Fatalf("smoke: bad -sites entry %q", kv)
		}
		s.sites = append(s.sites, &site{Name: name, Stripper: p[0], Dashboard: p[1], Export: p[2], Mode: p[3],
			SetupCode: os.Getenv("SMOKE_SETUP_CODE_" + strings.ToUpper(strings.ReplaceAll(name, "-", "_"))), api: newAPI("schild-"+name, p[1])})
	}
	for _, kv := range splitList(*labsF) {
		name, v, _ := strings.Cut(kv, "=")
		dash, feed, _ := strings.Cut(v, "|")
		s.labs = append(s.labs, &labNode{Name: name, Dashboard: dash, Feed: feed, users: map[string]*apiClient{}})
	}
	for _, kv := range splitList(*relaysF) {
		name, v, _ := strings.Cut(kv, "=")
		s.relays[name] = v
	}
	if len(s.sites) == 0 {
		log.Fatal("smoke: need -sites")
	}
	if len(s.labs) > 0 && (len(s.labs) < 3 || len(s.relays) < 2) {
		log.Fatal("smoke: the lab-side steps need at least 3 -labs and 2 -relays (or none)")
	}
	var err error
	if s.feed, err = tlsClient(); err != nil {
		log.Fatalf("smoke: %v", err)
	}

	// Steps that only touch labs and relays are skipped without a lab stack.
	// Steps of the lab chain need signals as input, which no gateway sends
	// since D72: they stay here, skipped, until the labs get a signal source.
	const labLater = "lab later (D72): the lab chain needs signals as input; the gateway sends none"
	noLabs := ""
	if len(s.labs) == 0 {
		noLabs = "no lab stack (-labs, -relays)"
	}
	chain := labLater
	if noLabs != "" {
		chain = noLabs
	}
	steps := []struct {
		name string
		fn   func() (string, any, error)
		skip string
	}{
		{"stack ready", s.ready, ""},
		{"logins (gateway admin; lab users carol, alice, bob)", s.logins, ""},
		{"legit and attack traffic through the label strippers", s.traffic, ""},
		{"local events with full IP and geo (gateway dashboard)", s.localEvents, ""},
		{"lab feed: collecting is not public (peer signature required)", s.collectingNeedsPeer, noLabs},
		{"lab: attack pattern visible in every lab dashboard", s.patterns, chain},
		{"lab: proposal with evidence; four eyes", s.proposal, chain},
		{"lab: human approval", s.approve, chain},
		{"lab: bundle assembled and co-signed by other operators", s.bundleCosign, chain},
		{"relays carry the bundle", s.relaysCarry, chain},
		{"lab dashboard: relay coverage and RFC 6962 log root", s.labViews, chain},
		{"lab: emergency stop co-signed, effective and carried by the relays", s.emergencyStop, chain},
		{"NDJSON event log for the evaluator", s.exports, ""},
	}
	ran := 0
	for _, st := range steps {
		if st.skip != "" {
			s.rep.Steps = append(s.rep.Steps, stepResult{Name: st.name, Skipped: st.skip})
			log.Printf("SKIP  %-70s         %s", st.name, st.skip)
			continue
		}
		ran++
		t0 := time.Now()
		detail, ev, err := st.fn()
		r := stepResult{Name: st.name, OK: err == nil, Seconds: round(time.Since(t0).Seconds()), Detail: detail, Evidence: ev}
		if err != nil {
			r.Detail = err.Error()
		}
		s.rep.Steps = append(s.rep.Steps, r)
		mark := "PASS"
		if err != nil {
			mark = "FAIL"
		}
		log.Printf("%s  %-70s %6.1fs  %s", mark, st.name, r.Seconds, r.Detail)
		if err != nil {
			break
		}
	}
	s.rep.OK = len(s.rep.Steps) == len(steps) && !slices.ContainsFunc(s.rep.Steps, func(r stepResult) bool { return !r.OK && r.Skipped == "" })
	s.rep.Finished = time.Now().UTC().Format(time.RFC3339)
	if *out != "" {
		b, _ := json.MarshalIndent(s.rep, "", "  ")
		_ = os.MkdirAll(filepath.Dir(*out), 0o755)
		if err := os.WriteFile(*out, append(b, '\n'), 0o644); err != nil {
			log.Printf("smoke: write report: %v", err)
		}
	}
	if !s.rep.OK {
		log.Printf("smoke %s: FAILED", s.profile)
		os.Exit(1)
	}
	log.Printf("smoke %s: OK (%d steps passed, %d skipped)", s.profile, ran, len(steps)-ran)
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func round(f float64) float64 { return float64(int(f*10+0.5)) / 10 }

func (s *smoke) lab0() *labNode { return s.labs[0] }

// ---------------------------------------------------------------- steps

func (s *smoke) ready() (string, any, error) {
	hc := &http.Client{Timeout: 5 * time.Second}
	get := func(c *http.Client, url string) (bool, error) {
		resp, err := c.Get(url)
		if err != nil {
			return false, err
		}
		resp.Body.Close()
		return resp.StatusCode == 200, nil
	}
	var checks []string
	for _, l := range s.labs {
		checks = append(checks, l.Dashboard+"/api/v0/auth/session", l.Feed+"/readyz")
	}
	for _, u := range s.relays {
		checks = append(checks, u+"/readyz")
	}
	for _, st := range s.sites {
		checks = append(checks, st.Dashboard+"/api/v0/auth/session", st.Stripper+"/healthz")
	}
	for _, u := range checks {
		c := hc
		if strings.HasPrefix(u, "https://") {
			c = s.feed
		}
		if err := eventually(s.ctx, 180*time.Second, time.Second, u, func() (bool, error) { return get(c, u) }); err != nil {
			return "", nil, err
		}
	}
	// The site answers through stripper and schild.
	for _, st := range s.sites {
		if err := eventually(s.ctx, 120*time.Second, time.Second, st.Name+" via stripper", func() (bool, error) { return get(hc, st.Stripper+"/healthz") }); err != nil {
			return "", nil, err
		}
	}
	return fmt.Sprintf("%d endpoints ready (%d labs, %d relays, %d sites)", len(checks), len(s.labs), len(s.relays), len(s.sites)), nil, nil
}

func (s *smoke) logins() (string, any, error) {
	for _, st := range s.sites {
		if err := st.api.loginClient(st.SetupCode, s.password); err != nil {
			return "", nil, err
		}
	}
	for _, l := range s.labs {
		for _, u := range []string{"carol", "alice", "bob"} {
			a := newAPI(l.Name+"/"+u, l.Dashboard)
			if err := a.loginLab(u, s.password); err != nil {
				return "", nil, err
			}
			l.users[u] = a
		}
	}
	return fmt.Sprintf("%d gateway dashboards, %d labs x 3 users", len(s.sites), len(s.labs)), nil, nil
}

// Visitor addresses: legit from 198.51.100.0/24 (fixture: DE, AS64496),
// attackers from 203.0.113.0/24 (fixture: NL, AS64500).
func legitIP(i int) string  { return fmt.Sprintf("198.51.100.%d", 10+i%40) }
func attackIP(i int) string { return fmt.Sprintf("203.0.113.%d", 50+i%20) }

func (s *smoke) traffic() (string, any, error) {
	var legit, attacks, blocked, legitBad int
	for _, st := range s.sites {
		l, err := s.gen.send(st.Name, st.Stripper, legitSpecs(0), legitIP)
		if err != nil {
			return "", nil, err
		}
		a, err := s.gen.send(st.Name, st.Stripper, attackSpecs(0), attackIP)
		if err != nil {
			return "", nil, err
		}
		for _, r := range l {
			if r.Status >= 400 || r.RequestID == "" {
				legitBad++
			}
		}
		for _, r := range a {
			if r.Status == 403 {
				blocked++
			}
		}
		legit += len(l)
		attacks += len(a)
		s.sentAll = append(append(s.sentAll, l...), a...)
	}
	if legitBad > 0 {
		return "", nil, fmt.Errorf("%d legit requests failed or got no X-Request-Id", legitBad)
	}
	return fmt.Sprintf("%d legit (all 2xx), %d attacks (%d answered 403 by autoblock sites)", legit, attacks, blocked), nil, nil
}

type eventSummary struct {
	ID      string   `json:"id"`
	Type    string   `json:"type"`
	Outcome string   `json:"outcome"`
	IP      string   `json:"ip"`
	Path    string   `json:"path"`
	Rules   []string `json:"rules"`
	Score   int      `json:"score"`
	Geo     *struct {
		Country string `json:"country"`
		ASN     int    `json:"asn"`
	} `json:"geo"`
}

func (st *site) events(query string) ([]eventSummary, error) {
	var page struct {
		Items []eventSummary `json:"items"`
	}
	_, err := st.api.do("GET", "/events?limit=500"+query, nil, &page)
	return page.Items, err
}

func (s *smoke) localEvents() (string, any, error) {
	var ev []map[string]any
	for _, st := range s.sites {
		var attacks, legit []eventSummary
		err := eventually(s.ctx, 60*time.Second, 2*time.Second, st.Name+" events", func() (bool, error) {
			items, err := st.events("")
			if err != nil {
				return false, err
			}
			attacks, legit = nil, nil
			for _, e := range items {
				switch {
				case strings.HasPrefix(e.IP, "203.0.113."):
					attacks = append(attacks, e)
				case strings.HasPrefix(e.IP, "198.51.100."):
					legit = append(legit, e)
				}
			}
			return len(attacks) >= len(attackSpecs(0)) && len(legit) >= len(legitSpecs(0)), nil
		})
		if err != nil {
			return "", nil, err
		}
		flagged, geoOK := 0, 0
		for _, e := range attacks {
			if e.Outcome == "would_block" || e.Outcome == "blocked" || e.Outcome == "challenged" {
				flagged++
			}
			if e.Geo != nil && e.Geo.Country == "NL" && e.Geo.ASN == 64500 {
				geoOK++
			}
		}
		legitFlagged := 0
		for _, e := range legit {
			if e.Outcome != "passed" && e.Outcome != "" {
				legitFlagged++
			}
		}
		if flagged < len(attackSpecs(0))-1 {
			return "", nil, fmt.Errorf("%s: only %d of %d attacks flagged", st.Name, flagged, len(attacks))
		}
		if geoOK != len(attacks) {
			return "", nil, fmt.Errorf("%s: %d of %d attack events without fixture geo (NL, AS64500)", st.Name, len(attacks)-geoOK, len(attacks))
		}
		if legitFlagged > 0 {
			return "", nil, fmt.Errorf("%s: %d legit requests flagged", st.Name, legitFlagged)
		}
		ex := attacks[0]
		ev = append(ev, map[string]any{"site": st.Name, "attack_events": len(attacks), "legit_events": len(legit), "flagged": flagged,
			"example": map[string]any{"ip": ex.IP, "country": ex.Geo.Country, "asn": ex.Geo.ASN, "outcome": ex.Outcome, "rules": ex.Rules, "path": ex.Path}})
	}
	return fmt.Sprintf("attacks flagged with full IP and fixture geo on %d sites, no legit request flagged", len(s.sites)), ev, nil
}

var ipv4Re = regexp.MustCompile(`\b[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\b`)

type patternSummary struct {
	PatternID string `json:"pattern_id"`
	ActionSig string `json:"action_sig"`
	Signals   int    `json:"signals"`
	Issuers   int    `json:"issuers"`
	Status    string `json:"status"`
}

func (s *smoke) patterns() (string, any, error) {
	ev := map[string]any{}
	for _, l := range s.labs {
		var found *patternSummary
		err := eventually(s.ctx, 60*time.Second, 2*time.Second, l.Name+" sqli pattern", func() (bool, error) {
			var page struct {
				Items []patternSummary `json:"items"`
			}
			if _, err := l.users["alice"].do("GET", "/patterns?sort=signals&limit=100", nil, &page); err != nil {
				return false, err
			}
			for i, p := range page.Items {
				if strings.HasPrefix(p.ActionSig, "sqli/") {
					found = &page.Items[i]
					return true, nil
				}
			}
			return false, nil
		})
		if err != nil {
			return "", nil, err
		}
		// The lab's raw signals carry no IP either.
		var sig struct {
			Items []json.RawMessage `json:"items"`
		}
		if _, err := l.users["alice"].do("GET", "/signals?limit=200&pattern_id="+found.PatternID, nil, &sig); err != nil {
			return "", nil, err
		}
		for _, raw := range sig.Items {
			if m := ipv4Re.FindString(string(raw)); m != "" {
				return "", nil, fmt.Errorf("%s: received signal with an IPv4-like token %s", l.Name, m)
			}
		}
		ev[l.Name] = found
		if l == s.lab0() {
			s.patternID = found.PatternID
		}
	}
	return fmt.Sprintf("pattern %s in %d labs", s.patternID, len(s.labs)), ev, nil
}

func (s *smoke) collectingNeedsPeer() (string, any, error) {
	resp, err := s.feed.Get(s.lab0().Feed + "/v0/collecting")
	if err != nil {
		return "", nil, err
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		return "", nil, fmt.Errorf("GET /v0/collecting without peer signature: %d %s", resp.StatusCode, trunc(string(b), 200))
	}
	return "unsigned GET /v0/collecting -> 401", nil, nil
}

type proposal struct {
	ID               string  `json:"id"`
	RuleID           string  `json:"rule_id"`
	Status           string  `json:"status"`
	AllowedMaxAction *string `json:"allowed_max_action"`
	CreatedBy        *string `json:"created_by"`
	Approvals        []struct {
		By, Org string
	} `json:"approvals"`
	Evidence struct {
		HumanApprovalOrgs   int `json:"human_approval_orgs"`
		ReproducedOperators int `json:"reproduced_operators"`
	} `json:"evidence"`
}

func (s *smoke) proposal() (string, any, error) {
	carol := s.lab0().users["carol"]
	s.secRuleID = fmt.Sprintf("77%05d", time.Now().Unix()%100000)
	rule := `SecRule ARGS "@detectSQLi" "id:` + s.secRuleID + `,phase:2,deny,status:403,severity:CRITICAL,msg:'SQL injection in request arguments (smoke test)'"`
	var p proposal
	if _, err := carol.do("POST", "/proposals", map[string]any{
		"pattern_id": s.patternID, "class": "virtual_patch", "stage": "general", "requested_max_action": "challenge",
		"seclang": rule, "target": map[string]any{"software": "testlab/site-api", "versions": "*"},
	}, &p, 201); err != nil {
		return "", nil, err
	}
	if p.CreatedBy == nil || *p.CreatedBy != "carol" {
		return "", nil, fmt.Errorf("created_by %v, want carol", p.CreatedBy)
	}
	s.proposalID, s.ruleID = p.ID, p.RuleID
	if _, err := carol.do("POST", "/proposals/"+p.ID+"/evidence", map[string]any{"kind": "reproduction", "image": "schild-testlab:dev site-api", "version": "0.1.0-alpha",
		"request": "GET /api/items?id=1%27%20OR%20%271%27%3D%271 HTTP/1.1\r\nHost: site-api\r\n\r\n"}, &p); err != nil {
		return "", nil, err
	}
	if _, err := carol.do("POST", "/proposals/"+p.ID+"/evidence", map[string]any{"kind": "negative_corpus", "corpus_version": "corpus-2026.10", "corpus_matches": 0}, &p); err != nil {
		return "", nil, err
	}
	// Four eyes: the author may not approve.
	code, err := carol.do("POST", "/proposals/"+p.ID+"/approve", map[string]any{"max_action": "observe", "org": "Betreiber A"}, nil, 403)
	var ae *apiError
	if err != nil || code != 403 {
		if errors.As(err, &ae) {
			return "", nil, fmt.Errorf("self approval was not refused with 403: %v", ae)
		}
		return "", nil, fmt.Errorf("self approval: %d %v", code, err)
	}
	allowed := "none"
	if p.AllowedMaxAction != nil {
		allowed = *p.AllowedMaxAction
	}
	return fmt.Sprintf("%s (%s) by carol, evidence allows %s, self approval refused (403 self_approval)", p.ID, p.RuleID, allowed),
		map[string]any{"proposal": p.ID, "rule_id": p.RuleID, "allowed_max_action": allowed}, nil
}

func (s *smoke) approve() (string, any, error) {
	until := time.Now().UTC().Add(72 * time.Hour).Format("2006-01-02T15:04:05Z")
	people := []struct{ user, org string }{{"alice", "Betreiber A"}, {"bob", "Betreiber B"}}[:s.approvers]
	var p proposal
	for _, who := range people {
		if _, err := s.lab0().users[who.user].do("POST", "/proposals/"+s.proposalID+"/approve",
			map[string]any{"max_action": "challenge", "max_action_until": until, "org": who.org, "note": "Smoke-Test: Reproduktion nachvollzogen"}, &p); err != nil {
			return "", nil, fmt.Errorf("approval by %s: %w", who.user, err)
		}
	}
	if p.Status != "approved" || len(p.Approvals) != len(people) || p.Evidence.HumanApprovalOrgs != len(people) {
		return "", nil, fmt.Errorf("proposal after approvals: status %s, %d approvals, %d organisations", p.Status, len(p.Approvals), p.Evidence.HumanApprovalOrgs)
	}
	return fmt.Sprintf("approved by %d named person(s) of %d organisation(s), max challenge until %s", len(people), p.Evidence.HumanApprovalOrgs, until), p.Approvals, nil
}

type bundleView struct {
	Version    int    `json:"version"`
	Status     string `json:"status"`
	ProposedBy string `json:"proposed_by"`
	Threshold  int    `json:"threshold"`
	Signatures []struct {
		Lab, Operator string
	} `json:"signatures"`
	Rules []struct {
		RuleID    string `json:"rule_id"`
		MaxAction string `json:"max_action"`
	} `json:"rules"`
}

func (s *smoke) bundleCosign() (string, any, error) {
	var b bundleView
	if _, err := s.lab0().users["alice"].do("POST", "/bundles", map[string]any{"add": []string{s.proposalID}, "remove": []string{}}, &b, 201); err != nil {
		return "", nil, err
	}
	if b.Status != "collecting" {
		return "", nil, fmt.Errorf("new bundle status %s", b.Status)
	}
	s.bundle = b.Version
	path := fmt.Sprintf("/bundles/%d", b.Version)
	var signed []string
	for _, l := range s.labs[1 : 1+s.cosigners] {
		bob := l.users["bob"]
		if err := eventually(s.ctx, 60*time.Second, 2*time.Second, l.Name+" sees the offered bundle", func() (bool, error) {
			var v bundleView
			if _, err := bob.do("GET", path, nil, &v, 200, 404); err != nil {
				return false, err
			}
			return v.Version == b.Version && v.ProposedBy == s.lab0().Name, nil
		}); err != nil {
			return "", nil, err
		}
		if _, err := bob.do("POST", path+"/cosign", map[string]any{"password": s.password}, nil); err != nil {
			return "", nil, fmt.Errorf("%s co-sign: %w", l.Name, err)
		}
		signed = append(signed, l.Name)
	}
	var final bundleView
	if err := eventually(s.ctx, 60*time.Second, time.Second, "bundle published at "+s.lab0().Name, func() (bool, error) {
		if _, err := s.lab0().users["alice"].do("GET", path, nil, &final); err != nil {
			return false, err
		}
		return final.Status == "published", nil
	}); err != nil {
		return "", nil, err
	}
	s.publishedAt = time.Now()
	ops := map[string]bool{}
	for _, sg := range final.Signatures {
		ops[sg.Operator] = true
	}
	return fmt.Sprintf("bundle v%d signed by %s + %s, published with %d distinct operators", b.Version, s.lab0().Name, strings.Join(signed, ", "), len(ops)), final, nil
}

// relayState reads a relay's full-sync state and returns the newest bundle
// version and withdrawal seq it would hand to a client.
func relayState(hc *http.Client, url string) (int, int, error) {
	resp, err := hc.Get(url + "/v0/state.json")
	if err != nil {
		return 0, 0, err
	}
	defer resp.Body.Close()
	var st struct {
		Events []struct {
			Type     string `json:"type"`
			Envelope *struct {
				Payload string `json:"payload"`
			} `json:"envelope"`
			Ref *struct {
				Version int `json:"version"`
			} `json:"ref"`
		} `json:"events"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		return 0, 0, err
	}
	bv, ws := 0, 0
	for _, e := range st.Events {
		v, q := 0, 0
		if e.Ref != nil {
			v = e.Ref.Version
		} else if e.Envelope != nil {
			raw, err := base64.StdEncoding.DecodeString(e.Envelope.Payload)
			if err == nil {
				var p struct {
					Version int `json:"version"`
					Seq     int `json:"seq"`
				}
				_ = json.Unmarshal(raw, &p)
				v, q = p.Version, p.Seq
			}
		}
		switch e.Type {
		case "schild.dist.bundle.v1":
			bv = max(bv, v)
		case "schild.dist.withdrawal.v1":
			ws = max(ws, q)
		}
	}
	return bv, ws, nil
}

func (s *smoke) relaysCarry() (string, any, error) {
	hc := &http.Client{Timeout: 10 * time.Second}
	ev := map[string]int{}
	for name, u := range s.relays {
		if err := eventually(s.ctx, 60*time.Second, time.Second, name+" carries bundle", func() (bool, error) {
			v, _, err := relayState(hc, u)
			ev[name] = v
			return v >= s.bundle, err
		}); err != nil {
			return "", nil, err
		}
	}
	s.rep.Timings["bundle_published_to_relays_s"] = round(time.Since(s.publishedAt).Seconds())
	return fmt.Sprintf("%d relays serve bundle v%d", len(s.relays), s.bundle), ev, nil
}

func (s *smoke) labViews() (string, any, error) {
	alice := s.lab0().users["alice"]
	var relays struct {
		Items []struct {
			ID            string `json:"id"`
			Kind          string `json:"kind"` // contracts v0.2: relay | peer_lab
			Status        string `json:"status"`
			BundleVersion int    `json:"bundle_version"`
		} `json:"items"`
	}
	if err := eventually(s.ctx, 30*time.Second, time.Second, "relay coverage", func() (bool, error) {
		if _, err := alice.do("GET", "/relays", nil, &relays); err != nil {
			return false, err
		}
		n := 0
		for _, r := range relays.Items {
			// Peer labs follow the feed too; only real relays count.
			if r.Kind == "relay" && r.BundleVersion >= s.bundle {
				n++
			}
		}
		return n >= len(s.relays), nil
	}); err != nil {
		return "", nil, err
	}
	// The whole public log through the dashboard API, newest first.
	type entry struct {
		logtree.Entry
		Envelope *struct {
			Payload string `json:"payload"`
		} `json:"envelope"`
	}
	var all []entry
	var head struct {
		Size uint64
		Root string
	}
	cursor := ""
	for {
		var page struct {
			Items      []entry `json:"items"`
			NextCursor *string `json:"next_cursor"`
			Head       struct {
				Size uint64 `json:"size"`
				Root string `json:"root"`
			} `json:"head"`
		}
		q := "/log?limit=500"
		if cursor != "" {
			q += "&cursor=" + cursor
		}
		if _, err := alice.do("GET", q, nil, &page); err != nil {
			return "", nil, err
		}
		if head.Root == "" {
			head.Size, head.Root = page.Head.Size, page.Head.Root
		}
		all = append(all, page.Items...)
		if page.NextCursor == nil {
			break
		}
		cursor = *page.NextCursor
	}
	slices.SortFunc(all, func(a, b entry) int { return int(a.Index) - int(b.Index) })
	var tree []logtree.Entry
	for _, e := range all {
		if e.Index < head.Size {
			tree = append(tree, e.Entry)
		}
	}
	if err := logtree.Check(tree, head.Size, head.Root); err != nil {
		return "", nil, fmt.Errorf("log head: %w", err)
	}
	// The newest checkpoint signs the root of the entries before it.
	var signed struct {
		Log struct {
			Size uint64 `json:"size"`
			Root string `json:"root"`
		} `json:"log"`
	}
	for i := len(all) - 1; i >= 0; i-- {
		if all[i].Kind == "checkpoint" && all[i].Envelope != nil {
			raw, _ := base64.StdEncoding.DecodeString(all[i].Envelope.Payload)
			_ = json.Unmarshal(raw, &signed)
			break
		}
	}
	if signed.Log.Size == 0 || signed.Log.Size > uint64(len(tree)) {
		return "", nil, fmt.Errorf("no checkpoint with a usable log head (size %d of %d)", signed.Log.Size, len(tree))
	}
	if err := logtree.Check(tree[:signed.Log.Size], signed.Log.Size, signed.Log.Root); err != nil {
		return "", nil, fmt.Errorf("signed checkpoint root: %w", err)
	}
	return fmt.Sprintf("%d relays have bundle v%d; log root of %d entries recomputed (RFC 6962), signed checkpoint root of %d entries matches",
		len(s.relays), s.bundle, head.Size, signed.Log.Size), relays.Items, nil
}

func (s *smoke) emergencyStop() (string, any, error) {
	var w struct {
		Seq       int    `json:"seq"`
		Status    string `json:"status"`
		Threshold int    `json:"threshold"`
	}
	if _, err := s.lab0().users["alice"].do("POST", "/emergency-stop", map[string]any{"confirm_text": "NOT-AUS", "password": s.password, "reason": "emergency_stop", "note": "Smoke-Test"}, &w, 201); err != nil {
		return "", nil, err
	}
	s.withdrawal = w.Seq
	start := time.Now()
	path := fmt.Sprintf("/withdrawals/%d/cosign", w.Seq)
	for _, l := range s.labs[1 : 1+s.cosigners] {
		bob := l.users["bob"]
		if err := eventually(s.ctx, 60*time.Second, time.Second, l.Name+" co-signs the emergency stop", func() (bool, error) {
			code, err := bob.do("POST", path, map[string]any{"password": s.password}, nil, 200, 404)
			return code == 200, err
		}); err != nil {
			return "", nil, err
		}
	}
	if err := eventually(s.ctx, 60*time.Second, 500*time.Millisecond, "emergency stop effective at "+s.lab0().Name, func() (bool, error) {
		var page struct {
			Items []struct {
				Seq    int    `json:"seq"`
				Status string `json:"status"`
			} `json:"items"`
		}
		if _, err := s.lab0().users["alice"].do("GET", "/withdrawals", nil, &page); err != nil {
			return false, err
		}
		for _, x := range page.Items {
			if x.Seq == w.Seq && x.Status == "effective" {
				return true, nil
			}
		}
		return false, nil
	}); err != nil {
		return "", nil, err
	}
	s.effectiveAt = time.Now()
	// D72: no gateway applies withdrawals any more; the relays carry the
	// emergency stop to whoever follows the feed.
	hc := &http.Client{Timeout: 10 * time.Second}
	ev := map[string]any{}
	var slowest float64
	for name, u := range s.relays {
		if err := eventually(s.ctx, 60*time.Second, 250*time.Millisecond, name+" carries the emergency stop", func() (bool, error) {
			_, ws, err := relayState(hc, u)
			return ws >= w.Seq, err
		}); err != nil {
			return "", nil, err
		}
		slowest = max(slowest, time.Since(s.effectiveAt).Seconds())
		ev[name] = map[string]any{"seconds_after_effective": round(time.Since(s.effectiveAt).Seconds())}
	}
	s.rep.Timings["emergency_stop_effective_to_all_relays_s"] = round(slowest)
	s.rep.Timings["emergency_stop_signed_to_effective_s"] = round(s.effectiveAt.Sub(start).Seconds())
	return fmt.Sprintf("withdrawal %d (scope all) effective after %d co-signatures; on every relay %.1f s later", w.Seq, s.cosigners, slowest), ev, nil
}

func (s *smoke) exports() (string, any, error) {
	ev := map[string]any{}
	for _, st := range s.sites {
		if st.Export == "" || st.Export == "-" {
			continue
		}
		evFile := filepath.Join(st.Export, "events.ndjson")
		evRaw, err := os.ReadFile(evFile)
		if err != nil {
			return "", nil, fmt.Errorf("%s: %w", st.Name, err)
		}
		found := 0
		for _, r := range s.sentAll {
			if r.Site == st.Name && r.RequestID != "" && strings.Contains(string(evRaw), r.RequestID) {
				found++
			}
		}
		if found == 0 {
			return "", nil, fmt.Errorf("%s: none of the smoke request ids in %s", st.Name, evFile)
		}
		ev[st.Name] = map[string]any{"events_ndjson_bytes": len(evRaw), "request_ids_found": found}
	}
	return "events.ndjson present with the smoke's request ids", ev, nil
}
