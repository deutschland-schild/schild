package app

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/auth"
	"github.com/deutschland-schild/schild/contract/config"
	"github.com/deutschland-schild/schild/contract/jsonx"
	"github.com/deutschland-schild/schild/contract/keys"
	"github.com/deutschland-schild/schild/contract/msg"
	"github.com/deutschland-schild/schild/contract/schema"
	"github.com/deutschland-schild/schild/contract/stream"
	"github.com/deutschland-schild/schild/contract/testkeys"
	"github.com/deutschland-schild/schild/contract/transport"
	"github.com/deutschland-schild/schild/contract/verify"
	"github.com/deutschland-schild/schild/lab/internal/publog"
	"github.com/deutschland-schild/schild/relay/upstream"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

// swap lets an httptest server exist before its handler.
type swap struct {
	mu sync.RWMutex
	h  http.Handler
}

func (s *swap) set(h http.Handler) {
	s.mu.Lock()
	s.h = h
	s.mu.Unlock()
}

func (s *swap) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	h := s.h
	s.mu.RUnlock()
	if h == nil {
		http.Error(w, "starting", http.StatusServiceUnavailable)
		return
	}
	h.ServeHTTP(w, r)
}

type labRig struct {
	name, op       string
	app            *App
	ingest, feed   *httptest.Server
	dash           *httptest.Server
	ingestH, feedH *swap
	dashH          *swap
	browser        *http.Client
	csrf           string
	cancel         context.CancelFunc
	done           chan struct{}
}

// extra site key of a third issuer (the test key set has two issuers).
func siteKey(name string) *keys.Signer {
	seed := sha256.Sum256([]byte("schild/apptest/" + name))
	s, _ := keys.NewSigner(name, ed25519.NewKeyFromSeed(seed[:]))
	return s
}

var labs = []struct{ name, op string }{{"lab-a", "op-test-a"}, {"lab-b", "op-test-b"}, {"lab-c", "op-test-c"}}

func startLabs(t *testing.T) map[string]*labRig {
	t.Helper()
	dir := t.TempDir()
	rigs := map[string]*labRig{}
	for _, l := range labs {
		r := &labRig{name: l.name, op: l.op, ingestH: &swap{}, feedH: &swap{}, dashH: &swap{}, done: make(chan struct{})}
		r.ingest = httptest.NewUnstartedServer(r.ingestH)
		r.feed = httptest.NewUnstartedServer(r.feedH)
		r.ingest.StartTLS()
		r.feed.StartTLS()
		r.dash = httptest.NewServer(r.dashH)
		t.Cleanup(func() { r.ingest.Close(); r.feed.Close(); r.dash.Close() })
		rigs[l.name] = r
	}
	tlsClient := rigs["lab-a"].feed.Client() // trusts the httptest certificate
	x3 := siteKey("site-x3")
	for _, l := range labs {
		r := rigs[l.name]
		keyFile := filepath.Join(dir, l.name+".key")
		if err := os.WriteFile(keyFile, keys.FormatSeedFile(testkeys.Private(l.name)), 0o600); err != nil {
			t.Fatal(err)
		}
		var peers strings.Builder
		for _, p := range labs {
			if p.name == l.name {
				continue
			}
			fmt.Fprintf(&peers, "  - lab: %s\n    operator: %s\n    endpoint: %q\n    keys:\n      - keyid: test-%s\n        public_key: %q\n        purposes: [ack, rules, checkpoint]\n",
				p.name, p.op, rigs[p.name].feed.URL, p.name, keys.FormatPublicKey(testkeys.Signer(p.name).Public()))
		}
		y := fmt.Sprintf(`config_version: 0
profile: test
identity: { operator: %s, lab: %s }
channel: schild-main
keys:
  - keyid: test-%s
    private_key_file: %s
    purposes: [ack, rules, checkpoint]
issuers:
  - id: issuer-test-1
  - id: issuer-test-2
  - id: issuer-x3
clients:
  - { keyid: test-site-a, public_key: %q, issuer: issuer-test-1 }
  - { keyid: test-site-b, public_key: %q, issuer: issuer-test-1 }
  - { keyid: test-site-c, public_key: %q, issuer: issuer-test-2 }
  - { keyid: site-x3, public_key: %q, issuer: issuer-x3 }
publish: { checkpoint_interval_s: 5, checkpoint_ttl_s: 60 }
storage: { path: %s }
peers:
%s`, l.op, l.name, l.name, keyFile,
			keys.FormatPublicKey(testkeys.Signer("site-a").Public()), keys.FormatPublicKey(testkeys.Signer("site-b").Public()),
			keys.FormatPublicKey(testkeys.Signer("site-c").Public()), keys.FormatPublicKey(x3.Public()),
			filepath.Join(dir, "data-"+l.name), peers.String())
		cfg, err := config.ParseLab([]byte(y))
		if err != nil {
			t.Fatalf("%s config: %v\n%s", l.name, err, y)
		}
		a, err := New(cfg, Options{Log: quiet, HTTPClient: tlsClient, QueueSync: "none", CheckpointInterval: 150 * time.Millisecond,
			Heartbeat: 200 * time.Millisecond, PeerPoll: 100 * time.Millisecond})
		if err != nil {
			t.Fatal(err)
		}
		r.app = a
		r.ingestH.set(a.IngestHandler())
		r.feedH.set(a.FeedHandler())
		r.dashH.set(a.DashboardHandler())
		ctx, cancel := context.WithCancel(context.Background())
		r.cancel = cancel
		go func() { a.Background(ctx); close(r.done) }()
		t.Cleanup(func() { cancel(); <-r.done; a.Close() })
		jar, _ := cookiejar.New(nil)
		r.browser = &http.Client{Jar: jar, Timeout: 10 * time.Second}
	}
	return rigs
}

// --- dashboard client -------------------------------------------------------------

type apiResp struct {
	status int
	body   []byte
}

func (r *labRig) call(t *testing.T, method, path string, body any) apiResp {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, r.dash.URL+"/api/v0"+path, rd)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if r.csrf != "" {
		req.Header.Set("X-CSRF-Token", r.csrf)
	}
	resp, err := r.browser.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if strings.HasPrefix(resp.Header.Get("Content-Type"), "application/problem+json") {
		validate(t, "Problem", b)
	}
	return apiResp{resp.StatusCode, b}
}

func (r *labRig) must(t *testing.T, method, path string, body any, status int, schemaName string, out any) apiResp {
	t.Helper()
	res := r.call(t, method, path, body)
	if res.status != status {
		t.Fatalf("%s %s %s: status %d, want %d: %s", r.name, method, path, res.status, status, res.body)
	}
	if schemaName != "" {
		validate(t, schemaName, res.body)
	}
	if out != nil {
		if err := json.Unmarshal(res.body, out); err != nil {
			t.Fatal(err)
		}
	}
	return res
}

const password = "korrekt-pferd-batterie"

func (r *labRig) login(t *testing.T) {
	var sess struct {
		FirstRun  bool   `json:"first_run"`
		CSRFToken string `json:"csrf_token"`
		Via       string `json:"via"`
	}
	r.must(t, "GET", "/auth/session", nil, 200, "", &sess)
	if !sess.FirstRun || sess.Via != "localhost" {
		t.Fatalf("%s: first run from localhost expected: %+v", r.name, sess)
	}
	r.must(t, "POST", "/auth/setup", map[string]any{"password": password, "setup_code": r.app.Dash.Auth.SetupCode}, 200, "", &sess)
	r.csrf = sess.CSRFToken
}

// --- API schema validation --------------------------------------------------------

var (
	compileOnce sync.Once
	compiler    *jsonschema.Compiler
)

func validate(t *testing.T, comp string, body []byte) {
	t.Helper()
	compileOnce.Do(func() {
		c := jsonschema.NewCompiler()
		c.DefaultDraft(jsonschema.Draft2020)
		for rel, b := range schema.Files() {
			doc, _ := jsonschema.UnmarshalJSON(bytes.NewReader(b))
			_ = c.AddResource(schema.BaseURL+rel, doc)
		}
		for _, name := range []string{"client-dashboard.openapi.yaml", "lab-dashboard.openapi.yaml"} {
			b, err := os.ReadFile(filepath.Join("..", "..", "..", "contracts", "api", name))
			if err != nil {
				t.Fatal(err)
			}
			j, err := config.YAMLToJSON(b)
			if err != nil {
				t.Fatal(err)
			}
			doc, _ := jsonschema.UnmarshalJSON(bytes.NewReader(j))
			_ = c.AddResource(schema.BaseURL+"api/"+name, doc)
		}
		compiler = c
	})
	doc := "lab-dashboard.openapi.yaml"
	if comp == "Problem" || comp == "Session" {
		doc = "client-dashboard.openapi.yaml"
	}
	sch, err := compiler.Compile(schema.BaseURL + "api/" + doc + "#/components/schemas/" + comp)
	if err != nil {
		t.Fatalf("schema %s: %v", comp, err)
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(body))
	if err != nil {
		t.Fatalf("%s: not JSON: %v", comp, err)
	}
	if err := sch.Validate(inst); err != nil {
		t.Fatalf("response does not match %s: %v\n%s", comp, err, body)
	}
	// Peer endpoints are lab addresses from lab.yaml (127.0.0.1 here), not
	// visitor data; everything else must be free of anything address-like.
	if comp != "PeerList" && ipv4.Match(body) {
		t.Fatalf("lab API response contains an IPv4-like value: %s", body)
	}
}

var ipv4 = regexp.MustCompile(`\b[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\b`)

// --- client side ------------------------------------------------------------------

func send(t *testing.T, tr *transport.HTTPS, labURL string, s *keys.Signer, sigs ...*msg.Signal) *msg.Ack {
	t.Helper()
	signer := auth.NewSiteKeySigner(s)
	sub := &msg.Submission{RequestID: msg.NewID()}
	for _, sg := range sigs {
		payload, _ := jsonx.Marshal(sg)
		sealed, err := signer.Seal(context.Background(), contract.KindSignal, payload)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := sealed.Envelope.Marshal()
		sub.Envelopes = append(sub.Envelopes, raw)
	}
	resp, err := tr.Submit(context.Background(), transport.Lab{ID: "lab-a", Endpoint: labURL}, sub, "")
	if err != nil {
		t.Fatal(err)
	}
	res, err := verify.Signed(contract.KindAck, resp.AckEnvelope, &verify.Context{Now: time.Now(), Trust: testkeys.TrustStore("lab-a"), ExpectedInReplyTo: sub.RequestID})
	if err != nil {
		t.Fatalf("client rejects the ack: %v", err)
	}
	return res.Value.(*msg.Ack)
}

func tip(actionSig string, i int) *msg.Signal {
	now := time.Now()
	return &msg.Signal{Schema: msg.SchemaSignal, ID: msg.NewID(), Kind: "tip", TimeBucket: msg.TimeBucket(now, 5), ActionSig: actionSig,
		RequestSig: msg.RequestSig(msg.RequestShape{Method: "POST", PathTemplate: fmt.Sprintf("/wp-json/gallery/v1/item/{n}/%d", i), ParamNames: []string{"id"}, ContentType: "application/json", RuleIDs: []int{942100}}),
		WAFRules:   []int{942100}, Score: 85, Category: "sqli", Origin: msg.Origin{Country: "NL", ASN: 64500, NetClass: "hosting", Attribution: "tcp_peer"},
		Agent: msg.Agent{Family: "python-requests", Major: 2}}
}

// feedReader collects verified events from a lab feed.
type feedReader struct {
	mu     sync.Mutex
	events []stream.Event
}

func (f *feedReader) follow(ctx context.Context, c *http.Client, base string) {
	sub := &upstream.Subscriber{Base: base, Client: c, OnEvent: func(ev upstream.Event) {
		f.mu.Lock()
		f.events = append(f.events, ev.Event)
		f.mu.Unlock()
	}, MinDelay: 50 * time.Millisecond, MaxDelay: 200 * time.Millisecond}
	sub.Run(ctx)
}

// find returns the first event of typ whose envelope verifies with k=3.
func (f *feedReader) find(typ string) (*verify.Result, bool) {
	f.mu.Lock()
	evs := append([]stream.Event(nil), f.events...)
	f.mu.Unlock()
	ctx := &verify.Context{Now: time.Now(), Trust: testkeys.TrustStore("lab-a", "lab-b", "lab-c"), Threshold: 3, Channel: "schild-main", SkipState: true}
	for _, e := range evs {
		if e.Type != typ {
			continue
		}
		if res, err := verify.Signed(verify.StreamKind(typ), e.Envelope, ctx); err == nil {
			return res, true
		}
	}
	return nil, false
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func TestLabEndToEnd(t *testing.T) {
	rigs := startLabs(t)
	a, b, c := rigs["lab-a"], rigs["lab-b"], rigs["lab-c"]
	tlsClient := a.feed.Client()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client := &feedReader{}
	go client.follow(ctx, tlsClient, a.feed.URL)

	// 1. Clients of three issuers report one pattern; the lab acks with its key.
	tr := transport.NewHTTPS(5 * time.Second)
	tr.Client.Transport = tlsClient.Transport
	for i, s := range []*keys.Signer{testkeys.Signer("site-a"), testkeys.Signer("site-c"), siteKey("site-x3")} {
		ack := send(t, tr, a.ingest.URL, s, tip("sqli/rest-api", i), tip("sqli/rest-api", i+10))
		if len(ack.Accepted) != 2 || ack.Control.Reason != "ok" || ack.Lab != "lab-a" {
			t.Fatalf("ack %+v", ack)
		}
	}
	// A revoked or unknown key is rejected; a replay is a duplicate.
	if ack := send(t, tr, a.ingest.URL, testkeys.Signer("evil"), tip("sqli/rest-api", 99)); len(ack.Rejected) != 1 || ack.Rejected[0].Reason != "signature" {
		t.Fatalf("unknown key: %+v", ack)
	}

	// 2. Dashboard: the pattern reaches the observe level (3 issuers).
	a.login(t)
	pid := "p_"
	eventually(t, "pattern with 3 issuers", func() bool {
		var page struct {
			Items []struct {
				PatternID string `json:"pattern_id"`
				Issuers   int    `json:"issuers"`
				Status    string `json:"status"`
			} `json:"items"`
		}
		a.must(t, "GET", "/patterns?sort=issuers", nil, 200, "PatternPage", &page)
		for _, p := range page.Items {
			if p.Issuers == 3 && p.Status == "watching" {
				pid = p.PatternID
				return true
			}
		}
		return false
	})
	a.must(t, "GET", "/patterns/"+pid, nil, 200, "PatternDetail", nil)
	a.must(t, "GET", "/signals?pattern_id="+pid+"&limit=2", nil, 200, "ReceivedSignalPage", nil)
	a.must(t, "GET", "/health", nil, 200, "LabHealth", nil)

	// 3. Proposal with evidence; the allowed action follows the evidence.
	var prop struct {
		ID               string  `json:"id"`
		AllowedMaxAction *string `json:"allowed_max_action"`
		Status           string  `json:"status"`
	}
	a.must(t, "POST", "/proposals", map[string]any{"pattern_id": pid, "class": "virtual_patch", "requested_max_action": "block",
		"seclang": `SecRule ARGS "@detectSQLi" "id:7700001,phase:2,deny,status:403,severity:CRITICAL,msg:'SQL injection in arguments'"`,
		"target":  map[string]any{"software": "wp-plugin/gallery", "versions": "<2.4.1", "cve": []string{"CVE-2026-12345"}}}, 201, "Proposal", &prop)
	if prop.AllowedMaxAction == nil || *prop.AllowedMaxAction != "observe" {
		t.Fatalf("tips of 3 issuers must allow observe, got %v", prop.AllowedMaxAction)
	}
	// No decision without a named login, and none without CSRF.
	saved := a.csrf
	a.csrf = "wrong-token-wrong-token"
	if res := a.call(t, "POST", "/proposals/"+prop.ID+"/approve", map[string]any{"max_action": "observe", "org": "Lab A"}); res.status != 403 {
		t.Fatalf("approve without CSRF: %d", res.status)
	}
	a.csrf = saved
	// v0.1: the author (admin) may not approve the proposal; bob does.
	if res := a.call(t, "POST", "/proposals/"+prop.ID+"/approve", map[string]any{"max_action": "observe", "org": "Lab A"}); res.status != 403 || !bytes.Contains(res.body, []byte(`"code":"self_approval"`)) {
		t.Fatalf("self approval must be refused: %d %s", res.status, res.body)
	}
	if err := a.app.Dash.Auth.SetPassword("bob", password); err != nil {
		t.Fatal(err)
	}
	var bob struct {
		CSRFToken string `json:"csrf_token"`
	}
	a.must(t, "POST", "/auth/login", map[string]any{"user": "bob", "password": password}, 200, "", &bob)
	a.csrf = bob.CSRFToken
	a.must(t, "POST", "/proposals/"+prop.ID+"/evidence", map[string]any{"kind": "reproduction", "image": "wordpress:6.6.2-gallery-2.4.0", "version": "2.4.0",
		"request": "POST /wp-json/gallery/v1/item HTTP/1.1\r\nHost: target.test\r\n\r\n{\"id\":\"1 OR 1=1\"}"}, 200, "Proposal", nil)
	a.must(t, "POST", "/proposals/"+prop.ID+"/evidence", map[string]any{"kind": "negative_corpus", "corpus_version": "corpus-2026.10", "corpus_matches": 0}, 200, "Proposal", &prop)
	if *prop.AllowedMaxAction != "challenge" {
		t.Fatalf("one reproduction and a clean corpus: %v", *prop.AllowedMaxAction)
	}
	until := msg.FormatTime(time.Now().Add(72 * time.Hour))
	res := a.call(t, "POST", "/proposals/"+prop.ID+"/approve", map[string]any{"max_action": "block", "max_action_until": until, "org": "Lab A"})
	if res.status != 409 || !bytes.Contains(res.body, []byte(`"code":"evidence"`)) {
		t.Fatalf("block above the evidence must be refused: %d %s", res.status, res.body)
	}
	a.must(t, "POST", "/proposals/"+prop.ID+"/approve", map[string]any{"max_action": "challenge", "max_action_until": until, "org": "Lab A"}, 200, "Proposal", nil)
	a.must(t, "GET", "/proposals", nil, 200, "ProposalPage", nil)

	// 4. Bundle signed by lab-a; co-signed by lab-b and lab-c through the
	//    feed protocol; published at k = 3 distinct operators.
	var bundle struct {
		Version uint64 `json:"version"`
		Status  string `json:"status"`
	}
	a.must(t, "POST", "/bundles", map[string]any{"add": []string{prop.ID}, "remove": []string{}}, 201, "Bundle", &bundle)
	if bundle.Status != "collecting" {
		t.Fatalf("bundle %+v", bundle)
	}
	for _, r := range []*labRig{b, c} {
		r.login(t)
		eventually(t, r.name+" sees the offered bundle", func() bool {
			return r.call(t, "GET", fmt.Sprintf("/bundles/%d", bundle.Version), nil).status == 200
		})
		r.must(t, "GET", fmt.Sprintf("/bundles/%d", bundle.Version), nil, 200, "Bundle", nil)
		if res := r.call(t, "POST", fmt.Sprintf("/bundles/%d/cosign", bundle.Version), map[string]any{"password": "falsch-falsch-falsch"}); res.status != 403 {
			t.Fatalf("co-sign with a wrong password: %d", res.status)
		}
		r.must(t, "POST", fmt.Sprintf("/bundles/%d/cosign", bundle.Version), map[string]any{"password": password}, 200, "Bundle", nil)
	}
	eventually(t, "verified bundle on the lab-a feed", func() bool { _, ok := client.find(stream.TypeBundle); return ok })
	br, _ := client.find(stream.TypeBundle)
	if r := br.Value.(*msg.Bundle).Rules; len(r) != 1 || r[0].MaxAction != "challenge" || len(br.Operators) != 3 {
		t.Fatalf("published bundle: %+v operators %v", r, br.Operators)
	}
	a.must(t, "GET", "/bundles", nil, 200, "BundlePage", nil)
	// Lab-b follows lab-a's feed and serves the bundle too (labs are relays).
	eventually(t, "lab-b imports the bundle", func() bool { return b.app.Engine.CurrentState().BundleVersion == bundle.Version })

	// 5. Emergency stop: typed confirmation, password, k-of-n.
	if res := a.call(t, "POST", "/emergency-stop", map[string]any{"confirm_text": "NOTAUS", "password": password, "reason": "emergency_stop"}); res.status != 400 {
		t.Fatalf("emergency stop without the typed word: %d", res.status)
	}
	var stop struct {
		Seq       uint64 `json:"seq"`
		Status    string `json:"status"`
		Threshold int    `json:"threshold"`
	}
	a.must(t, "POST", "/emergency-stop", map[string]any{"confirm_text": "NOT-AUS", "password": password, "reason": "emergency_stop", "note": "Fehlalarme im Checkout"}, 201, "Withdrawal", &stop)
	if stop.Status != "collecting" || stop.Threshold != 3 {
		t.Fatalf("stop %+v", stop)
	}
	for _, r := range []*labRig{b, c} {
		eventually(t, r.name+" sees the emergency stop", func() bool {
			var page struct {
				Items []struct {
					Seq    uint64 `json:"seq"`
					Status string `json:"status"`
				} `json:"items"`
			}
			r.must(t, "GET", "/withdrawals", nil, 200, "WithdrawalPage", &page)
			return len(page.Items) > 0 && page.Items[0].Seq == stop.Seq
		})
		r.must(t, "POST", fmt.Sprintf("/withdrawals/%d/cosign", stop.Seq), map[string]any{"password": password}, 200, "Withdrawal", nil)
	}
	eventually(t, "verified emergency stop on the feed", func() bool { _, ok := client.find(stream.TypeWithdrawal); return ok })
	wr, _ := client.find(stream.TypeWithdrawal)
	if w := wr.Value.(*msg.Withdrawal); w.Scope != "all" || w.UpToVersion != bundle.Version {
		t.Fatalf("withdrawal %+v", w)
	}

	// 6. Checkpoint announces the state and the public log head; the log
	//    chain verifies against the signed root.
	var cp *msg.Checkpoint
	eventually(t, "checkpoint with withdrawal 1", func() bool {
		resp, err := tlsClient.Get(a.feed.URL + "/v0/checkpoint")
		if err != nil {
			return false
		}
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		r, err := verify.Signed(contract.KindCheckpoint, raw, &verify.Context{Now: time.Now(), Trust: testkeys.TrustStore("lab-a")})
		if err != nil {
			return false
		}
		cp = r.Value.(*msg.Checkpoint)
		return cp.WithdrawalSeq == stop.Seq && cp.Bundle.Version == bundle.Version
	})
	resp, err := tlsClient.Get(a.feed.URL + "/v0/log?from=0&limit=500")
	if err != nil {
		t.Fatal(err)
	}
	var lp struct {
		Head    publog.Head     `json:"head"`
		Entries []*publog.Entry `json:"entries"`
	}
	json.NewDecoder(resp.Body).Decode(&lp)
	resp.Body.Close()
	head, err := publog.Verify(lp.Entries)
	if err != nil || head != lp.Head {
		t.Fatalf("public log tree: %v (%+v vs %+v)", err, head, lp.Head)
	}
	if cp.Log == nil || cp.Log.Size == 0 || cp.Log.Size > uint64(len(lp.Entries)) {
		t.Fatalf("checkpoint log head %+v does not fit the log", cp.Log)
	}
	if prefix, _ := publog.Verify(lp.Entries[:cp.Log.Size]); prefix.Root != cp.Log.Root {
		t.Fatalf("checkpoint log root %s is not the RFC 6962 root of the first %d entries (%s)", cp.Log.Root, cp.Log.Size, prefix.Root)
	}
	kinds := map[string]bool{}
	for _, e := range lp.Entries {
		kinds[e.Kind] = true
		if bytes.Contains([]byte(e.Summary), []byte("site")) {
			t.Fatalf("log entry mentions a client: %s", e.Summary)
		}
	}
	for _, k := range []string{"proposal", "bundle", "withdrawal", "checkpoint"} {
		if !kinds[k] {
			t.Fatalf("public log lacks %s entries", k)
		}
	}
	a.must(t, "GET", "/log?limit=5", nil, 200, "LogPage", nil)
	a.must(t, "GET", "/log/0", nil, 200, "LogEntry", nil)

	// 7. Remaining views and access management.
	a.must(t, "GET", "/relays", nil, 200, "RelayList", nil)
	a.must(t, "GET", "/peers", nil, 200, "PeerList", nil)
	a.must(t, "GET", "/settings", nil, 200, "LabSettings", nil)
	a.must(t, "PATCH", "/settings", map[string]any{"scoring": map[string]any{"min_issuers": 4}}, 200, "LabSettings", nil)
	if res := a.call(t, "PATCH", "/settings", map[string]any{"scoring": map[string]any{"min_issuers": 2}}); res.status != 400 {
		t.Fatalf("min_issuers below 3 must be refused: %d", res.status)
	}
	a.must(t, "GET", "/issuers", nil, 200, "IssuerList", nil)
	a.must(t, "GET", "/clients?limit=2", nil, 200, "ClientPage", nil)
	a.must(t, "POST", "/issuers/issuer-x3/revoke", map[string]any{"password": password}, 200, "Issuer", nil)
	if ack := send(t, tr, a.ingest.URL, siteKey("site-x3"), tip("xss/comments", 1)); len(ack.Rejected) != 1 || ack.Rejected[0].Reason != "revoked" {
		t.Fatalf("revoked issuer still counted: %+v", ack)
	}
	a.must(t, "PATCH", "/clients/test-site-a", map[string]any{"quota_per_day": 7}, 200, "Client", nil)

	// 8. Metrics.
	rec := httptest.NewRecorder()
	a.app.MetricsHandler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	for _, m := range []string{"schild_lab_ack_seconds_bucket", "schild_lab_queue_depth", "schild_lab_feed_clients", "schild_lab_checkpoints_total"} {
		if !strings.Contains(rec.Body.String(), m) {
			t.Errorf("metrics lack %s", m)
		}
	}
}

func TestDashboardSecurityBaseline(t *testing.T) {
	rigs := startLabs(t)
	a := rigs["lab-a"]
	resp, err := http.Get(a.dash.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	csp := resp.Header.Get("Content-Security-Policy")
	// Strict CSP: no inline scripts and no inline styles (the UI needs neither).
	if strings.Contains(csp, "unsafe-inline") || !strings.Contains(csp, "script-src 'self'") || !strings.Contains(csp, "style-src 'self'") {
		t.Fatalf("CSP allows inline code: %s", csp)
	}
	if !strings.Contains(csp, "default-src 'self'") || !strings.Contains(csp, "frame-ancestors 'none'") ||
		resp.Header.Get("X-Content-Type-Options") != "nosniff" || resp.Header.Get("Referrer-Policy") != "no-referrer" {
		t.Fatalf("security headers missing: %v", resp.Header)
	}
	// Without a session nothing is readable.
	if r := a.call(t, "GET", "/health", nil); r.status != 401 {
		t.Fatalf("health without session: %d", r.status)
	}
	// D40: the setup code is required from everywhere, loopback included.
	if res := a.call(t, "POST", "/auth/setup", map[string]any{"password": password}); res.status != 403 {
		t.Fatalf("local setup without code: %d", res.status)
	}
	if res := a.call(t, "POST", "/auth/setup", map[string]any{"password": password, "setup_code": "wrong"}); res.status != 403 {
		t.Fatalf("local setup with a wrong code: %d", res.status)
	}
	// A non-local request (via a proxy) gets no localhost session and needs
	// the setup code for first-run setup.
	req, _ := http.NewRequest("POST", a.dash.URL+"/api/v0/auth/setup", strings.NewReader(`{"password":"`+password+`"}`))
	req.Header.Set("X-Forwarded-For", "192.0.2.10")
	r, _ := http.DefaultClient.Do(req)
	r.Body.Close()
	if r.StatusCode != 403 {
		t.Fatalf("remote setup without code: %d", r.StatusCode)
	}
	a.login(t)
	// Login rate limit.
	for i := 0; i < 6; i++ {
		a.call(t, "POST", "/auth/login", map[string]any{"user": "admin", "password": "nicht-das-passwort"})
	}
	if res := a.call(t, "POST", "/auth/login", map[string]any{"user": "admin", "password": password}); res.status != 429 {
		t.Fatalf("login after 6 failures: %d", res.status)
	}
	// The placeholder UI is served while no dashboard build is embedded.
	resp, _ = http.Get(a.dash.URL + "/#/signals")
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !bytes.Contains(body, []byte("<html")) {
		t.Fatal("no UI page")
	}
}

// v0.1: GET /api/v0/events/stream sends topic-named events: health at once,
// a LiveNotice for the topic of every state change.
func TestLiveStreamTopics(t *testing.T) {
	rigs := startLabs(t)
	a := rigs["lab-a"]
	a.login(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", a.dash.URL+"/api/v0/events/stream", nil)
	resp, err := a.browser.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		t.Fatalf("stream: %d %s", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	events := make(chan [2]string, 64)
	go func() {
		sc := bufio.NewScanner(resp.Body)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		var name string
		for sc.Scan() {
			line := sc.Text()
			if v, ok := strings.CutPrefix(line, "event: "); ok {
				name = v
			} else if v, ok := strings.CutPrefix(line, "data: "); ok {
				events <- [2]string{name, v}
			}
		}
		close(events)
	}()
	wait := func(topic string) string {
		t.Helper()
		for {
			select {
			case ev, ok := <-events:
				if !ok {
					t.Fatalf("stream ended before %s", topic)
				}
				if ev[0] == topic {
					return ev[1]
				}
			case <-ctx.Done():
				t.Fatalf("no %s event", topic)
			}
		}
	}
	validate(t, "LabHealth", []byte(wait("health")))
	a.must(t, "POST", "/proposals", map[string]any{"class": "heuristic", "requested_max_action": "observe",
		"seclang": `SecRule ARGS "@detectSQLi" "id:7700009,phase:2,pass,log,severity:NOTICE,msg:'SQL injection in arguments'"`}, 201, "Proposal", nil)
	validate(t, "LiveNotice", []byte(wait("proposals")))
}
