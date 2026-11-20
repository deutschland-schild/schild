package rules

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"sync"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/dsse"
	"github.com/deutschland-schild/schild/contract/jsonx"
	"github.com/deutschland-schild/schild/contract/msg"
	"github.com/deutschland-schild/schild/contract/testkeys"
	"github.com/deutschland-schild/schild/contract/verify"
	"github.com/deutschland-schild/schild/lab/internal/queue"
	"github.com/deutschland-schild/schild/lab/internal/scoring"
	"github.com/deutschland-schild/schild/lab/internal/store"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

type fakePub struct {
	mu          sync.Mutex
	bundles     [][]byte
	withdrawals [][]byte
}

func (f *fakePub) PublishBundle(_ uint64, env []byte) {
	f.mu.Lock()
	f.bundles = append(f.bundles, env)
	f.mu.Unlock()
}
func (f *fakePub) PublishWithdrawal(_ uint64, env []byte) {
	f.mu.Lock()
	f.withdrawals = append(f.withdrawals, env)
	f.mu.Unlock()
}
func (f *fakePub) Changed() {}

type lab struct {
	name string
	e    *Engine
	pub  *fakePub
	q    *queue.Queue
	sc   *scoring.Scorer
}

var operators = map[string]string{"lab-a": "op-test-a", "lab-a2": "op-test-a", "lab-b": "op-test-b", "lab-c": "op-test-c"}

func newLab(t *testing.T, name string, threshold int, simulated map[string]string) *lab {
	t.Helper()
	dir := t.TempDir()
	db, err := store.Open(filepath.Join(dir, "store.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	q, err := queue.Open(queue.Options{Path: filepath.Join(dir, "queue.db"), NoSync: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { q.Close() })
	e, err := New(db, Config{Lab: name, Operator: operators[name], Channel: "schild-main", Threshold: threshold,
		RulesSigner: testkeys.Signer(name), Trust: testkeys.TrustStore("lab-a", "lab-a2", "lab-b", "lab-c"), Simulated: simulated}, quiet)
	if err != nil {
		t.Fatal(err)
	}
	pub := &fakePub{}
	e.Publisher = pub
	sc := scoring.New(q, db, scoring.Config{MinIssuers: 3, MaxIssuerShare: 0.34, WindowMinutes: 1440, MinScore: 40}, quiet, nil)
	e.Scoring = sc.Config
	return &lab{name: name, e: e, pub: pub, q: q, sc: sc}
}

// feed puts tips into the lab: n signals per issuer, each from its own
// client key, with distinct request signatures.
func (l *lab) feed(t *testing.T, actionSig string, issuers []string, perIssuer int) string {
	t.Helper()
	now := time.Now().UTC()
	var items []queue.Item
	for _, iss := range issuers {
		for i := 0; i < perIssuer; i++ {
			s := msg.Signal{Schema: msg.SchemaSignal, ID: msg.NewID(), Kind: "tip", TimeBucket: msg.TimeBucket(now, 5),
				ActionSig: actionSig, RequestSig: msg.RequestSig(msg.RequestShape{Method: "POST", PathTemplate: fmt.Sprintf("/api/{n}/%d", i), ContentType: "application/json", RuleIDs: []int{942100}}),
				WAFRules: []int{942100}, Score: 80, Category: "sqli",
				Origin: msg.Origin{Country: "NL", ASN: 64500, NetClass: "hosting", Attribution: "tcp_peer"}, Agent: msg.Agent{Family: "python-requests", Major: 2}}
			b, _ := jsonx.Marshal(&s)
			items = append(items, queue.Item{Prio: queue.NewPattern, Kind: "signal", ID: s.ID, ReceivedMS: now.UnixMilli(), Issuer: iss,
				KeyID: fmt.Sprintf("site-%s-%d", iss, i), Expires: now.Add(25 * time.Hour).Unix(), Payload: b})
		}
	}
	for len(items) > 0 {
		n := min(len(items), 500)
		done, err := l.q.Enqueue(items[:n])
		if err != nil {
			t.Fatal(err)
		}
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		items = items[n:]
		for {
			k, err := l.sc.Step(1000)
			if err != nil {
				t.Fatal(err)
			}
			if k == 0 {
				break
			}
		}
	}
	return scoring.PatternID(actionSig)
}

const sqliRule = `SecRule ARGS "@detectSQLi" "id:7700001,phase:2,deny,status:403,severity:CRITICAL,msg:'SQL injection in arguments'"`
const observeRule = `SecRule ARGS "@detectSQLi" "id:7700002,phase:2,pass,log,severity:NOTICE,msg:'SQL injection in arguments'"`

func s(v string) *string { return &v }

func raw(v string) *json.RawMessage { r := json.RawMessage(v); return &r }

func mustCode(t *testing.T, err error, code string) {
	t.Helper()
	var re *Error
	if !errors.As(err, &re) || re.Code != code {
		t.Fatalf("want error code %q, got %v", code, err)
	}
}

func level(v ProposalView) string {
	if v.AllowedMaxAction == nil {
		return ""
	}
	return *v.AllowedMaxAction
}

func repro(l *lab, t *testing.T, id string) ProposalView {
	t.Helper()
	v, err := l.e.AddEvidence(id, EvidenceInput{Kind: "reproduction", Image: "wordpress:6.6.2-gallery-2.4.0", Version: "2.4.0",
		Request: "POST /wp-json/gallery/v1/upload HTTP/1.1\r\nHost: target.test\r\n\r\nid=1' OR '1'='1"})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestSybilOnlyNeverReachesObserve(t *testing.T) {
	l := newLab(t, "lab-a", 3, nil)
	pid := l.feed(t, "sqli/rest-api", []string{"issuer-test-evil"}, 500) // 500 fake clients, one issuer
	v, err := l.e.CreateProposal(ProposalInput{PatternID: &pid, Class: s("heuristic"), SecLang: s(observeRule), RequestedMaxAction: s("observe")}, "carol")
	if err != nil {
		t.Fatal(err)
	}
	if v.Evidence.TipIssuers != 1 || v.Evidence.MaxIssuerShare != 1 || level(v) != "" {
		t.Fatalf("Sybil pattern: issuers=%d share=%v level=%q", v.Evidence.TipIssuers, v.Evidence.MaxIssuerShare, level(v))
	}
	// Even with a reproduction attached, approval above the evidence fails,
	// and the pattern's tips add nothing.
	_, err = l.e.Approve(v.ID, ApproveInput{MaxAction: "observe", Org: "Lab A"}, "alice")
	mustCode(t, err, "evidence")
}

func TestTipsAloneCapAtObserve(t *testing.T) {
	l := newLab(t, "lab-a", 3, nil)
	pid := l.feed(t, "sqli/rest-api", []string{"issuer-test-1", "issuer-test-2", "issuer-test-3"}, 20)
	v, err := l.e.CreateProposal(ProposalInput{PatternID: &pid, Class: s("virtual_patch"), SecLang: s(sqliRule), RequestedMaxAction: s("block")}, "carol")
	if err != nil {
		t.Fatal(err)
	}
	if level(v) != "observe" || v.Evidence.TipIssuers != 3 {
		t.Fatalf("three issuers: level %q issuers %d", level(v), v.Evidence.TipIssuers)
	}
	// Two issuers carrying most of the tips: the share rule refuses observe.
	pid2 := l.feed(t, "xss/comments", []string{"issuer-test-1", "issuer-test-2"}, 20)
	l.feed(t, "xss/comments", []string{"issuer-test-3"}, 1)
	v2, _ := l.e.CreateProposal(ProposalInput{PatternID: &pid2, SecLang: s(observeRule)}, "carol")
	if level(v2) != "" {
		t.Fatalf("dominant issuers must not reach observe, got %q (share %v)", level(v2), v2.Evidence.MaxIssuerShare)
	}
	// Own sensor of one operator: still observe at most.
	v, _ = l.e.AddEvidence(v.ID, EvidenceInput{Kind: "sensor"})
	if level(v) != "observe" {
		t.Fatalf("single-operator sensor gave %q", level(v))
	}
	// Approval above observe fails without stronger evidence.
	repro(l, t, v.ID) // now reproduced by one operator, but no negative corpus run
	_, err = l.e.Approve(v.ID, ApproveInput{MaxAction: "challenge", MaxActionUntil: msg.FormatTime(time.Now().Add(72 * time.Hour)), Org: "Lab A"}, "alice")
	mustCode(t, err, "evidence")
}

func TestEvidenceLevelsAndApprovals(t *testing.T) {
	l := newLab(t, "lab-a", 3, nil)
	pid := l.feed(t, "sqli/rest-api", []string{"issuer-test-1", "issuer-test-2", "issuer-test-3"}, 5)
	v, _ := l.e.CreateProposal(ProposalInput{PatternID: &pid, Class: s("virtual_patch"), SecLang: s(sqliRule), RequestedMaxAction: s("block"),
		Target: raw(`{"software":"wp-plugin/gallery","versions":"<2.4.1","cve":["CVE-2026-12345"]}`)}, "carol")
	_, err := l.e.Approve(v.ID, ApproveInput{MaxAction: "observe", Org: "Lab A"}, "alice")
	mustCode(t, err, "evidence") // no reproduction yet
	v = repro(l, t, v.ID)
	if v.Status != StatusReview || level(v) != "observe" {
		t.Fatalf("reproduction without negative corpus: status %s level %q", v.Status, level(v))
	}
	v, _ = l.e.AddEvidence(v.ID, EvidenceInput{Kind: "negative_corpus", CorpusVersion: "corpus-2026.10", CorpusMatches: new(int)})
	if level(v) != "challenge" || v.Evidence.ReproducedOperators != 1 {
		t.Fatalf("one reproduction + clean corpus: level %q", level(v))
	}
	until := msg.FormatTime(time.Now().Add(72 * time.Hour))
	// Block needs reproduction by 2 operators and 2 organisations: refused.
	_, err = l.e.Approve(v.ID, ApproveInput{MaxAction: "block", MaxActionUntil: until, Org: "Lab A"}, "alice")
	mustCode(t, err, "evidence")
	// The deny rule cannot be approved as observe (observe requires pass).
	_, err = l.e.Approve(v.ID, ApproveInput{MaxAction: "observe", Org: "Lab A"}, "alice")
	mustCode(t, err, "seclang")
	v, err = l.e.Approve(v.ID, ApproveInput{MaxAction: "challenge", MaxActionUntil: until, Org: "Lab A"}, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if v.Status != StatusApproved || len(v.Approvals) != 1 || v.Approvals[0].By != "alice" {
		t.Fatalf("approval not recorded: %+v", v)
	}
	_, err = l.e.Approve(v.ID, ApproveInput{MaxAction: "challenge", MaxActionUntil: until, Org: "Other Org"}, "alice")
	mustCode(t, err, "conflict") // same person twice
	// Editing the text clears approvals.
	v, _ = l.e.UpdateProposal(v.ID, ProposalInput{SecLang: s(sqliRule + "\n")})
	if len(v.Approvals) != 0 || v.Status != StatusReview {
		t.Fatalf("edit must clear approvals: %+v", v.Approvals)
	}
	// Reject with reason.
	v, err = l.e.Reject(v.ID, "Regel zu breit", "bob")
	if err != nil || v.Status != StatusRejected || v.RejectedReason == nil {
		t.Fatalf("reject: %v %+v", err, v)
	}
}

// approved creates an approved challenge proposal on l.
func approved(t *testing.T, l *lab, action string) ProposalView {
	pid := l.feed(t, "sqli/rest-api", []string{"issuer-test-1", "issuer-test-2", "issuer-test-3"}, 3)
	text := sqliRule
	if action == "observe" {
		text = observeRule
	}
	v, err := l.e.CreateProposal(ProposalInput{PatternID: &pid, Class: s("virtual_patch"), SecLang: s(text), RequestedMaxAction: s(action),
		Target: raw(`{"software":"wp-plugin/gallery","versions":"<2.4.1"}`)}, "carol")
	if err != nil {
		t.Fatal(err)
	}
	repro(l, t, v.ID)
	l.e.AddEvidence(v.ID, EvidenceInput{Kind: "negative_corpus", CorpusVersion: "corpus-2026.10", CorpusMatches: new(int)})
	in := ApproveInput{MaxAction: action, Org: "Lab A"}
	if action != "observe" {
		in.MaxActionUntil = msg.FormatTime(time.Now().Add(72 * time.Hour))
	}
	v, err = l.e.Approve(v.ID, in, "alice")
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// courier delivers co-signatures directly to the proposing engine.
type courier map[string]*lab

func (c courier) SendSignature(peer string, kind contract.Kind, digest string, sig dsse.Signature) error {
	_, _, err := c[peer].e.AddSignature(kind, digest, sig)
	return err
}

func TestCoSigningPublishesAtThreshold(t *testing.T) {
	a, b, c := newLab(t, "lab-a", 3, nil), newLab(t, "lab-b", 3, nil), newLab(t, "lab-c", 3, nil)
	cr := courier{"lab-a": a, "lab-b": b, "lab-c": c}
	for _, l := range []*lab{a, b, c} {
		l.e.Courier = cr
	}
	p := approved(t, a, "challenge")
	bv, err := a.e.Assemble([]string{p.ID}, nil, 0, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if bv.Status != Collecting || bv.Version != 1 || len(bv.Signatures) != 1 || bv.Envelope != nil {
		t.Fatalf("assembled: %+v", bv)
	}
	if len(a.pub.bundles) != 0 {
		t.Fatal("published with one operator")
	}
	offer := func(to *lab) {
		for _, it := range a.e.Collecting() {
			if err := to.e.OfferFromPeer("lab-a", contract.Kind(it.Kind), it.Envelope); err != nil {
				t.Fatal(err)
			}
		}
	}
	offer(b)
	if _, err := b.e.CosignBundle(1, "bert"); err != nil {
		t.Fatal(err)
	}
	if len(a.pub.bundles) != 0 {
		t.Fatal("published with two of three operators")
	}
	offer(c)
	if _, err := c.e.CosignBundle(1, "carla"); err != nil {
		t.Fatal(err)
	}
	if len(a.pub.bundles) != 1 {
		t.Fatal("not published at three operators")
	}
	env := a.pub.bundles[0]
	res, err := verify.Signed(contract.KindBundle, env, &verify.Context{Now: time.Now(), Trust: testkeys.TrustStore("lab-a", "lab-b", "lab-c"), Threshold: 3, Channel: "schild-main"})
	if err != nil {
		t.Fatalf("published bundle does not verify for a default client: %v", err)
	}
	r := res.Value.(*msg.Bundle).Rules[0]
	if r.MaxAction != "challenge" || r.Evidence.ReproducedOperators != 1 || r.Evidence.TipIssuers != 3 || r.FeedbackPolicy != "narrow_only" {
		t.Fatalf("rule %+v", r)
	}
	pv, _ := a.e.GetProposal(p.ID)
	if pv.Status != StatusPublished || pv.BundleVersion == nil || *pv.BundleVersion != 1 {
		t.Fatalf("proposal after publish: %s", pv.Status)
	}
	// Lab B learns the published bundle from A's feed.
	if ok, err := b.e.ImportPublished(contract.KindBundle, env, "lab-a"); err != nil || !ok {
		t.Fatalf("import: %v %v", ok, err)
	}
	if st := b.e.CurrentState(); st.BundleVersion != 1 {
		t.Fatalf("lab-b state %+v", st)
	}

	// Emergency stop at A: effective only with three operators.
	wv, err := a.e.CreateWithdrawal("all", nil, "emergency_stop", "Fehlalarme", "alice")
	if err != nil {
		t.Fatal(err)
	}
	if wv.Status != Collecting || wv.UpToVersion != 1 {
		t.Fatalf("withdrawal %+v", wv)
	}
	offer(b)
	offer(c)
	if _, err := b.e.CosignWithdrawal(wv.Seq, "bert"); err != nil {
		t.Fatal(err)
	}
	if len(a.pub.withdrawals) != 0 {
		t.Fatal("emergency stop effective with two operators")
	}
	if _, err := c.e.CosignWithdrawal(wv.Seq, "carla"); err != nil {
		t.Fatal(err)
	}
	if len(a.pub.withdrawals) != 1 {
		t.Fatal("emergency stop not effective at three operators")
	}
	if st := a.e.CurrentState(); st.WithdrawalSeq != 1 || len(st.Withdrawals) != 1 {
		t.Fatalf("state after stop %+v", st)
	}
	pv, _ = a.e.GetProposal(p.ID)
	if pv.Status != StatusWithdrawn {
		t.Fatalf("proposal after emergency stop: %s", pv.Status)
	}
	// The next bundle does not bring the withdrawn rule back.
	bv, err = a.e.Assemble(nil, nil, 0, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if bv.Version != 2 || len(bv.Rules) != 0 {
		t.Fatalf("bundle after emergency stop: %+v", bv)
	}
}

func TestSignatureFromUnknownKeyRejected(t *testing.T) {
	a := newLab(t, "lab-a", 2, nil)
	p := approved(t, a, "challenge")
	bv, _ := a.e.Assemble([]string{p.ID}, nil, 0, "alice")
	var digest string
	for _, it := range a.e.Collecting() {
		digest = it.Digest
	}
	_ = bv
	var rec BundleRecord
	a.e.DB.View(func(tx *bolt.Tx) error { r, _, _ := getBundle(tx, 1); rec = *r; return nil })
	evil := testkeys.Signer("evil")
	sig, _ := evil.Sign(dsse.PAE(contract.KindBundle.PayloadType(), rec.Payload))
	_, _, err := a.e.AddSignature(contract.KindBundle, digest, dsse.Signature{KeyID: "test-evil", Sig: b64(sig)})
	mustCode(t, err, "signature")
	// A valid key with a signature over other bytes is refused too.
	lb := testkeys.Signer("lab-b")
	bad, _ := lb.Sign([]byte("something else"))
	_, _, err = a.e.AddSignature(contract.KindBundle, digest, dsse.Signature{KeyID: "test-lab-b", Sig: b64(bad)})
	mustCode(t, err, "signature")
	good, _ := lb.Sign(dsse.PAE(contract.KindBundle.PayloadType(), rec.Payload))
	ops, published, err := a.e.AddSignature(contract.KindBundle, digest, dsse.Signature{KeyID: "test-lab-b", Sig: b64(good)})
	if err != nil || ops != 2 || !published {
		t.Fatalf("k=2: ops=%d published=%v err=%v", ops, published, err)
	}
}

func TestSimulatedOperatorsOnlyObserve(t *testing.T) {
	sim := map[string]string{"lab-a2": "sim-a2"}
	a := newLab(t, "lab-a", 2, sim)
	a2 := newLab(t, "lab-a2", 2, sim)
	a2.e.Courier = courier{"lab-a": a}
	// A challenge rule co-signed by a second lab of the same real operator
	// (independent only through the simulation) is never published.
	p := approved(t, a, "challenge")
	a.e.Assemble([]string{p.ID}, nil, 0, "alice")
	for _, it := range a.e.Collecting() {
		a2.e.OfferFromPeer("lab-a", contract.Kind(it.Kind), it.Envelope)
	}
	a2.e.CosignBundle(1, "alex")
	if len(a.pub.bundles) != 0 {
		t.Fatal("challenge rule published through simulated operators")
	}
	bv, _ := a.e.GetBundle(1)
	if bv.Status != Collecting {
		t.Fatalf("status %s", bv.Status)
	}
	// An observe-only bundle may be published in the test profile.
	po := approved(t, a, "observe")
	_, err := a.e.Assemble([]string{po.ID}, nil, 0, "alice")
	if err != nil {
		t.Fatal(err)
	}
	for _, it := range a.e.Collecting() {
		a2.e.OfferFromPeer("lab-a", contract.Kind(it.Kind), it.Envelope)
	}
	if _, err := a2.e.CosignBundle(2, "alex"); err != nil {
		t.Fatal(err)
	}
	if len(a.pub.bundles) != 1 {
		t.Fatal("observe bundle with simulated operators not published")
	}
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func TestAuthorMayNotApprove(t *testing.T) {
	l := newLab(t, "lab-a", 3, nil)
	pid := l.feed(t, "sqli/rest-api", []string{"issuer-1", "issuer-2", "issuer-3"}, 2)
	v, err := l.e.CreateProposal(ProposalInput{PatternID: &pid, Class: s("heuristic"), SecLang: s(observeRule), RequestedMaxAction: s("observe")}, "carol")
	if err != nil {
		t.Fatal(err)
	}
	if v.CreatedBy == nil || *v.CreatedBy != "carol" {
		t.Fatalf("created_by %v", v.CreatedBy)
	}
	_, err = l.e.Approve(v.ID, ApproveInput{MaxAction: "observe", Org: "Lab A"}, "carol")
	var re *Error
	if !errors.As(err, &re) || re.Code != "self_approval" || re.Status != 403 {
		t.Fatalf("author approved own proposal: %v", err)
	}
	// Drafts from a localhost session have no named author.
	v, _ = l.e.CreateProposal(ProposalInput{SecLang: s(observeRule)}, LocalhostUser)
	if v.CreatedBy != nil {
		t.Fatalf("localhost draft has author %v", *v.CreatedBy)
	}
}
