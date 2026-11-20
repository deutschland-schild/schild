//go:build !release

package hosts

// Independent review probes of the MVP-11 kill criterion "an unenrolled
// agent's report is accepted" (and the enrolment code rules). Each probe
// tries to get a report or an enrolment past the gateway that must not pass.
//
// The probes of the defects the review found (limiter reset, values in
// reject details) run normally since the fixes.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/dsse"
	hc "github.com/deutschland-schild/schild/contract/hostcheck"
	"github.com/deutschland-schild/schild/contract/keys"
	"github.com/deutschland-schild/schild/contract/msg"
	"github.com/deutschland-schild/schild/contract/testkeys"
	"github.com/deutschland-schild/schild/gateway/internal/hostcheck"
)

// reviewReport returns a valid agent report payload for signer at now.
func reviewReport(t *testing.T, now time.Time, keyid, gateway, nonce string) hc.AgentReport {
	t.Helper()
	r := hostcheck.Run(context.Background(), &hostcheck.FixtureEnv{Dir: "../hostcheck/testdata/hosts/debian12", Time: now},
		hostcheck.Options{Role: hc.RoleAgent, AgentKeyID: keyid, SchildVersion: "review"})
	if _, err := hostcheck.Marshal(r); err != nil {
		t.Fatal(err)
	}
	return hc.AgentReport{Schema: hc.SchemaAgentReport, Gateway: gateway, IssuedAt: msg.FormatTime(now), Nonce: nonce, Report: *r}
}

func signAs(t *testing.T, payloadType string, p any, signers ...dsse.Signer) []byte {
	t.Helper()
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	env, err := dsse.Sign(payloadType, b, signers...)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := env.Marshal()
	return raw
}

func nonceN(i int) string { return fmt.Sprintf("%032x", i+1) }

// serve posts raw to the agent listener handler from peer and returns
// HTTP status and "status[:error]" of the ack.
func serve(t *testing.T, g *testGW, path, peer string, raw []byte) (int, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(raw))
	req.RemoteAddr = peer + ":40000"
	rec := httptest.NewRecorder()
	g.Handler().ServeHTTP(rec, req)
	var a hc.Ack
	if err := json.Unmarshal(rec.Body.Bytes(), &a); err != nil {
		t.Fatalf("no ack: %s", rec.Body.String())
	}
	if a.Error != nil {
		return rec.Code, a.Status + ":" + *a.Error
	}
	return rec.Code, a.Status
}

func historyLen(t *testing.T, g *testGW, id string) int {
	t.Helper()
	d, err := g.Host(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return len(d.History)
}

// TestReviewReportsThatMustNotPass: every way a report without a valid,
// enrolled, matching agent signature for this gateway and time could be
// sent is rejected with the contract code and nothing is stored.
func TestReviewReportsThatMustNotPass(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	g := newGW(t, "gw-1", now, 30, "")
	idA := g.enrolKey(t, "agent-a", "enrolled")
	idB := g.enrolKey(t, "agent-b", "enrolled")
	g.enrolKey(t, "agent-c", "pending")
	a, b, c := testkeys.Signer("agent-a"), testkeys.Signer("agent-b"), testkeys.Signer("agent-c")
	pt := contract.KindAgentReport.PayloadType()
	n := 0
	next := func() string { n++; return nonceN(n) }

	cases := []struct {
		name string
		raw  []byte
		want string
	}{
		{"unenrolled key (not in the store)", signAs(t, pt, reviewReport(t, now, testkeys.Signer("evil").KeyID(), "gw-1", next()), testkeys.Signer("evil")), "rejected:signature"},
		{"pending agent", signAs(t, pt, reviewReport(t, now, c.KeyID(), "gw-1", next()), c), "rejected:signature"},
		{"lab key of schild.yaml", signAs(t, pt, reviewReport(t, now, testkeys.Signer("lab-a").KeyID(), "gw-1", next()), testkeys.Signer("lab-a")), "rejected:signature"},
		{"site key", signAs(t, pt, reviewReport(t, now, testkeys.Signer("site-a").KeyID(), "gw-1", next()), testkeys.Signer("site-a")), "rejected:signature"},
		{"B re-signs a report naming A", signAs(t, pt, reviewReport(t, now, a.KeyID(), "gw-1", next()), b), "rejected:signature"},
		{"A and B both sign", signAs(t, pt, reviewReport(t, now, a.KeyID(), "gw-1", next()), a, b), "rejected:envelope"},
		{"signal payload type", signAs(t, contract.KindSignal.PayloadType(), reviewReport(t, now, a.KeyID(), "gw-1", next()), a), "rejected:payload_type"},
		{"enrolment payload type", signAs(t, hc.EnrolmentPayloadType, reviewReport(t, now, a.KeyID(), "gw-1", next()), a), "rejected:payload_type"},
		{"other gateway", signAs(t, pt, reviewReport(t, now, a.KeyID(), "gw-2", next()), a), "rejected:channel"},
		{"issued 6 min ago", signAs(t, pt, reviewReport(t, now.Add(-6*time.Minute), a.KeyID(), "gw-1", next()), a), "rejected:expired"},
		{"issued 3 min ahead", signAs(t, pt, reviewReport(t, now.Add(3*time.Minute), a.KeyID(), "gw-1", next()), a), "rejected:clock_skew"},
	}
	// A signature over other bytes (payload swapped after signing).
	good := signAs(t, pt, reviewReport(t, now, a.KeyID(), "gw-1", next()), a)
	var env dsse.Envelope
	_ = json.Unmarshal(good, &env)
	other, _ := json.Marshal(reviewReport(t, now, a.KeyID(), "gw-2", next()))
	env.Payload = base64.StdEncoding.EncodeToString(other)
	swapped, _ := env.Marshal()
	cases = append(cases, struct {
		name string
		raw  []byte
		want string
	}{"payload swapped after signing", swapped, "rejected:signature"})

	for i, tc := range cases {
		// One peer per case: the per-peer request limit is not under test.
		code, got := serve(t, g, "/v0/agent/report", fmt.Sprintf("10.66.1.%d", i+1), tc.raw)
		if got != tc.want {
			t.Errorf("%s: got %s (HTTP %d), want %s", tc.name, got, code, tc.want)
		}
	}
	if h := historyLen(t, g, idA) + historyLen(t, g, idB); h != 0 {
		t.Fatalf("%d reports stored from rejected deliveries", h)
	}
}

// TestReviewOversize: bodies over the limit are refused with 413 and never
// parsed; a chunked body without Content-Length too.
func TestReviewOversize(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	g := newGW(t, "gw-1", now, 30, "")
	g.enrolKey(t, "agent-a", "enrolled")
	a := testkeys.Signer("agent-a")
	p := reviewReport(t, now, a.KeyID(), "gw-1", nonceN(1))
	// Pad an evidence-free field until the envelope is > 768 KiB.
	pad(&p, 800<<10)
	raw := signAs(t, contract.KindAgentReport.PayloadType(), p, a)
	if code, got := serve(t, g, "/v0/agent/report", "10.66.2.1", raw); code != 413 || got != "rejected:oversize" {
		t.Fatalf("oversize envelope: %d %s", code, got)
	}
	// 600 KiB payload in a < 768 KiB envelope is impossible with base64
	// (4/3); a payload just over 512 KiB gives an envelope ~ 700 KiB.
	p.Report.Inventory = p.Report.Inventory[:0]
	pad(&p, 520<<10)
	raw = signAs(t, contract.KindAgentReport.PayloadType(), p, a)
	if code, got := serve(t, g, "/v0/agent/report", "10.66.2.2", raw); code != 413 || got != "rejected:oversize" {
		t.Fatalf("oversize payload: %d %s (envelope %d bytes)", code, got, len(raw))
	}
	big := bytes.Repeat([]byte("a"), 2<<20)
	if code, got := serve(t, g, "/v0/agent/enrol", "10.66.2.3", big); code != 413 && got != "rejected:oversize" && got != "rejected:malformed" {
		t.Fatalf("oversize enrolment: %d %s", code, got)
	}
}

func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }

// pad grows the inventory until the payload has at least size bytes.
func pad(p *hc.AgentReport, size int) {
	for i := 0; len(mustJSON(p)) < size; {
		for j := 0; j < 500; j, i = j+1, i+1 {
			p.Report.Inventory = append(p.Report.Inventory, hc.InventoryItem{Kind: "os_package", Name: fmt.Sprintf("pad-%06d", i), Version: "1.0", Source: "dpkg"})
		}
	}
}

// TestReviewReplayWindow: the same envelope is a duplicate (stored once)
// while the nonce is remembered, and expired (not accepted) once the nonce
// has been dropped; a message issued at the edge of the future skew stays
// covered by its nonce until it expires.
func TestReviewReplayWindow(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	g := newGW(t, "gw-1", now, 30, "")
	id := g.enrolKey(t, "agent-a", "enrolled")
	a := testkeys.Signer("agent-a")
	pt := contract.KindAgentReport.PayloadType()
	raw := signAs(t, pt, reviewReport(t, now, a.KeyID(), "gw-1", nonceN(1)), a)
	if _, got := serve(t, g, "/v0/agent/report", "10.66.3.1", raw); got != "accepted" {
		t.Fatal(got)
	}
	for i := 0; i < 3; i++ {
		if _, got := serve(t, g, "/v0/agent/report", "10.66.3.1", raw); got != "duplicate" {
			t.Fatalf("resend %d: %s", i, got)
		}
	}
	if h := historyLen(t, g, id); h != 1 {
		t.Fatalf("duplicates stored: %d", h)
	}
	// Future edge: issued now+119 s.
	edge := signAs(t, pt, reviewReport(t, now.Add(119*time.Second), a.KeyID(), "gw-1", nonceN(2)), a)
	if _, got := serve(t, g, "/v0/agent/report", "10.66.3.2", edge); got != "accepted" {
		t.Fatal(got)
	}
	// Walk the clock in 30 s steps over 10 minutes, expiring nonces like
	// the loop does, and resend both: never accepted again.
	for step := 0; step < 20; step++ {
		g.clock.Add(30 * time.Second)
		g.expireNonces(context.Background())
		for j, r := range [][]byte{raw, edge} {
			_, got := serve(t, g, "/v0/agent/report", fmt.Sprintf("10.66.4.%d", step*2+j+1), r)
			if got == "accepted" {
				t.Fatalf("replay accepted after %ds (message %d)", (step+1)*30, j)
			}
		}
	}
	if h := historyLen(t, g, id); h != 2 {
		t.Fatalf("history %d, want 2", h)
	}
}

// TestReviewRevokedStaysOut: after revocation the key is answered with
// revoked, and it cannot come back through a new enrolment code.
func TestReviewRevokedStaysOut(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	g := newGW(t, "gw-1", now, 30, "")
	id := g.enrolKey(t, "agent-a", "enrolled")
	a := testkeys.Signer("agent-a")
	if _, err := g.Revoke(context.Background(), id, ""); err != nil {
		t.Fatal(err)
	}
	if _, got := serve(t, g, "/v0/agent/report", "10.66.5.1", signAs(t, contract.KindAgentReport.PayloadType(), reviewReport(t, now, a.KeyID(), "gw-1", nonceN(1)), a)); got != "rejected:revoked" {
		t.Fatal(got)
	}
	en, err := g.CreateEnrolment(context.Background(), "", 30, "")
	if err != nil {
		t.Fatal(err)
	}
	k := testkeys.Get("agent-a")
	e := hc.Enrolment{Schema: hc.SchemaEnrolment, Gateway: "gw-1", Code: en.Code, KeyID: k.KeyID, PublicKey: k.Public, Hostname: "again.example", IssuedAt: msg.FormatTime(now), Nonce: nonceN(2)}
	if _, got := serve(t, g, "/v0/agent/enrol", "10.66.5.2", signAs(t, hc.EnrolmentPayloadType, e, a)); got != "rejected:enrolment_code" {
		t.Fatalf("revoked key re-enrolled: %s", got)
	}
	// Same public key under a new key id: also known.
	e.KeyID, e.Nonce = "again/agent/2026-10", nonceN(3)
	s, _ := keys.NewSigner(e.KeyID, testkeys.Private("agent-a"))
	if _, got := serve(t, g, "/v0/agent/enrol", "10.66.5.3", signAs(t, hc.EnrolmentPayloadType, e, s)); got != "rejected:enrolment_code" {
		t.Fatalf("revoked public key re-enrolled under a new key id: %s", got)
	}
}

// TestReviewEnrolmentCodeRace: one code, many agents at the same time:
// exactly one becomes pending.
func TestReviewEnrolmentCodeRace(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	g := newGW(t, "gw-1", now, 30, "")
	en, err := g.CreateEnrolment(context.Background(), "", 30, "")
	if err != nil {
		t.Fatal(err)
	}
	const n = 16
	var pending atomic.Int64
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		seed := bytes.Repeat([]byte{byte(i + 1)}, 32)
		kid := fmt.Sprintf("race-%d/agent/2026-10", i)
		s, err := keys.NewSigner(kid, ed25519.NewKeyFromSeed(seed))
		if err != nil {
			t.Fatal(err)
		}
		e := hc.Enrolment{Schema: hc.SchemaEnrolment, Gateway: "gw-1", Code: en.Code, KeyID: kid, PublicKey: keys.FormatPublicKey(s.Public()),
			Hostname: fmt.Sprintf("race-%d.example", i), IssuedAt: msg.FormatTime(now), Nonce: nonceN(100 + i)}
		raw := signAs(t, hc.EnrolmentPayloadType, e, s)
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for {
				st, _, _ := g.Enrol(context.Background(), raw)
				if st == "retry" {
					continue
				}
				if st == "pending" {
					pending.Add(1)
				}
				return
			}
		}()
	}
	close(start)
	wg.Wait()
	as, _ := g.Agents(context.Background(), "")
	if pending.Load() != 1 || len(as) != 1 {
		t.Fatalf("one code enrolled %d agents (%d listed)", pending.Load(), len(as))
	}
}

// TestReviewEnrolmentBruteForceLimit: wrong codes from one address are cut
// off after the failure limit (429 retry) even with a valid code.
func TestReviewEnrolmentBruteForceLimit(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	g := newGW(t, "gw-1", now, 30, "")
	wrong := func(i int) []byte {
		seed := bytes.Repeat([]byte{byte(i + 1)}, 32)
		kid := fmt.Sprintf("bf-%d/agent/2026-10", i)
		s, _ := keys.NewSigner(kid, ed25519.NewKeyFromSeed(seed))
		e := hc.Enrolment{Schema: hc.SchemaEnrolment, Gateway: "gw-1", Code: "AAAA-BBBB-CCCC-" + fmt.Sprintf("%04d", 2222+i)[:4], KeyID: kid,
			PublicKey: keys.FormatPublicKey(s.Public()), Hostname: "bf.example", IssuedAt: msg.FormatTime(now), Nonce: nonceN(200 + i)}
		e.Code = strings.NewReplacer("0", "2", "1", "3").Replace(e.Code)
		return signAs(t, hc.EnrolmentPayloadType, e, s)
	}
	limited := -1
	for i := 0; i < 30; i++ {
		code, got := serve(t, g, "/v0/agent/enrol", "203.0.113.7", wrong(i))
		if code == 429 {
			limited = i
			break
		}
		if got != "rejected:enrolment_code" {
			t.Fatalf("attempt %d: %s", i, got)
		}
	}
	if limited < 0 || limited > 11 {
		t.Fatalf("no rate limit within 30 wrong codes (limited at %d)", limited)
	}
	t.Logf("cut off after %d wrong codes", limited)
}

// TestReviewLimiterResetByAddressFlood: the limiter forgets every counter
// once it holds more than 10000 keys. An attacker with many source addresses
// (one IPv6 /64) sends one cheap request per address to the report endpoint
// and so resets the enrolment failure counter of its brute-force address.
// The 80-bit code space keeps brute force infeasible anyway, so the impact
// is small, but the limit the contract promises does not hold.
func TestReviewLimiterResetByAddressFlood(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	g := newGW(t, "gw-1", now, 30, "")
	for i := 0; i < 11; i++ {
		_, _ = serve(t, g, "/v0/agent/enrol", "2001:db8::1", []byte("{}"))
	}
	if code, _ := serve(t, g, "/v0/agent/enrol", "2001:db8::1", []byte("{}")); code != 429 {
		t.Fatalf("precondition: not limited (%d)", code)
	}
	for i := 0; i < 10001; i++ {
		_, _ = serve(t, g, "/v0/agent/report", fmt.Sprintf("2001:db8::%x:%x", i>>16+1, i&0xffff), []byte("x"))
	}
	if code, _ := serve(t, g, "/v0/agent/enrol", "2001:db8::1", []byte("{}")); code == 429 {
		return
	}
	t.Fatal("enrolment failure limit of 2001:db8::1 was reset by 10001 one-shot report requests from other addresses")
}

// TestReviewRejectDetailEchoesValues: the rejection detail of an enrolled
// agent's delivery is stored and shown in the dashboard (GET /hosts/{id}
// last_rejected.detail) and logged. Schema errors quote the offending
// string, so whatever a (buggy or modified) agent put in a field that
// fails the schema ends up verbatim in the dashboard and the gateway log,
// bypassing the forbidden-content net when the value does not match the
// detectors (e.g. a bare token with a space).
func TestReviewRejectDetailEchoesValues(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	g := newGW(t, "gw-1", now, 30, "")
	id := g.enrolKey(t, "agent-a", "enrolled")
	a := testkeys.Signer("agent-a")
	p := reviewReport(t, now, a.KeyID(), "gw-1", nonceN(1))
	const canary = "ghp_rvwcanary7Hk2 x"
	v := canary
	p.Report.Findings[0].Evidence.Value = &v
	if _, got := serve(t, g, "/v0/agent/report", "10.66.6.1", signAs(t, contract.KindAgentReport.PayloadType(), p, a)); got != "rejected:schema" {
		t.Fatalf("precondition: %s", got)
	}
	d, err := g.Host(context.Background(), id)
	if err != nil || d.LastRejected == nil {
		t.Fatalf("no last_rejected: %v", err)
	}
	if strings.Contains(d.LastRejected.Detail, "rvwcanary") {
		t.Fatalf("dashboard shows the rejected value: %q", d.LastRejected.Detail)
	}
}
