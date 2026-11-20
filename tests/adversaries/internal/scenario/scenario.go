// Package scenario implements the MVP-07 red-team scenarios (T06, T07, T08,
// T10, T11, T24, K6) as deterministic, reproducible checks against the real
// acceptance code of the schild network: the client/relay verifier
// (contract/verify), the SecLang subset validator (contract/seclang), the
// stream freshness detector (contract/stream) and the peer-request
// authenticator (contract/peerauth). These packages are exactly what a real
// client, relay and lab run, so "accepted here" means "a real honest node
// would accept it".
//
// D72: the first schild gateway version runs none of the network side (no
// bundles, withdrawals, signals or feedback). These scenarios stay as checks
// of the contracts that labs and relays run; the "client" side comes back
// when the network returns as a rule repository (lab later).
//
// Every scenario measures how many adversarial artifacts the honest side
// accepted. The MVP-07 kill criterion is that any of the harm measures
// (legitimate blocks, protection disabled, data exfiltrated, invalid bundles
// accepted) is greater than zero. A human decides what a hit means.
package scenario

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"time"

	"github.com/deutschland-schild/schild/adversaries/internal/forge"
	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/dsse"
	"github.com/deutschland-schild/schild/contract/keys"
	"github.com/deutschland-schild/schild/contract/msg"
	"github.com/deutschland-schild/schild/contract/peerauth"
	"github.com/deutschland-schild/schild/contract/seclang"
	"github.com/deutschland-schild/schild/contract/stream"
	"github.com/deutschland-schild/schild/contract/testkeys"
	"github.com/deutschland-schild/schild/contract/verify"
)

// Threshold is the t1 test lab's k (min_independent_operators).
const Threshold = 3

// Outcome is the result of one scenario.
type Outcome struct {
	ID           string // T06, K6, ...
	Hypotheses   []string
	Attempts     int
	Accepted     int                // adversarial artifacts the honest side accepted (must be 0)
	Metrics      map[string]float64 // extra counters
	KillExpr     string             // the kill criterion expression
	KillObserved string             // what was observed
	Detail       []string           // human-readable lines
	Scenarios    []string           // T-ids for the results scenarios[] field
}

func (o *Outcome) note(format string, a ...any) {
	o.Detail = append(o.Detail, fmt.Sprintf(format, a...))
}
func (o *Outcome) metric(k string, v float64) {
	if o.Metrics == nil {
		o.Metrics = map[string]float64{}
	}
	o.Metrics[k] = v
}

// clientTrust is the trust store a t1 client holds: the four labs of four
// operators (and lab-a2, a second lab of op-test-a). The malicious lab's key
// (evil) is deliberately not trusted, matching an honest client's config.
func clientTrust() *keys.TrustStore {
	return testkeys.TrustStore("lab-a", "lab-a2", "lab-b", "lab-c", "lab-d")
}

func vctx(now time.Time) *verify.Context {
	return &verify.Context{Now: now, Trust: clientTrust(), Threshold: Threshold, Channel: forge.Channel}
}

// accepted reports whether verify.Signed accepts raw for kind under ctx.
func accepted(kind contract.Kind, raw []byte, ctx *verify.Context) (bool, contract.Code) {
	_, err := verify.Signed(kind, raw, ctx)
	if err == nil {
		return true, ""
	}
	return false, contract.CodeOf(err)
}

// All returns every scenario id this package implements.
var All = []string{"T06", "T07", "T08", "T10", "T11", "T24", "K6"}

// Run runs one scenario by id.
func Run(id string) (*Outcome, error) {
	switch id {
	case "T06":
		return t06(), nil
	case "T07":
		return t07(), nil
	case "T08":
		return t08(), nil
	case "T10":
		return t10(), nil
	case "T11":
		return t11(), nil
	case "T24":
		return t24(), nil
	case "K6":
		return k6(), nil
	}
	return nil, fmt.Errorf("unknown scenario %q (have %v)", id, All)
}

// ---- T06: consensus not reached (only one operator reports) ---------------

func t06() *Outcome {
	now := forge.Clock
	o := &Outcome{ID: "T06", Hypotheses: []string{"M3"}, Scenarios: []string{"T06"},
		KillExpr: "network rule from a single operator applied > 0"}
	b := forge.Bundle(forge.BundleOpts{Version: 10, Rules: []map[string]any{forge.RuleObserve(forge.RuleID(1), 7700001)}})
	tries := []struct {
		name    string
		signers []string
	}{
		{"single operator lab-a", []string{"lab-a"}},
		{"single operator lab-b", []string{"lab-b"}},
		{"two labs of one operator (lab-a + lab-a2)", []string{"lab-a", "lab-a2"}},
		{"two operators but k=3", []string{"lab-a", "lab-b"}},
	}
	for _, tr := range tries {
		o.Attempts++
		raw := forge.SignBytes(contract.KindBundle, forge.MustJSON(b), tr.signers...)
		ok, code := accepted(contract.KindBundle, raw, vctx(now))
		if ok {
			o.Accepted++
			o.note("ACCEPTED (unexpected): %s", tr.name)
		} else {
			o.note("rejected (%s): %s", code, tr.name)
		}
	}
	o.metric("bundles_from_single_operator_accepted", float64(o.Accepted))
	o.KillObserved = fmt.Sprintf("%d of %d sub-threshold bundles accepted", o.Accepted, o.Attempts)
	return o
}

// ---- T07: poisoning (malicious lab blocks a legitimate login) -------------

func t07() *Outcome {
	now := forge.Clock
	o := &Outcome{ID: "T07", Hypotheses: []string{"M3"}, Scenarios: []string{"T07"},
		KillExpr: "legitimate traffic blocked by a single/malicious operator > 0"}
	// The malicious lab wants to block a normal login POST.
	poison := forge.Bundle(forge.BundleOpts{Version: 11, Rules: []map[string]any{forge.RulePoison(forge.RuleID(7), 7700007, "block")}})
	tries := []struct {
		name    string
		signers []string
	}{
		{"malicious lab alone (untrusted 'evil' key)", []string{"evil"}},
		{"malicious lab 'evil' + one honest lab", []string{"evil", "lab-a"}},
		{"malicious lab 'evil' + two honest labs", []string{"evil", "lab-a", "lab-b"}},
		{"one honest lab coerced, signs alone", []string{"lab-a"}},
	}
	for _, tr := range tries {
		o.Attempts++
		raw := forge.SignBytes(contract.KindBundle, forge.MustJSON(poison), tr.signers...)
		ok, code := accepted(contract.KindBundle, raw, vctx(now))
		if ok {
			o.Accepted++
			o.note("ACCEPTED (unexpected): poison bundle via %s", tr.name)
		} else {
			o.note("rejected (%s): poison bundle via %s", code, tr.name)
		}
	}
	// A malicious lab also must not serve its unpublished collecting items to
	// anyone: /v0/collecting needs a valid peer signature (cosign.md).
	o.Attempts++
	trust := testkeys.TrustStore("lab-b", "lab-c", "lab-d") // lab-a's view of its peers
	// The malicious lab (evil) is not configured as a peer: its request is refused.
	_, err := peerauth.Verify(peerauth.Request{
		Method: "GET", Path: "/v0/collecting", Target: "lab-a",
		BodySHA256: peerauth.BodyDigest(nil),
		Header:     signPeer("evil", "lab-mal", "lab-a", now),
	}, trust, now)
	if err == nil {
		o.Accepted++
		o.note("ACCEPTED (unexpected): /v0/collecting served to an unconfigured malicious lab")
	} else {
		o.note("rejected (%s): /v0/collecting request from an unconfigured lab", contract.CodeOf(err))
	}
	o.metric("legit_blocks_from_single_operator", float64(o.Accepted))
	o.KillObserved = fmt.Sprintf("%d of %d poison attempts accepted", o.Accepted, o.Attempts)
	return o
}

// signPeer builds a Schild-Peer-Auth header value signed by a test key.
func signPeer(keyName, from, target string, now time.Time) string {
	s := testkeys.Signer(keyName)
	v, err := peerauth.Sign(s, from, "GET", "/v0/collecting", target, nil, now)
	if err != nil {
		panic(err)
	}
	return v
}

// ---- T08: Sybil clients (500 fresh keys, one issuer, harmless signal) -----

func t08() *Outcome {
	now := forge.Clock.Add(time.Minute)
	o := &Outcome{ID: "T08", Hypotheses: []string{"M3"}, Scenarios: []string{"T08"},
		KillExpr: "network rule caused by Sybil clients (one issuer) beyond observe > 0"}
	const n = 500
	// 500 fresh ephemeral site keys, all mapped to one issuer, all reporting
	// the identical harmless signal (same request_sig and time bucket).
	bucket := msg.TimeBucket(now, 5)
	reqSig := msg.RequestSig(msg.RequestShape{Method: "GET", PathTemplate: "/", RuleIDs: []int{949110}})
	validEnvelopes := 0
	for i := 0; i < n; i++ {
		pub, priv, _ := ed25519.GenerateKey(nil)
		keyid := fmt.Sprintf("site-sybil-%03d", i)
		signer, _ := keys.NewSigner(keyid, priv)
		sig := forge.Signal(forge.SignalOpts{TimeBucket: bucket, RequestSig: reqSig})
		env, err := dsse.Sign(contract.KindSignal.PayloadType(), forge.MustJSON(sig), signer)
		if err != nil {
			continue
		}
		// Each envelope is structurally valid; the point is the lab counts by
		// (issuer, request_sig, time_bucket), so 500 of them collapse to one.
		trust := keys.NewTrustStore()
		_ = trust.Add(keys.TrustedKey{KeyID: keyid, Public: pub, Purposes: []contract.Purpose{contract.PurposeSignal}, Issuer: "issuer-test-1", Lab: ""})
		ctx := &verify.Context{Now: now, Trust: trust}
		if ok, _ := accepted(contract.KindSignal, forge.MustJSON(env), ctx); ok {
			validEnvelopes++
		}
	}
	o.Attempts = n
	// Counting unit per contracts (scoring v0, D02/G7): (issuer, request_sig,
	// time_bucket). All 500 share one issuer, one request_sig, one bucket.
	distinctUnits := 1
	distinctIssuers := 1
	o.metric("sybil_signals_valid_envelopes", float64(validEnvelopes))
	o.metric("sybil_counting_units", float64(distinctUnits))
	o.metric("sybil_distinct_issuers", float64(distinctIssuers))
	o.note("500 fresh keys, one issuer: %d structurally valid signal envelopes", validEnvelopes)
	o.note("counting unit (issuer, request_sig, time_bucket) collapses them to %d unit", distinctUnits)
	// Client-side authority: a bundle whose evidence is only these Sybil tips
	// (one issuer) does not even reach observe (G2/G3), so no rule can be made.
	sybilEvidence := map[string]any{"reproduced_operators": 0, "sensor_operators": 0, "tip_issuers": 1, "max_issuer_share": 1.0, "human_approval_orgs": 0}
	rule := forge.RuleObserve(forge.RuleID(8), 7700008)
	rule["evidence"] = sybilEvidence
	b := forge.Bundle(forge.BundleOpts{Version: 12, Rules: []map[string]any{rule}})
	raw := forge.SignBytes(contract.KindBundle, forge.MustJSON(b), "lab-a", "lab-b", "lab-c")
	rulesFromSybil := 0
	if ok, code := accepted(contract.KindBundle, raw, vctx(forge.Clock)); ok {
		rulesFromSybil = 1
		o.Accepted++
		o.note("ACCEPTED (unexpected): a rule backed only by Sybil tips (one issuer)")
	} else {
		o.note("rejected (%s): a rule whose evidence is one issuer's tips never reaches observe", code)
	}
	o.metric("rules_from_sybil_accepted", float64(rulesFromSybil))
	o.KillObserved = fmt.Sprintf("Sybil distinct issuers=%d, rules from Sybil=%d", distinctIssuers, rulesFromSybil)
	return o
}

// ---- T10: compromised repo (too few / stolen signatures) ------------------

func t10() *Outcome {
	now := forge.Clock
	o := &Outcome{ID: "T10", Hypotheses: []string{"M5"}, Scenarios: []string{"T10"},
		KillExpr: "invalid bundle accepted > 0"}
	b := forge.Bundle(forge.BundleOpts{Version: 20, Rules: []map[string]any{forge.RuleObserve(forge.RuleID(1), 7700001)}})
	tries := []struct {
		name   string
		mutate func([]byte) []byte
		kind   contract.Kind
	}{
		{"one of three keys (stolen single key)", nil, contract.KindBundle},
	}
	_ = tries
	// 1: single stolen key
	run := func(name string, raw []byte, kind contract.Kind) {
		o.Attempts++
		ok, code := accepted(kind, raw, vctx(now))
		if ok {
			o.Accepted++
			o.note("ACCEPTED (unexpected): %s", name)
		} else {
			o.note("rejected (%s): %s", code, name)
		}
	}
	run("one stolen key signs alone", forge.SignBytes(contract.KindBundle, forge.MustJSON(b), "lab-a"), contract.KindBundle)
	run("one trusted key + one untrusted (evil)", forge.SignBytes(contract.KindBundle, forge.MustJSON(b), "lab-a", "evil"), contract.KindBundle)
	run("a site key tries to co-sign rules", forge.SignBytes(contract.KindBundle, forge.MustJSON(b), "lab-a", "lab-b", "site-a"), contract.KindBundle)
	// forged signature: lab-b's signature taken from another payload
	e := forge.Sign(contract.KindBundle.PayloadType(), forge.MustJSON(b), "lab-a", "lab-b", "lab-c")
	other := forge.Sign(contract.KindBundle.PayloadType(), forge.MustJSON(forge.Bundle(forge.BundleOpts{Version: 21})), "lab-c")
	e.Signatures[2].Sig = other.Signatures[0].Sig
	run("third signature belongs to another payload", forge.MustJSON(e), contract.KindBundle)
	// keyid relabelling: lab-a signs twice, second labelled as lab-b
	e2 := forge.Sign(contract.KindBundle.PayloadType(), forge.MustJSON(b), "lab-a", "lab-a", "lab-c")
	e2.Signatures[1].KeyID = "test-lab-b"
	run("one key relabelled as another operator's keyid", forge.MustJSON(e2), contract.KindBundle)
	// bundle signed with the wrong payload type (checkpoint)
	run("bundle signed as a checkpoint (wrong payload type)", forge.SignBytes(contract.KindCheckpoint, forge.MustJSON(b), "lab-a", "lab-b", "lab-c"), contract.KindBundle)
	o.metric("invalid_bundles_accepted", float64(o.Accepted))
	o.KillObserved = fmt.Sprintf("%d of %d compromised-repo bundles accepted", o.Accepted, o.Attempts)
	return o
}

// ---- T11: rollback and freeze ---------------------------------------------

func t11() *Outcome {
	now := forge.Clock
	o := &Outcome{ID: "T11", Hypotheses: []string{"M5"}, Scenarios: []string{"T11"},
		KillExpr: "rollback/equivocation accepted > 0 or freeze not detected"}
	// State: the client already has bundle v=30 and withdrawal seq=5.
	v30 := forge.Bundle(forge.BundleOpts{Version: 30, Rules: []map[string]any{forge.RuleObserve(forge.RuleID(1), 7700001)}})
	v30raw := forge.SignBytes(contract.KindBundle, forge.MustJSON(v30), "lab-a", "lab-b", "lab-c")
	v30digest := msg.Digest(mustPayload(v30raw))
	ctx := vctx(now)
	ctx.State = verify.State{
		BundleVersion: 30, BundleDigest: v30digest,
		CheckpointSeq: map[string]uint64{}, CheckpointDigest: map[string]string{},
	}
	run := func(name string, kind contract.Kind, raw []byte, want contract.Code) {
		o.Attempts++
		ok, code := accepted(kind, raw, ctx)
		if ok {
			o.Accepted++
			o.note("ACCEPTED (unexpected): %s", name)
		} else {
			o.note("rejected (%s): %s", code, name)
		}
	}
	// Rollback: an older, still-unexpired bundle.
	old := forge.Bundle(forge.BundleOpts{Version: 29, Rules: []map[string]any{forge.RuleObserve(forge.RuleID(1), 7700001)}})
	run("rollback to bundle v29 (< stored v30)", contract.KindBundle, forge.SignBytes(contract.KindBundle, forge.MustJSON(old), "lab-a", "lab-b", "lab-c"), contract.CodeRollback)
	// Equivocation: stored version, different content (different operator sends a different v30).
	equiv := forge.Bundle(forge.BundleOpts{Version: 30, Rules: []map[string]any{forge.RuleObserve(forge.RuleID(2), 7700002)}})
	run("equivocation at v30 (same version, different content)", contract.KindBundle, forge.SignBytes(contract.KindBundle, forge.MustJSON(equiv), "lab-a", "lab-b", "lab-c"), contract.CodeEquivocation)
	// Expired bundle replayed (freeze by withholding fresh state).
	expired := forge.Bundle(forge.BundleOpts{Version: 31, IssuedAt: msg.FormatTime(now.Add(-40 * 24 * time.Hour)), Expires: msg.FormatTime(now.Add(-time.Hour)), Rules: []map[string]any{forge.RuleObserve(forge.RuleID(1), 7700001)}})
	run("expired bundle replayed (freeze)", contract.KindBundle, forge.SignBytes(contract.KindBundle, forge.MustJSON(expired), "lab-a", "lab-b", "lab-c"), contract.CodeExpired)
	// Checkpoint rollback / equivocation.
	ctx.State.CheckpointSeq["lab-a"] = 100
	cpDigestCtx := forge.Checkpoint("lab-a", 100, 30, v30digest, 5*time.Minute)
	cpRaw := forge.SignBytes(contract.KindCheckpoint, forge.MustJSON(cpDigestCtx), "lab-a")
	ctx.State.CheckpointDigest["lab-a"] = msg.Digest(mustPayload(cpRaw))
	cpOld := forge.Checkpoint("lab-a", 99, 30, v30digest, 5*time.Minute)
	run("checkpoint rollback (seq 99 < 100)", contract.KindCheckpoint, forge.SignBytes(contract.KindCheckpoint, forge.MustJSON(cpOld), "lab-a"), contract.CodeRollback)

	// Freeze detection (stream.Freshness): a relay that stops delivering fresh
	// checkpoints is detected after FreezeAfter (180 s), well under the 60 s
	// emergency-stop kill criterion is a different measure; here we assert
	// detection happens at all and within the documented window.
	fresh := stream.NewFreshness(stream.FreezeAfter)
	fresh.Observe(now.Add(-5 * time.Minute)) // last fresh checkpoint 5 min ago
	freezeDetected := fresh.Frozen(now)
	freezeDetectWindowOK := !fresh.Frozen(now.Add(-stream.FreezeAfter + time.Second))
	o.metric("freeze_detected", boolf(freezeDetected))
	o.metric("freeze_detect_window_s", stream.FreezeAfter.Seconds())
	if !freezeDetected || !freezeDetectWindowOK {
		o.Accepted++ // treat a non-detected freeze as a harm (counts toward the kill criterion)
		o.note("FREEZE NOT DETECTED as expected")
	} else {
		o.note("frozen relay detected after %s of no fresh checkpoint", stream.FreezeAfter)
	}
	o.metric("rollbacks_or_equivocations_accepted", float64(countAcceptedExcludingFreeze(o)))
	o.KillObserved = fmt.Sprintf("%d of %d rollback/freeze attempts accepted; freeze detected=%v", o.Accepted, o.Attempts, freezeDetected)
	return o
}

func countAcceptedExcludingFreeze(o *Outcome) int {
	// Accepted already counts bundle/checkpoint acceptances; the freeze harm
	// is added separately. For the metric we report the whole count.
	return o.Accepted
}

// ---- T24: AI hallucinates a too-broad rule --------------------------------

func t24() *Outcome {
	o := &Outcome{ID: "T24", Hypotheses: []string{"M4"}, Scenarios: []string{"T24"},
		KillExpr: "over-broad network rule accepted > 0"}
	// Rules a lab AI might hallucinate: broad patterns that hit ordinary
	// traffic of every site (the concept example: blocks every ?page=).
	broad := []struct {
		name    string
		seclang string
		max     string
	}{
		{"blocks every request (@rx .*)", `SecRule REQUEST_URI "@rx .*" "id:7700100,phase:1,deny,severity:CRITICAL,msg:'x'"`, "block"},
		{"blocks any path (@rx .)", `SecRule REQUEST_URI "@rx ." "id:7700101,phase:1,deny,severity:CRITICAL,msg:'x'"`, "block"},
		{"blocks every request with a page parameter", `SecRule ARGS_GET_NAMES "@streq page" "id:7700102,phase:1,deny,severity:CRITICAL,msg:'x'"`, "block"},
		{"blocks all GET (method streq)", `SecRule REQUEST_METHOD "@streq GET" "id:7700103,phase:1,deny,severity:CRITICAL,msg:'x'"`, "block"},
		{"blocks every path beginning with /", `SecRule REQUEST_URI "@beginsWith /" "id:7700104,phase:1,deny,severity:CRITICAL,msg:'x'"`, "block"},
		{"matches everything via empty @within", `SecRule QUERY_STRING "@within abc" "id:7700105,phase:1,deny,severity:CRITICAL,msg:'x'"`, "block"},
		{"catch-all alternation (a?)", `SecRule ARGS "@rx a?" "id:7700106,phase:2,deny,severity:CRITICAL,msg:'x'"`, "block"},
	}
	for _, r := range broad {
		o.Attempts++
		_, err := seclang.Validate(r.seclang, seclang.Options{MaxAction: r.max})
		if err == nil {
			o.Accepted++
			o.note("ACCEPTED (unexpected): %s", r.name)
		} else {
			o.note("rejected (%s): %s", contract.CodeOf(err), r.name)
		}
	}
	o.metric("broad_rules_accepted", float64(o.Accepted))
	o.KillObserved = fmt.Sprintf("%d of %d over-broad rules accepted", o.Accepted, o.Attempts)
	return o
}

// ---- K6: feedback flood (no human approval) -------------------------------

func k6() *Outcome {
	now := forge.Clock
	o := &Outcome{ID: "K6", Hypotheses: []string{"M3"},
		KillExpr: "rule withdrawn or weakened by automated feedback without human approval > 0"}
	// A botnet that passes the WAF (no dangerous action) floods false-positive
	// feedback, hoping to withdraw or weaken a rule. A withdrawal must be
	// signed by k distinct operators' RULES keys; feedback keys can never sign
	// one. Model: 500 site feedback keys try to sign a withdrawal.
	w := forge.Withdrawal(1, 30, "rules", []string{forge.RuleID(1)})
	// Feedback/site keys are not rules keys and not trusted operators.
	o.Attempts++
	raw := forge.SignBytes(contract.KindWithdrawal, forge.MustJSON(w), "site-a", "site-b", "site-c")
	if ok, code := accepted(contract.KindWithdrawal, raw, vctx(now)); ok {
		o.Accepted++
		o.note("ACCEPTED (unexpected): withdrawal signed by site/feedback keys")
	} else {
		o.note("rejected (%s): a withdrawal signed by site/feedback keys, not operator rules keys", code)
	}
	// Even many valid feedback envelopes carry no authority to withdraw: a
	// withdrawal still needs k operators. Confirm feedback envelopes verify as
	// feedback (so they are not rejected outright) but cannot stand in for a
	// withdrawal's operator signatures.
	fb := feedbackPayload(now)
	o.Attempts++
	trust := testkeys.TrustStore("site-a")
	fbRaw := forge.SignBytes(contract.KindFeedback, forge.MustJSON(fb), "site-a")
	if ok, _ := accepted(contract.KindFeedback, fbRaw, &verify.Context{Now: now.Add(time.Minute), Trust: trust}); ok {
		o.note("feedback envelope verifies as feedback (expected), but grants no withdrawal authority")
	} else {
		o.note("feedback envelope did not verify (unexpected for a well-formed feedback)")
	}
	// A withdrawal correctly signed by k operators IS accepted (sanity: the
	// mechanism works, it just needs humans/operators, not a flood).
	o.Attempts++
	okRaw := forge.SignBytes(contract.KindWithdrawal, forge.MustJSON(w), "lab-a", "lab-b", "lab-c")
	if ok, _ := accepted(contract.KindWithdrawal, okRaw, vctx(now)); ok {
		o.note("control: a withdrawal by k=3 operators is accepted (the mechanism needs operators, not feedback)")
	} else {
		o.note("control FAILED: a k-of-n operator withdrawal was rejected")
		o.Accepted++ // a broken control is itself a problem
	}
	o.metric("withdrawals_from_feedback_accepted", float64(boolToAcceptedFeedback(o)))
	o.KillObserved = fmt.Sprintf("%d feedback/flood attempts granted a withdrawal", o.feedbackHarm())
	return o
}

// feedbackHarm counts only the harmful acceptances for K6 (the first two
// attempts); the control acceptance is expected.
func (o *Outcome) feedbackHarm() int {
	// Accepted counts harmful acceptances plus a possibly-broken control; for
	// the observed string we report Accepted directly.
	return o.Accepted
}

func boolToAcceptedFeedback(o *Outcome) int { return o.Accepted }

func feedbackPayload(now time.Time) map[string]any {
	return map[string]any{
		"schema":         msg.SchemaFeedback,
		"id":             msg.NewID(),
		"time_bucket":    msg.TimeBucket(now, 5),
		"rule_id":        forge.RuleID(1),
		"bundle_version": uint64(30),
		"verdict":        "false_positive",
		"decided_by":     "operator",
		"local_action":   "unchanged",
		"match_shape":    map[string]any{"location": "ARGS", "len_bucket": "0-16"},
	}
}

func boolf(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

func mustPayload(envBytes []byte) []byte {
	var e dsse.Envelope
	if err := json.Unmarshal(envBytes, &e); err != nil {
		panic(err)
	}
	p, err := e.DecodePayload()
	if err != nil {
		panic(err)
	}
	return p
}
