//go:build !release

package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/msg"
	"github.com/deutschland-schild/schild/contract/seclang"
	"github.com/deutschland-schild/schild/contract/vectors"
)

const channel = "schild-main"

func baseCheckpoint(lab string, seq uint64) msg.Checkpoint {
	return msg.Checkpoint{
		Schema:        msg.SchemaCheckpoint,
		Lab:           lab,
		Seq:           seq,
		IssuedAt:      ts(-30 * time.Second),
		Expires:       ts(150 * time.Second),
		Bundle:        msg.BundleRef{BundleID: channel, Version: 42, Digest: msg.Digest([]byte("bundle-42"))},
		WithdrawalSeq: 3,
	}
}

func ctxDist() vectors.Context {
	x := ctxDefault()
	x.Threshold = 2
	x.Channel = channel
	return x
}

func genCheckpoint(g *gen) {
	const c = "checkpoint"
	k := contract.KindCheckpoint
	base := func(lab string, seq uint64) map[string]any { return toMap(baseCheckpoint(lab, seq)) }
	sg := func(m any, signer string) []byte { return signed(k, mustJSON(m), signer) }

	cp := base("lab-a", 10)
	g.valid(c, "fresh", "Fresh checkpoint of lab-a.", ctxDist(), sg(cp, "lab-a"), decodedOf(mustJSON(cp)))
	cp = base("lab-b", 7)
	cp["log"] = map[string]any{"size": 1234, "root": msg.Digest([]byte("root"))}
	g.valid(c, "with-log", "Checkpoint with transparency log state.", ctxDist(), sg(cp, "lab-b"), decodedOf(mustJSON(cp)))
	cp = base("lab-a2", 1)
	cp["bundle"] = map[string]any{"bundle_id": channel, "version": 0, "digest": msg.Digest(nil)}
	cp["withdrawal_seq"] = 0
	g.valid(c, "no-bundle-yet", "Version 0: no bundle published yet.", ctxDist(), sg(cp, "lab-a2"), decodedOf(mustJSON(cp)))
	cp = base("lab-a", 11)
	x := ctxDist()
	x.State = &vectors.State{CheckpointSeq: map[string]uint64{"lab-a": 10}}
	g.valid(c, "next-seq", "seq advances over the stored state.", x, sg(cp, "lab-a"), decodedOf(mustJSON(cp)))
	cp = base("lab-a", 10)
	x = ctxDist()
	x.State = &vectors.State{CheckpointSeq: map[string]uint64{"lab-a": 10}, CheckpointDigest: map[string]string{"lab-a": msg.Digest(mustJSON(cp))}}
	g.valid(c, "redelivery", "Same seq and same content again (heartbeat repeats it): idempotent.", x, sg(cp, "lab-a"), decodedOf(mustJSON(cp)))
	cp = base("lab-c", 3)
	cp["issued_at"] = ts(-9 * time.Minute)
	cp["expires"] = ts(time.Minute)
	g.valid(c, "max-validity", "Validity of exactly 10 minutes.", ctxDist(), sg(cp, "lab-c"), decodedOf(mustJSON(cp)))

	g.invalid(c, "foreign-lab", contract.CodeSignature, "lab-a key signs a checkpoint claiming to be lab-b.", ctxDist(), sg(base("lab-b", 5), "lab-a"), nil)
	g.invalid(c, "rules-only-key", contract.CodeSignature, "lab-d key may not sign checkpoints.", ctxDist(), sg(base("lab-d", 5), "lab-d"), nil)
	g.invalid(c, "wrong-key", contract.CodeSignature, "Untrusted signer.", ctxDist(), sg(base("evil", 5), "evil"), nil)
	g.invalid(c, "site-key", contract.CodeSignature, "Site keys never sign checkpoints.", ctxDist(), sg(base("lab-a", 5), "site-a"), nil)
	g.invalid(c, "wrong-payload-type", contract.CodePayloadType, "Checkpoint signed as withdrawal.", ctxDist(), signed(contract.KindWithdrawal, mustJSON(base("lab-a", 5)), "lab-a"), nil)
	cp = base("lab-a", 5)
	cp["issued_at"] = ts(-20 * time.Minute)
	cp["expires"] = ts(-15 * time.Minute)
	g.invalid(c, "expired", contract.CodeExpired, "Old checkpoint replayed by a frozen relay.", ctxDist(), sg(cp, "lab-a"), decodedOf(mustJSON(cp)))
	cp = base("lab-a", 5)
	cp["expires"] = ts(time.Hour)
	g.invalid(c, "validity-too-long", contract.CodeValidity, "Checkpoint valid for more than 10 minutes.", ctxDist(), sg(cp, "lab-a"), decodedOf(mustJSON(cp)))
	cp = base("lab-a", 5)
	cp["issued_at"] = ts(5 * time.Minute)
	cp["expires"] = ts(8 * time.Minute)
	g.invalid(c, "clock-skew", contract.CodeClockSkew, "Issued 5 minutes in the future.", ctxDist(), sg(cp, "lab-a"), decodedOf(mustJSON(cp)))
	cp = base("lab-a", 9)
	x = ctxDist()
	x.State = &vectors.State{CheckpointSeq: map[string]uint64{"lab-a": 10}}
	g.invalid(c, "rollback", contract.CodeRollback, "seq lower than the last seen.", x, sg(cp, "lab-a"), decodedOf(mustJSON(cp)))
	cp = base("lab-a", 10)
	x = ctxDist()
	x.State = &vectors.State{CheckpointSeq: map[string]uint64{"lab-a": 10}, CheckpointDigest: map[string]string{"lab-a": msg.Digest([]byte("other"))}}
	g.invalid(c, "equivocation", contract.CodeEquivocation, "Same seq, different content: signed proof of equivocation.", x, sg(cp, "lab-a"), decodedOf(mustJSON(cp)))
	cp = base("lab-a", 5)
	delete(cp, "withdrawal_seq")
	g.invalid(c, "missing-field", contract.CodeSchema, "withdrawal_seq missing.", ctxDist(), sg(cp, "lab-a"), decodedOf(mustJSON(cp)))
	cp = base("lab-a", 5)
	cp["rules"] = []any{}
	g.invalid(c, "extra-field", contract.CodeSchema, "Unknown field.", ctxDist(), sg(cp, "lab-a"), decodedOf(mustJSON(cp)))
	g.invalid(c, "oversize", contract.CodeOversize, "Envelope larger than 16 KiB.", ctxDist(), []byte(string(sg(base("lab-a", 5), "lab-a"))+strings.Repeat(" ", 16*1024)), nil)
}

// rules used in bundles (valid SecLang subset cases with matching evidence).
func ruleSQLi(id string, secID int) map[string]any {
	return map[string]any{
		"rule_id":          id,
		"class":            "virtual_patch",
		"stage":            "general",
		"max_action":       "block",
		"max_action_until": ts(10 * 24 * time.Hour),
		"max_match_share":  0.01,
		"target":           map[string]any{"software": "wp-plugin/gallery", "versions": "<2.4.1", "cve": []string{"CVE-2026-12345"}},
		"evidence":         map[string]any{"reproduced_operators": 2, "sensor_operators": 1, "tip_issuers": 7, "max_issuer_share": 0.29, "human_approval_orgs": 2, "reproduced_by": []string{"lab-a", "lab-b"}, "negative_corpus": "corpus-2026.10"},
		"feedback_policy":  "narrow_only",
		"seclang":          fmt.Sprintf(`SecRule ARGS "@detectSQLi" "id:%d,phase:2,deny,status:403,severity:CRITICAL,msg:'SQL injection in arguments',tag:'schild-remote',t:none,t:urlDecodeUni"`, secID),
	}
}

func ruleObserve(id string, secID int) map[string]any {
	return map[string]any{
		"rule_id":         id,
		"class":           "behavioral",
		"stage":           "shadow",
		"max_action":      "observe",
		"max_match_share": 0.001,
		"target":          map[string]any{"software": "wordpress", "versions": "*"},
		"evidence":        map[string]any{"reproduced_operators": 0, "sensor_operators": 0, "tip_issuers": 5, "max_issuer_share": 0.2, "human_approval_orgs": 0},
		"feedback_policy": "auto_downgrade",
		"seclang":         fmt.Sprintf(`SecRule REQUEST_HEADERS:User-Agent "@pm sqlmap nikto nuclei" "id:%d,phase:1,pass,log,severity:NOTICE,msg:'scanner user agent'"`, secID),
	}
}

func ruleChallenge(id string, secID int) map[string]any {
	return map[string]any{
		"rule_id":          id,
		"class":            "heuristic",
		"stage":            "canary",
		"max_action":       "challenge",
		"max_action_until": ts(6 * 24 * time.Hour),
		"max_match_share":  0.005,
		"target":           map[string]any{"software": "wordpress", "versions": ">=6.0"},
		"evidence":         map[string]any{"reproduced_operators": 0, "sensor_operators": 2, "tip_issuers": 3, "max_issuer_share": 0.34, "human_approval_orgs": 1},
		"feedback_policy":  "auto_downgrade",
		"seclang":          caseText("chain-numeric"), // id 7700004
	}
}

func baseBundle(version uint64, rules ...map[string]any) map[string]any {
	rs := make([]any, len(rules))
	for i, r := range rules {
		rs[i] = r
	}
	return map[string]any{
		"schema":    msg.SchemaBundle,
		"bundle_id": channel,
		"version":   version,
		"issued_at": ts(-time.Hour),
		"expires":   ts(14 * 24 * time.Hour),
		"rules":     rs,
	}
}

func genBundle(g *gen) {
	const c = "rule-bundle"
	k := contract.KindBundle
	sg := func(m any, signers ...string) []byte { return signed(k, mustJSON(m), signers...) }
	two := func(v uint64) map[string]any {
		return baseBundle(v, ruleSQLi("schild-2026-0412", 7700001), ruleObserve("schild-2026-0413", 7700003))
	}

	b := two(42)
	g.valid(c, "two-of-two", "Two rules, signed by two independent operators (k=2).", ctxDist(), sg(b, "lab-a", "lab-b"), decodedOf(mustJSON(b)))
	b = baseBundle(43)
	x := ctxDist()
	x.Threshold = 3
	g.valid(c, "empty-k3", "Empty bundle (all network rules removed), three operators with k=3.", x, sg(b, "lab-a", "lab-b", "lab-c"), decodedOf(mustJSON(b)))
	b = baseBundle(44, ruleSQLi("schild-2026-0412", 7700001), ruleObserve("schild-2026-0413", 7700003), ruleChallenge("schild-2026-0414", 7700004))
	g.valid(c, "same-operator-counted-once", "lab-a and lab-a2 (same operator) count once; lab-b makes two.", ctxDist(), sg(b, "lab-a", "lab-a2", "lab-b"), decodedOf(mustJSON(b)))
	b = two(42)
	x = ctxDist()
	x.State = &vectors.State{BundleVersion: 41, BundleDigest: msg.Digest([]byte("bundle-41"))}
	g.valid(c, "newer-version", "Version 42 over stored version 41.", x, sg(b, "lab-b", "lab-c"), decodedOf(mustJSON(b)))
	b = two(42)
	x = ctxDist()
	x.State = &vectors.State{BundleVersion: 42, BundleDigest: msg.Digest(mustJSON(b))}
	g.valid(c, "redelivery", "Same version, same digest: idempotent re-delivery.", x, sg(b, "lab-a", "lab-b"), decodedOf(mustJSON(b)))
	b = two(42)
	x = ctxDist()
	x.SimulatedOperators = map[string]string{"lab-a": "sim-1", "lab-a2": "sim-2"}
	g.valid(c, "test-profile-simulated-operators", "Test profile (E5): two labs of one real operator count as two simulated operators. Client side only in observe mode, never in release builds.", x, sg(b, "lab-a", "lab-a2"), decodedOf(mustJSON(b)))
	b = baseBundle(45, ruleChallenge("schild-2026-0414", 7700004), ruleObserve("schild-2026-0415", 7700005))
	g.valid(c, "lab-d-and-lab-c", "lab-d holds a rules-only key.", ctxDist(), sg(b, "lab-d", "lab-c"), decodedOf(mustJSON(b)))

	b = two(42)
	g.invalid(c, "one-signature", contract.CodeThreshold, "Only one operator signed (T10).", ctxDist(), sg(b, "lab-a"), nil)
	g.invalid(c, "same-operator", contract.CodeThreshold, "Two labs of the same operator are not independent.", ctxDist(), sg(b, "lab-a", "lab-a2"), nil)
	g.invalid(c, "stolen-plus-untrusted", contract.CodeThreshold, "One trusted key plus an untrusted key.", ctxDist(), sg(b, "lab-a", "evil"), nil)
	g.invalid(c, "site-key-cosign", contract.CodeThreshold, "A site key cannot co-sign rules.", ctxDist(), sg(b, "lab-a", "site-a"), nil)
	e := sign(k.PayloadType(), mustJSON(b), "lab-a", "lab-b")
	other := sign(k.PayloadType(), mustJSON(two(43)), "lab-b")
	e.Signatures[1].Sig = other.Signatures[0].Sig
	g.invalid(c, "second-signature-invalid", contract.CodeThreshold, "lab-b signature belongs to another payload.", ctxDist(), envBytes(e), nil)
	e = sign(k.PayloadType(), mustJSON(b), "lab-a", "lab-a")
	e.Signatures[1].KeyID = "test-lab-b"
	g.invalid(c, "keyid-relabelled", contract.CodeThreshold, "lab-a signs twice and labels the second signature with lab-b's key id: keyid is binding, so it does not count for lab-b.", ctxDist(), envBytes(e), nil)
	x = ctxDist()
	x.Threshold = 3
	g.invalid(c, "k3-two-signatures", contract.CodeThreshold, "k=3 but only two operators.", x, sg(b, "lab-a", "lab-b"), nil)
	x = ctxDist()
	x.Threshold = 1
	g.invalid(c, "floor-two", contract.CodeThreshold, "A threshold of 1 is raised to the floor of 2.", x, sg(b, "lab-a"), nil)
	g.invalid(c, "wrong-payload-type", contract.CodePayloadType, "Bundle signed as checkpoint.", ctxDist(), signed(contract.KindCheckpoint, mustJSON(b), "lab-a", "lab-b"), nil)
	x = ctxDist()
	x.State = &vectors.State{BundleVersion: 41, BundleDigest: msg.Digest([]byte("bundle-41"))}
	b = two(40)
	g.invalid(c, "rollback", contract.CodeRollback, "Older version than stored (T11).", x, sg(b, "lab-a", "lab-b"), decodedOf(mustJSON(b)))
	b = two(41)
	g.invalid(c, "equivocation", contract.CodeEquivocation, "Stored version with different content.", x, sg(b, "lab-a", "lab-b"), decodedOf(mustJSON(b)))
	b = two(42)
	b["issued_at"] = ts(-20 * 24 * time.Hour)
	b["expires"] = ts(-time.Hour)
	g.invalid(c, "expired", contract.CodeExpired, "Expired bundle (freeze attack).", ctxDist(), sg(b, "lab-a", "lab-b"), decodedOf(mustJSON(b)))
	b = two(42)
	b["expires"] = ts(60 * 24 * time.Hour)
	g.invalid(c, "validity-too-long", contract.CodeValidity, "Valid for more than 31 days.", ctxDist(), sg(b, "lab-a", "lab-b"), decodedOf(mustJSON(b)))
	b = two(42)
	b["issued_at"] = ts(time.Hour)
	g.invalid(c, "clock-skew", contract.CodeClockSkew, "Issued in the future.", ctxDist(), sg(b, "lab-a", "lab-b"), decodedOf(mustJSON(b)))
	b = two(42)
	b["bundle_id"] = "schild-other"
	g.invalid(c, "channel", contract.CodeChannel, "Bundle of another channel.", ctxDist(), sg(b, "lab-a", "lab-b"), decodedOf(mustJSON(b)))
	r := ruleSQLi("schild-2026-0420", 7700021)
	r["seclang"] = caseText("ctl-disable-engine")
	r["max_action"] = "observe"
	delete(r, "max_action_until")
	b = baseBundle(42, r)
	g.invalid(c, "seclang-ctl", contract.CodeSecLang, "Rule switches the engine off with ctl: (K7).", ctxDist(), sg(b, "lab-a", "lab-b"), decodedOf(mustJSON(b)))
	r = ruleSQLi("schild-2026-0421", 7700029)
	r["seclang"] = caseText("remote-addr")
	b = baseBundle(42, r)
	g.invalid(c, "seclang-remote-addr", contract.CodeSecLang, "Rule targets client IPs (G1).", ctxDist(), sg(b, "lab-a", "lab-b"), decodedOf(mustJSON(b)))
	r = ruleSQLi("schild-2026-0422", 7700014)
	r["seclang"] = caseText("logdata-args-macro")
	b = baseBundle(42, r)
	g.invalid(c, "seclang-exfiltration", contract.CodeSecLang, "logdata copies a request argument (data exfiltration).", ctxDist(), sg(b, "lab-a", "lab-b"), decodedOf(mustJSON(b)))
	r = ruleSQLi("schild-2026-0424", 7700117)
	r["seclang"] = caseText("rx-dot-catch-all")
	b = baseBundle(42, r)
	g.invalid(c, "seclang-catch-all", contract.CodeSecLang, "Rule matches every request (@rx .): rejected by the catch-all check.", ctxDist(), sg(b, "lab-a", "lab-b"), decodedOf(mustJSON(b)))
	r = ruleSQLi("schild-2026-0425", 7700113)
	r["seclang"] = caseText("streq-macro-remote-addr")
	b = baseBundle(42, r)
	g.invalid(c, "seclang-macro-ip", contract.CodeSecLang, "Operator argument expands %{REMOTE_ADDR}.", ctxDist(), sg(b, "lab-a", "lab-b"), decodedOf(mustJSON(b)))
	r = ruleSQLi("schild-2026-0423", 7700001)
	r["evidence"] = map[string]any{"reproduced_operators": 1, "sensor_operators": 3, "tip_issuers": 50, "max_issuer_share": 0.1, "human_approval_orgs": 2}
	b = baseBundle(42, r)
	g.invalid(c, "evidence-block-one-reproduction", contract.CodeEvidence, "block needs reproduction by two operators (G2).", ctxDist(), sg(b, "lab-a", "lab-b"), decodedOf(mustJSON(b)))
	r = ruleSQLi("schild-2026-0424", 7700001)
	r["class"] = "heuristic"
	r["feedback_policy"] = "auto_downgrade"
	b = baseBundle(42, r)
	g.invalid(c, "evidence-heuristic-block", contract.CodeEvidence, "Only virtual patches can reach block.", ctxDist(), sg(b, "lab-a", "lab-b"), decodedOf(mustJSON(b)))
	r = ruleObserve("schild-2026-0425", 7700003)
	r["evidence"] = map[string]any{"reproduced_operators": 0, "sensor_operators": 0, "tip_issuers": 3, "max_issuer_share": 0.5, "human_approval_orgs": 0}
	b = baseBundle(42, r)
	g.invalid(c, "evidence-issuer-share", contract.CodeEvidence, "One issuer carries half of the tips (Sybil).", ctxDist(), sg(b, "lab-a", "lab-b"), decodedOf(mustJSON(b)))
	r = ruleChallenge("schild-2026-0426", 7700004)
	r["max_action_until"] = ts(10 * 24 * time.Hour)
	b = baseBundle(42, r)
	g.invalid(c, "challenge-too-long", contract.CodeValidity, "challenge for more than 7 days (G2).", ctxDist(), sg(b, "lab-a", "lab-b"), decodedOf(mustJSON(b)))
	b = baseBundle(42, ruleSQLi("schild-2026-0412", 7700001), ruleObserve("schild-2026-0412", 7700003))
	g.invalid(c, "duplicate-rule-id", contract.CodeDuplicateRule, "Two rules with the same rule_id.", ctxDist(), sg(b, "lab-a", "lab-b"), decodedOf(mustJSON(b)))
	r2 := ruleObserve("schild-2026-0427", 7700001)
	b = baseBundle(42, ruleSQLi("schild-2026-0412", 7700001), r2)
	g.invalid(c, "duplicate-secrule-id", contract.CodeDuplicateRule, "Two rules with the same SecRule id.", ctxDist(), sg(b, "lab-a", "lab-b"), decodedOf(mustJSON(b)))
	r = ruleSQLi("schild-2026-0428", 7700001)
	r["feedback_policy"] = "auto_downgrade"
	b = baseBundle(42, r)
	g.invalid(c, "virtual-patch-auto-downgrade", contract.CodeSchema, "Virtual patches are never downgraded by feedback (G4).", ctxDist(), sg(b, "lab-a", "lab-b"), decodedOf(mustJSON(b)))
	r = ruleChallenge("schild-2026-0429", 7700004)
	delete(r, "max_action_until")
	b = baseBundle(42, r)
	g.invalid(c, "missing-max-action-until", contract.CodeSchema, "challenge without an end date.", ctxDist(), sg(b, "lab-a", "lab-b"), decodedOf(mustJSON(b)))
	r = ruleSQLi("schild-2026-0430", 7700001)
	r["max_match_share"] = 0.5
	b = baseBundle(42, r)
	g.invalid(c, "match-share-too-high", contract.CodeSchema, "Local brake above 5 %.", ctxDist(), sg(b, "lab-a", "lab-b"), decodedOf(mustJSON(b)))
	r = ruleSQLi("schild-2026-0431", 7700001)
	r["target"].(map[string]any)["hosts"] = []string{"shop.example"}
	b = baseBundle(42, r)
	g.invalid(c, "targeted-host", contract.CodeSchema, "A rule may not name target hosts.", ctxDist(), sg(b, "lab-a", "lab-b"), decodedOf(mustJSON(b)))
	var many []string
	for i := 0; i < 17; i++ {
		many = append(many, "lab-a")
	}
	g.invalid(c, "too-many-signatures", contract.CodeEnvelope, "More than 16 signatures.", ctxDist(), sg(two(42), many...), nil)
}

func genWithdrawal(g *gen) {
	const c = "withdrawal"
	k := contract.KindWithdrawal
	sg := func(m any, signers ...string) []byte { return signed(k, mustJSON(m), signers...) }
	base := func(seq uint64, scope string, rules ...string) map[string]any {
		m := map[string]any{"schema": msg.SchemaWithdrawal, "bundle_id": channel, "seq": seq, "issued_at": ts(-time.Minute), "scope": scope, "up_to_version": 42, "reason": "emergency_stop"}
		if len(rules) > 0 {
			m["rule_ids"] = rules
			m["reason"] = "false_positives"
		}
		return m
	}
	w := base(4, "all")
	g.valid(c, "emergency-stop", "Emergency stop: all network rules up to bundle 42 removed (SEC-02).", ctxDist(), sg(w, "lab-a", "lab-b"), decodedOf(mustJSON(w)))
	w = base(4, "rules", "schild-2026-0412")
	g.valid(c, "single-rule", "Withdraw one rule.", ctxDist(), sg(w, "lab-b", "lab-c"), decodedOf(mustJSON(w)))
	w = base(5, "rules", "schild-2026-0412", "schild-2026-0413")
	w["note"] = "Breaks the checkout of plugin x, narrowing follows."
	x := ctxDist()
	x.State = &vectors.State{WithdrawalSeq: 4, WithdrawalDigest: msg.Digest([]byte("w4"))}
	g.valid(c, "next-seq-with-note", "Next seq over stored state, with a note.", x, sg(w, "lab-a", "lab-c"), decodedOf(mustJSON(w)))
	w = base(4, "all")
	x = ctxDist()
	x.State = &vectors.State{WithdrawalSeq: 4, WithdrawalDigest: msg.Digest(mustJSON(w))}
	g.valid(c, "redelivery", "Same seq and digest again: idempotent.", x, sg(w, "lab-a", "lab-b"), decodedOf(mustJSON(w)))
	w = base(6, "all")
	w["reason"] = "compromised_key"
	x = ctxDist()
	x.Threshold = 3
	g.valid(c, "k3", "Three operators with k=3.", x, sg(w, "lab-a", "lab-b", "lab-c"), decodedOf(mustJSON(w)))

	w = base(4, "all")
	g.invalid(c, "one-operator", contract.CodeThreshold, "A single lab cannot pull the emergency stop.", ctxDist(), sg(w, "lab-a"), nil)
	g.invalid(c, "same-operator", contract.CodeThreshold, "Two labs of one operator.", ctxDist(), sg(w, "lab-a", "lab-a2"), nil)
	g.invalid(c, "untrusted", contract.CodeThreshold, "Untrusted co-signer.", ctxDist(), sg(w, "evil", "lab-b"), nil)
	g.invalid(c, "wrong-payload-type", contract.CodePayloadType, "Withdrawal signed as bundle.", ctxDist(), signed(contract.KindBundle, mustJSON(w), "lab-a", "lab-b"), nil)
	x = ctxDist()
	x.State = &vectors.State{WithdrawalSeq: 4, WithdrawalDigest: msg.Digest([]byte("w4"))}
	w3 := base(3, "all")
	g.invalid(c, "rollback", contract.CodeRollback, "Old withdrawal replayed.", x, sg(w3, "lab-a", "lab-b"), decodedOf(mustJSON(w3)))
	g.invalid(c, "equivocation", contract.CodeEquivocation, "Same seq, different content.", x, sg(w, "lab-a", "lab-b"), decodedOf(mustJSON(w)))
	w = base(4, "all")
	w["bundle_id"] = "schild-other"
	g.invalid(c, "channel", contract.CodeChannel, "Withdrawal for another channel.", ctxDist(), sg(w, "lab-a", "lab-b"), decodedOf(mustJSON(w)))
	w = base(4, "all")
	w["issued_at"] = ts(time.Hour)
	g.invalid(c, "clock-skew", contract.CodeClockSkew, "Issued in the future.", ctxDist(), sg(w, "lab-a", "lab-b"), decodedOf(mustJSON(w)))
	w = base(4, "rules")
	g.invalid(c, "rules-without-ids", contract.CodeSchema, "scope rules needs rule_ids.", ctxDist(), sg(w, "lab-a", "lab-b"), decodedOf(mustJSON(w)))
	w = base(4, "all")
	w["rule_ids"] = []string{"schild-2026-0412"}
	g.invalid(c, "all-with-ids", contract.CodeSchema, "scope all takes no rule_ids.", ctxDist(), sg(w, "lab-a", "lab-b"), decodedOf(mustJSON(w)))
	w = base(4, "all")
	w["reason"] = "because"
	g.invalid(c, "reason", contract.CodeSchema, "Unknown reason.", ctxDist(), sg(w, "lab-a", "lab-b"), decodedOf(mustJSON(w)))
	w = base(4, "all")
	w["add_rules"] = []any{}
	g.invalid(c, "cannot-add", contract.CodeSchema, "A withdrawal can never add anything.", ctxDist(), sg(w, "lab-a", "lab-b"), decodedOf(mustJSON(w)))
	g.invalid(c, "oversize", contract.CodeOversize, "Envelope larger than 64 KiB.", ctxDist(), []byte(string(sg(base(4, "all"), "lab-a", "lab-b"))+strings.Repeat(" ", 65*1024)), nil)
}

func genStream(g *gen) {
	const c = "stream"
	cpEnv := func(lab string, seq uint64, mut func(map[string]any)) map[string]any {
		cp := toMap(baseCheckpoint(lab, seq))
		if mut != nil {
			mut(cp)
		}
		return toMap(sign(contract.KindCheckpoint.PayloadType(), mustJSON(cp), lab))
	}
	bundleEnv := func(signers ...string) map[string]any {
		return toMap(sign(contract.KindBundle.PayloadType(), mustJSON(baseBundle(42, ruleSQLi("schild-2026-0412", 7700001))), signers...))
	}
	wEnv := func(signers ...string) map[string]any {
		w := map[string]any{"schema": msg.SchemaWithdrawal, "bundle_id": channel, "seq": 4, "issued_at": ts(-time.Minute), "scope": "all", "up_to_version": 42, "reason": "emergency_stop"}
		return toMap(sign(contract.KindWithdrawal.PayloadType(), mustJSON(w), signers...))
	}
	ev := func(typ, id string, kv ...any) map[string]any {
		m := map[string]any{"type": typ, "id": id}
		for i := 0; i+1 < len(kv); i += 2 {
			m[kv[i].(string)] = kv[i+1]
		}
		return m
	}
	relay := map[string]any{"id": "relay-1", "time": ts(0)}
	ref := map[string]any{"bundle_id": channel, "version": 42, "url_path": "/v0/bundles/schild-main/42.json", "sha256": msg.Digest([]byte("envelope")), "size": 240000}

	e := ev("schild.dist.checkpoint.v1", "r1a-100", "envelope", cpEnv("lab-a", 10, nil))
	g.valid(c, "checkpoint", "Checkpoint event.", ctxDist(), mustJSON(e), e)
	e = ev("schild.dist.heartbeat.v1", "r1a-101", "relay", relay, "checkpoint", cpEnv("lab-b", 7, nil))
	g.valid(c, "heartbeat", "Heartbeat carries the newest lab-signed checkpoint.", ctxDist(), mustJSON(e), e)
	e = ev("schild.dist.bundle.v1", "r1a-102", "envelope", bundleEnv("lab-a", "lab-b"))
	g.valid(c, "bundle-inline", "Small bundle inline.", ctxDist(), mustJSON(e), e)
	e = ev("schild.dist.bundle.v1", "r1a-103", "ref", ref)
	g.valid(c, "bundle-by-reference", "Large bundle by reference; verified after download.", ctxDist(), mustJSON(e), e)
	e = ev("schild.dist.withdrawal.v1", "r1a-104", "envelope", wEnv("lab-b", "lab-c"))
	g.valid(c, "withdrawal", "Withdrawal, always inline, highest priority.", ctxDist(), mustJSON(e), e)

	e = ev("schild.dist.rule.v1", "r1a-1", "envelope", cpEnv("lab-a", 10, nil))
	g.invalid(c, "unknown-type", contract.CodeSchema, "Unknown event type.", ctxDist(), mustJSON(e), e)
	e = ev("schild.dist.checkpoint.v1", "R1A:1", "envelope", cpEnv("lab-a", 10, nil))
	g.invalid(c, "bad-id", contract.CodeSchema, "id not in <epoch>-<seq> form.", ctxDist(), mustJSON(e), e)
	e = ev("schild.dist.heartbeat.v1", "r1a-2", "checkpoint", cpEnv("lab-a", 10, nil))
	g.invalid(c, "heartbeat-without-relay", contract.CodeSchema, "Heartbeat needs relay info.", ctxDist(), mustJSON(e), e)
	e = ev("schild.dist.bundle.v1", "r1a-3", "envelope", bundleEnv("lab-a", "lab-b"), "ref", ref)
	g.invalid(c, "bundle-envelope-and-ref", contract.CodeSchema, "Either inline or by reference, not both.", ctxDist(), mustJSON(e), e)
	e = ev("schild.dist.checkpoint.v1", "r1a-4", "ref", ref)
	g.invalid(c, "checkpoint-by-ref", contract.CodeSchema, "Checkpoints are always inline.", ctxDist(), mustJSON(e), e)
	r2 := clone(ref)
	r2["url_path"] = "/v0/bundles/../../etc/passwd"
	e = ev("schild.dist.bundle.v1", "r1a-5", "ref", r2)
	g.invalid(c, "ref-path-traversal", contract.CodeSchema, "Reference path outside /v0/bundles.", ctxDist(), mustJSON(e), e)
	e = ev("schild.dist.checkpoint.v1", "r1a-6", "envelope", bundleEnv("lab-a", "lab-b"))
	g.invalid(c, "type-mismatch", contract.CodePayloadType, "checkpoint event carrying a bundle envelope.", ctxDist(), mustJSON(e), e)
	e = ev("schild.dist.bundle.v1", "r1a-7", "envelope", bundleEnv("lab-a"))
	g.invalid(c, "bundle-under-signed", contract.CodeThreshold, "Relay forwards an under-signed bundle.", ctxDist(), mustJSON(e), e)
	e = ev("schild.dist.withdrawal.v1", "r1a-8", "envelope", wEnv("lab-a"))
	g.invalid(c, "withdrawal-under-signed", contract.CodeThreshold, "Single-lab emergency stop.", ctxDist(), mustJSON(e), e)
	stale := cpEnv("lab-a", 3, func(m map[string]any) { m["issued_at"] = ts(-time.Hour); m["expires"] = ts(-55 * time.Minute) })
	e = ev("schild.dist.heartbeat.v1", "r1a-9", "relay", relay, "checkpoint", stale)
	g.invalid(c, "frozen-relay", contract.CodeExpired, "Relay keeps sending an old checkpoint (T11, B12).", ctxDist(), mustJSON(e), e)
	forged := cpEnv("lab-a", 10, nil)
	forged["signatures"] = toMap(sign(contract.KindCheckpoint.PayloadType(), []byte(`{}`), "evil"))["signatures"]
	e = ev("schild.dist.checkpoint.v1", "r1a-10", "envelope", forged)
	g.invalid(c, "relay-forged-signature", contract.CodeSignature, "Relay replaces the signature.", ctxDist(), mustJSON(e), e)
	e = ev("schild.dist.checkpoint.v1", "r1a-11", "envelope", cpEnv("lab-a", 10, nil))
	e["priority"] = "high"
	g.invalid(c, "extra-field", contract.CodeSchema, "Unknown field.", ctxDist(), mustJSON(e), e)
	g.invalid(c, "malformed", contract.CodeMalformed, "Broken JSON line.", ctxDist(), []byte(`{"type":"schild.dist.heartbeat.v1",`), nil)
	e = ev("schild.dist.checkpoint.v1", "r1a-12", "envelope", cpEnv("lab-a", 10, nil))
	g.invalid(c, "oversize", contract.CodeOversize, "Event larger than 64 KiB.", ctxDist(), []byte(string(mustJSON(e))+strings.Repeat(" ", 64*1024)), nil)
}

func caseText(name string) string {
	for _, c := range seclang.Cases {
		if c.Name == name {
			return c.Text
		}
	}
	panic("unknown seclang case " + name)
}
