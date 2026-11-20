//go:build !release

// Package testfeed builds signed checkpoints, bundles and withdrawals with
// the TEST ONLY keys of contracts/testkeys. Tests only.
package testfeed

import (
	"encoding/json"
	"time"

	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/dsse"
	"github.com/deutschland-schild/schild/contract/jsonx"
	"github.com/deutschland-schild/schild/contract/msg"
	"github.com/deutschland-schild/schild/contract/testkeys"
)

// Channel used by the fixtures.
const Channel = "schild-main"

func sign(kind contract.Kind, payload any, signers ...string) json.RawMessage {
	b, err := jsonx.Marshal(payload)
	if err != nil {
		panic(err)
	}
	var ss []dsse.Signer
	for _, n := range signers {
		ss = append(ss, testkeys.Signer(n))
	}
	env, err := dsse.Sign(kind.PayloadType(), b, ss...)
	if err != nil {
		panic(err)
	}
	out, err := env.Marshal()
	if err != nil {
		panic(err)
	}
	return out
}

// Checkpoint signs a checkpoint of lab (test key name, e.g. "lab-a").
func Checkpoint(lab string, seq uint64, at time.Time, bundleVersion uint64, bundleDigest string, wseq uint64) json.RawMessage {
	if bundleDigest == "" {
		bundleDigest = msg.Digest(nil)
	}
	return sign(contract.KindCheckpoint, msg.Checkpoint{
		Schema: msg.SchemaCheckpoint, Lab: lab, Seq: seq,
		IssuedAt: msg.FormatTime(at), Expires: msg.FormatTime(at.Add(3 * time.Minute)),
		Bundle:        msg.BundleRef{BundleID: Channel, Version: bundleVersion, Digest: bundleDigest},
		WithdrawalSeq: wseq,
	}, lab)
}

// Bundle signs an empty-or-given bundle with the named lab keys.
func Bundle(version uint64, at time.Time, rules []msg.Rule, signers ...string) json.RawMessage {
	if rules == nil {
		rules = []msg.Rule{}
	}
	return sign(contract.KindBundle, msg.Bundle{
		Schema: msg.SchemaBundle, BundleID: Channel, Version: version,
		IssuedAt: msg.FormatTime(at), Expires: msg.FormatTime(at.Add(7 * 24 * time.Hour)), Rules: rules,
	}, signers...)
}

// Withdrawal signs an emergency stop (scope all).
func Withdrawal(seq, upTo uint64, at time.Time, signers ...string) json.RawMessage {
	return sign(contract.KindWithdrawal, msg.Withdrawal{
		Schema: msg.SchemaWithdrawal, BundleID: Channel, Seq: seq, IssuedAt: msg.FormatTime(at),
		Scope: "all", UpToVersion: upTo, Reason: "emergency_stop",
	}, signers...)
}

// ObserveRule returns a valid observe-level rule.
func ObserveRule(n int) msg.Rule {
	return msg.Rule{
		RuleID: "schild-2026-" + pad4(n), Class: "heuristic", Stage: "shadow", MaxAction: "observe", MaxMatchShare: 0.001,
		Target:         msg.Target{Software: "wordpress", Versions: "*"},
		Evidence:       msg.Evidence{TipIssuers: 3, MaxIssuerShare: 0.34},
		FeedbackPolicy: "auto_downgrade",
		SecLang:        `SecRule REQUEST_HEADERS:User-Agent "@pm sqlmap nikto nuclei" "id:` + itoa(7700000+n) + `,phase:1,pass,log,severity:NOTICE,msg:'scanner user agent'"`,
	}
}

func itoa(n int) string { b, _ := json.Marshal(n); return string(b) }

func pad4(n int) string {
	s := itoa(n)
	for len(s) < 4 {
		s = "0" + s
	}
	return s
}
