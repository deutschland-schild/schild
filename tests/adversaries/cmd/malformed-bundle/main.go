// Command malformed-bundle prints deliberately invalid rule bundles and
// withdrawals as signed DSSE envelope JSON, for negative tests (T10, T11). It
// covers: below threshold, a single stolen key, a rollback version, an
// expired bundle, a frozen (stale) stream, a wrong payload type, duplicate
// operator keys. Every one of these must be rejected by an honest client
// (contract/verify); the scenario runner (cmd/adversary T10/T11) asserts that.
//
//	go run ./cmd/malformed-bundle -case all          # print every case, one JSON per line (NDJSON)
//	go run ./cmd/malformed-bundle -case rollback     # one case
//
// The output is an injection corpus: it can be fed to a relay in a live run,
// or inspected. It is never accepted; that is the point. D72: no schild
// gateway consumes bundles or withdrawals today, so there is no live client
// to feed (lab later); the offline check against contract/verify stays.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/deutschland-schild/schild/adversaries/internal/forge"
	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/msg"
)

type artifact struct {
	Case        string          `json:"case"`
	Kind        string          `json:"kind"`
	ExpectCode  string          `json:"expect_code"`
	Description string          `json:"description"`
	Envelope    json.RawMessage `json:"envelope"`
}

func main() {
	which := flag.String("case", "all", "case name or all")
	flag.Parse()

	arts := cases()
	for _, a := range arts {
		if *which != "all" && a.Case != *which {
			continue
		}
		b, _ := json.Marshal(a)
		fmt.Println(string(b))
	}
}

func cases() []artifact {
	base := forge.Bundle(forge.BundleOpts{Version: 50, Rules: []map[string]any{forge.RuleObserve(forge.RuleID(1), 7700001)}})
	env := func(kind contract.Kind, payload map[string]any, signers ...string) json.RawMessage {
		return json.RawMessage(forge.SignBytes(kind, forge.MustJSON(payload), signers...))
	}
	now := forge.Clock
	var out []artifact
	add := func(name, kind, code, desc string, raw json.RawMessage) {
		out = append(out, artifact{Case: name, Kind: kind, ExpectCode: code, Description: desc, Envelope: raw})
	}

	add("below-threshold", "rule-bundle", string(contract.CodeThreshold),
		"bundle signed by one operator (k=3 required)", env(contract.KindBundle, base, "lab-a"))
	add("single-stolen-key", "rule-bundle", string(contract.CodeThreshold),
		"a single stolen operator key cannot reach k", env(contract.KindBundle, base, "lab-b"))
	add("duplicate-operator-keys", "rule-bundle", string(contract.CodeThreshold),
		"two labs of one operator (lab-a + lab-a2) count once", env(contract.KindBundle, base, "lab-a", "lab-a2"))

	rollback := forge.Bundle(forge.BundleOpts{Version: 1, Rules: []map[string]any{forge.RuleObserve(forge.RuleID(1), 7700001)}})
	add("rollback", "rule-bundle", string(contract.CodeRollback),
		"version 1 delivered to a client that already has a newer bundle", env(contract.KindBundle, rollback, "lab-a", "lab-b", "lab-c"))

	expired := forge.Bundle(forge.BundleOpts{
		Version:  51,
		IssuedAt: msg.FormatTime(now.Add(-40 * 24 * time.Hour)),
		Expires:  msg.FormatTime(now.Add(-time.Hour)),
		Rules:    []map[string]any{forge.RuleObserve(forge.RuleID(1), 7700001)},
	})
	add("expired", "rule-bundle", string(contract.CodeExpired),
		"expired bundle replayed (freeze by withholding fresh state)", env(contract.KindBundle, expired, "lab-a", "lab-b", "lab-c"))

	staleCP := forge.Checkpoint("lab-a", 1, 50, msg.Digest(forge.MustJSON(base)), 10*time.Minute)
	staleCP["issued_at"] = msg.FormatTime(now.Add(-20 * time.Minute))
	staleCP["expires"] = msg.FormatTime(now.Add(-10 * time.Minute))
	add("frozen-stream", "checkpoint", string(contract.CodeExpired),
		"stale checkpoint (frozen stream): expired and older than the freeze window", env(contract.KindCheckpoint, staleCP, "lab-a"))

	add("wrong-payload-type", "rule-bundle", string(contract.CodePayloadType),
		"a bundle signed under the checkpoint payload type", env(contract.KindCheckpoint, base, "lab-a", "lab-b", "lab-c"))

	// scope-all withdrawal signed by too few operators (emergency stop forged).
	w := forge.Withdrawal(1, 50, "all", nil)
	w["reason"] = "emergency_stop"
	add("withdrawal-below-threshold", "withdrawal", string(contract.CodeThreshold),
		"emergency stop signed by one operator", env(contract.KindWithdrawal, w, "lab-a"))

	if len(out) == 0 {
		fmt.Fprintln(os.Stderr, "no cases")
	}
	return out
}
