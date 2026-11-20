package main

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/adversaries/internal/forge"
	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/keys"
	"github.com/deutschland-schild/schild/contract/testkeys"
	"github.com/deutschland-schild/schild/contract/verify"
)

// Every malformed artifact must be rejected by the real verifier with the
// code the generator claims (T10, T11): 0 accepted.
func TestEveryCaseRejected(t *testing.T) {
	trust := testkeys.TrustStore("lab-a", "lab-a2", "lab-b", "lab-c", "lab-d")
	for _, a := range cases() {
		ctx := &verify.Context{Now: forge.Clock, Trust: trust, Threshold: 3, Channel: forge.Channel}
		// The rollback case needs stored state newer than the delivered one.
		if a.Case == "rollback" {
			ctx.State = verify.State{BundleVersion: 40, BundleDigest: "sha256:00", CheckpointSeq: map[string]uint64{}, CheckpointDigest: map[string]string{}}
		}
		ctx.Now = forge.Clock.Add(time.Minute)
		kind := contract.Kind(a.Kind)
		_, err := verify.Signed(kind, []byte(a.Envelope), ctx)
		if err == nil {
			t.Errorf("%s: ACCEPTED, expected rejection %s", a.Case, a.ExpectCode)
			continue
		}
		if got := string(contract.CodeOf(err)); got != a.ExpectCode {
			t.Errorf("%s: rejected with %q, expected %q (%v)", a.Case, got, a.ExpectCode, err)
		}
	}
}

func TestEnvelopesAreWellFormedJSON(t *testing.T) {
	for _, a := range cases() {
		var e map[string]any
		if err := json.Unmarshal([]byte(a.Envelope), &e); err != nil {
			t.Errorf("%s: envelope is not JSON: %v", a.Case, err)
		}
	}
	_ = keys.Release
}
