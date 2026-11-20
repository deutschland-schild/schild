//go:build release

package verify

import (
	"testing"

	"github.com/deutschland-schild/schild/contract/keys"
)

// In release builds a plugged-in operator mapping (test profile, E5) is
// ignored: only the configured operator of a key counts.
func TestReleaseIgnoresSimulatedOperators(t *testing.T) {
	ctx := &Context{OperatorOf: func(*keys.TrustedKey) string { return "sim-1" }}
	k := &keys.TrustedKey{KeyID: "lab-x/rules/2026-10", Operator: "op-x"}
	if got := ctx.operator(k); got != "op-x" {
		t.Fatalf("release build counted simulated operator %q", got)
	}
}
