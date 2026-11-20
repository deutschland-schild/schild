package contract

import (
	"errors"
	"fmt"
	"testing"
)

func TestKindsDistinct(t *testing.T) {
	seen := map[string]bool{}
	for _, k := range SignedKinds {
		pt := k.PayloadType()
		if seen[pt] {
			t.Fatalf("payload type %s reused (no domain separation)", pt)
		}
		seen[pt] = true
		if k.Purpose() == "" {
			t.Fatalf("%s has no purpose", k)
		}
		l := LimitsFor(k)
		if l.MaxPayloadBytes <= 0 || l.MaxPayloadBytes >= l.MaxEnvelopeBytes {
			t.Fatalf("%s limits %+v", k, l)
		}
	}
	if !KindBundle.Threshold() || !KindWithdrawal.Threshold() || KindCheckpoint.Threshold() {
		t.Fatal("threshold kinds")
	}
	if MinIndependentOperatorsFloor != 2 || DefaultMinIndependentOperators != 3 {
		t.Fatal("E5 floor/default changed: this is a contract change")
	}
}

func TestCodeOf(t *testing.T) {
	err := fmt.Errorf("wrap: %w", Errf(CodeReplay, "x %d", 1))
	if CodeOf(err) != CodeReplay || CodeOf(errors.New("x")) != "" {
		t.Fatal("CodeOf")
	}
	if Errf(CodeSchema, "a").Error() != "schema: a" {
		t.Fatal("Error()")
	}
}
