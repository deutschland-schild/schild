package scenario

import "testing"

// TestScenariosAcceptNoAttack runs every scenario against the real acceptance
// code and requires that no adversarial artifact was accepted: the MVP-07
// kill criterion (any harm measure > 0) must not be hit.
func TestScenariosAcceptNoAttack(t *testing.T) {
	for _, id := range All {
		o, err := Run(id)
		if err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		if o.Attempts == 0 {
			t.Errorf("%s: no attempts", id)
		}
		if o.Accepted != 0 {
			t.Errorf("%s: %d adversarial artifacts accepted (want 0)\n%v", id, o.Accepted, o.Detail)
		}
		t.Logf("%s: attempts=%d accepted=%d observed=%q", id, o.Attempts, o.Accepted, o.KillObserved)
	}
}
