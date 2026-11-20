package grammar

import (
	"testing"

	"github.com/deutschland-schild/schild/adversaries/internal/seclang3"
	"github.com/deutschland-schild/schild/contract/seclang"
)

// TestDifferentialNoBypass generates rules and checks the core M4 property:
// every rule that the independent seclang3 checker flags as forbidden is
// rejected by the reference validator. A rule flagged forbidden but accepted
// is a validator bypass (a network rule that could disable protection,
// exfiltrate data or target one site would reach clients).
func TestDifferentialNoBypass(t *testing.T) {
	const n = 100000
	g := New(1)
	bypasses := 0
	flagged, accepted := 0, 0
	for i := 0; i < n; i++ {
		r := g.Next()
		_, err := seclang.Validate(r.Text, seclang.Options{MaxAction: r.MaxAction})
		ok := err == nil
		if ok {
			accepted++
		}
		if fs := seclang3.Check(r.Text); len(fs) > 0 {
			flagged++
			if ok {
				bypasses++
				t.Errorf("BYPASS i=%d class=%s: reference accepted a forbidden rule: %q", i, fs[0].Class, r.Text)
			}
		}
	}
	t.Logf("n=%d accepted=%d flagged_by_seclang3=%d bypasses=%d", n, accepted, flagged, bypasses)
	if flagged == 0 {
		t.Fatal("seclang3 flagged nothing; the generator is not producing forbidden constructs")
	}
	if accepted == 0 {
		t.Fatal("no rule was accepted; the generator is not producing valid rules")
	}
}

// TestBadAlwaysRejected: a rule the generator built with an injected forbidden
// construct must always be rejected by the reference validator.
func TestBadAlwaysRejected(t *testing.T) {
	g := New(42)
	for i := 0; i < 20000; i++ {
		r := g.Bad()
		if _, err := seclang.Validate(r.Text, seclang.Options{MaxAction: r.MaxAction}); err == nil {
			t.Fatalf("injected-forbidden rule accepted (class %s): %q", r.Forbidden, r.Text)
		}
	}
}
