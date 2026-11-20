package plan

import (
	"reflect"
	"testing"

	"github.com/deutschland-schild/schild/testlab/internal/label"
)

var sites = []string{"wp", "dvwa", "juice", "api"}

// TestDeterministicCounts is the MVP-06 kill criterion: two runs with the same
// seed must produce the same labelled request counts.
func TestDeterministicCounts(t *testing.T) {
	for _, sc := range Scenarios {
		a, err := Build(sc, 42, sites, Options{})
		if err != nil {
			t.Fatalf("%s: %v", sc, err)
		}
		b, err := Build(sc, 42, sites, Options{})
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(a.Counts(), b.Counts()) {
			t.Fatalf("%s: counts differ for same seed: %v vs %v", sc, a.Counts(), b.Counts())
		}
		// Full request equality, not just counts.
		if !reflect.DeepEqual(a.Requests, b.Requests) {
			t.Fatalf("%s: request lists differ for same seed", sc)
		}
	}
}

// TestDifferentSeedDiffers checks the generator actually uses the seed.
func TestDifferentSeedDiffers(t *testing.T) {
	a, _ := Build("T04", 1, sites, Options{})
	b, _ := Build("T04", 2, sites, Options{})
	if reflect.DeepEqual(a.Requests, b.Requests) {
		t.Fatal("different seeds produced identical plans")
	}
}

func TestScenarioShape(t *testing.T) {
	// T01 is all legitimate; no malicious/bypass.
	p, _ := Build("T01", 42, sites, Options{})
	c := p.Counts()
	if c[label.Malicious] != 0 || c[label.Bypass] != 0 {
		t.Fatalf("T01 should be legit-only, got %v", c)
	}
	if c[label.Benign] == 0 {
		t.Fatal("T01 has no benign requests")
	}
	// T02 has attacks and at least one bypass variant.
	p2, _ := Build("T02", 42, sites, Options{})
	c2 := p2.Counts()
	if c2[label.Malicious] == 0 {
		t.Fatal("T02 has no malicious requests")
	}
	if c2[label.Bypass] == 0 {
		t.Fatal("T02 has no bypass variants")
	}
	// Every request has a unique, dense seq and a known site.
	seen := map[int]bool{}
	for i, r := range p2.Requests {
		if r.Label.Seq != i {
			t.Fatalf("seq not dense at %d: %d", i, r.Label.Seq)
		}
		if seen[r.Label.Seq] {
			t.Fatalf("duplicate seq %d", r.Label.Seq)
		}
		seen[r.Label.Seq] = true
	}
}

func TestUnknownScenario(t *testing.T) {
	if _, err := Build("ZZ", 42, sites, Options{}); err == nil {
		t.Fatal("unknown scenario accepted")
	}
}

func TestCanariesPresentInT01(t *testing.T) {
	p, _ := Build("T01", 42, sites, Options{})
	if len(p.Canaries) == 0 {
		t.Fatal("T01 planted no canaries")
	}
	// Each canary must appear in some request's label.
	inLabels := map[string]bool{}
	for _, r := range p.Requests {
		if r.Label.Canary != "" {
			inLabels[r.Label.Canary] = true
		}
	}
	for _, c := range p.Canaries {
		if !inLabels[c] {
			t.Fatalf("canary %s not attached to any request", c)
		}
	}
}
