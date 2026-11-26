package behaviour

import "testing"

// A node of a group draws no incident number it knows already: in the group
// the number is the identity of a block (D109).
func TestNewIncidentDrawsAnotherThanAKnownOne(t *testing.T) {
	e := New(Config{})
	if id := e.NewIncident(); len(id) != 9 {
		t.Fatalf("a number of the default generator: %q", id)
	}
	draws := []string{"AAAA-0001", "AAAA-0002", "AAAA-0003"}
	n := 0
	e.DrawIncidents(func() string { n++; return draws[min(n, len(draws))-1] })
	if id := e.NewIncident(); id != "AAAA-0001" || n != 1 {
		t.Fatalf("on a single gateway: %q after %d draws, want the first draw", id, n)
	}
	n = 0
	e.KnownIncidents(func(id string) bool { return id != "AAAA-0003" })
	if id := e.NewIncident(); id != "AAAA-0003" || n != 3 {
		t.Fatalf("with two known numbers: %q after %d draws, want the third draw", id, n)
	}
	// A generator that gives known numbers only does not hold a block up.
	n = 0
	e.KnownIncidents(func(string) bool { return true })
	if id := e.NewIncident(); id == "" || n != incidentDraws {
		t.Fatalf("with every number known: %q after %d draws, want %d draws", id, n, incidentDraws)
	}
}
