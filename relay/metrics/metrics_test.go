package metrics

import (
	"bytes"
	"strings"
	"testing"
)

func TestExposition(t *testing.T) {
	r := NewRegistry()
	c := r.Counter("schild_test_total", "A counter.", "reason")
	c.With("queue_full").Inc()
	c.With("queue_full").Add(2)
	c.With(`we"ird`).Inc()
	g := r.Gauge("schild_test_depth", "A gauge.", "priority")
	g.With("new_pattern").Set(7)
	r.GaugeFunc("schild_test_fn", "A func gauge.", func() float64 { return 1.5 })
	h := r.Histogram("schild_test_seconds", "A histogram.", []float64{0.01, 0.1}).With()
	h.Observe(0.005)
	h.Observe(0.05)
	h.Observe(5)
	var b bytes.Buffer
	r.Write(&b)
	out := b.String()
	for _, want := range []string{
		"# TYPE schild_test_total counter",
		`schild_test_total{reason="queue_full"} 3`,
		`schild_test_total{reason="we\"ird"} 1`,
		`schild_test_depth{priority="new_pattern"} 7`,
		"schild_test_fn 1.5",
		`schild_test_seconds_bucket{le="0.01"} 1`,
		`schild_test_seconds_bucket{le="0.1"} 2`,
		`schild_test_seconds_bucket{le="+Inf"} 3`,
		"schild_test_seconds_count 3",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
	defer func() {
		if recover() == nil {
			t.Error("duplicate registration must panic")
		}
	}()
	r.Counter("schild_test_total", "dup")
}
