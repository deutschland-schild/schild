// Package metrics is a small, dependency-free Prometheus text exposition
// (format 0.0.4) for counters, gauges and histograms with labels. It is used
// by schild-relay and schild-lab; it avoids pulling client_golang into images.
package metrics

import (
	"fmt"
	"io"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

// Registry holds metric families in registration order.
type Registry struct {
	mu       sync.Mutex
	families []family
	names    map[string]bool
}

type family interface {
	name() string
	write(w io.Writer)
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry { return &Registry{names: map[string]bool{}} }

func (r *Registry) add(f family) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.names[f.name()] {
		panic("metrics: duplicate metric " + f.name())
	}
	r.names[f.name()] = true
	r.families = append(r.families, f)
}

// Write renders all metrics.
func (r *Registry) Write(w io.Writer) {
	r.mu.Lock()
	fs := append([]family(nil), r.families...)
	r.mu.Unlock()
	for _, f := range fs {
		f.write(w)
	}
}

// Handler serves the registry on /metrics.
func (r *Registry) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		r.Write(w)
	})
}

// atomicFloat is a float64 updated with CAS.
type atomicFloat struct{ bits atomic.Uint64 }

func (a *atomicFloat) add(v float64) {
	for {
		old := a.bits.Load()
		if a.bits.CompareAndSwap(old, math.Float64bits(math.Float64frombits(old)+v)) {
			return
		}
	}
}
func (a *atomicFloat) set(v float64) { a.bits.Store(math.Float64bits(v)) }
func (a *atomicFloat) get() float64  { return math.Float64frombits(a.bits.Load()) }

// vec is the shared label handling.
type vec[T any] struct {
	n, help, typ string
	labels       []string
	mu           sync.RWMutex
	children     map[string]*T
	order        []string
	values       map[string][]string
	mk           func() *T
}

func (v *vec[T]) name() string { return v.n }

func (v *vec[T]) with(vals ...string) *T {
	if len(vals) != len(v.labels) {
		panic(fmt.Sprintf("metrics: %s wants %d labels, got %d", v.n, len(v.labels), len(vals)))
	}
	key := strings.Join(vals, "\x00")
	v.mu.RLock()
	c, ok := v.children[key]
	v.mu.RUnlock()
	if ok {
		return c
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if c, ok = v.children[key]; ok {
		return c
	}
	c = v.mk()
	v.children[key] = c
	v.order = append(v.order, key)
	v.values[key] = append([]string(nil), vals...)
	return c
}

func (v *vec[T]) header(w io.Writer) {
	fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s %s\n", v.n, escapeHelp(v.help), v.n, v.typ)
}

func (v *vec[T]) each(f func(labels string, c *T)) {
	v.mu.RLock()
	keys := append([]string(nil), v.order...)
	v.mu.RUnlock()
	sort.Strings(keys)
	for _, k := range keys {
		v.mu.RLock()
		c, vals := v.children[k], v.values[k]
		v.mu.RUnlock()
		f(labelString(v.labels, vals, "", ""), c)
	}
}

func newVec[T any](name, help, typ string, labels []string, mk func() *T) *vec[T] {
	return &vec[T]{n: name, help: help, typ: typ, labels: labels, children: map[string]*T{}, values: map[string][]string{}, mk: mk}
}

// Counter is a monotonically increasing value.
type Counter struct{ v atomicFloat }

// Inc adds 1.
func (c *Counter) Inc() { c.v.add(1) }

// Add adds d (must be >= 0).
func (c *Counter) Add(d float64) {
	if d > 0 {
		c.v.add(d)
	}
}

// Value returns the current value.
func (c *Counter) Value() float64 { return c.v.get() }

// CounterVec is a counter family.
type CounterVec struct{ *vec[Counter] }

// With returns the counter for the label values.
func (c *CounterVec) With(vals ...string) *Counter { return c.with(vals...) }

func (c *CounterVec) write(w io.Writer) {
	c.header(w)
	c.each(func(l string, x *Counter) { fmt.Fprintf(w, "%s%s %s\n", c.n, l, fmtFloat(x.v.get())) })
}

// Counter registers a counter family.
func (r *Registry) Counter(name, help string, labels ...string) *CounterVec {
	c := &CounterVec{newVec(name, help, "counter", labels, func() *Counter { return &Counter{} })}
	r.add(c)
	return c
}

// Gauge is a value that can go up and down.
type Gauge struct{ v atomicFloat }

// Set sets the value.
func (g *Gauge) Set(v float64) { g.v.set(v) }

// Add adds d.
func (g *Gauge) Add(d float64) { g.v.add(d) }

// Value returns the current value.
func (g *Gauge) Value() float64 { return g.v.get() }

// GaugeVec is a gauge family.
type GaugeVec struct{ *vec[Gauge] }

// With returns the gauge for the label values.
func (g *GaugeVec) With(vals ...string) *Gauge { return g.with(vals...) }

func (g *GaugeVec) write(w io.Writer) {
	g.header(w)
	g.each(func(l string, x *Gauge) { fmt.Fprintf(w, "%s%s %s\n", g.n, l, fmtFloat(x.v.get())) })
}

// Gauge registers a gauge family.
func (r *Registry) Gauge(name, help string, labels ...string) *GaugeVec {
	g := &GaugeVec{newVec(name, help, "gauge", labels, func() *Gauge { return &Gauge{} })}
	r.add(g)
	return g
}

type gaugeFunc struct {
	n, help string
	f       func() float64
}

func (g *gaugeFunc) name() string { return g.n }
func (g *gaugeFunc) write(w io.Writer) {
	fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s gauge\n%s %s\n", g.n, escapeHelp(g.help), g.n, g.n, fmtFloat(g.f()))
}

// GaugeFunc registers a gauge whose value is read at scrape time.
func (r *Registry) GaugeFunc(name, help string, f func() float64) {
	r.add(&gaugeFunc{n: name, help: help, f: f})
}

// Histogram counts observations in cumulative buckets.
type Histogram struct {
	upper  []float64
	counts []atomic.Uint64
	sum    atomicFloat
	count  atomic.Uint64
}

// Observe records one value.
func (h *Histogram) Observe(v float64) {
	i := sort.SearchFloat64s(h.upper, v)
	if i < len(h.counts) {
		h.counts[i].Add(1)
	}
	h.sum.add(v)
	h.count.Add(1)
}

// Count returns the number of observations.
func (h *Histogram) Count() uint64 { return h.count.Load() }

// HistogramVec is a histogram family.
type HistogramVec struct{ *vec[Histogram] }

// With returns the histogram for the label values.
func (h *HistogramVec) With(vals ...string) *Histogram { return h.with(vals...) }

func (h *HistogramVec) write(w io.Writer) {
	h.header(w)
	h.vec.mu.RLock()
	keys := append([]string(nil), h.order...)
	h.vec.mu.RUnlock()
	sort.Strings(keys)
	for _, k := range keys {
		h.vec.mu.RLock()
		x, vals := h.children[k], h.values[k]
		h.vec.mu.RUnlock()
		var cum uint64
		for i, u := range x.upper {
			cum += x.counts[i].Load()
			fmt.Fprintf(w, "%s_bucket%s %d\n", h.n, labelString(h.labels, vals, "le", fmtFloat(u)), cum)
		}
		n := x.count.Load()
		fmt.Fprintf(w, "%s_bucket%s %d\n", h.n, labelString(h.labels, vals, "le", "+Inf"), n)
		l := labelString(h.labels, vals, "", "")
		fmt.Fprintf(w, "%s_sum%s %s\n%s_count%s %d\n", h.n, l, fmtFloat(x.sum.get()), h.n, l, n)
	}
}

// Histogram registers a histogram family with the given upper bounds.
func (r *Registry) Histogram(name, help string, buckets []float64, labels ...string) *HistogramVec {
	b := append([]float64(nil), buckets...)
	sort.Float64s(b)
	h := &HistogramVec{newVec(name, help, "histogram", labels, func() *Histogram {
		return &Histogram{upper: b, counts: make([]atomic.Uint64, len(b))}
	})}
	r.add(h)
	return h
}

// LatencyBuckets are seconds from 100 µs to 10 s.
var LatencyBuckets = []float64{0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}

func labelString(names, vals []string, extraName, extraVal string) string {
	if len(names) == 0 && extraName == "" {
		return ""
	}
	var b strings.Builder
	b.WriteByte('{')
	for i, n := range names {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(n)
		b.WriteString(`="`)
		b.WriteString(escapeLabel(vals[i]))
		b.WriteByte('"')
	}
	if extraName != "" {
		if len(names) > 0 {
			b.WriteByte(',')
		}
		b.WriteString(extraName)
		b.WriteString(`="`)
		b.WriteString(extraVal)
		b.WriteByte('"')
	}
	b.WriteByte('}')
	return b.String()
}

func escapeLabel(s string) string {
	return strings.NewReplacer(`\`, `\\`, "\n", `\n`, `"`, `\"`).Replace(s)
}

func escapeHelp(s string) string {
	return strings.NewReplacer(`\`, `\\`, "\n", `\n`).Replace(s)
}

func fmtFloat(v float64) string {
	switch {
	case math.IsInf(v, 1):
		return "+Inf"
	case math.IsInf(v, -1):
		return "-Inf"
	case math.IsNaN(v):
		return "NaN"
	}
	return strconv.FormatFloat(v, 'g', -1, 64)
}
