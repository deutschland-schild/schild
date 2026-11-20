package monitoring

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/deutschland-schild/schild/contract/schema"
)

// v0.5 (D36) additions: merged series, per-website latency, hint site,
// TrafficNow, the OpenTelemetry mapping.

func TestPlan(t *testing.T) {
	now := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		rings []Ring
		back  time.Duration
		res   string
		want  Resolution
		merge int
		pts   int
		err   error
	}{
		{Rings(6, 48, 14), time.Hour, "auto", Res10s, 1, 360, nil},
		{Rings(6, 48, 14), 14 * 24 * time.Hour, "auto", Res10m, 3, 672, nil},
		{Rings(6, 48, 14), 14 * 24 * time.Hour, "10m", Res10m, 1, 2016, ErrTooManyPoints},
		{Rings(6, 48, 90), 90 * 24 * time.Hour, "", Res10m, 18, 720, nil},
		{Rings(6, 48, 14), 7 * 24 * time.Hour, "auto", Res10m, 3, 336, nil},
	} {
		p, err := Plan(c.rings, c.res, now.Add(-c.back), now, now)
		if p.Ring.Resolution != c.want || p.Merge != c.merge || p.Points != c.pts || !errors.Is(err, c.err) {
			t.Errorf("%v %s: got %s x%d %d %v", c.back, c.res, p.Ring.Resolution, p.Merge, p.Points, err)
		}
		if err == nil && (p.First.Unix()%int64(p.Step/time.Second) != 0 || p.Step != p.Ring.Step*time.Duration(p.Merge)) {
			t.Errorf("%v: misaligned plan %+v", c.back, p)
		}
	}
	d, _ := openAPI(t)
	var steps []int
	for _, x := range comp(d, "SeriesResult")["properties"].(map[string]any)["buckets_per_point"].(map[string]any)["enum"].([]any) {
		steps = append(steps, int(x.(float64)))
	}
	if !reflect.DeepEqual(steps, MergeFactors) {
		t.Errorf("buckets_per_point enum %v != MergeFactors %v", steps, MergeFactors)
	}
}

func TestOTelMapping(t *testing.T) {
	for _, m := range Catalogue {
		o, ok := OTelMetrics[m.ID]
		if !ok || o.Name == "" || o.Unit == "" {
			t.Errorf("%s: no OpenTelemetry mapping", m.ID)
		}
		if m.Unit == "ms" && o.Scale != 0.001 {
			t.Errorf("%s: ms must scale to s", m.ID)
		}
	}
	if len(OTelMetrics) != len(Catalogue) {
		t.Errorf("%d mappings for %d metrics", len(OTelMetrics), len(Catalogue))
	}
	for _, dim := range Dimensions {
		if _, ok := OTelAttributes[dim]; !ok {
			t.Errorf("dimension %s: no attribute", dim)
		}
	}
}

func TestWireTypesD36(t *testing.T) {
	_, c := openAPI(t)
	tr := traffic()
	hist := LatencyHistogram{Scheme: HistogramScheme, Counts: map[string]int64{"20": 700}}
	p95, share := 91.3, 0.008
	for _, c0 := range []struct {
		name  string
		v     any
		proto any
	}{
		{"MetricBucket", MetricBucket{T: "2026-10-28T12:00:00Z", Resolution: Res1m, StepS: 60, Traffic: tr,
			Latency: BucketLatency{Total: hist, Overhead: hist, Upstream: hist},
			Sites:   []SiteTraffic{{Site: "verein.example", Traffic: tr, Latency: &BucketLatency{Total: hist, Overhead: hist, Upstream: hist}}, {Site: "_.kunden.example.org", Traffic: TrafficCounters{}}}}, MetricBucket{}},
		{"SeriesResult", SeriesResult{From: "2026-10-14T12:00:00Z", To: "2026-10-28T12:00:00Z", Resolution: Res10m, StepS: 1800, BucketsPerPoint: 3, Points: 1,
			Series: []MetricSeries{{Metric: "traffic.requests", Stat: Rate, Kind: Counter, Unit: "requests", Exact: true, Values: []*float64{&p95}}}, Restarts: []string{}}, SeriesResult{}},
		{"MetricBucket", MetricBucket{T: "2026-10-28T12:00:00Z", Resolution: Res10m, StepS: 600, Traffic: tr,
			Latency: BucketLatency{Total: hist, Overhead: hist, Upstream: hist}, Clients: BucketClients{Unique: i64(90), New: i64(4), UniqueDay: i64(700)},
			Sites: []SiteTraffic{{Site: "verein.example", Traffic: tr, Clients: &BucketClients{Unique: i64(40), New: i64(2), UniqueDay: i64(310)},
				Top: &BucketTop{Country: []TopEntry{{Key: "DE", Requests: 800, Stopped: 10, WouldBlock: 1}}, NetClass: []TopEntry{{Key: "hosting", Requests: 50, Stopped: 9}}}}}}, MetricBucket{}},
		{"SeriesResult", SeriesResult{From: "2026-10-29T11:00:00Z", To: "2026-10-29T11:02:00Z", Resolution: Res1m, StepS: 60, Points: 2, Site: "verein.example",
			Series:   []MetricSeries{{Metric: "traffic.stopped", Stat: Sum, Kind: Counter, Unit: "requests", Exact: false, Values: []*float64{&p95, &p95}}},
			Restarts: []string{}, Partial: []bool{false, true}, Filters: []string{"country:DE"}, Source: "rings"}, SeriesResult{}},
		{"HealthHint", HealthHint{Code: HintUpstreamSlow, Level: "notice", Since: "2026-10-28T09:00:00Z", Site: "verein.example"}, HealthHint{}},
		{"TrafficNow", TrafficNow{WindowS: 60, RequestsPerS: 42.5, StoppedShare: &share, LatencyTotalP95MS: &p95}, TrafficNow{}},
	} {
		sch, err := c.Compile(schema.BaseURL + "api/client-dashboard.openapi.yaml#/components/schemas/" + c0.name)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := json.Marshal(c0.v)
		inst, _ := jsonschema.UnmarshalJSON(bytes.NewReader(b))
		if err := sch.Validate(inst); err != nil {
			t.Errorf("%s: %v\n%s", c0.name, err, b)
			continue
		}
		v := reflect.New(reflect.TypeOf(c0.proto)).Interface()
		dec := json.NewDecoder(bytes.NewReader(b))
		dec.DisallowUnknownFields()
		if err := dec.Decode(v); err != nil {
			t.Errorf("%s: %v", c0.name, err)
		}
	}
	for _, id := range []string{"verein.example", "_any", "_other", "default", "_.kunden.example.org", "ipv6-2001-db8--1", "192.0.2.10", "xn--bcher-kva.example"} {
		sch, _ := c.Compile(schema.BaseURL + "api/client-dashboard.openapi.yaml#/components/schemas/SiteKey")
		inst, _ := jsonschema.UnmarshalJSON(strings.NewReader(`"` + id + `"`))
		if err := sch.Validate(inst); err != nil {
			t.Errorf("SiteKey %s: %v", id, err)
		}
	}
	for _, id := range []string{"_all", "Verein.example", "-a.example", "a..example", "*.example.org"} {
		sch, _ := c.Compile(schema.BaseURL + "api/client-dashboard.openapi.yaml#/components/schemas/SiteKey")
		inst, _ := jsonschema.UnmarshalJSON(strings.NewReader(`"` + id + `"`))
		if err := sch.Validate(inst); err == nil {
			t.Errorf("SiteKey %s accepted", id)
		}
	}
}
