//go:build !release

package dashboard_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/gateway/internal/apptest"
	"github.com/deutschland-schild/schild/gateway/internal/monitoring"
)

// TestMonitoringThroughTheGate: requests through the proxy show up in
// /monitoring/now within about a second, classified exactly, without any
// visitor address in the answer (MVP-21).
func TestMonitoringThroughTheGate(t *testing.T) {
	h := apptest.New(t, apptest.Options{})
	h.Login()
	for i := 0; i < 6; i++ {
		if r := h.Visit("GET", "/produkte/42", "198.51.100.23", "", ""); r.StatusCode != 200 {
			t.Fatalf("clean request: %d", r.StatusCode)
		}
	}
	if r := h.Visit("GET", "/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E", "203.0.113.5", "", ""); r.StatusCode != 403 {
		t.Fatalf("xss: %d", r.StatusCode)
	}
	var now monitoring.MonitoringNow
	deadline := time.Now().Add(5 * time.Second)
	for {
		b := expect(t, h, "GET", "/monitoring/now", nil, 200, "MonitoringNow")
		_ = json.Unmarshal(b, &now)
		if now.Traffic.RequestsPerS*60 >= 7 || time.Now().After(deadline) {
			if strings.Contains(string(b), "198.51.100.23") || strings.Contains(string(b), "203.0.113.5") {
				t.Fatalf("address in monitoring answer: %s", b)
			}
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if got := now.Traffic.RequestsPerS * 60; got < 6.99 || got > 7.01 {
		t.Fatalf("requests in the last minute: %.2f, want 7", got)
	}
	if now.Traffic.StoppedShare == nil || *now.Traffic.StoppedShare < 0.14 || *now.Traffic.StoppedShare > 0.15 {
		t.Fatalf("stopped share %v, want 1/7", now.Traffic.StoppedShare)
	}
	if now.Traffic.LatencyTotalP95MS == nil || now.Traffic.LatencyOverheadP95MS == nil {
		t.Fatalf("latency missing: %+v", now.Traffic)
	}
	expect(t, h, "GET", "/monitoring/server", nil, 200, "ServerSnapshot")
	expect(t, h, "GET", "/monitoring/catalogue", nil, 200, "MetricCatalogue")
	from := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	expect(t, h, "GET", "/monitoring/series?metric=traffic.requests&metric=server.cpu_usage&from="+from, nil, 200, "SeriesResult")
	expect(t, h, "GET", "/monitoring/traffic/breakdown?by=path&from="+from, nil, 200, "TrafficBreakdown")
	expect(t, h, "GET", "/monitoring/buckets?resolution=10s", nil, 200, "MetricBucketPage")
	expect(t, h, "GET", "/monitoring/now?site=nope", nil, 400, "Problem")
}

// TestMonitoringOff: monitoring.enabled false answers 409 monitoring_off.
func TestMonitoringOff(t *testing.T) {
	h := apptest.New(t, apptest.Options{Extra: "monitoring:\n  enabled: false\n"})
	h.Login()
	b := expect(t, h, "GET", "/monitoring/now", nil, 409, "Problem")
	if !strings.Contains(string(b), `"monitoring_off"`) {
		t.Fatalf("%s", b)
	}
}
