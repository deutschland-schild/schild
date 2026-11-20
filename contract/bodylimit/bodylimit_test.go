package bodylimit

import (
	"encoding/json"
	"testing"

	"github.com/deutschland-schild/schild/contract/schema"
)

// The Go defaults are the defaults of schild.schema.json.
func TestDefaultsMatchSchema(t *testing.T) {
	var doc struct {
		Properties struct {
			WAF struct {
				Properties struct {
					Body struct {
						Properties map[string]struct {
							Default int64 `json:"default"`
						} `json:"properties"`
					} `json:"body"`
					Raw struct {
						Default int64 `json:"default"`
					} `json:"raw_body_limit_bytes"`
				} `json:"properties"`
			} `json:"waf"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(schema.Files()["config/schild.schema.json"], &doc); err != nil {
		t.Fatal(err)
	}
	p := doc.Properties.WAF.Properties
	for key, want := range map[string]int64{"max_per_client": DefaultMaxPerClient, "max_per_network": DefaultMaxPerNetwork, "max_in_flight_bytes": DefaultMaxInFlightBytes,
		"max_waiting_bytes_per_client": DefaultMaxWaitingBytesPerClient, "max_waiting_bytes_per_network": DefaultMaxWaitingBytesPerNetwork} {
		if got := p.Body.Properties[key].Default; got != want {
			t.Errorf("%s: schema default %d, Go %d", key, got, want)
		}
	}
	if p.Raw.Default != DefaultRawLimitBytes {
		t.Errorf("raw_body_limit_bytes: schema default %d, Go %d", p.Raw.Default, DefaultRawLimitBytes)
	}
}

// A shared address never gets a 429, whichever limit it reaches (D29, E5).
func TestSharedNeverRateLimited(t *testing.T) {
	l := Limits{MaxPerClient: 1, MaxPerNetwork: 1, MaxInFlight: 1, MaxInFlightBytes: 1, MaxWaitingBytesPerClient: 1, MaxWaitingBytesPerNetwork: 1, MaxWaitingBytes: 1}
	for _, nc := range []string{"cgnat", "mobile", "tor"} {
		for _, s := range []State{{Client: 9}, {Network: 9}, {InFlight: 9}, {InFlightBytes: 9},
			{ClientWaitingBytes: 9}, {NetWaitingBytes: 9}, {WaitingBytes: 9}} {
			if d := Admit(l, s, nc, true, 0); d.Admitted || *d.Status != 503 || *d.FailClosed != FailClosedBusy {
				t.Errorf("%s %+v: %+v", nc, s, d)
			}
		}
	}
}

// A class only ever selects a limit: no media type gets past the whole limit.
func TestNoClassExceedsTheWholeLimit(t *testing.T) {
	for _, ct := range []string{"", "image/jpeg", "application/json", "multipart/form-data", "text/plain", "application/octet-stream"} {
		if LimitOf(Classify(ct), 1<<30, 1<<20) != 1<<20 {
			t.Errorf("%q exceeds request_body_limit_bytes", ct)
		}
	}
}
