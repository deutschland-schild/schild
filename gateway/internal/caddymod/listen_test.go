package caddymod

import (
	"slices"
	"testing"
)

func TestListenAddresses(t *testing.T) {
	for cfg, want := range map[string][]string{
		`{"apps":{"http":{"servers":{"a":{"listen":[":443"]},"b":{"listen":["127.0.0.1:80"],"protocols":["h1"]}}}}}`: {"127.0.0.1:80", ":443", ":443 (HTTP/3)"},
		`{"apps":{"http":{"servers":{"a":{"listen":[":443"],"protocols":["h1","h2"]}}}}}`:                            {":443"},
		`{}`: {},
	} {
		got, err := ListenAddresses([]byte(cfg))
		if err != nil || !slices.Equal(got, want) {
			t.Fatalf("%s: %q %v", cfg, got, err)
		}
	}
	if _, err := ListenAddresses([]byte(`{"apps":{"http":{"servers":{"a":{"listen":[":x-y"]}}}}}`)); err == nil {
		t.Fatal("an address that is none")
	}
}
