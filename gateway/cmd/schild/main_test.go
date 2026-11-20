package main

import "testing"

// TestReadyURL: `schild status` asks wildcard listeners on loopback; an
// empty host (":9101") used to give "http://:9101/readyz", which never
// connects, so a running gateway showed as "not reachable".
func TestReadyURL(t *testing.T) {
	for addr, want := range map[string]string{
		"127.0.0.1:9101": "http://127.0.0.1:9101/readyz",
		"0.0.0.0:8788":   "http://127.0.0.1:8788/readyz",
		":9101":          "http://127.0.0.1:9101/readyz",
		"[::]:9101":      "http://[::1]:9101/readyz",
		"10.0.0.5:8788":  "http://10.0.0.5:8788/readyz",
		"localhost:8788": "http://localhost:8788/readyz",
		"[fd00::5]:8788": "http://[fd00::5]:8788/readyz",
	} {
		if got := readyURL(addr); got != want {
			t.Errorf("%s: %s, want %s", addr, got, want)
		}
	}
}
