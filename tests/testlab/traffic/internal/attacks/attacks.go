// Package attacks generates a small, curated, deterministic set of web-attack
// requests (SQLi, XSS, path traversal, command injection) and a credential-
// stuffing wave with a tiny test list. These are the lightweight, in-process
// attacks the Go runner sends itself; the heavier external suites (nuclei,
// sqlmap, GoTestWAF, go-ftw, nikto, ffuf) run as their own containers against
// the same internal networks.
//
// Every request is labelled malicious (or bypass, for evasion variants) and is
// sent only against the test lab's own containers on internal networks.
package attacks

import (
	"fmt"
	"math/rand"

	"github.com/deutschland-schild/schild/testlab/internal/label"
	"github.com/deutschland-schild/schild/testlab/traffic/internal/req"
)

type payload struct {
	technique string
	method    string
	path      string
	query     string
	body      string
	bypass    bool // crafted to evade detection
}

// curated payloads use only well-known public attack patterns; no live target
// outside the test lab is ever involved.
var curated = []payload{
	{"sqli", "GET", "/search", "q=1' OR '1'='1", "", false},
	{"sqli", "GET", "/api/items", "q=1 UNION SELECT username,password FROM users--", "", false},
	{"sqli", "GET", "/search", "q=1'/**/OR/**/1=1--", "", true}, // comment-evasion
	{"xss", "GET", "/search", "q=<script>alert(1)</script>", "", false},
	{"xss", "GET", "/search", "q=<img src=x onerror=alert(1)>", "", false},
	{"xss", "GET", "/search", "q=<svg/onload=alert(1)>", "", true},
	{"traversal", "GET", "/download", "file=../../../../etc/passwd", "", false},
	{"traversal", "GET", "/download", "file=..%2f..%2f..%2fetc%2fpasswd", "", true},
	{"cmdi", "GET", "/ping", "host=127.0.0.1;cat /etc/passwd", "", false},
	{"cmdi", "POST", "/api/items", "", `{"name":"$(id)","owner":"x"}`, false},
}

// Web returns n curated web-attack requests across the given sites.
func Web(seed int64, scenario string, sites []string, n int) []req.Request {
	if len(sites) == 0 {
		return nil
	}
	rng := rand.New(rand.NewSource(seed))
	var out []req.Request
	for i := 0; i < n; i++ {
		p := curated[i%len(curated)]
		site := sites[rng.Intn(len(sites))]
		class := label.Malicious
		if p.bypass {
			class = label.Bypass
		}
		r := req.Request{Method: p.method, Site: site, Path: p.path, Query: p.query,
			Headers: map[string]string{"User-Agent": "sec-scan/1.0"},
			Label: label.Label{Class: class, Scenario: scenario, Source: "web-attacks",
				Technique: p.technique, ExpectBlock: true, Seq: i}}
		if p.body != "" {
			r.Body = []byte(p.body)
			r.Headers["Content-Type"] = "application/json"
		}
		out = append(out, r)
	}
	return out
}

// testLogins is a tiny, obviously-fake credential list for stuffing.
var testLogins = []struct{ user, pass string }{
	{"admin", "admin"}, {"admin", "password"}, {"root", "toor"},
	{"user", "123456"}, {"test", "test"}, {"guest", "guest"},
}

// CredentialStuffing returns n login POSTs using the test list.
func CredentialStuffing(seed int64, scenario string, sites []string, n int) []req.Request {
	if len(sites) == 0 {
		return nil
	}
	rng := rand.New(rand.NewSource(seed))
	var out []req.Request
	for i := 0; i < n; i++ {
		c := testLogins[i%len(testLogins)]
		site := sites[rng.Intn(len(sites))]
		out = append(out, req.Request{Method: "POST", Site: site, Path: "/login",
			Body:    []byte(fmt.Sprintf(`{"username":%q,"password":%q}`, c.user, c.pass)),
			Headers: map[string]string{"Content-Type": "application/json", "User-Agent": "cred-stuffer/1.0"},
			Label: label.Label{Class: label.Malicious, Scenario: scenario, Source: "cred-stuffing",
				Technique: "credential_stuffing", ExpectBlock: true, Seq: i}})
	}
	return out
}
