package main

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/deutschland-schild/schild/testlab/internal/label"
)

// sent is one request of the smoke traffic.
type sent struct {
	Site      string `json:"site"`
	RequestID string `json:"request_id"`
	Class     string `json:"class"`
	Technique string `json:"technique,omitempty"`
	IP        string `json:"ip"`
	Method    string `json:"method"`
	Path      string `json:"path"`
	Status    int    `json:"status"`
}

type reqSpec struct {
	method, target, body, technique string
	class                           label.Class
}

// Legit traffic: browsing and API use of the tiny REST site.
func legitSpecs(round int) []reqSpec {
	var out []reqSpec
	for i := 0; i < 6; i++ {
		out = append(out,
			reqSpec{method: "GET", target: "/", class: label.Benign, technique: "browse"},
			reqSpec{method: "GET", target: fmt.Sprintf("/api/items?page=%d&sort=name", i+1+round*10), class: label.Benign, technique: "api"},
			reqSpec{method: "GET", target: fmt.Sprintf("/api/items/%d", i+1), class: label.Benign, technique: "api"},
			reqSpec{method: "POST", target: "/api/items", body: fmt.Sprintf(`{"name":"Lampe %d","price":%d}`, i, 10+i), class: label.Benign, technique: "api"},
		)
	}
	return out
}

// Attacks: SQL injection variants with distinct parameter names (each gives
// its own request signature, so the client signals each of them), plus XSS
// and path traversal.
func attackSpecs(round int) []reqSpec {
	sqli := []string{
		"/api/items?id=" + url.QueryEscape("1' OR '1'='1"),
		"/api/items?q=" + url.QueryEscape("x' UNION SELECT username,password FROM users--"),
		"/api/items?sort=" + url.QueryEscape("name;DROP TABLE items--"),
		"/api/items?filter=" + url.QueryEscape("1 AND 1=1 UNION ALL SELECT NULL,NULL,version()--"),
		"/api/items?cat=" + url.QueryEscape("' OR 1=1 LIMIT 1 -- -"),
		"/api/items?ref=" + url.QueryEscape("1); SELECT pg_sleep(5)--"),
	}
	var out []reqSpec
	for i, t := range sqli {
		if round > 0 {
			t += fmt.Sprintf("&r=%d", round*100+i)
		}
		out = append(out, reqSpec{method: "GET", target: t, class: label.Malicious, technique: "sqli"})
	}
	out = append(out,
		reqSpec{method: "GET", target: "/api/items?q=" + url.QueryEscape("<script>alert(document.cookie)</script>"), class: label.Malicious, technique: "xss"},
		reqSpec{method: "GET", target: "/api/items?file=" + url.QueryEscape("../../../../etc/passwd"), class: label.Malicious, technique: "traversal"},
	)
	return out
}

type trafficGen struct {
	secret []byte
	hc     *http.Client
	seq    int
}

// send sends specs through a site's label stripper with a signed ground-truth
// label and X-Forwarded-For of a documentation address (the stripper and this
// generator are trusted proxies of the site's schild).
func (g *trafficGen) send(site, stripper string, specs []reqSpec, ip func(i int) string) ([]sent, error) {
	var out []sent
	for i, s := range specs {
		g.seq++
		l := label.Label{Class: s.class, Scenario: "SMOKE", Source: "smoke", Technique: s.technique, ExpectBlock: label.ExpectedOutcome(s.class), Seq: g.seq}
		hdr, err := label.Sign(g.secret, l)
		if err != nil {
			return out, err
		}
		var body io.Reader
		if s.body != "" {
			body = strings.NewReader(s.body)
		}
		req, err := http.NewRequest(s.method, strings.TrimRight(stripper, "/")+s.target, body)
		if err != nil {
			return out, err
		}
		if s.body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0 Safari/537.36")
		if s.class == label.Malicious {
			req.Header.Set("User-Agent", "python-requests/2.32.3")
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set(label.HeaderName, hdr)
		addr := ip(i)
		req.Header.Set("X-Forwarded-For", addr)
		resp, err := g.hc.Do(req)
		if err != nil {
			return out, fmt.Errorf("%s %s: %w", s.method, s.target, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		out = append(out, sent{Site: site, RequestID: resp.Header.Get(label.RequestIDHeader), Class: string(s.class), Technique: s.technique,
			IP: addr, Method: s.method, Path: strings.SplitN(s.target, "?", 2)[0], Status: resp.StatusCode})
		// Below the client's default rate for recording unremarkable requests
		// (20/s), so every legit request gets a local event to join.
		time.Sleep(70 * time.Millisecond)
	}
	return out, nil
}
