//go:build !release

package app_test

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/contract/monitoring"
	"github.com/deutschland-schild/schild/contract/waitingpage"
	"github.com/deutschland-schild/schild/gateway/internal/apptest"
	"github.com/deutschland-schild/schild/gateway/internal/blockpage"
	"github.com/deutschland-schild/schild/gateway/internal/gate"
)

// overload holds the only evaluation slot of the running gateway, so every
// further request is answered waf_busy after a 1 ms queue wait. It returns
// the release function.
func overload(t *testing.T, h *apptest.Harness, host string) func() {
	t.Helper()
	g := h.App.Gate
	g.SetEvalLimits(gate.EvalLimits{MaxConcurrent: 1, QueueWait: time.Millisecond})
	entered, release := make(chan struct{}), make(chan struct{})
	var held atomic.Bool
	g.TestHook = func(p string) {
		if p == "headers" && held.CompareAndSwap(false, true) {
			close(entered)
			<-release
		}
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		req, _ := http.NewRequest("GET", "http://"+h.IngressAddr+"/held", nil)
		req.Host = host
		if resp, err := http.DefaultClient.Do(req); err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
	}()
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("the held request never reached the WAF")
	}
	var once sync.Once
	return func() { once.Do(func() { close(release); <-done }) }
}

type answer struct {
	code   int
	header http.Header
	body   string
}

func send(t *testing.T, h *apptest.Harness, method, host string, hdr map[string]string, body string) answer {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, _ := http.NewRequest(method, "http://"+h.IngressAddr+"/kontakt", rd)
	req.Host = host
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return answer{resp.StatusCode, resp.Header, string(b)}
}

var (
	browser = map[string]string{
		"User-Agent":      "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0",
		"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		"Accept-Language": "de-DE,de;q=0.9,en;q=0.5",
		"Sec-Fetch-Dest":  "document", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Site": "none",
	}
	fetchAPI = map[string]string{"User-Agent": browser["User-Agent"], "Accept": "*/*", "Sec-Fetch-Dest": "empty", "Sec-Fetch-Mode": "cors"}
	curl     = map[string]string{"User-Agent": "curl/8.7.1", "Accept": "*/*"}
)

func retryOK(t *testing.T, a answer) int {
	t.Helper()
	n, err := strconv.Atoi(a.header.Get("Retry-After"))
	if err != nil || n < waitingpage.RetryMinS || n > waitingpage.RetryMaxS {
		t.Fatalf("Retry-After %q outside [%d, %d]", a.header.Get("Retry-After"), waitingpage.RetryMinS, waitingpage.RetryMaxS)
	}
	return n
}

// TestWaitingPageEndToEnd runs `schild run` as the ingress (embedded Caddy),
// overloads the WAF and checks what each client sees: a browser navigation
// the waiting page with the website name and a refresh equal to
// Retry-After, a form submit the form variant without refresh, fetch() and
// curl problem details. Nothing reaches the app; the overlay counter
// reaches Prometheus.
func TestWaitingPageEndToEnd(t *testing.T) {
	h := apptest.New(t, apptest.Options{Listeners: true, Caddyfile: ingressCaddyfile})
	_, port, _ := strings.Cut(h.IngressAddr, ":")
	host := "shop.example:" + port
	if code, _ := getHost(t, "http://"+h.IngressAddr+"/hello", host); code != 200 {
		t.Fatalf("before: %d", code)
	}
	release := overload(t, h, host)
	defer release()

	page := send(t, h, "GET", host, browser, "")
	n := retryOK(t, page)
	if page.code != 503 || page.header.Get("Content-Type") != "text/html; charset=utf-8" || page.header.Get("Content-Language") != "de" ||
		page.header.Get("Cache-Control") != "no-store" || page.header.Get("Content-Security-Policy") != waitingpage.CSP ||
		page.header.Get("X-Schild-Incident") != "" || page.header.Get(waitingpage.MarkerHeader) != waitingpage.MarkerValue {
		t.Fatalf("browser: %d %v", page.code, page.header)
	}
	for _, want := range []string{`<meta http-equiv="refresh" content="` + strconv.Itoa(n) + `">`, waitingpage.Texts["de"].Headline,
		"<strong>shop.example</strong>", "<svg", "<b>" + strconv.Itoa(n) + "</b>"} {
		if !strings.Contains(page.body, want) {
			t.Errorf("browser page lacks %q", want)
		}
	}
	if strings.Contains(page.body, "<script") || len(page.body) > waitingpage.MaxPageBytes {
		t.Error("script on the page or page too large")
	}

	form := map[string]string{"Content-Type": "application/x-www-form-urlencoded", "Origin": "http://" + host}
	for k, v := range browser {
		form[k] = v
	}
	post := send(t, h, "POST", host, form, "name=Kim&message=Hallo")
	retryOK(t, post)
	if post.code != 503 || post.header.Get("Content-Type") != "text/html; charset=utf-8" || strings.Contains(post.body, "http-equiv") ||
		!strings.Contains(post.body, waitingpage.Texts["de"].NextForm) {
		t.Fatalf("form submit: %d %v", post.code, post.header)
	}

	for name, hdr := range map[string]map[string]string{"fetch": fetchAPI, "curl": curl} {
		a := send(t, h, "GET", host, hdr, "")
		n := retryOK(t, a)
		var p blockpage.Problem
		if a.code != 503 || a.header.Get("Content-Type") != "application/problem+json" || json.Unmarshal([]byte(a.body), &p) != nil ||
			p.Code != waitingpage.ProblemCode || p.RetryAfter != n || a.header.Get(waitingpage.MarkerHeader) != waitingpage.MarkerValue {
			t.Fatalf("%s: %d %v %s", name, a.code, a.header, a.body)
		}
	}
	if h.Hits.Load() != 1 {
		t.Fatalf("backend hits %d: an overloaded request reached the app", h.Hits.Load())
	}
	// Prometheus on the metrics port (1 Hz aggregation): the overlay counts
	// the two waiting pages, the busy class all four answers.
	deadline := time.Now().Add(10 * time.Second)
	for {
		_, m := get(t, "http://"+h.MetricsAddr+"/metrics", nil)
		if strings.Contains(m, monitoring.PromWaitingPageShown+" 2") && strings.Contains(m, `schild_http_requests_total{class="fail_closed_waf_busy"} 4`) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("metrics lack the waiting page counter:\n%s", grepLines(m, "schild_http_"))
		}
		time.Sleep(100 * time.Millisecond)
	}
	release()
}

// TestWaitingPageDisabled: waiting_page.enabled false keeps the answer from
// before D37 (the block page with an incident number, Retry-After 5).
func TestWaitingPageDisabled(t *testing.T) {
	h := apptest.New(t, apptest.Options{Listeners: true, Caddyfile: ingressCaddyfile, Extra: "waiting_page:\n  enabled: false\n"})
	if h.App.Gate.WaitingPage() {
		t.Fatal("waiting_page.enabled false not applied")
	}
	_, port, _ := strings.Cut(h.IngressAddr, ":")
	host := "shop.example:" + port
	if code, _ := getHost(t, "http://"+h.IngressAddr+"/hello", host); code != 200 {
		t.Fatalf("before: %d", code)
	}
	release := overload(t, h, host)
	defer release()
	a := send(t, h, "GET", host, browser, "")
	if a.code != 503 || a.header.Get("Retry-After") != "5" || a.header.Get("X-Schild-Incident") == "" || !strings.Contains(a.body, "Vorfallnummer") ||
		a.header.Get(waitingpage.MarkerHeader) != "" {
		t.Fatalf("disabled: %d %v", a.code, a.header)
	}
}

func grepLines(s, sub string) string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if strings.Contains(l, sub) {
			out = append(out, l)
		}
	}
	return strings.Join(out, "\n")
}
