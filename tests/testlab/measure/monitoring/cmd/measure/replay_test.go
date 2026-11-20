package main

import (
	"net/http"
	"testing"
)

// TestWaitingPageClass (evening measurement 2026-10-29 D): a 503 without
// incident number that carries the waiting page's headers (D37) is
// fail_closed with waiting_page_shown, not "unknown"; other 503 answers
// are not taken for it.
func TestWaitingPageClass(t *testing.T) {
	wp := func(mod func(h http.Header)) *http.Response {
		h := http.Header{}
		h.Set("Content-Type", "text/html; charset=utf-8")
		h.Set("Cache-Control", "no-store")
		h.Set("Retry-After", "7")
		h.Set("Vary", "Accept, Accept-Language, Sec-Fetch-Dest, Sec-Fetch-Mode, X-Requested-With")
		if mod != nil {
			mod(h)
		}
		return &http.Response{StatusCode: 503, Header: h}
	}
	if !isWaitingPage(wp(nil)) {
		t.Fatal("waiting page not recognised")
	}
	for name, r := range map[string]*http.Response{
		"backend 503":     wp(func(h http.Header) { h.Set("X-Backend", "1") }),
		"retry after 30":  wp(func(h http.Header) { h.Set("Retry-After", "30") }),
		"problem json":    wp(func(h http.Header) { h.Set("Content-Type", "application/problem+json") }),
		"cacheable":       wp(func(h http.Header) { h.Del("Cache-Control") }),
		"no waiting vary": wp(func(h http.Header) { h.Set("Vary", "Accept") }),
		"plain 503":       {StatusCode: 503, Header: http.Header{}},
	} {
		if isWaitingPage(r) {
			t.Errorf("%s taken for the waiting page", name)
		}
	}
	r := wp(nil)
	r.StatusCode = 200
	if isWaitingPage(r) {
		t.Error("200 taken for the waiting page")
	}

	// D37 amendment: the marker is the primary signal; a marked page is
	// recognised even when the heuristic headers differ, the marked problem
	// variant is no page, and a backend answer never counts.
	marked := func(mod func(h http.Header)) *http.Response {
		h := http.Header{}
		h.Set("Schild-Waiting", "1")
		if mod != nil {
			mod(h)
		}
		return &http.Response{StatusCode: 503, Header: h}
	}
	if !isWaitingPage(marked(nil)) || !isWaitingPage(marked(func(h http.Header) { h.Set("Retry-After", "30") })) {
		t.Error("marked waiting page not recognised")
	}
	for name, r := range map[string]*http.Response{
		"marked problem":    marked(func(h http.Header) { h.Set("Content-Type", "application/problem+json") }),
		"marked backend":    marked(func(h http.Header) { h.Set("X-Backend", "1") }),
		"marker value 0":    marked(func(h http.Header) { h.Set("Schild-Waiting", "0") }),
		"marked page + 200": {StatusCode: 200, Header: http.Header{"Schild-Waiting": {"1"}}},
	} {
		if isWaitingPage(r) {
			t.Errorf("%s taken for the waiting page", name)
		}
	}

	tr := newTruth(0)
	seen := map[string]bool{}
	tr.add(result{class: "fail_closed", waitingPage: true, status: 503, client: "a", dims: map[string]string{}}, seen)
	tr.add(result{class: "fail_closed", status: 503, client: "b", dims: map[string]string{}}, seen)
	if tr.Counters["fail_closed"] != 2 || tr.Counters["waiting_page_shown"] != 1 || len(tr.Unknown) != 0 {
		t.Fatalf("counters %v unknown %v", tr.Counters, tr.Unknown)
	}
}
