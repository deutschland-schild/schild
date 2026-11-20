package blockpage

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHTML(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Accept", "text/html,*/*")
	w := httptest.NewRecorder()
	Write(w, r, 403, "K7QM-4XWD", time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC))
	body := w.Body.String()
	if w.Code != 403 || !strings.Contains(body, "K7QM-4XWD") || !strings.Contains(body, "Vorfallnummer") || !strings.Contains(w.Header().Get("Content-Type"), "text/html") {
		t.Fatalf("%d %s", w.Code, body)
	}
	for _, bad := range []string{"geschützt", "sicher ", "anonym", "http://", "https://"} {
		if strings.Contains(body, bad) {
			t.Errorf("block page contains %q", bad)
		}
	}
}

func TestProblem(t *testing.T) {
	r := httptest.NewRequest("POST", "/api/x", nil)
	r.Header.Set("Accept", "application/json")
	w := httptest.NewRecorder()
	Write(w, r, 503, "AAAA-BBBB", time.Now())
	var p Problem
	if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil {
		t.Fatal(err)
	}
	if w.Code != 503 || p.Status != 503 || p.Incident != "AAAA-BBBB" || p.Code != KindTimeout || w.Header().Get("Content-Type") != "application/problem+json" || w.Header().Get("Retry-After") == "" {
		t.Fatalf("%+v %v", p, w.Header())
	}
}

// D37 amendment: the waiting page's problem variant has code and type
// waiting and the marker; the ordinary 503 problem keeps timeout and no
// marker.
func TestWaitingProblem(t *testing.T) {
	w := httptest.NewRecorder()
	WriteProblem(w, "AAAA-BBBB", 7, true)
	var p Problem
	if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil {
		t.Fatal(err)
	}
	if w.Code != 503 || p.Code != "waiting" || p.Type != "https://schild.invalid/problems/waiting" || p.RetryAfter != 7 ||
		p.Title != texts[KindTimeout].Title || w.Header().Get("Schild-Waiting") != "1" || w.Header().Get("Retry-After") != "7" {
		t.Fatalf("%+v %v", p, w.Header())
	}
	r := httptest.NewRequest("GET", "/api/x", nil)
	r.Header.Set("Accept", "application/json")
	w = httptest.NewRecorder()
	Write(w, r, 503, "AAAA-BBBB", time.Now())
	if w.Header().Get("Schild-Waiting") != "" {
		t.Fatal("an ordinary 503 carries the waiting marker")
	}
}

// MVP-17: a behaviour block names its end and keeps the incident number; a
// rate limit answers 429 without an incident.
func TestPausedAndRateLimited(t *testing.T) {
	now := time.Date(2026, 10, 28, 9, 0, 0, 0, time.UTC)
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Accept", "text/html")
	w := httptest.NewRecorder()
	WritePaused(w, r, "M4QX-7KRT", now.Add(15*time.Minute), now)
	body := w.Body.String()
	if w.Code != 403 || w.Header().Get("Retry-After") != "900" || !strings.Contains(body, "M4QX-7KRT") || !strings.Contains(body, "09:15 UTC") {
		t.Fatalf("paused: %d %v %s", w.Code, w.Header(), body)
	}
	w = httptest.NewRecorder()
	WriteRateLimited(w, r, 12, now)
	body = w.Body.String()
	if w.Code != 429 || w.Header().Get("Retry-After") != "12" || strings.Contains(body, "Vorfallnummer") || !strings.Contains(body, "12 Sekunden") {
		t.Fatalf("429: %d %v %s", w.Code, w.Header(), body)
	}
	for _, bad := range []string{"geschützt", "sicher ", "anonym"} {
		if strings.Contains(body, bad) {
			t.Errorf("page contains %q", bad)
		}
	}
	r.Header.Set("Accept", "application/json")
	w = httptest.NewRecorder()
	WriteRateLimited(w, r, 12, now)
	var p Problem
	if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil || p.Status != 429 || p.Code != KindRateLimited || p.RetryAfter != 12 || p.Incident != "" || p.Instance != "" {
		t.Fatalf("problem: %+v %v", p, err)
	}
}
