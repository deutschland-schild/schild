package webui

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestServes(t *testing.T) {
	h := Handler()
	for _, p := range []string{"/", "/#/overview", "/some/spa/route"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", p, nil))
		if w.Code != 200 || !strings.Contains(w.Header().Get("Content-Type"), "text/html") {
			t.Fatalf("%s: %d", p, w.Code)
		}
		if !Built() && !strings.Contains(w.Body.String(), "make ui") {
			t.Fatal("placeholder without hint")
		}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("POST", "/", nil))
	if w.Code != 405 {
		t.Fatal(w.Code)
	}
}
