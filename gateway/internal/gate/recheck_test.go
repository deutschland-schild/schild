package gate

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/gateway/internal/decide"
	"github.com/deutschland-schild/schild/gateway/internal/monitoring"
	"github.com/deutschland-schild/schild/gateway/internal/stats"
	"github.com/deutschland-schild/schild/gateway/internal/store"
)

// recheckEnv serves requests through two schild evaluations sharing one
// Recheck, as the Caddy adapter does: nested (rewrite between two schild
// handlers) or sequential (an error goes back to Caddy, handle_errors
// evaluates again).
func recheckEnv(t *testing.T, mode string) (*tenv, *monitoring.Monitor) {
	e := newEnv(t, mode)
	m, err := monitoring.New(monitoring.Config{StoragePath: t.TempDir(), Log: quiet}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Close() })
	e.g.Monitor = m
	return e, m
}

type recheckPath struct{ path, query string }

type checkedEvent struct {
	Data struct {
		Path         string   `json:"path"`
		Outcome      string   `json:"outcome"`
		CheckedPaths []string `json:"checked_paths"`
	} `json:"data"`
}

func TestRecheckNestedCountsOnce(t *testing.T) {
	for _, tc := range []struct {
		name            string
		second          recheckPath // what the second evaluation inspects
		status          int
		outcome         string
		blocked, detect int64
	}{
		{"clean twice", recheckPath{"/inner/blog", "q=hello"}, 200, decide.Logged, 0, 0}, // a rule below the threshold matches the bare test client,
		{"second blocks", recheckPath{"/inner/blog", "id=1%27%20OR%20%271%27%3D%271%27--"}, 403, decide.Blocked, 1, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, m := recheckEnv(t, decide.ModeAutoblock)
			backend := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				st := NewRecheck()
				e.g.ServeChecked(w, r, http.HandlerFunc(func(w2 http.ResponseWriter, r2 *http.Request) {
					// A rewrite after the first schild, then schild again.
					r2.URL.Path, r2.URL.RawQuery = tc.second.path, tc.second.query
					r2.RequestURI = r2.URL.RequestURI()
					e.g.ServeChecked(w2, r2, http.HandlerFunc(func(w3 http.ResponseWriter, r3 *http.Request) {
						// A later rewrite never shows in the event.
						r3.URL.Path = "/after-schild"
						backend.ServeHTTP(w3, r3)
					}), st)
				}), st)
			}))
			defer srv.Close()
			req, _ := http.NewRequest("GET", srv.URL+"/blog?q=hello", nil)
			req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0")
			req.Header.Set("Accept", "text/html")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != tc.status {
				t.Fatalf("status %d, want %d", resp.StatusCode, tc.status)
			}
			c := liveCounters(t, m)
			if c.Requests != 1 || c.Rechecked != 1 || c.BlockedWAF != tc.blocked || c.Detections != tc.detect {
				t.Fatalf("counters: %+v", c)
			}
			if n := e.g.Counters.Rolling.Sum(stats.Requests, time.Hour, time.Now()); n != 1 {
				t.Fatalf("rolling requests %d", n)
			}
			rows := e.events(t, store.EventFilter{})
			if len(rows) != 1 {
				t.Fatalf("%d events, want 1", len(rows))
			}
			var ev checkedEvent
			if err := json.Unmarshal(rows[0].Body, &ev); err != nil {
				t.Fatal(err)
			}
			if ev.Data.Path != tc.second.path || ev.Data.Outcome != tc.outcome || strings.Join(ev.Data.CheckedPaths, " ") != "/blog "+tc.second.path {
				t.Fatalf("event: %+v", ev.Data)
			}
		})
	}
}

// The site's schild passes, the route's error goes back to Caddy and
// handle_errors' schild checks the stripped path: one request, one event;
// without a second schild the first evaluation is recorded when the
// request is done.
func TestRecheckSequentialCountsOnce(t *testing.T) {
	for _, second := range []bool{true, false} {
		e, m := recheckEnv(t, decide.ModeAutoblock)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			st := NewRecheck()
			e.g.ServeChecked(w, r, http.HandlerFunc(func(w2 http.ResponseWriter, r2 *http.Request) {
				r2.URL.Path = strings.TrimPrefix(r2.URL.Path, "/app") // handle_path strip
				NoteStatus(w2, 404)
				st.MayFollow() // the error goes back to Caddy
			}), st)
			if second {
				e.g.ServeChecked(w, r, http.HandlerFunc(func(w2 http.ResponseWriter, _ *http.Request) {
					w2.WriteHeader(404)
				}), st)
			} else {
				w.WriteHeader(404)
			}
		}))
		req, _ := http.NewRequest("GET", srv.URL+"/app/missing", nil)
		req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0")
		req.Header.Set("Accept", "text/html")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		srv.Close() // waits for the handler, so the end-of-request flush ran
		deadline := time.Now().Add(2 * time.Second)
		var c = liveCounters(t, m)
		total := c.Requests
		for total == 0 && time.Now().Before(deadline) {
			time.Sleep(20 * time.Millisecond)
			total += liveCounters(t, m).Requests
		}
		if total != 1 || second && c.Rechecked != 1 || !second && c.Rechecked != 0 {
			t.Fatalf("second %v: requests %d, counters %+v", second, total, c)
		}
		e.ev.Flush(context.Background())
		rows := e.events(t, store.EventFilter{})
		if !second {
			continue // a clean request without a second check is sampled like any other
		}
		if len(rows) != 1 {
			t.Fatalf("%d events, want 1", len(rows))
		}
		var ev checkedEvent
		_ = json.Unmarshal(rows[0].Body, &ev)
		if ev.Data.Path != "/missing" || strings.Join(ev.Data.CheckedPaths, " ") != "/app/missing /missing" {
			t.Fatalf("event: %+v", ev.Data)
		}
	}
}
