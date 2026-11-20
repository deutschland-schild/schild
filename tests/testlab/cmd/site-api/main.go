// Command site-api is a tiny REST API used as one of the test-lab target
// sites behind a schild client. It is intentionally ordinary: it is not a
// deliberately vulnerable app (DVWA/Juice Shop fill that role), but a plausible
// JSON API with a few endpoints so legitimate API-client traffic and attack
// traffic both have something realistic to hit.
package main

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type item struct {
	ID    int    `json:"id"`
	Name  string `json:"name"`
	Owner string `json:"owner"`
}

type store struct {
	mu    sync.Mutex
	items []item
	next  int
}

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil)).With("component", "site-api")
	listen := os.Getenv("SITE_API_LISTEN")
	if listen == "" {
		listen = ":8080"
	}
	s := &store{next: 1}
	s.seed()

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })

	mux.HandleFunc("/api/items", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			q := r.URL.Query().Get("q")
			writeJSON(w, http.StatusOK, s.search(q))
		case http.MethodPost:
			var in item
			if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad json"})
				return
			}
			writeJSON(w, http.StatusCreated, s.add(in.Name, in.Owner))
		default:
			w.Header().Set("Allow", "GET, POST")
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		}
	})

	mux.HandleFunc("/api/items/", func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/api/items/"))
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad id"})
			return
		}
		if it, ok := s.get(id); ok {
			writeJSON(w, http.StatusOK, it)
			return
		}
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			writeJSON(w, http.StatusOK, map[string]string{"service": "site-api", "version": "0.1.0"})
			return
		}
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
	})

	srv := &http.Server{Addr: listen, Handler: echoID(mux), ReadHeaderTimeout: 10 * time.Second}
	log.Info("listening", "addr", listen)
	if err := srv.ListenAndServe(); err != nil {
		log.Error("serve", "err", err)
		os.Exit(1)
	}
}

// echoID copies the X-Request-Id the stripper set into the response, so the
// whole chain shares one id.
func echoID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if id := r.Header.Get("X-Request-Id"); id != "" {
			w.Header().Set("X-Request-Id", id)
		}
		next.ServeHTTP(w, r)
	})
}

func (s *store) seed() {
	for _, n := range []string{"alpha", "bravo", "charlie"} {
		s.add(n, "system")
	}
}

func (s *store) add(name, owner string) item {
	s.mu.Lock()
	defer s.mu.Unlock()
	it := item{ID: s.next, Name: name, Owner: owner}
	s.next++
	s.items = append(s.items, it)
	return it
}

func (s *store) get(id int) (item, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, it := range s.items {
		if it.ID == id {
			return it, true
		}
	}
	return item{}, false
}

// search is a plain substring match over names. It uses no SQL and no string
// concatenation into a query, so an injection payload simply returns no match.
func (s *store) search(q string) []item {
	s.mu.Lock()
	defer s.mu.Unlock()
	if q == "" {
		return append([]item(nil), s.items...)
	}
	var out []item
	for _, it := range s.items {
		if strings.Contains(strings.ToLower(it.Name), strings.ToLower(q)) {
			out = append(out, it)
		}
	}
	if out == nil {
		out = []item{}
	}
	return out
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
