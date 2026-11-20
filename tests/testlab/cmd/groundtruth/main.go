// Command groundtruth is a small read-only HTTP service over the ground-truth
// SQLite that the label stripper writes. The evaluator can read the file
// directly from a shared volume; this service exists so an operator can
// inspect ground truth live (GET /truth, GET /truth/<request_id>, GET /count)
// on the obs network, port 9201.
package main

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/deutschland-schild/schild/testlab/internal/groundtruth"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil)).With("component", "ground-truth")
	listen := envOr("GT_LISTEN", ":9201")
	dbPath := envOr("GT_DB", "/var/lib/testlab/ground-truth.sqlite")

	store, err := groundtruth.Open(dbPath)
	if err != nil {
		log.Error("open", "path", dbPath, "err", err)
		os.Exit(1)
	}
	defer store.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		if _, err := store.Count(); err != nil {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		w.Write([]byte("ok"))
	})
	mux.HandleFunc("/count", func(w http.ResponseWriter, _ *http.Request) {
		n, err := store.Count()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]int{"count": n})
	})
	mux.HandleFunc("/truth", func(w http.ResponseWriter, _ *http.Request) {
		all, err := store.All()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if all == nil {
			all = []groundtruth.Record{}
		}
		writeJSON(w, http.StatusOK, all)
	})
	mux.HandleFunc("/truth/", func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/truth/")
		rec, ok, err := store.Get(id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if !ok {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		writeJSON(w, http.StatusOK, rec)
	})

	srv := &http.Server{Addr: listen, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	log.Info("listening", "addr", listen, "db", dbPath)
	if err := srv.ListenAndServe(); err != nil {
		log.Error("serve", "err", err)
		os.Exit(1)
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func envOr(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}
