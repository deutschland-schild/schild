// Command sitepages writes the pages schild answers visitors with as HTML
// files: the block page, the login page of the access lock and the
// maintenance page. site/scripts/shots.mjs takes its screenshots of them, so
// the website and the docs show the pages as the gateway serves them.
//
//	go run ./internal/tools/sitepages -out DIR [-incident XXXX-XXXX] [-time RFC3339]
package main

import (
	"flag"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"time"

	"github.com/deutschland-schild/schild/contract/access"
	"github.com/deutschland-schild/schild/gateway/internal/accesslock"
	"github.com/deutschland-schild/schild/gateway/internal/blockpage"
)

func main() {
	out := flag.String("out", ".", "directory for block.html, login.html and maintenance.html")
	incident := flag.String("incident", "RN9T-F36Q", "incident number on the block page")
	at := flag.String("time", "", "time on the block page, RFC 3339 (default: now)")
	flag.Parse()

	now := time.Now().UTC()
	if *at != "" {
		t, err := time.Parse(time.RFC3339, *at)
		if err != nil {
			log.Fatalf("sitepages: -time: %v", err)
		}
		now = t.UTC()
	}
	pages := map[string]func(http.ResponseWriter, *http.Request){
		"block.html": func(w http.ResponseWriter, r *http.Request) {
			blockpage.Write(w, r, http.StatusForbidden, *incident, now)
		},
		"login.html": func(w http.ResponseWriter, r *http.Request) {
			v := accesslock.Verdict{Result: access.Result{Answer: access.AnswerLogin, Status: http.StatusUnauthorized, LoginForm: true}}
			accesslock.Write(w, r, v, "", now)
		},
		"maintenance.html": func(w http.ResponseWriter, r *http.Request) {
			v := accesslock.Verdict{Result: access.Result{Answer: access.AnswerMaintenance, Status: http.StatusServiceUnavailable}, Entry: &accesslock.Entry{}}
			accesslock.Write(w, r, v, "", now)
		},
	}
	for name, write := range pages {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("Accept", "text/html")
		w := httptest.NewRecorder()
		write(w, r)
		if err := os.WriteFile(filepath.Join(*out, name), w.Body.Bytes(), 0o644); err != nil {
			log.Fatalf("sitepages: %v", err)
		}
	}
}
