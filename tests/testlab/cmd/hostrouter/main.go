// Command hostrouter is a TEST ONLY stand-in for kamal-proxy in the MVP-19
// measurement: it routes by Host to named "apps", answers with a small JSON
// body and counts every request it sees (GET /__count, /__reset), so a test
// can tell whether a request reached the backend. Optional slow paths
// (/__sleep?ms=) for load tests.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

func main() {
	addr := flag.String("listen", "127.0.0.1:18081", "listen address")
	logReq := flag.Bool("log", false, "log every request (method host uri)")
	flag.Parse()
	apps := map[string]string{}
	for _, kv := range strings.Split(os.Getenv("HOSTROUTER_APPS"), ",") {
		if h, a, ok := strings.Cut(kv, "="); ok {
			apps[strings.ToLower(h)] = a
		}
	}
	var mu sync.Mutex
	seen := map[string]int{}
	total := 0
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/__count":
			mu.Lock()
			defer mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{"total": total, "by_path": seen})
			return
		case "/__reset":
			mu.Lock()
			seen, total = map[string]int{}, 0
			mu.Unlock()
			return
		}
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		total++
		seen[r.Host+" "+r.URL.Path]++
		mu.Unlock()
		if *logReq {
			log.Printf("%s %s %s", r.Method, r.Host, r.URL.RequestURI())
		}
		if r.URL.Path == "/__sleep" {
			ms, _ := strconv.Atoi(r.URL.Query().Get("ms"))
			time.Sleep(time.Duration(ms) * time.Millisecond)
		}
		host, _, err := net.SplitHostPort(r.Host)
		if err != nil {
			host = r.Host
		}
		app := apps[strings.ToLower(host)]
		if app == "" {
			app = "default"
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-App", app)
		w.Header().Set("Cache-Control", "no-cache, private")
		w.Header().Set("Set-Cookie", "app_session=test; Path=/; HttpOnly; SameSite=Lax")
		if r.URL.Path == "/login" && r.Method == http.MethodPost && strings.Contains(string(body), "password=wrong") {
			// Failed login as Laravel answers it: back to the form.
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		if r.URL.Path == "/boom" {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"app": app, "host": r.Host, "method": r.Method, "uri": r.URL.RequestURI(), "body_bytes": len(body),
			"filler": strings.Repeat("lorem ipsum dolor sit amet ", 60)})
	})
	fmt.Println("hostrouter listening on", *addr)
	log.Fatal(http.ListenAndServe(*addr, nil))
}
