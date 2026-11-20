package main

// Backend for the replay: reads the whole request body, answers with the
// status (X-Status), body size (X-Size) and delay (X-Delay-Ms) the client
// asked for and marks every answer with X-Backend: 1, so the client knows
// which answers came from the app.

import (
	"flag"
	"io"
	"net/http"
	"strconv"
	"time"
)

func cmdBackend(args []string) error {
	fs := flag.NewFlagSet("backend", flag.ExitOnError)
	listen := fs.String("listen", "127.0.0.1:18099", "")
	_ = fs.Parse(args)
	filler := make([]byte, 1<<20)
	for i := range filler {
		filler[i] = 'a' + byte(i%26)
	}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, _ := io.Copy(io.Discard, r.Body)
		status, _ := strconv.Atoi(r.Header.Get("X-Status"))
		if status == 0 {
			status = 200
		}
		size, _ := strconv.Atoi(r.Header.Get("X-Size"))
		if size < 0 || size > len(filler) {
			size = 0
		}
		if d, _ := strconv.Atoi(r.Header.Get("X-Delay-Ms")); d > 0 {
			time.Sleep(time.Duration(d) * time.Millisecond)
		}
		w.Header().Set("X-Backend", "1")
		w.Header().Set("X-Body-Read", strconv.FormatInt(n, 10))
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if status == 204 || status == 304 || r.Method == http.MethodHead {
			w.WriteHeader(status)
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(size))
		w.WriteHeader(status)
		_, _ = w.Write(filler[:size])
	})
	srv := &http.Server{Addr: *listen, Handler: h, ReadHeaderTimeout: 10 * time.Second}
	return srv.ListenAndServe()
}
