// Command label-stripper sits in front of a schild client in the test lab. It
// removes the secret ground-truth label header so the client never sees it,
// assigns a fresh random X-Request-Id, records request_id -> label in the
// ground-truth SQLite, and forwards the request upstream to schild.
//
// A request that arrives without a valid label is still forwarded (so the test
// keeps running) but is recorded as unlabelled, which the evaluator reports as
// a finding: a generator that forgot the label, or an injected header.
//
// Test-lab component only. It is never part of a shipping build.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/deutschland-schild/schild/testlab/internal/groundtruth"
	"github.com/deutschland-schild/schild/testlab/internal/label"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil)).With("component", "label-stripper")

	listen := env("STRIPPER_LISTEN", ":8080")
	upstream := env("STRIPPER_UPSTREAM", "http://schild:8080")
	dbPath := env("STRIPPER_GT_DB", "/var/lib/testlab/ground-truth.sqlite")
	secret := []byte(os.Getenv(label.EnvSecret))
	if len(secret) == 0 {
		log.Error("missing secret", "env", label.EnvSecret)
		os.Exit(2)
	}

	target, err := url.Parse(upstream)
	if err != nil {
		log.Error("bad upstream", "upstream", upstream, "err", err)
		os.Exit(2)
	}
	store, err := groundtruth.Open(dbPath)
	if err != nil {
		log.Error("open ground truth", "path", dbPath, "err", err)
		os.Exit(1)
	}
	defer store.Close()

	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		log.Warn("upstream error", "err", err)
		w.WriteHeader(http.StatusBadGateway)
	}
	// Own the X-Request-Id on the response exactly once: whatever the upstream
	// echoes, overwrite it with the id we assigned (carried on the proxied
	// request header), so the response never has a duplicate header.
	proxy.ModifyResponse = func(resp *http.Response) error {
		if id := resp.Request.Header.Get(label.RequestIDHeader); id != "" {
			resp.Header.Set(label.RequestIDHeader, id)
		}
		return nil
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		if _, err := store.Count(); err != nil {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		w.Write([]byte("ok"))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		reqID := newRequestID()
		rec := groundtruth.Record{
			RequestID: reqID, Host: r.Host, Method: r.Method,
			Path: r.URL.Path, SrcIP: clientIP(r), Labelled: false,
		}
		if hdr := r.Header.Get(label.HeaderName); hdr != "" {
			if l, err := label.Parse(secret, hdr); err == nil {
				rec = groundtruth.FromLabel(reqID, l, r.Host, r.Method, r.URL.Path, clientIP(r))
			} else {
				log.Warn("invalid label", "err", err, "request_id", reqID, "path", r.URL.Path)
			}
		}
		// Strip the label before it can reach the client, set the id.
		r.Header.Del(label.HeaderName)
		r.Header.Set(label.RequestIDHeader, reqID)
		if err := store.Put(rec); err != nil {
			log.Error("write ground truth", "err", err, "request_id", reqID)
		}
		// The response X-Request-Id is set by proxy.ModifyResponse so the
		// header appears exactly once (not duplicated with the upstream echo).
		proxy.ServeHTTP(w, r)
	})

	srv := &http.Server{Addr: listen, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		log.Info("listening", "addr", listen, "upstream", upstream, "db", dbPath)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("serve", "err", err)
			os.Exit(1)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
	log.Info("stopped")
}

func newRequestID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func env(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}
