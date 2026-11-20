// Command schild-relay is the public SSE relay of Schild (MVP-04).
//
// Configuration by environment (contracts/conventions.md §5):
//
//	SCHILD_RELAY_ID          relay id (default: sanitised hostname)
//	SCHILD_RELAY_LISTEN      public listener (default :7480)
//	SCHILD_RELAY_METRICS     metrics listener (default :9103, empty disables)
//	SCHILD_RELAY_UPSTREAMS   comma-separated lab feed or relay base URLs
//	SCHILD_RELAY_BUFFER      events buffered per client (default 256)
//	SCHILD_RELAY_MAX_PER_IP  concurrent streams per source IP (default 32)
//	SCHILD_RELAY_MAX_CLIENTS concurrent streams in total (default 50000)
//	SCHILD_RELAY_TLS_CERT, SCHILD_RELAY_TLS_KEY  serve TLS when both are set
//	SCHILD_TEST_CA           PEM bundle trusted for upstream TLS (test lab only)
//	SCHILD_ALLOW_TEST_KEYS   "1" = test lab only: start despite the test lab CA (D24)
//	SCHILD_LOG_LEVEL, SCHILD_LOG_FORMAT
//
// Commands: (none) run, preflight (or -check: D24 check, print and exit),
// keygen -out-dir DIR -host NAME (TLS key and CSR), health, watch, version.
//
//go:debug multipathtcp=0
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/deutschland-schild/schild/contract/preflight"
	"github.com/deutschland-schild/schild/relay/internal/relay"
	"github.com/deutschland-schild/schild/relay/metrics"
	"github.com/deutschland-schild/schild/relay/upstream"
)

func main() {
	if len(os.Args) > 1 {
		var err error
		switch os.Args[1] {
		case "preflight", "-check", "--check":
			pf := preflight.Relay()
			pf.Print(os.Stdout)
			err = pf.Err()
		case "keygen":
			err = keygenCmd(os.Args[2:], os.Stdout)
		case "health":
			err = health()
		case "watch":
			err = watch(os.Args[2:])
		case "version":
			fmt.Println("schild-relay 0.1.0-alpha")
		default:
			err = fmt.Errorf("unknown command %q (preflight, keygen, health, watch, version; no command = run)", os.Args[1])
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "schild-relay:", err)
			os.Exit(1)
		}
		return
	}
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "schild-relay:", err)
		os.Exit(1)
	}
}

func env(k, def string) string {
	if v, ok := os.LookupEnv(k); ok {
		return v
	}
	return def
}

func envInt(k string, def int) (int, error) {
	v := os.Getenv(k)
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("%s: want a positive integer, got %q", k, v)
	}
	return n, nil
}

// health is the container health check: GET /healthz on the listener.
func health() error {
	addr := env("SCHILD_RELAY_LISTEN", ":7480")
	if strings.HasPrefix(addr, ":") || strings.HasPrefix(addr, "0.0.0.0:") {
		addr = "127.0.0.1:" + addr[strings.LastIndexByte(addr, ':')+1:]
	}
	scheme := "http"
	c := &http.Client{Timeout: 3 * time.Second}
	if os.Getenv("SCHILD_RELAY_TLS_CERT") != "" {
		scheme = "https"
		c.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} // own listener, liveness only
	}
	resp, err := c.Get(scheme + "://" + addr + "/healthz")
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("healthz: %d", resp.StatusCode)
	}
	return nil
}

// SanitizeID turns a hostname into a valid id ([a-z0-9][a-z0-9-]{0,62}).
func SanitizeID(s string) string {
	s = strings.ToLower(s)
	var b strings.Builder
	for _, c := range s {
		if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' {
			b.WriteRune(c)
		} else {
			b.WriteByte('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	if len(out) > 63 {
		out = out[:63]
	}
	if out == "" {
		out = "relay"
	}
	return out
}

func newLogger() *slog.Logger {
	var lvl slog.Level
	_ = lvl.UnmarshalText([]byte(env("SCHILD_LOG_LEVEL", "info")))
	opts := &slog.HandlerOptions{Level: lvl}
	var h slog.Handler = slog.NewJSONHandler(os.Stdout, opts)
	if env("SCHILD_LOG_FORMAT", "json") == "text" {
		h = slog.NewTextHandler(os.Stdout, opts)
	}
	return slog.New(h).With("component", "schild-relay")
}

func run() error {
	log := newLogger()
	if err := preflight.Relay().Enforce(log); err != nil {
		return err
	}
	host, _ := os.Hostname()
	id := SanitizeID(env("SCHILD_RELAY_ID", host))
	buffer, err := envInt("SCHILD_RELAY_BUFFER", 256)
	if err != nil {
		return err
	}
	perIP, err := envInt("SCHILD_RELAY_MAX_PER_IP", 32)
	if err != nil {
		return err
	}
	maxClients, err := envInt("SCHILD_RELAY_MAX_CLIENTS", 50000)
	if err != nil {
		return err
	}
	proxies, err := relay.ParseTrustedProxies(os.Getenv("SCHILD_RELAY_TRUSTED_PROXIES"))
	if err != nil {
		return err
	}
	var ups []string
	for _, u := range strings.Split(os.Getenv("SCHILD_RELAY_UPSTREAMS"), ",") {
		if u = strings.TrimSpace(u); u != "" {
			if !strings.HasPrefix(u, "https://") && !strings.HasPrefix(u, "http://") {
				return fmt.Errorf("SCHILD_RELAY_UPSTREAMS: %q is not an http(s) URL", u)
			}
			ups = append(ups, u)
		}
	}
	if len(ups) == 0 {
		log.Warn("no upstreams configured (SCHILD_RELAY_UPSTREAMS); the relay will serve nothing")
	}
	client, err := upstream.HTTPClient()
	if err != nil {
		return err
	}
	reg := metrics.NewRegistry()
	r := relay.New(relay.Config{
		ID: id, Upstreams: ups, Buffer: buffer, MaxPerIP: perIP, MaxClients: maxClients,
		TrustedProxies: proxies, ClientIPHeader: os.Getenv("SCHILD_RELAY_CLIENT_IP_HEADER"),
		Client: client, Log: log, Registry: reg,
	})

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	srv := &http.Server{
		Addr:              env("SCHILD_RELAY_LISTEN", ":7480"),
		Handler:           r.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	errc := make(chan error, 2)
	cert, key := os.Getenv("SCHILD_RELAY_TLS_CERT"), os.Getenv("SCHILD_RELAY_TLS_KEY")
	go func() {
		log.Info("relay listening", "addr", srv.Addr, "id", id, "epoch", r.Hub.Epoch(), "upstreams", ups, "tls", cert != "")
		var err error
		if cert != "" && key != "" {
			err = srv.ListenAndServeTLS(cert, key)
		} else {
			err = srv.ListenAndServe()
		}
		if !errors.Is(err, http.ErrServerClosed) {
			errc <- err
		}
	}()
	var msrv *http.Server
	if addr := env("SCHILD_RELAY_METRICS", ":9103"); addr != "" {
		mux := http.NewServeMux()
		mux.Handle("GET /metrics", reg.Handler())
		mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok\n")) })
		msrv = &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
		go func() {
			if err := msrv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
				errc <- err
			}
		}()
	}
	done := make(chan struct{})
	go func() { r.Run(ctx); close(done) }()
	select {
	case <-ctx.Done():
	case err := <-errc:
		stop()
		return err
	}
	log.Info("shutting down")
	sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	r.Hub.Close()
	_ = srv.Shutdown(sctx)
	if msrv != nil {
		_ = msrv.Shutdown(sctx)
	}
	<-done
	return nil
}
