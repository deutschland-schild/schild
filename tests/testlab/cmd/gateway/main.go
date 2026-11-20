// Command gateway is the single test-lab container on the non-internal mgmt
// network (conventions §6): it publishes the dashboards of the internal
// stack on 127.0.0.1 of the host and nothing else. Each route is one
// listener forwarding to one internal service; the incoming Host header is
// kept (the dashboards check Origin against it), X-Forwarded-For is set, so
// the dashboards treat every request as remote (login required).
//
//	GATEWAY_ROUTES=":18788=http://schild-api:8788,:18789=http://lab-a:8789"
//
// Test-lab component only. It never forwards to the sites or the federation
// ports, only to dashboard listeners.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil)).With("component", "gateway")
	routes := strings.Split(os.Getenv("GATEWAY_ROUTES"), ",")
	var servers []*http.Server
	for _, r := range routes {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}
		listen, target, ok := strings.Cut(r, "=")
		u, err := url.Parse(target)
		if !ok || err != nil || u.Scheme != "http" || u.Host == "" {
			log.Error("bad route (want :PORT=http://service:port)", "route", r)
			os.Exit(2)
		}
		proxy := httputil.NewSingleHostReverseProxy(u)
		proxy.FlushInterval = -1 // stream SSE at once
		proxy.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, err error) {
			log.Warn("upstream error", "target", u.Host, "err", err)
			http.Error(w, "dashboard not reachable", http.StatusBadGateway)
		}
		srv := &http.Server{Addr: listen, Handler: proxy, ReadHeaderTimeout: 10 * time.Second}
		servers = append(servers, srv)
		go func() {
			log.Info("route", "listen", listen, "target", u.String())
			if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Error("serve", "listen", listen, "err", err)
				os.Exit(1)
			}
		}()
	}
	if len(servers) == 0 {
		log.Error("no routes: set GATEWAY_ROUTES")
		os.Exit(2)
	}
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, s := range servers {
		_ = s.Shutdown(ctx)
	}
}
