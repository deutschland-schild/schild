package app

import (
	"net/netip"

	"github.com/deutschland-schild/schild/contract/bodylimit"
	"github.com/deutschland-schild/schild/contract/config"
	"github.com/deutschland-schild/schild/gateway/internal/clientip"
	"github.com/deutschland-schild/schild/gateway/internal/connlimit"
)

// newConnLimiter builds the limit of open connections (D46). resolver decides who
// is a proxy, so a list that is too broad counts every peer as a client (G5).
func (a *App) newConnLimiter(cfg *config.Site, resolver *clientip.Resolver, requests bodylimit.RequestLimits) *connlimit.Limiter {
	lim := bodylimit.ConnLimits{MaxPerClient: cfg.WAF.Connections.MaxPerClient, MaxPerNetwork: cfg.WAF.Connections.MaxPerNetwork,
		Max: bodylimit.ConnLimit(cfg.WAF.Connections.MaxOpen, bodyMemory(a.mem))}
	a.log.Info("open connection limits", "per_client", lim.MaxPerClient, "per_network", lim.MaxPerNetwork, "gateway", lim.Max)
	// Over HTTP/1.1 a running request holds a connection, so this limit would
	// answer first, and with a closed connection instead of a page.
	if lim.MaxPerClient < requests.MaxPerClient || lim.MaxPerNetwork < requests.MaxPerNetwork || lim.Max < requests.Max {
		a.log.Warn("waf.connections is below waf.requests: clients on HTTP/1.1 meet the connection limit first and get a closed connection, not a page")
	}
	return connlimit.New(connlimit.Options{Limits: lim, Trusted: resolver.Trusted, Log: a.log,
		NetClass: func(ip netip.Addr) string {
			if a.Geo == nil {
				return ""
			}
			return a.Geo.Lookup(ip).NetClass
		},
		Open:    a.Metrics.ConnectionsOpen.Add,
		Refused: func(scope string) { a.Metrics.ConnsRefused.WithLabelValues(scope).Inc() },
		Evicted: func(scope string) { a.Metrics.ConnsEvicted.WithLabelValues(scope).Inc() }})
}
