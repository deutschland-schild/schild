package app

import (
	"log/slog"
	"net"
	"net/netip"

	"github.com/deutschland-schild/schild/contract/config"
)

// Loopback reports whether a listen address only serves this host. An empty
// host, a name other than localhost and an unreadable address do not count.
func Loopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.IsLoopback()
}

// DashboardExposedMsg says what a dashboard outside loopback means. Actions
// there ask for no further password (D40), so the session and the way to the
// port are all that stands in front of them.
const DashboardExposedMsg = "the dashboard is not on loopback: everybody who reaches this port can try to log in, and a logged-in session can use every action without a further password. Set listen.dashboard to 127.0.0.1 and reach it with ssh -L, or restrict the port to a VPN"

// WarnDashboardExposed warns at start when the dashboard listens beyond
// loopback. No contract forbids that (a VPN address is a fair choice), so the
// gateway starts and says so.
func WarnDashboardExposed(log *slog.Logger, cfg *config.Site) {
	if *cfg.Dashboard.Enabled && !Loopback(cfg.Listen.Dashboard) {
		log.Warn(DashboardExposedMsg, "listen", cfg.Listen.Dashboard)
	}
}

// DashboardURL is the address to open for a dashboard listen address as seen
// from the host itself: a wildcard or empty host becomes loopback.
func DashboardURL(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "http://" + addr
	}
	if ip, err := netip.ParseAddr(host); host == "" || (err == nil && ip.IsUnspecified()) {
		host = "127.0.0.1"
	}
	return "http://" + net.JoinHostPort(host, port)
}
