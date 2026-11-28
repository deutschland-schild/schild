package app

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/deutschland-schild/schild/contract/config"
)

func TestLoopback(t *testing.T) {
	Parallel(t)
	for addr, want := range map[string]bool{
		"127.0.0.1:8788": true, "127.5.0.1:8788": true, "[::1]:8788": true, "localhost:8788": true,
		"0.0.0.0:8788": false, ":8788": false, "[::]:8788": false, "192.0.2.1:8788": false, "dash.example:8788": false, "nonsense": false,
	} {
		if got := Loopback(addr); got != want {
			t.Errorf("%s: %v", addr, got)
		}
	}
}

func TestWarnDashboardExposed(t *testing.T) {
	Parallel(t)
	on, off := true, false
	for _, c := range []struct {
		listen  string
		enabled *bool
		warns   bool
	}{{"0.0.0.0:8788", &on, true}, {":8788", &on, true}, {"127.0.0.1:8788", &on, false}, {"0.0.0.0:8788", &off, false}} {
		var b bytes.Buffer
		cfg := &config.Site{}
		cfg.Listen.Dashboard = c.listen
		cfg.Dashboard.Enabled = c.enabled
		WarnDashboardExposed(slog.New(slog.NewTextHandler(&b, nil)), cfg)
		if strings.Contains(b.String(), "not on loopback") != c.warns {
			t.Errorf("%+v: %q", c, b.String())
		}
	}
}
