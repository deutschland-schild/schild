package app

import (
	"context"
	"errors"
	"net/http"
	"os"

	"github.com/deutschland-schild/schild/contract/config"
	"github.com/deutschland-schild/schild/contract/keys"
	"github.com/deutschland-schild/schild/gateway/internal/buildinfo"
	"github.com/deutschland-schild/schild/gateway/internal/hosts"
)

// HostAgentsEnv switches app servers with schild-agent back on (TEST ONLY:
// the test lab and tests). They are not part of the first gateway version
// (D60b). Release builds never honour it (D77), like the other test hooks.
const HostAgentsEnv = "SCHILD_HOST_AGENTS"

// CheckHostAgents refuses host_check.agents in the first gateway version
// (D60b): no agent listener, no enrolment, no agent keys. The server check of
// the gateway itself stays.
func CheckHostAgents(cfg *config.Site, getenv func(string) string) error {
	return checkHostAgents(cfg, getenv, keys.Release)
}

func checkHostAgents(cfg *config.Site, getenv func(string) string, release bool) error {
	hc := cfg.HostCheck
	hook := getenv(HostAgentsEnv) == "1"
	if hc == nil || (hook && !release) {
		return nil
	}
	if (hc.Agents.Enabled != nil && *hc.Agents.Enabled) || len(hc.Agents.Keys) > 0 {
		msg := "host_check.agents: app servers with schild-agent are not part of this version; remove host_check.agents from schild.yaml, the server check of this host keeps working"
		if hook {
			msg += " (" + HostAgentsEnv + " is a test lab switch and is ignored in release builds)"
		}
		return errors.New(msg)
	}
	return nil
}

// newHosts sets up the server check and agents (MVP-11) when host_check is
// configured. A failure here never stops schild: request handling and the
// baseline protection do not depend on it, the Server section just stays empty.
func (a *App) newHosts(ctx context.Context, cfg *config.Site) *hosts.Gateway {
	if cfg.HostCheck == nil {
		return nil
	}
	g, err := hosts.New(ctx, hosts.Options{DB: a.Store.DB(), Config: a.Config, DataDir: a.dataDir, Log: a.log})
	if err != nil {
		a.log.Error("server check not available (request handling is not affected)", "err", err)
		return nil
	}
	g.InProcess = os.Getenv("SCHILD_HOST_CHECK_INPROCESS") == "1"
	g.TriggerFile = os.Getenv("SCHILD_HOST_CHECK_TRIGGER")
	g.CheckVersion = buildinfo.Version
	if err := g.ScanLocal(ctx); err != nil {
		a.log.Warn("local host reports not read", "dir", cfg.HostCheck.ReportDir, "err", err)
	}
	return g
}

// startAgentListener starts the agent TLS listener (host_check.agents). Its
// errors are logged, never fatal: agents must not affect request handling.
func (a *App) startAgentListener(servers *[]*http.Server) {
	if a.Hosts == nil || !a.Hosts.AgentsEnabled() {
		return
	}
	srv, err := a.Hosts.Server()
	if err != nil {
		a.log.Error("agent listener not started (request handling is not affected)", "err", err)
		return
	}
	*servers = append(*servers, srv)
	go func() {
		defer func() {
			// Nothing in the agent listener may take the site down.
			if p := recover(); p != nil {
				a.log.Error("agent listener crashed (request handling is not affected)", "panic", p)
			}
		}()
		a.log.Info("agent listener running", "listen", srv.Addr, "pin", a.Hosts.Pin())
		if err := a.Hosts.ListenAndServeTLS(srv); err != nil && err != http.ErrServerClosed {
			a.log.Error("agent listener stopped (request handling is not affected)", "listen", srv.Addr, "err", err)
		}
	}()
}
