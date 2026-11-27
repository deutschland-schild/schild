package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	contractapi "github.com/deutschland-schild/schild/contract/agentapi"
	"github.com/deutschland-schild/schild/gateway/internal/dashboard"
	"github.com/deutschland-schild/schild/gateway/internal/store"
)

// agentAPIStoreKey holds the switch of the agent API set in the dashboard
// (D103). No row: schild.yaml decides.
const agentAPIStoreKey = "agent_api_v1"

// agentAPIOverlay is the stored switch.
type agentAPIOverlay struct {
	Enabled   bool      `json:"enabled"`
	UpdatedAt time.Time `json:"updated_at"`
	User      string    `json:"user,omitempty"`
}

// agentSwitch is the listener of the agent API and the switch that opens
// and closes it without a restart (D103).
type agentSwitch struct {
	mu      sync.Mutex
	overlay *agentAPIOverlay
	// serving: Run opened the listeners of this process. Before that, and
	// with NoListeners, the switch only stores its value.
	serving bool
	srv     *http.Server
	lastErr string
}

func (a *App) loadAgentSwitch(ctx context.Context) {
	raw, err := a.Store.Get(ctx, agentAPIStoreKey)
	if errors.Is(err, store.ErrNotFound) {
		return
	}
	var o agentAPIOverlay
	if err != nil || json.Unmarshal(raw, &o) != nil {
		a.log.Warn("agent API: the stored switch is not readable; schild.yaml decides", "err", err)
		return
	}
	a.agent.overlay = &o
}

// followAgentSwitch brings the switch into force after another node of a
// group changed it (D105: what is set in a dashboard holds on every node):
// the value is in the store already, the listener of this node follows. An
// empty value gives the switch back to schild.yaml. enabled false in this
// node's schild.yaml stays final, as for its own dashboard.
func (a *App) followAgentSwitch(_ context.Context, v []byte) {
	a.agent.mu.Lock()
	defer a.agent.mu.Unlock()
	before := a.agentAPIOnLocked()
	var overlay *agentAPIOverlay
	if len(v) > 0 {
		var o agentAPIOverlay
		if json.Unmarshal(v, &o) != nil {
			a.log.Warn("agent API: the switch another node set is not readable; this node keeps its own")
			return
		}
		overlay = &o
	}
	a.agent.overlay = overlay
	next := a.agentAPIOnLocked()
	if next == before {
		return
	}
	if !next {
		a.closeAgentAPILocked()
	} else if a.agent.serving {
		if err := a.openAgentAPILocked(); err != nil {
			a.log.Error("agent API listener not started after another node switched it on (request handling is not affected)", "addr", a.Config().AgentAPI.Listen, "err", err)
		}
	}
	a.log.Info("agent API switched by another node of the group", "enabled", next)
}

// agentAPIOnLocked: enabled false in schild.yaml is final, the dashboard
// cannot switch the agent API on against it. Otherwise the value of the
// dashboard holds.
func (a *App) agentAPIOnLocked() bool {
	if !a.Config().AgentAPI.On() {
		return false
	}
	return a.agent.overlay == nil || a.agent.overlay.Enabled
}

// anyInterfaceEnv lets the agent API listen on every interface where schild
// does not see that it runs in a container.
const anyInterfaceEnv = "SCHILD_AGENT_API_ANY_INTERFACE"

// errAnyInterface: 0.0.0.0 is for a container that publishes the port on the
// loopback of its host. On a host it would open the API to the network over
// plain HTTP, so the listener stays closed there.
var errAnyInterface = errors.New("agent_api.listen names every interface, which schild opens in a container only: use 127.0.0.1, or set " + anyInterfaceEnv + "=1 if the port is not reachable from outside")

func anyInterface(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsUnspecified()
}

// openAgentAPILocked opens the listener. The address is bound before it
// returns, so a port in use is an error here and not a line in the log.
func (a *App) openAgentAPILocked() error {
	if a.agent.srv != nil {
		return nil
	}
	addr := a.Config().AgentAPI.Listen
	if anyInterface(addr) && !inContainer() && os.Getenv(anyInterfaceEnv) != "1" {
		a.agent.lastErr = errAnyInterface.Error()
		return errAnyInterface
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		a.agent.lastErr = err.Error()
		return err
	}
	srv := &http.Server{Addr: addr, Handler: a.AgentAPI.Handler(addr), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 2 * time.Minute}
	a.agent.srv, a.agent.lastErr = srv, ""
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			a.log.Error("agent API listener stopped (request handling is not affected)", "addr", addr, "err", err)
		}
	}()
	a.log.Info("agent API listening (bearer tokens from `schild token add`)", "addr", addr, "openapi", "http://"+addr+"/agent/v0/openapi.json")
	return nil
}

// closeAgentAPILocked ends the listener and every call in flight; a long
// poll of `schild firewall run` would hold a graceful shutdown open.
func (a *App) closeAgentAPILocked() {
	if a.agent.srv == nil {
		return
	}
	_ = a.agent.srv.Close()
	a.agent.srv, a.agent.lastErr = nil, ""
	a.log.Info("agent API closed")
}

// inContainer: Docker, Podman or Kubernetes.
func inContainer() bool {
	for _, p := range []string{"/.dockerenv", "/run/.containerenv"} {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	return os.Getenv("KUBERNETES_SERVICE_HOST") != ""
}

// startAgentAPI starts the call log writer and, with the switch on, the
// listener. A port in use is logged and never stops the gateway.
func (a *App) startAgentAPI(ctx context.Context) {
	a.goLoop(ctx, "agent-api-log", a.AgentAPI.Run)
	a.agent.mu.Lock()
	defer a.agent.mu.Unlock()
	a.agent.serving = true
	if !a.agentAPIOnLocked() {
		a.log.Info("agent API off", "source", a.agentSourceLocked())
		return
	}
	if err := a.openAgentAPILocked(); err != nil {
		a.log.Error("agent API listener not started (request handling is not affected)", "addr", a.Config().AgentAPI.Listen, "err", err)
	}
}

func (a *App) stopAgentAPI() {
	a.agent.mu.Lock()
	defer a.agent.mu.Unlock()
	a.agent.serving = false
	a.closeAgentAPILocked()
}

func (a *App) agentSourceLocked() string {
	if a.agent.overlay != nil && a.Config().AgentAPI.On() {
		return "dashboard"
	}
	return "config"
}

// agentAPIState is getAgentAPI.
func (a *App) agentAPIState(ctx context.Context) dashboard.AgentAPIState {
	a.agent.mu.Lock()
	defer a.agent.mu.Unlock()
	return a.agentAPIStateLocked(ctx)
}

func (a *App) agentAPIStateLocked(ctx context.Context) dashboard.AgentAPIState {
	c := a.Config().AgentAPI
	st := dashboard.AgentAPIState{Enabled: a.agentAPIOnLocked(), ConfigEnabled: c.On(), StateSource: a.agentSourceLocked(),
		Listen: c.Listen, Listening: a.agent.srv != nil, Error: a.agent.lastErr}
	if o := a.agent.overlay; o != nil && c.On() {
		t := o.UpdatedAt.UTC().Format("2006-01-02T15:04:05Z")
		st.UpdatedAt = &t
		if o.User != "" {
			st.Actor = &o.User
		}
	}
	now := time.Now()
	toks, _ := a.Store.ListAgentTokens(ctx)
	for _, t := range toks {
		if !t.RevokedAt.IsZero() || !now.Before(t.Expires) {
			continue
		}
		st.ActiveTokens++
		if t.Scope == contractapi.ScopeFirewallSync {
			st.FirewallTokens++
		}
	}
	return st
}

// setAgentAPI is setAgentAPI: enabled switches, nil gives the switch back
// to schild.yaml. The listener follows before the answer returns. A listener
// that does not open leaves the switch as it was, and so does switching on
// against enabled false in schild.yaml.
func (a *App) setAgentAPI(ctx context.Context, enabled *bool, user string) (dashboard.AgentAPIState, error) {
	a.agent.mu.Lock()
	defer a.agent.mu.Unlock()
	before := a.agentAPIOnLocked()
	next := a.Config().AgentAPI.On()
	if enabled != nil && *enabled && !next {
		return a.agentAPIStateLocked(ctx), dashboard.ErrAgentAPIConfigOff
	}
	var overlay *agentAPIOverlay
	if enabled != nil {
		next = next && *enabled
		overlay = &agentAPIOverlay{Enabled: next, UpdatedAt: time.Now().UTC().Truncate(time.Second), User: user}
	}
	if next && a.agent.serving {
		if err := a.openAgentAPILocked(); err != nil {
			return a.agentAPIStateLocked(ctx), fmt.Errorf("%w: %s", dashboard.ErrAgentAPIListen, a.Config().AgentAPI.Listen)
		}
	}
	// What agent_api.set records: whether the API is on and who says so.
	source := "config"
	if overlay != nil {
		source = "dashboard"
	}
	entries := one("agent_api.set", "agent_api", "", map[string]any{"enabled": before, "source": a.agentSourceLocked()}, map[string]any{"enabled": next, "source": source})
	var err error
	if overlay == nil {
		err = a.writeAudited(ctx, entries, func(ctx context.Context) error { return a.Store.Delete(ctx, agentAPIStoreKey) })
	} else {
		var raw []byte
		if raw, err = json.Marshal(overlay); err == nil {
			err = a.putAudited(ctx, agentAPIStoreKey, raw, entries)
		}
	}
	if err != nil {
		// Not stored: the listener goes back to what holds.
		if next && !before {
			a.closeAgentAPILocked()
		}
		return dashboard.AgentAPIState{}, err
	}
	a.agent.overlay = overlay
	if !next {
		a.closeAgentAPILocked()
	}
	if next != before || enabled == nil {
		a.log.Info("agent API switched", "enabled", next, "source", a.agentSourceLocked(), "user", user)
	}
	return a.agentAPIStateLocked(ctx), nil
}
