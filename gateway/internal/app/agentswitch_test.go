//go:build !release

package app_test

import (
	"encoding/json"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/deutschland-schild/schild/gateway/internal/app"
	"github.com/deutschland-schild/schild/gateway/internal/apptest"
	"github.com/deutschland-schild/schild/gateway/internal/dashboard"
)

// agentStatus calls the agent API without a token: 401 while it listens,
// 0 when nothing listens.
func agentStatus(addr string) int {
	resp, err := http.Get("http://" + addr + "/agent/v0/status")
	if err != nil {
		return 0
	}
	resp.Body.Close()
	return resp.StatusCode
}

func agentState(t *testing.T, h *apptest.Harness, method string, body any, want int) dashboard.AgentAPIState {
	t.Helper()
	code, b := h.API(method, "/agent-api", body)
	if code != want {
		t.Fatalf("%s /agent-api %v: %d %s", method, body, code, b)
	}
	var st dashboard.AgentAPIState
	_ = json.Unmarshal(b, &st)
	return st
}

// TestAgentAPISwitch: the agent API is on by default and answers 401 without
// a token; the dashboard closes and opens its listener without a restart, the
// value survives a restart, and a reset gives the switch back to schild.yaml
// (D103).
func TestAgentAPISwitch(t *testing.T) {
	h := apptest.New(t, apptest.Options{Listeners: true})
	h.Login()
	if code := agentStatus(h.AgentAddr); code != 401 {
		t.Fatalf("default: agent API without a token answers %d, want 401", code)
	}
	st := agentState(t, h, "GET", nil, 200)
	if !st.Enabled || !st.ConfigEnabled || st.StateSource != "config" || !st.Listening || st.Listen != h.AgentAddr || st.UpdatedAt != nil {
		t.Fatalf("default state: %+v", st)
	}
	for _, bad := range []any{map[string]any{}, map[string]any{"enabled": true, "reset": true}, map[string]any{"reset": false}} {
		agentState(t, h, "PUT", bad, 400)
	}

	st = agentState(t, h, "PUT", map[string]any{"enabled": false}, 200)
	if st.Enabled || !st.ConfigEnabled || st.StateSource != "dashboard" || st.Listening || st.UpdatedAt == nil {
		t.Fatalf("off: %+v", st)
	}
	if code := agentStatus(h.AgentAddr); code != 0 {
		t.Fatalf("off: the listener still answers %d", code)
	}

	// Switching on while another process holds the port: 409, still off.
	ln, err := net.Listen("tcp", h.AgentAddr)
	if err != nil {
		t.Fatal(err)
	}
	agentState(t, h, "PUT", map[string]any{"enabled": true}, 409)
	if st = agentState(t, h, "GET", nil, 200); st.Enabled || st.Listening || st.Error == "" {
		t.Fatalf("after a refused switch: %+v", st)
	}
	ln.Close()

	st = agentState(t, h, "PUT", map[string]any{"enabled": true}, 200)
	if !st.Enabled || st.StateSource != "dashboard" || !st.Listening || st.Error != "" {
		t.Fatalf("on: %+v", st)
	}
	if code := agentStatus(h.AgentAddr); code != 401 {
		t.Fatalf("on again: %d", code)
	}

	st = agentState(t, h, "PUT", map[string]any{"reset": true}, 200)
	if !st.Enabled || st.StateSource != "config" || st.UpdatedAt != nil || !st.Listening {
		t.Fatalf("reset: %+v", st)
	}
}

// TestAgentAPIOffInConfigIsFinal: enabled false in schild.yaml cannot be
// switched on in the dashboard (409 config_limit); a reset is fine.
func TestAgentAPIOffInConfigIsFinal(t *testing.T) {
	addr := apptest.FreeAddr(t)
	h := apptest.New(t, apptest.Options{Listeners: true, Extra: "agent_api: {enabled: false, listen: \"" + addr + "\"}\n"})
	h.Login()
	code, b := h.API("PUT", "/agent-api", map[string]any{"enabled": true})
	if code != 409 || !strings.Contains(string(b), "config_limit") {
		t.Fatalf("switching on against schild.yaml: %d %s", code, b)
	}
	st := agentState(t, h, "PUT", map[string]any{"reset": true}, 200)
	if st.Enabled || st.ConfigEnabled || st.StateSource != "config" || st.Listening {
		t.Fatalf("state: %+v", st)
	}
	if code := agentStatus(addr); code != 0 {
		t.Fatalf("the listener answers %d", code)
	}
}

// TestAgentAPIOffSurvivesRestart: switched off in the dashboard, off after a
// restart, although schild.yaml has it on.
func TestAgentAPIOffSurvivesRestart(t *testing.T) {
	addr := apptest.FreeAddr(t)
	o := apptest.Options{Listeners: true, Extra: "agent_api: {listen: \"" + addr + "\"}\n"}
	h := apptest.New(t, o)
	h.Login()
	agentState(t, h, "PUT", map[string]any{"enabled": false}, 200)
	if err := h.Stop(); err != nil {
		t.Fatal(err)
	}
	o.Dir = h.Dir
	h = apptest.New(t, o)
	if code := agentStatus(addr); code != 0 {
		t.Fatalf("after a restart the listener answers %d", code)
	}
	h.Login()
	if st := agentState(t, h, "GET", nil, 200); st.Enabled || st.StateSource != "dashboard" || !st.ConfigEnabled {
		t.Fatalf("after a restart: %+v", st)
	}
}

// TestAgentAPIAnyInterfaceNeedsContainer: 0.0.0.0 is for a container. On a
// host the listener stays closed and the state says why; the environment
// variable opens it.
func TestAgentAPIAnyInterfaceNeedsContainer(t *testing.T) {
	if _, err := os.Stat("/.dockerenv"); err == nil || os.Getenv("KUBERNETES_SERVICE_HOST") != "" {
		t.Skip("runs in a container")
	}
	if _, err := os.Stat("/run/.containerenv"); err == nil {
		t.Skip("runs in a container")
	}
	_, port, _ := net.SplitHostPort(apptest.FreeAddr(t))
	o := apptest.Options{Listeners: true, Extra: "agent_api: {listen: \"0.0.0.0:" + port + "\"}\n"}
	h := apptest.New(t, o)
	h.Login()
	st := agentState(t, h, "GET", nil, 200)
	if !st.Enabled || st.Listening || !strings.Contains(st.Error, "container") {
		t.Fatalf("on a host: %+v", st)
	}
	if code := agentStatus("127.0.0.1:" + port); code != 0 {
		t.Fatalf("the listener answers %d", code)
	}
	if err := h.Stop(); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SCHILD_AGENT_API_ANY_INTERFACE", "1")
	o.Dir = h.Dir
	apptest.New(t, o)
	if code := agentStatus("127.0.0.1:" + port); code != 401 {
		t.Fatalf("with the variable: %d, want 401", code)
	}
}

// The switch of the agent API is a setting like every other: set in the
// dashboard of one node of a group, it holds on the other, and given back
// there it is given back here.
func TestAgentAPISwitchHoldsOnEveryNodeOfAGroup(t *testing.T) {
	app.Parallel(t)
	a, b := pair(t)
	a.h.Login()
	b.h.Login()
	off := false
	if st := agentState(t, a.h, "PUT", map[string]any{"enabled": off}, 200); st.Enabled {
		t.Fatal("web-1 did not switch the agent API off")
	}
	b.h.WaitFor("the agent API is off on web-2", func() bool {
		st := agentState(t, b.h, "GET", nil, 200)
		return !st.Enabled && st.StateSource == "dashboard"
	})
	on := true
	agentState(t, b.h, "PUT", map[string]any{"enabled": on}, 200)
	a.h.WaitFor("the agent API is on again on web-1", func() bool { return agentState(t, a.h, "GET", nil, 200).Enabled })
}
