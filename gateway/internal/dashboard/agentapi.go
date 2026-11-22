package dashboard

import (
	"context"
	"errors"
	"net/http"
)

// AgentAPIState is getAgentAPI and the answer of setAgentAPI (D103).
type AgentAPIState struct {
	// Enabled is what holds: off when schild.yaml says so, else the value of
	// the dashboard, else on.
	Enabled       bool   `json:"enabled"`
	ConfigEnabled bool   `json:"config_enabled"`
	StateSource   string `json:"state_source"`
	Listen        string `json:"listen"`
	// Listening: the listener is open. Error says why not while Enabled.
	Listening      bool    `json:"listening"`
	Error          string  `json:"error,omitempty"`
	ActiveTokens   int     `json:"active_tokens"`
	FirewallTokens int     `json:"firewall_tokens"`
	UpdatedAt      *string `json:"updated_at"`
	Actor          *string `json:"actor"`
}

// AgentAPIInput is the body of setAgentAPI: enabled, or reset true.
type AgentAPIInput struct {
	Enabled *bool `json:"enabled,omitempty"`
	Reset   *bool `json:"reset,omitempty"`
}

// ErrAgentAPIListen: the listener of the agent API did not open.
// ErrAgentAPIConfigOff: schild.yaml has enabled false, which only the file
// takes back.
var (
	ErrAgentAPIListen    = errors.New("agent API listener did not open")
	ErrAgentAPIConfigOff = errors.New("agent API is off in schild.yaml")
)

func (s *Server) agentAPIState(ctx context.Context) AgentAPIState {
	if s.AgentAPI != nil {
		return s.AgentAPI(ctx)
	}
	c := s.Config().AgentAPI
	return AgentAPIState{Enabled: c.On(), ConfigEnabled: c.On(), StateSource: "config", Listen: c.Listen}
}

func (s *Server) getAgentAPI(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.agentAPIState(r.Context()))
}

// setAgentAPI switches the agent API on or off, or gives the switch back to
// schild.yaml (D103). Session and CSRF, no password: a token is still needed
// for every call, and tokens come from the host only.
func (s *Server) setAgentAPI(w http.ResponseWriter, r *http.Request) {
	var in AgentAPIInput
	if !decode(w, r, &in) {
		return
	}
	reset := in.Reset != nil && *in.Reset
	if (in.Enabled == nil) == !reset || (in.Reset != nil && !reset) {
		invalid(w, "Entweder enabled oder reset: true.", FieldError{Pointer: "/enabled", Detail: "genau eines von enabled und reset"})
		return
	}
	if s.SetAgentAPI == nil {
		problem(w, http.StatusConflict, "conflict", "Die Agent-API lässt sich auf diesem Server nicht im Dashboard schalten.", nil)
		return
	}
	user := ""
	if se := sessionOf(r); se != nil {
		user = se.User
	}
	st, err := s.SetAgentAPI(r.Context(), in.Enabled, user)
	switch {
	case errors.Is(err, ErrAgentAPIListen):
		problem(w, http.StatusConflict, "conflict", "Die Agent-API ließ sich auf "+st.Listen+" nicht öffnen. Der Port ist belegt, oder die Adresse ist außerhalb eines Containers nicht erlaubt. Der Schalter bleibt, wie er war.", nil)
		return
	case errors.Is(err, ErrAgentAPIConfigOff):
		problem(w, http.StatusConflict, "config_limit", "Die Agent-API ist in schild.yaml ausgeschaltet (agent_api.enabled: false) und lässt sich nur dort wieder einschalten.", nil)
		return
	case err != nil:
		s.internal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, st)
}
