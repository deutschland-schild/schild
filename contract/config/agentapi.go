package config

import "github.com/deutschland-schild/schild/contract"

// AgentAPI is the v0.4 (MVP-21, D33) API for agents on its
// own loopback listener: it reads, and tokens with a write scope may set the
// CrowdSec Hub switch (D39 amendment) or single blocks (D42). Tokens never
// appear in schild.yaml;
// they are created on the host and stored hashed.
type AgentAPI struct {
	Enabled           *bool  `json:"enabled"`
	Listen            string `json:"listen"`
	RequestsPerMinute int    `json:"requests_per_minute"`
	MaxConcurrent     int    `json:"max_concurrent"`
	LogDays           int    `json:"log_days"`
	// D42: creating and lifting blocks per token and rolling hour, and the
	// running agent blocks of the whole gateway.
	BlockWritesPerHour int `json:"block_writes_per_hour"`
	MaxAgentBlocks     int `json:"max_agent_blocks"`
}

// DefaultAgentAPIListen is the loopback listener of the agent API (and of
// the MVP-20 export).
const DefaultAgentAPIListen = "127.0.0.1:8789"

// On reports whether schild.yaml has the agent API on (default true, D103).
// The switch in the dashboard wins over it.
func (a *AgentAPI) On() bool { return a.Enabled != nil && *a.Enabled }

func (a *AgentAPI) defaults() {
	if a.Enabled == nil {
		a.Enabled = boolp(true)
	}
	orStr(&a.Listen, DefaultAgentAPIListen)
	orInt(&a.RequestsPerMinute, 120)
	orInt(&a.MaxConcurrent, 2)
	orInt(&a.LogDays, 30)
	orInt(&a.BlockWritesPerHour, 600)
	orInt(&a.MaxAgentBlocks, 2000)
}

// checkAgentAPI: the agent listener is its own (never the dashboard or the
// metrics listener, so session and token routes never share a port).
func (s *Site) checkAgentAPI() error {
	if l := s.AgentAPI.Listen; l == s.Listen.Dashboard || l == s.Listen.Metrics {
		return contract.Errf(contract.CodeConfig, "agent_api.listen %s equals listen.dashboard or listen.metrics", l)
	}
	return nil
}
