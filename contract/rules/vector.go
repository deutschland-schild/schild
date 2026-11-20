package rules

import (
	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/agentapi"
	"github.com/deutschland-schild/schild/contract/jsonx"
	"github.com/deutschland-schild/schild/contract/schema"
)

// AgentWrite is the verdict on a token for a write of the agent API.
type AgentWrite struct {
	Allowed bool   `json:"allowed"`
	Status  int    `json:"status"`
	Code    string `json:"code,omitempty"`
}

// CheckAgentWrite applies the scope rule of a write operation to a token that
// already authenticated: rules:write may change repositories and disable
// rules (D89: there are no approvals any more).
func CheckAgentWrite(scope, operation string) AgentWrite {
	if agentapi.AllowsWrite(scope, operation) {
		return AgentWrite{Allowed: true, Status: 200}
	}
	return AgentWrite{Status: 403, Code: agentapi.CodeScopeRequired}
}

// RunVector runs one rule-effect input (rule-effect.schema.json).
func RunVector(raw []byte) (any, error) {
	if len(raw) > MaxInputBytes {
		return nil, contract.Errf(contract.CodeOversize, "%d bytes > %d", len(raw), MaxInputBytes)
	}
	v, err := jsonx.ParseObject(raw)
	if err != nil {
		return nil, contract.Errf(contract.CodeMalformed, "%v", err)
	}
	if err := schema.Validate(Schema, v); err != nil {
		return nil, err
	}
	str := func(k string) string { s, _ := v[k].(string); return s }
	flag := func(k string) bool { b, _ := v[k].(bool); return b }
	num := func(k string) int64 {
		x, ok := v[k].(interface{ Int64() (int64, error) })
		if !ok {
			return 0
		}
		i, _ := x.Int64()
		return i
	}
	in := func() Input {
		return Input{Mode: str("mode"), State: str("state"), Origin: str("origin"), Disabled: flag("disabled"), DisabledBy: str("disabled_by"),
			SettlingUntil: num("settling_until"), Now: num("now")}
	}
	switch str("op") {
	case "effect":
		return Compute(in()), nil
	case "request":
		return Apply(Compute(in()), Request{SiteMode: str("site_mode"), Allow: str("allow"), Excepted: flag("excepted")}), nil
	case "repository":
		return EffectOfRepository(str("state"), str("mode")), nil
	case "switch":
		return ApplySwitch(str("repository"), str("config"), str("overlay"), str("overlay_by"), str("requested"), str("actor"), flag("reset")), nil
	case "agent_write":
		return CheckAgentWrite(str("scope"), str("operation")), nil
	}
	return nil, contract.Errf(contract.CodeSchema, "unknown op %v", v["op"])
}
