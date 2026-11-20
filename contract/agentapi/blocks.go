package agentapi

import (
	"encoding/json"
	"net/netip"
	"strings"
	"time"

	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/events"
	"github.com/deutschland-schild/schild/contract/jsonx"
	"github.com/deutschland-schild/schild/contract/schema"
)

// Single blocks through the agent API (D42). An agent never names an address:
// it names an event, an incident or a client pseudonym, and the gateway reads
// the address it recorded for that target. CheckBlock and CheckLift are the
// decisions after that lookup; both are fixed by the agent-block vectors.

// Limits of the block writes.
const (
	// MinBlockS is the shortest block an agent may set.
	MinBlockS = 60
	// BlockEvidenceWindow: an event or incident older than this is no ground
	// for a new block (target_gone).
	BlockEvidenceWindow = 7 * 24 * time.Hour
	// BlockBudgetWindowS is the rolling window of block_writes_per_hour.
	BlockBudgetWindowS = 3600
	// DefaultBlockWritesPerHour and DefaultMaxAgentBlocks are the defaults of
	// agent_api.block_writes_per_hour and agent_api.max_agent_blocks.
	DefaultBlockWritesPerHour = 600
	DefaultMaxAgentBlocks     = 2000
	// MaxBlockBody bounds the JSON body of a block write.
	MaxBlockBody = 1 << 10
)

// Problem codes of the block writes, beside scope_required, invalid and
// not_found.
const (
	CodeBlockBudget    = "block_budget"           // 429: the token's writes per hour are used up
	CodeBlockCap       = "block_cap"              // 429: max_agent_blocks are running
	CodeDurationOver   = "duration_over_cap"      // 400: above the cap of the net class
	CodeOwnAddress     = "own_address"            // 409: allowlist, the gateway itself, a trusted proxy
	CodePrivateAddress = "private_address"        // 409: private or special range
	CodeSharedAddress  = "shared_address"         // 409: cgnat, mobile, tor
	CodeReleased       = "released"               // 409: the operator released this client
	CodeTargetGone     = "target_gone"            // 409: the address is no longer stored, or the evidence is too old
	CodeUnreliable     = "unreliable_attribution" // 409: the address was not attributed by tcp_peer or trusted_proxy
	CodeNoRunningBlock = "no_running_block"       // 409: the incident has no block that runs
)

// Effects of a block write.
const (
	EffectBlock      = "block"
	EffectWouldBlock = "would_block"
)

// LimitedByGatewayObserve says why a write only recorded would_block.
const LimitedByGatewayObserve = "gateway_observe"

// protectedRanges can never be blocked: private and special use. The
// documentation ranges are not in the list, because fixtures use them.
var protectedRanges = func() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4", "240.0.0.0/4",
		"::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8",
	} {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()

// ProtectedAddress reports whether a is in a range no agent can block.
func ProtectedAddress(a netip.Addr) bool {
	a = a.Unmap()
	for _, p := range protectedRanges {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// MaxBlockS is the longest block an agent may set for a net class: the cap of
// the ladder of that class (D29 amendment).
func MaxBlockS(netClass string) int {
	if netClass == "hosting" {
		return events.MaxBlockHostingS
	}
	return events.MaxBlockDefaultS
}

// BlockTarget is what the gateway found for the named target. Exists false:
// nothing of that name. Gone: the address is no longer stored in full, or the
// evidence is older than BlockEvidenceWindow.
type BlockTarget struct {
	Exists      bool   `json:"exists"`
	Gone        bool   `json:"gone"`
	Address     string `json:"address"`
	Attribution string `json:"attribution"`
	NetClass    string `json:"net_class"`
	// Own: on the allowlist, an address of the gateway host or in
	// ingress.trusted_proxies.
	Own bool `json:"own"`
	// Released: an unblock exception of the operator runs for this client.
	Released bool `json:"released"`
	// Running: a block of this client key runs already.
	Running bool `json:"running"`
}

// BlockBudget is the state of the limits at the moment of a write.
type BlockBudget struct {
	WritesPerHour int `json:"writes_per_hour"`
	WritesUsed    int `json:"writes_used"`
	// OldestWriteAgeS is the age of the oldest write in the window.
	OldestWriteAgeS int `json:"oldest_write_age_s"`
	MaxBlocks       int `json:"max_blocks"`
	Running         int `json:"running"`
}

// BlockInput is one createAgentBlock after the gateway looked up its target.
type BlockInput struct {
	Scope     string      `json:"scope"`
	Mode      string      `json:"mode"`
	DurationS int         `json:"duration_s"`
	Reason    string      `json:"reason"`
	Target    BlockTarget `json:"target"`
	Budget    BlockBudget `json:"budget"`
}

// BlockVerdict is the decision on a block write. Null fields do not apply.
type BlockVerdict struct {
	Allowed bool    `json:"allowed"`
	Status  int     `json:"status"`
	Code    *string `json:"code"`
	// Effect block or would_block; Changed false: an existing block stands,
	// its end does not move.
	Effect  *string `json:"effect"`
	Changed bool    `json:"changed"`
	// LimitedBy is gateway_observe with effect would_block.
	LimitedBy *string `json:"limited_by"`
	// MaxDurationS with duration_over_cap.
	MaxDurationS *int `json:"max_duration_s"`
	// Persisted: the block is kept in schild.db (over 24 h).
	Persisted bool `json:"persisted"`
	// CountsBudget: this call uses one write of the token's budget.
	CountsBudget bool `json:"counts_budget"`
	// RetryAfter in seconds with a 429.
	RetryAfter *int `json:"retry_after"`
}

func refuse(status int, code string) BlockVerdict { return BlockVerdict{Status: status, Code: &code} }

func budgetRefusal(b BlockBudget) *BlockVerdict {
	if b.WritesUsed >= b.WritesPerHour {
		v := refuse(429, CodeBlockBudget)
		retry := max(BlockBudgetWindowS-b.OldestWriteAgeS, 1)
		v.RetryAfter = &retry
		return &v
	}
	return nil
}

func blankReason(s string) bool { return strings.TrimSpace(s) == "" }

// CheckBlock decides on createAgentBlock. The checks run in this order, in
// every mode, so that a would_block record is what a real block would have
// been.
func CheckBlock(in BlockInput) BlockVerdict {
	if !AllowsWrite(in.Scope, OpCreateBlock) {
		return refuse(403, CodeScopeRequired)
	}
	if blankReason(in.Reason) || in.DurationS < MinBlockS {
		return refuse(400, "invalid")
	}
	t := in.Target
	if !t.Exists {
		return refuse(404, "not_found")
	}
	if t.Gone {
		return refuse(409, CodeTargetGone)
	}
	if t.Attribution != "tcp_peer" && t.Attribution != "trusted_proxy" {
		return refuse(409, CodeUnreliable)
	}
	addr, err := netip.ParseAddr(t.Address)
	if err != nil || ProtectedAddress(addr) {
		return refuse(409, CodePrivateAddress)
	}
	if t.Own {
		return refuse(409, CodeOwnAddress)
	}
	if t.NetClass == "cgnat" || t.NetClass == "mobile" || t.NetClass == "tor" {
		return refuse(409, CodeSharedAddress)
	}
	if t.Released {
		return refuse(409, CodeReleased)
	}
	if limit := MaxBlockS(t.NetClass); in.DurationS > limit {
		v := refuse(400, CodeDurationOver)
		v.MaxDurationS = &limit
		return v
	}
	if t.Running {
		e := EffectBlock
		return BlockVerdict{Allowed: true, Status: 200, Effect: &e}
	}
	if v := budgetRefusal(in.Budget); v != nil {
		return *v
	}
	if in.Mode == "observe" {
		e, l := EffectWouldBlock, LimitedByGatewayObserve
		return BlockVerdict{Allowed: true, Status: 200, Effect: &e, LimitedBy: &l, CountsBudget: true}
	}
	if in.Budget.Running >= in.Budget.MaxBlocks {
		v := refuse(429, CodeBlockCap)
		retry := BlockBudgetWindowS
		v.RetryAfter = &retry
		return v
	}
	e := EffectBlock
	return BlockVerdict{Allowed: true, Status: 200, Effect: &e, Changed: true, Persisted: in.DurationS > events.PersistOverS, CountsBudget: true}
}

// LiftInput is one liftAgentBlock after the gateway looked up the incident.
type LiftInput struct {
	Scope  string `json:"scope"`
	Reason string `json:"reason"`
	// Status of the incident: blocked, unblocked, or missing.
	Status string `json:"status"`
	// Running: a timed block of a behaviour scenario, a rate limit or an agent
	// runs under this incident. A single request the WAF refused has none:
	// there is nothing to lift, and a later request is judged on its own.
	Running bool        `json:"running"`
	Budget  BlockBudget `json:"budget"`
}

// CheckLift decides on liftAgentBlock.
func CheckLift(in LiftInput) BlockVerdict {
	if !AllowsWrite(in.Scope, OpLiftBlock) {
		return refuse(403, CodeScopeRequired)
	}
	if blankReason(in.Reason) {
		return refuse(400, "invalid")
	}
	switch {
	case in.Status == "missing":
		return refuse(404, "not_found")
	case in.Status == "unblocked":
		return BlockVerdict{Allowed: true, Status: 200}
	case !in.Running:
		return refuse(409, CodeNoRunningBlock)
	}
	if v := budgetRefusal(in.Budget); v != nil {
		return *v
	}
	return BlockVerdict{Allowed: true, Status: 200, Changed: true, CountsBudget: true}
}

// MaxBlockInputBytes bounds a vector input.
const MaxBlockInputBytes = 64 << 10

// RunBlockVector checks one agent-block vector and returns its verdict.
func RunBlockVector(raw []byte) (any, error) {
	if len(raw) > MaxBlockInputBytes {
		return nil, contract.Errf(contract.CodeOversize, "%d bytes > %d", len(raw), MaxBlockInputBytes)
	}
	v, err := jsonx.ParseObject(raw)
	if err != nil {
		return nil, contract.Errf(contract.CodeMalformed, "%v", err)
	}
	if err := schema.Validate(schema.AgentBlock, v); err != nil {
		return nil, err
	}
	if v["op"] == "create" {
		var in BlockInput
		if err := json.Unmarshal(raw, &in); err != nil {
			return nil, contract.Errf(contract.CodeSchema, "%v", err)
		}
		return CheckBlock(in), nil
	}
	var in LiftInput
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil, contract.Errf(contract.CodeSchema, "%v", err)
	}
	return CheckLift(in), nil
}

// Wire types of the block writes (gateway-agent.openapi.yaml).

// BlockTargetName is the body field that names a target: exactly one of them.
type BlockTargetName struct {
	EventID         string `json:"event_id,omitempty"`
	Incident        string `json:"incident,omitempty"`
	ClientPseudonym string `json:"client_pseudonym,omitempty"`
}

// BlockRequest is the body of createAgentBlock.
type BlockRequest struct {
	Target    BlockTargetName `json:"target"`
	DurationS int             `json:"duration_s"`
	Reason    string          `json:"reason"`
}

// LiftRequest is the body of liftAgentBlock.
type LiftRequest struct {
	Reason string `json:"reason"`
}

// BlockResult is the answer of createAgentBlock. It has no address.
type BlockResult struct {
	Effect          string  `json:"effect"`
	Changed         bool    `json:"changed"`
	LimitedBy       string  `json:"limited_by,omitempty"`
	ClientPseudonym string  `json:"client_pseudonym"`
	ClientNet       string  `json:"client_net"`
	NetClass        string  `json:"net_class"`
	DurationS       int     `json:"duration_s"`
	Until           *string `json:"until"`
	Persisted       bool    `json:"persisted"`
	Incident        string  `json:"incident,omitempty"`
	EventID         string  `json:"event_id,omitempty"`
}

// BlockSetBy names the token that set a block.
type BlockSetBy struct {
	TokenID    string `json:"token_id"`
	TokenLabel string `json:"token_label"`
}

// IncidentBlock is BehaviourBlock of the client dashboard API for agents.
type IncidentBlock struct {
	Source      string      `json:"source"`
	Until       string      `json:"until"`
	Level       int         `json:"level"`
	NetClass    string      `json:"net_class,omitempty"`
	DurationS   int         `json:"duration_s,omitempty"`
	Persisted   bool        `json:"persisted,omitempty"`
	EndedAt     string      `json:"ended_at,omitempty"`
	Incident    string      `json:"incident,omitempty"`
	SetBy       *BlockSetBy `json:"set_by,omitempty"`
	AgentReason string      `json:"agent_reason,omitempty"` // untrusted
}
