package events

// Behaviour block ladder per net class (D29 amendment, initiator
// 2026-10-29; events.schema.json behaviourTriggered enforces the same
// steps). Data-centre addresses (net_class hosting) may be blocked up to 7
// days when they come back; every other class keeps the 24 h cap. cgnat,
// mobile and tor are never blocked by behaviour (D29). Network blocking of
// listed prefixes (Spamhaus DROP, D28) is not a behaviour block and lasts
// as long as the prefix is listed.

// Ladders in seconds; level n uses step n, levels beyond the last use the
// last step (the cap).
var (
	LadderDefault = []int{900, 3600, 14400, 86400}
	LadderHosting = []int{900, 3600, 86400, 604800}
)

// MaxBlockDefaultS and MaxBlockHostingS are the caps.
const (
	MaxBlockDefaultS = 86400
	MaxBlockHostingS = 604800
	// PersistOverS: blocks longer than this are kept in schild.db with
	// their expiry and reloaded at start, so a restart never ends them
	// early. Shorter blocks may live in memory only.
	PersistOverS = 86400
)

// Ladder returns the ladder of a net class.
func Ladder(netClass string) []int {
	if netClass == "hosting" {
		return LadderHosting
	}
	return LadderDefault
}

// BlockDurationS returns the block duration of a level (1-based) for a net
// class.
func BlockDurationS(netClass string, level int) int {
	l := Ladder(netClass)
	if level < 1 {
		level = 1
	}
	if level > len(l) {
		level = len(l)
	}
	return l[level-1]
}

// ActiveBlock is a running behaviour block as the gateway keeps it (a row
// in schild.db for blocks over PersistOverS). At start the gateway reloads
// the rows whose Until lies in the future; expiry is always enforced. An
// Art. 17 deletion of the address removes the row and lifts the block, and
// an address on the operator's allowlist is never blocked (the row is
// dropped at load and at every allowlist change).
type ActiveBlock struct {
	ClientKey string `json:"client_key"` // IPv4 address or IPv6 /64 (local only)
	KeyBits   int    `json:"key_bits"`   // 32 or 64
	NetClass  string `json:"net_class"`
	Source    string `json:"source"` // behaviour:<scenario> or, D42, agent:<token id>
	Level     int    `json:"level"`
	DurationS int    `json:"duration_s"`
	Since     string `json:"since"`
	Until     string `json:"until"`
	Incident  string `json:"incident"`
}
