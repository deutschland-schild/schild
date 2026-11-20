// Package agentapi is the contract of the agent API of the gateway
// (contracts/api/gateway-agent.openapi.yaml). It reads, with the writes listed
// in WriteOperations, each for tokens with its own write scope: rule
// repositories and single rules (rules:write), single blocks (blocks:write), rule exceptions
// (exceptions:write) and the crawler policy (crawlers:write). Bearer tokens,
// scopes and lifetimes, the keyed client pseudonym and network truncation that
// replace IP addresses, the escaping of attacker-controlled text, the hard
// caps, the OpenAPI document the gateway serves and the wire types of events
// and incidents. The gateway serves it on its own loopback listener; the
// central dashboard's export joins the same listener with scope export:read.
package agentapi

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Scopes of agent API tokens.
const (
	ScopeAgentRead  = "agent:read"
	ScopeExportRead = "export:read" // reserved for the central dashboard's export
	// ScopeRulesWrite: everything agent:read may, plus the state, sync and
	// reset of a rule repository and disabling single rules.
	ScopeRulesWrite = "rules:write"
	// ScopeBlocksWrite: everything agent:read may, plus creating and lifting
	// single blocks.
	ScopeBlocksWrite = "blocks:write"
	// ScopeExceptionsWrite: everything agent:read may, plus setting and
	// removing rule exceptions.
	ScopeExceptionsWrite = "exceptions:write"
	// ScopeCrawlersWrite: everything agent:read may, plus changing the
	// crawler policy of a website.
	ScopeCrawlersWrite = "crawlers:write"
	// ScopeFirewallSync is the token of `schild firewall run` (D87): only
	// syncAgentFirewall, no read of anything else.
	ScopeFirewallSync = "firewall:sync"
)

// Scopes lists every scope a token may carry, in the order of help texts and
// the API enum. Every write scope needs a label.
var Scopes = []string{ScopeAgentRead, ScopeExportRead, ScopeRulesWrite, ScopeBlocksWrite, ScopeExceptionsWrite, ScopeCrawlersWrite, ScopeFirewallSync}

// ScopeHelp says in a few words what each scope of Scopes may do, for the
// help of `schild token`.
var ScopeHelp = map[string]string{
	ScopeAgentRead:       "read everything and run testAgentRequest (the default)",
	ScopeExportRead:      "the central dashboard's export only",
	ScopeRulesWrite:      "also rule repositories (state, sync, reset) and disabling single rules",
	ScopeBlocksWrite:     "also setting and lifting single blocks",
	ScopeExceptionsWrite: "also setting and removing rule exceptions",
	ScopeCrawlersWrite:   "also changing the crawler policy of a website",
	ScopeFirewallSync:    "schild firewall run only: the blocks for the host's firewall",
}

// ScopeList is Scopes for help and error texts: "agent:read, export:read, ...".
func ScopeList() string { return strings.Join(Scopes, ", ") }

// CodeScopeRequired is the problem code of a 403 on a write operation with a
// token that lacks its scope. It differs from forbidden on purpose, so that an
// agent can tell the operator what to do.
const CodeScopeRequired = "scope_required"

// Write operations of this API.
const (
	OpUpdateRuleRepository = "updateAgentRuleRepository"
	OpSyncRuleRepository   = "syncAgentRuleRepository"
	OpResetRuleRepository  = "resetAgentRuleRepository"
	OpUpdateRule           = "updateAgentRule"
	OpCreateBlock          = "createAgentBlock"
	OpLiftBlock            = "liftAgentBlock"
	OpCreateException      = "createAgentException"
	OpRemoveException      = "removeAgentException"
	OpSetCrawlers          = "setAgentCrawlers"
	// OpSyncFirewall: the handoff of the blocks to the host's firewall (D87).
	OpSyncFirewall = "syncAgentFirewall"
)

// WriteOperations lists the only operations of this API that change state,
// with the scope each needs. Anything else stays read only.
var WriteOperations = map[string]string{
	OpUpdateRuleRepository: ScopeRulesWrite,
	OpSyncRuleRepository:   ScopeRulesWrite,
	OpResetRuleRepository:  ScopeRulesWrite,
	OpUpdateRule:           ScopeRulesWrite,
	OpCreateBlock:          ScopeBlocksWrite,
	OpLiftBlock:            ScopeBlocksWrite,
	OpCreateException:      ScopeExceptionsWrite,
	OpRemoveException:      ScopeExceptionsWrite,
	OpSetCrawlers:          ScopeCrawlersWrite,
	OpSyncFirewall:         ScopeFirewallSync,
}

// AllowsWrite reports whether a token with scope may run a write operation.
func AllowsWrite(scope, operation string) bool {
	need, ok := WriteOperations[operation]
	return ok && scope == need
}

// CanRead reports whether a token with scope may run the read operations.
// export:read is not one of them: it reads the buckets of the export only.
func CanRead(scope string) bool {
	return scope == ScopeAgentRead || NeedsLabel(scope)
}

// NeedsLabel reports whether a token with scope needs a label: every write
// scope does, the label names the token in the history.
func NeedsLabel(scope string) bool {
	switch scope {
	case ScopeRulesWrite, ScopeBlocksWrite, ScopeExceptionsWrite, ScopeCrawlersWrite:
		return true
	}
	return false
}

// Token format: "sat1_" + 43 characters of unpadded base64url (32 random
// bytes). Only the SHA-256 is stored; the token is shown once by the CLI.
const (
	TokenPrefix = "sat1_"
	// MaxTTL of a token; an expiry is required.
	MaxTTL = 365 * 24 * time.Hour
)

var tokenRe = regexp.MustCompile(`^sat1_[A-Za-z0-9_-]{43}$`)

// NewToken returns a fresh token.
func NewToken() string {
	var b [32]byte
	_, _ = rand.Read(b[:])
	return TokenPrefix + base64.RawURLEncoding.EncodeToString(b[:])
}

// ValidToken reports whether s has the token format (constant structure, no
// lookup).
func ValidToken(s string) bool { return tokenRe.MatchString(s) }

// HashToken is the stored form of a token (hex SHA-256).
func HashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

// TokenID is the public id of a token ("tok_" + 12 hex of its hash), shown
// by `schild token list` and in the call log.
func TokenID(token string) string { return "tok_" + HashToken(token)[:12] }

// ParseTTL parses the CLI expiry "<n>d" (1 to 365 days); there is no
// "never".
func ParseTTL(s string) (time.Duration, error) {
	n, err := strconv.Atoi(strings.TrimSuffix(s, "d"))
	if !strings.HasSuffix(s, "d") || err != nil || n < 1 || time.Duration(n)*24*time.Hour > MaxTTL {
		return 0, fmt.Errorf("expiry %q: want 1d to 365d", s)
	}
	return time.Duration(n) * 24 * time.Hour, nil
}

// ValidScope reports whether scope may be put on a token.
func ValidScope(scope string) bool {
	return scope == ScopeAgentRead || scope == ScopeExportRead || scope == ScopeFirewallSync || NeedsLabel(scope)
}

// Pseudonyms. The key is a gateway-local random 32-byte key (stored in the
// gateway's database, never exported); regenerating it unlinks all earlier
// pseudonyms.
const pseudonymDomain = "schild-agent-client-v1\x00"

// ClientPseudonym returns the keyed pseudonym of a client: HMAC-SHA256 over the
// client key of the behaviour engine (the IPv4 address, the IPv6 /64), first
// 8 bytes as hex, prefixed "p1-". Same client key, same pseudonym.
func ClientPseudonym(key []byte, a netip.Addr) string {
	a = a.Unmap()
	p := netip.PrefixFrom(a, a.BitLen())
	if a.Is6() {
		p, _ = a.Prefix(64)
	}
	m := hmac.New(sha256.New, key)
	m.Write([]byte(pseudonymDomain + p.String()))
	return "p1-" + hex.EncodeToString(m.Sum(nil)[:8])
}

const visitorPseudonymDomain = "schild-agent-visitor-v1\x00"

// VisitorPseudonym re-keys a visitor key of the request ring (v0.5, MVP-22)
// for agents: HMAC-SHA256 with the same gateway-local key as
// ClientPseudonym over a separate domain and the visitor key, first 8 bytes
// as hex, prefixed "p1-". It lives as long as the visitor key (one day) and
// differs from the ClientPseudonym of the same client; events and requests
// are linked through the event id.
func VisitorPseudonym(key []byte, visitorKey string) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(visitorPseudonymDomain + visitorKey))
	return "p1-" + hex.EncodeToString(m.Sum(nil)[:8])
}

// ClientNet returns the truncated network of a client: IPv4 /24, IPv6 /48.
func ClientNet(a netip.Addr) string {
	a = a.Unmap()
	bits := 24
	if a.Is6() {
		bits = 48
	}
	p, _ := a.Prefix(bits)
	return p.String()
}

// Sanitize escapes attacker-controlled text for an agent: control
// characters (C0, DEL, C1), line and paragraph separators and bidi controls
// become U+FFFD, invalid UTF-8 too; the result is cut to max bytes on a rune
// boundary and then ends with "…" (counted in max).
func Sanitize(s string, max int) string {
	var b strings.Builder
	for _, r := range strings.ToValidUTF8(s, "\ufffd") {
		if unicode.IsControl(r) || r == '\u2028' || r == '\u2029' || (r >= '\u202a' && r <= '\u202e') || (r >= '\u2066' && r <= '\u2069') || r == '\u200e' || r == '\u200f' {
			r = '\ufffd'
		}
		b.WriteRune(r)
	}
	out := b.String()
	if len(out) <= max {
		return out
	}
	cut := max - len("…")
	for cut > 0 && !utf8.RuneStart(out[cut]) {
		cut--
	}
	return out[:cut] + "…"
}

// Caps of the agent API (also in the OpenAPI document).
const (
	MaxRows        = 200            // items per page
	MaxBytes       = 1 << 20        // response body
	MaxScanRows    = 10000          // rows read per request before scan_capped
	EventWindow    = 24 * time.Hour // to - from of listAgentEvents
	IncidentWindow = 7 * 24 * time.Hour
	// Length caps of untrusted fields (bytes, after Sanitize).
	MaxHost      = 253
	MaxPath      = 512
	MaxUserAgent = 256
	MaxRuleMsg   = 512
	MaxReason    = 300
	MaxReferrer  = 253
	// v0.5 (MVP-22): queryRequests window and read cap, context size.
	RequestWindow      = time.Hour
	MaxRequestScan     = 10000
	MaxContextRequests = 200
)
