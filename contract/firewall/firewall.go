// Package firewall is the handoff of schild's address blocks to the host's
// firewall (D87, the first step of MVP-15). `schild firewall run` - the same
// image or binary, as its own process with CAP_NET_ADMIN - asks the agent API
// of the gateway (syncAgentFirewall, scope firewall:sync) for the blocks that
// run and keeps the nftables table Table in step with them, each element with
// its remaining time as the kernel timeout. The call is a long poll: the
// gateway answers at once when the blocks changed since the revision the
// firewall applied last, else after Wait. The firewall says in each call what
// it applied, which the dashboard shows. Like a CrowdSec firewall bouncer, but
// with the gateway's own tokens on its loopback agent API.
package firewall

import (
	"crypto/sha256"
	"encoding/hex"
	"net/netip"
	"slices"
	"strings"
	"time"
)

const (
	// Table is the nftables table the firewall owns (family inet): every
	// element in it is schild's.
	Table = "inet schild"
	// MaxBlocks bounds one answer; above it the blocks ending last are left
	// out (they still run in schild).
	MaxBlocks = 10000
	// Wait is the longest a sync call waits for a change.
	Wait = 50 * time.Second
	// Stale: a firewall whose last call is older than this says nothing any
	// more (it calls again within Wait).
	Stale = 2 * time.Minute
	// Ports are the web ports a block covers, TCP and UDP.
	Ports = "80, 443"
)

// Block is one client schild blocks: an IPv4 address or an IPv6 /64.
type Block struct {
	Client   string    `json:"client"`
	Until    time.Time `json:"until"`
	Incident string    `json:"incident,omitempty"`
}

// SyncRequest is the body of syncAgentFirewall: what the firewall applied.
type SyncRequest struct {
	// Applied is the revision of the last answer the firewall applied
	// completely; empty at its start.
	Applied string `json:"applied"`
	// Held is the number of clients the table holds now.
	Held int `json:"held"`
	// Table names the table, Version the program of the firewall.
	Table   string `json:"table"`
	Version string `json:"version"`
	// Error is the last failure of the firewall in one line; empty when the
	// last apply worked.
	Error string `json:"error,omitempty"`
}

// SyncResponse is the answer: every block that runs, and its revision.
type SyncResponse struct {
	Revision string  `json:"revision"`
	Blocks   []Block `json:"blocks"`
}

// Revision names a list of blocks: equal lists, equal revision.
func Revision(blocks []Block) string {
	h := sha256.New()
	for _, b := range blocks {
		h.Write([]byte(b.Client + "|" + b.Until.UTC().Format(time.RFC3339) + "\n"))
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// Client normalises a client key: an IPv4 address without /32, an IPv6
// prefix as /64 (or an address as given). ok is false for anything else.
func Client(s string) (string, bool) {
	if p, err := netip.ParsePrefix(s); err == nil {
		p = p.Masked()
		if p.Addr().Is4() && p.Bits() == 32 {
			return p.Addr().String(), true
		}
		if p.Addr().Is6() && !p.Addr().Is4In6() && p.Bits() == 64 {
			return p.String(), true
		}
		return "", false
	}
	if a, err := netip.ParseAddr(s); err == nil && a.Zone() == "" {
		return a.Unmap().String(), true
	}
	return "", false
}

// ClientOf is the client of a block key (an IPv4 /32 or an IPv6 /64).
func ClientOf(p netip.Prefix) string {
	if p.Addr().Is4() && p.Bits() == 32 {
		return p.Addr().String()
	}
	return p.Masked().String()
}

// Valid reports whether every block of r names a client key; the firewall
// applies nothing else.
func (r SyncResponse) Valid() bool {
	if r.Revision == "" || len(r.Blocks) > MaxBlocks {
		return false
	}
	for _, b := range r.Blocks {
		if c, ok := Client(b.Client); !ok || c != b.Client {
			return false
		}
	}
	return true
}

// Running returns the clients of blocks still running at now, sorted.
func Running(blocks []Block, now time.Time) []string {
	var out []string
	for _, b := range blocks {
		if b.Until.After(now) {
			out = append(out, b.Client)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// OneLine cuts s to one line of at most n runes, for an error shown in the
// dashboard.
func OneLine(s string, n int) string {
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = s[:i]
	}
	r := []rune(s)
	if len(r) > n {
		r = r[:n]
	}
	return string(r)
}

// Report is what the firewall said in its last call, as the gateway keeps it
// for the dashboard.
type Report struct {
	At      time.Time
	Applied string
	Held    int
	Table   string
	Version string
	Error   string
	// Clients are the clients of the applied revision; Complete is false when
	// the gateway no longer knows that revision (after its restart).
	Clients  map[string]bool
	Complete bool
}
