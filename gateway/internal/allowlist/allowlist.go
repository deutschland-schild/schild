// Package allowlist matches visitor addresses against the local allowlist:
// own IPs, ranges and DynDNS names with expiry. The allowlist is local only:
// it is never sent anywhere, and allowlisted requests never produce signals.
package allowlist

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"regexp"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/deutschland-schild/schild/contract/msg"
	"github.com/deutschland-schild/schild/gateway/internal/store"
)

// Levels.
const (
	NoBlock   = "no_block"
	BypassWAF = "bypass_waf"
)

// Entry is a compiled entry.
type Entry struct {
	store.AllowEntry
	Prefix   netip.Prefix // ip or cidr
	Resolved []netip.Addr // host entries
	Until    time.Time    // zero = never
}

// Expired reports whether the entry has expired at now.
func (e *Entry) Expired(now time.Time) bool { return !e.Until.IsZero() && !now.Before(e.Until) }

type snapshot struct{ entries []*Entry }

// List is the hot-swappable allowlist.
type List struct {
	cur      atomic.Pointer[snapshot]
	mu       sync.Mutex
	hosts    map[string][]netip.Addr
	Resolver func(ctx context.Context, host string) ([]netip.Addr, error)
}

// New returns an empty list using the system resolver for DynDNS names.
func New() *List {
	l := &List{hosts: map[string][]netip.Addr{}}
	l.Resolver = func(ctx context.Context, host string) ([]netip.Addr, error) {
		return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	}
	l.cur.Store(&snapshot{})
	return l
}

// Set replaces all entries. Invalid entries are skipped and reported.
func (l *List) Set(entries []store.AllowEntry) []error {
	var errs []error
	snap := &snapshot{}
	l.mu.Lock()
	hosts := l.hosts
	l.mu.Unlock()
	for _, e := range entries {
		c, err := compile(e)
		if err != nil {
			errs = append(errs, fmt.Errorf("allowlist %s: %w", e.ID, err))
			continue
		}
		if c.Host != "" {
			c.Resolved = hosts[c.Host]
		}
		snap.entries = append(snap.entries, c)
	}
	l.cur.Store(snap)
	return errs
}

func compile(e store.AllowEntry) (*Entry, error) {
	c := &Entry{AllowEntry: e}
	switch {
	case e.IP != "":
		a, err := netip.ParseAddr(e.IP)
		if err != nil {
			return nil, err
		}
		a = a.Unmap()
		c.Prefix = netip.PrefixFrom(a, a.BitLen())
	case e.CIDR != "":
		p, err := netip.ParsePrefix(e.CIDR)
		if err != nil {
			return nil, err
		}
		c.Prefix = p.Masked()
	case e.Host == "":
		return nil, errors.New("needs ip, cidr or host")
	}
	if e.Level != NoBlock && e.Level != BypassWAF {
		return nil, fmt.Errorf("level %q", e.Level)
	}
	if e.Expires != "" && e.Expires != "never" {
		t, err := time.Parse(time.RFC3339, e.Expires)
		if err != nil {
			return nil, fmt.Errorf("expires: %w", err)
		}
		c.Until = t
	}
	return c, nil
}

// Match returns the strongest level that applies to addr ("" = none).
func (l *List) Match(addr netip.Addr, now time.Time) (string, *Entry) {
	addr = addr.Unmap()
	level, match := "", (*Entry)(nil)
	for _, e := range l.cur.Load().entries {
		if e.Expired(now) {
			continue
		}
		hit := e.Prefix.IsValid() && e.Prefix.Contains(addr)
		if !hit {
			for _, r := range e.Resolved {
				if r.Unmap() == addr {
					hit = true
					break
				}
			}
		}
		if !hit {
			continue
		}
		if e.Level == BypassWAF {
			return BypassWAF, e
		}
		level, match = NoBlock, e
	}
	return level, match
}

// Entries returns the compiled entries.
func (l *List) Entries() []*Entry { return l.cur.Load().entries }

// RefreshDNS resolves every host entry (never in the request path). The
// resolved addresses are swapped as a new map, never written into the one in
// use: Set and other refreshes read it without the lock.
func (l *List) RefreshDNS(ctx context.Context) {
	snap := l.cur.Load()
	l.mu.Lock()
	hosts := maps.Clone(l.hosts)
	l.mu.Unlock()
	if hosts == nil {
		hosts = map[string][]netip.Addr{}
	}
	seen := map[string]bool{}
	for _, e := range snap.entries {
		if e.Host == "" || seen[e.Host] {
			continue
		}
		seen[e.Host] = true
		cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		addrs, err := l.Resolver(cctx, e.Host)
		cancel()
		if err != nil {
			continue // keep the last known addresses
		}
		sort.Slice(addrs, func(i, j int) bool { return addrs[i].Less(addrs[j]) })
		hosts[e.Host] = addrs
	}
	l.mu.Lock()
	l.hosts = hosts
	l.mu.Unlock()
	next := &snapshot{}
	for _, e := range snap.entries {
		c := *e
		if c.Host != "" {
			c.Resolved = hosts[c.Host]
		}
		next.entries = append(next.entries, &c)
	}
	l.cur.CompareAndSwap(snap, next)
}

var hostRe = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,62}\.)+[A-Za-z]{2,63}$`)

// ErrTooBroad is returned for ranges that would switch the WAF off for large parts of the internet.
var ErrTooBroad = errors.New("range too broad (IPv4 at least /8, IPv6 at least /32)")

// Input is a new entry from the dashboard or CLI.
type Input struct {
	IP, CIDR, Host, Label, Level, TTL string
}

// Validate checks an input and builds the entry. Field names in errors
// match the API (ip, cidr, host, label, level, ttl).
func Validate(in Input, now time.Time) (*store.AllowEntry, map[string]string) {
	errs := map[string]string{}
	n := 0
	for _, v := range []string{in.IP, in.CIDR, in.Host} {
		if v != "" {
			n++
		}
	}
	if n != 1 {
		errs["ip"] = "exactly one of ip, cidr or host"
	}
	e := &store.AllowEntry{Label: in.Label, Level: in.Level, CreatedAt: now}
	if in.IP != "" {
		a, err := netip.ParseAddr(in.IP)
		if err != nil {
			errs["ip"] = "not an IP address"
		} else {
			e.IP = a.Unmap().String()
		}
	}
	if in.CIDR != "" {
		p, err := netip.ParsePrefix(in.CIDR)
		switch {
		case err != nil:
			errs["cidr"] = "not a CIDR range"
		case (p.Addr().Is4() && p.Bits() < 8) || (!p.Addr().Is4() && p.Bits() < 32):
			errs["cidr"] = ErrTooBroad.Error()
		default:
			e.CIDR = p.Masked().String()
		}
	}
	if in.Host != "" {
		if !hostRe.MatchString(in.Host) {
			errs["host"] = "not a host name"
		} else {
			e.Host = in.Host
		}
	}
	if l := len(in.Label); l < 1 || l > 64 {
		errs["label"] = "1 to 64 characters"
	}
	if in.Level != NoBlock && in.Level != BypassWAF {
		errs["level"] = "no_block or bypass_waf"
	}
	exp, err := Expiry(in.TTL, now)
	if err != nil {
		errs["ttl"] = err.Error()
	}
	e.Expires = exp
	if len(errs) > 0 {
		return nil, errs
	}
	return e, nil
}

// Expiry maps a TTL (24h, 7d, 30d, never) to the stored expiry.
func Expiry(ttl string, now time.Time) (string, error) {
	var d time.Duration
	switch ttl {
	case "", "never":
		return "never", nil
	case "24h":
		d = 24 * time.Hour
	case "7d":
		d = 7 * 24 * time.Hour
	case "30d":
		d = 30 * 24 * time.Hour
	default:
		return "", errors.New("24h, 7d, 30d or never")
	}
	return msg.FormatTime(now.Add(d)), nil
}
