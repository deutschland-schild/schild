// Package clientip attributes a request to a client address (G5): only the
// TCP peer, or a forwarding header when the peer is a trusted proxy. A header
// from an untrusted peer is never believed.
package clientip

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
)

// Attribution values (events.schema.json client.attribution).
const (
	TCPPeer      = "tcp_peer"
	TrustedProxy = "trusted_proxy"
)

// Resolver resolves client addresses.
type Resolver struct {
	trusted []netip.Prefix
	headers []string
	broad   []string // ranges too broad to believe (G5, D40)
}

// DefaultHeaders is used when the peer is trusted and no header is configured
// (inner mode behind nginx/Caddy on loopback).
var DefaultHeaders = []string{"X-Forwarded-For"}

// New builds a resolver from ingress.trusted_proxies and ingress.client_ip_headers.
// With a too broad range in the list nobody counts as a proxy (TooBroad): a
// forwarding header would let any client pick an address, also a victim's
// that then gets blocked, so attribution falls back to the TCP peer.
func New(trustedProxies, headers []string) (*Resolver, error) {
	r := &Resolver{}
	for _, c := range trustedProxies {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			return nil, fmt.Errorf("clientip: trusted proxy %q: %w", c, err)
		}
		p = p.Masked()
		r.trusted = append(r.trusted, p)
		if (p.Addr().Is4() && p.Bits() < 8) || (!p.Addr().Is4() && p.Bits() < 32) {
			r.broad = append(r.broad, p.String())
		}
	}
	r.headers = headers
	if len(r.headers) == 0 {
		r.headers = DefaultHeaders
	}
	return r, nil
}

// TooBroad reports trusted proxy ranges that would let anybody spoof a client
// address (G5): anything shorter than /8 (IPv4) or /32 (IPv6). While it
// reports any, forwarding headers are ignored (see New).
func (r *Resolver) TooBroad() []string { return r.broad }

// Trusted reports whether addr is a trusted proxy. Nobody is while the list
// is too broad.
func (r *Resolver) Trusted(addr netip.Addr) bool {
	if len(r.broad) > 0 {
		return false
	}
	addr = addr.Unmap()
	for _, p := range r.trusted {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// TrustedOverlaps reports whether p shares an address with a trusted proxy
// range (a proxy inside a blocked IPv6 /64 counts). Nobody is trusted while
// the list is too broad.
func (r *Resolver) TrustedOverlaps(p netip.Prefix) bool {
	if len(r.broad) > 0 || !p.IsValid() {
		return false
	}
	p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()).Masked()
	for _, t := range r.trusted {
		if t.Overlaps(p) {
			return true
		}
	}
	return false
}

// Result of attribution.
type Result struct {
	IP          netip.Addr
	Port        int
	Attribution string
	Peer        netip.Addr
	// Ignored: the peer is a private or loopback address that is not a
	// trusted proxy, and the request carries a forwarding header (D91, see
	// Watch). Not set while the list is too broad, which has its own hint.
	Ignored bool
}

// Peer parses r.RemoteAddr.
func Peer(remoteAddr string) (netip.Addr, int) {
	host, port, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	a, err := netip.ParseAddr(strings.Trim(host, "[]"))
	if err != nil {
		return netip.Addr{}, 0
	}
	p, _ := strconv.Atoi(port)
	return a.Unmap().WithZone(""), p
}

// Resolve attributes the request.
func (r *Resolver) Resolve(req *http.Request) Result {
	peer, port := Peer(req.RemoteAddr)
	res := Result{IP: peer, Port: port, Attribution: TCPPeer, Peer: peer}
	if !peer.IsValid() {
		return res
	}
	if !r.Trusted(peer) {
		if len(r.broad) == 0 && (peer.IsPrivate() || peer.IsLoopback()) {
			for _, h := range r.headers {
				if req.Header.Get(h) != "" {
					res.Ignored = true
					break
				}
			}
		}
		return res
	}
	for _, h := range r.headers {
		vals := req.Header.Values(h)
		if len(vals) == 0 {
			continue
		}
		if client, ok := r.client(vals, strings.EqualFold(h, "forwarded")); ok {
			return Result{IP: client, Attribution: TrustedProxy, Peer: peer}
		}
	}
	return res
}

// client walks the hops of a forwarding header from the right (the last
// header line first): trusted proxies are skipped, the first untrusted
// address is the client; if all are trusted, the leftmost. Only the hops
// walked have to parse: what stands left of the client came from the client
// itself, and garbage there ("X-Forwarded-For: x") must not move the
// attribution to the proxy, where a block would hit every visitor. A hop that
// does not parse before the client is found: no guess (false). The walk cuts
// the values in place, so a header of many hops costs no allocation.
func (r *Resolver) client(vals []string, forwarded bool) (netip.Addr, bool) {
	var last netip.Addr
	for i := len(vals) - 1; i >= 0; i-- {
		v := vals[i]
		for v != "" {
			hop := v
			v = ""
			if j := strings.LastIndexByte(hop, ','); j >= 0 {
				v, hop = hop[:j], hop[j+1:]
			}
			if forwarded {
				hop = forwardedFor(hop)
			}
			if hop = strings.TrimSpace(hop); hop == "" {
				continue
			}
			a, ok := parseAddr(hop)
			if !ok {
				return netip.Addr{}, false
			}
			if !r.Trusted(a) {
				return a, true
			}
			last = a
		}
	}
	return last, last.IsValid()
}

// forwardedFor returns the for= value of one Forwarded element (RFC 7239),
// "" without one.
func forwardedFor(elem string) string {
	for elem != "" {
		var pair string
		pair, elem, _ = strings.Cut(elem, ";")
		if k, val, ok := strings.Cut(strings.TrimSpace(pair), "="); ok && strings.EqualFold(k, "for") {
			return strings.Trim(val, `"`)
		}
	}
	return ""
}

func parseAddr(s string) (netip.Addr, bool) {
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap.Addr().Unmap().WithZone(""), true
	}
	s = strings.TrimPrefix(strings.TrimSuffix(s, "]"), "[")
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, false
	}
	return a.Unmap().WithZone(""), true
}

// Truncate shortens an address for retention: IPv4 to /24, IPv6 to /48.
func Truncate(a netip.Addr) netip.Addr {
	a = a.Unmap()
	bits := 48
	if a.Is4() {
		bits = 24
	}
	p, err := a.Prefix(bits)
	if err != nil {
		return a
	}
	return p.Addr()
}

// Key renders a fixed-width sortable key (32 hex digits of the 16-byte form)
// so CIDR filters become range queries.
func Key(a netip.Addr) string {
	b := a.As16()
	const hex = "0123456789abcdef"
	out := make([]byte, 32)
	for i, c := range b {
		out[2*i] = hex[c>>4]
		out[2*i+1] = hex[c&0xf]
	}
	return string(out)
}

// Range returns the key range [lo, hi] of a prefix.
func Range(p netip.Prefix) (string, string) {
	p = p.Masked()
	lo := p.Addr()
	b := lo.As16()
	bits := p.Bits()
	if lo.Is4() {
		bits += 96
	}
	for i := 0; i < 16; i++ {
		for j := 0; j < 8; j++ {
			if i*8+j >= bits {
				b[i] |= 1 << (7 - j)
			}
		}
	}
	return Key(lo), Key(netip.AddrFrom16(b))
}
