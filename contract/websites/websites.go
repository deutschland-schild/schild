// Package websites is the v0.5 contract (DECISIONS D36) of the website model
// of the dashboards: which websites a gateway serves, their stable ids, how
// a request host maps to one of them, and the status rules ("ok", "bitte
// ansehen", "gestört", "keine Messwerte"). The gateway derives its websites
// at every config load; the client dashboard and agent APIs list them
// (listWebsites, getWebsite) and filter by them (parameter site); the MVP-20
// central dashboard merges the same website id across gateways.
// contracts/tools/crosscheck.py implements the same rules independently; the
// website-derive and website-status vectors keep both in step.
package websites

import (
	"net"
	"net/netip"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/jsonx"
	"github.com/deutschland-schild/schild/contract/schema"
)

// Vector input schemas.
const (
	SchemaDerive = "website-derive"
	SchemaStatus = "website-status"
)

// Limits.
const (
	MaxInputBytes = 1 << 20
	// MaxTracked websites have their own series in the monitoring rings
	// (contract/monitoring MaxSites); the traffic of the others is summed as
	// OtherSite.
	MaxTracked = 32
	// MaxHostLen of a normalised host.
	MaxHostLen = 253
)

// Reserved ids.
const (
	// DefaultID is the one website of a proxy-mode gateway without
	// upstream.site_hosts. It is local to its gateway: the central dashboard
	// never merges "default" across gateways.
	DefaultID = "default"
	// AnyID is the website of site blocks without a host (":443",
	// "http://"): they serve every host no other block names.
	AnyID = "_any"
	// OtherSite sums the untracked websites in the monitoring rings.
	OtherSite = "_other"
)

// Modes of the derivation.
const (
	ModeIngress = "ingress"
	ModeProxy   = "proxy"
)

// Protection of a website.
const (
	Protected   = "protected"   // every block of it runs schild
	Partial     = "partial"     // some blocks run schild, others are listed unprotected
	Unprotected = "unprotected" // listed in ingress.unprotected_sites only: schild sees none of its requests
)

// Block is one Caddyfile site block (ingress mode).
type Block struct {
	Addresses []string
	// Schild: the block runs the schild handler in front of what it serves.
	Schild bool
	// Proxies: the block reaches a backend (reverse_proxy, php_fastcgi).
	Proxies bool
}

// Input of Derive.
type Input struct {
	Mode             string
	Blocks           []Block
	UnprotectedSites []string
	// SiteHosts is upstream.site_hosts (proxy mode).
	SiteHosts []string
}

// Website is one derived website.
type Website struct {
	ID         string   `json:"id"`
	Label      string   `json:"label"`
	Hosts      []string `json:"hosts"`
	Protection string   `json:"protection"`
	Tracked    bool     `json:"tracked"`
}

// Set is the result of Derive: the websites in order and the host index
// Resolve uses.
type Set struct {
	Mode     string
	Websites []Website
	exact    map[string]int
	wild     []wildHost
	any      int
}

type wildHost struct {
	labels []string
	site   int
	stars  int
}

func schemaErr(format string, args ...any) error {
	return contract.Errf(contract.CodeSchema, format, args...)
}

func configErr(format string, args ...any) error {
	return contract.Errf(contract.CodeConfig, format, args...)
}

// host kinds of a parsed address.
const (
	kindName = iota
	kindIPv4
	kindIPv6
	kindAny
)

// Host is a normalised host: Key is what websites are merged and resolved
// by (A-labels, "*" for a wildcard label, IP literal in canonical form, ""
// for every host).
type Host struct {
	Key  string
	kind int
}

// ID returns the website id derived from h: the key with every "*" label
// written "_", an IPv6 literal as "ipv6-" + its canonical form with ":"
// replaced by "-", and AnyID for every host.
func (h Host) ID() string {
	switch h.kind {
	case kindAny:
		return AnyID
	case kindIPv6:
		return "ipv6-" + strings.ReplaceAll(h.Key, ":", "-")
	case kindName:
		labels := strings.Split(h.Key, ".")
		for i, l := range labels {
			if l == "*" {
				labels[i] = "_"
			}
		}
		return strings.Join(labels, ".")
	}
	return h.Key
}

// Label returns the display name of h: A-labels decoded to Unicode where
// they decode (else kept), an IPv6 literal in brackets, AnyID for every host.
func (h Host) Label() string {
	switch h.kind {
	case kindAny:
		return AnyID
	case kindIPv6:
		return "[" + h.Key + "]"
	case kindName:
		labels := strings.Split(h.Key, ".")
		for i, l := range labels {
			if rest, ok := strings.CutPrefix(l, "xn--"); ok {
				if u, err := punyDecode(rest); err == nil && u != "" {
					labels[i] = u
				}
			}
		}
		return strings.Join(labels, ".")
	}
	return h.Key
}

// ParseAddress parses one Caddyfile site address
// ([scheme://][host][:port][/path]) and returns its normalised host.
func ParseAddress(addr string) (Host, error) {
	if addr == "" || len(addr) > 1024 || !utf8.ValidString(addr) {
		return Host{}, schemaErr("address: empty or too long")
	}
	for _, r := range addr {
		if r <= ' ' || r == 0x7f || r == '{' || r == '}' || unicode.IsSpace(r) {
			return Host{}, schemaErr("address %q: space, control character or placeholder", addr)
		}
	}
	rest := addr
	if i := strings.Index(rest, "://"); i >= 0 {
		switch asciiLower(rest[:i]) {
		case "http", "https":
		default:
			return Host{}, schemaErr("address %q: scheme must be http or https", addr)
		}
		rest = rest[i+3:]
	}
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		rest = rest[:i]
	}
	return parseHostPort(rest, true)
}

// parseHostPort parses host[:port]; port is optional.
func parseHostPort(hp string, allowWildcard bool) (Host, error) {
	host := hp
	if strings.HasPrefix(hp, "[") {
		end := strings.IndexByte(hp, ']')
		if end < 0 {
			return Host{}, schemaErr("host %q: unclosed bracket", hp)
		}
		host = hp[1:end]
		if after := hp[end+1:]; after != "" {
			p, ok := strings.CutPrefix(after, ":")
			if !ok || !validPort(p) {
				return Host{}, schemaErr("host %q: bad port", hp)
			}
		}
		a, err := netip.ParseAddr(host)
		if err != nil || !a.Is6() || a.Zone() != "" || a.Is4In6() {
			return Host{}, schemaErr("host %q: not an IPv6 address", hp)
		}
		return Host{Key: a.String(), kind: kindIPv6}, nil
	}
	if i := strings.LastIndexByte(hp, ':'); i >= 0 {
		if !validPort(hp[i+1:]) {
			return Host{}, schemaErr("host %q: bad port", hp)
		}
		host = hp[:i]
	}
	if host == "" {
		return Host{kind: kindAny}, nil
	}
	return normaliseName(host, allowWildcard)
}

func validPort(p string) bool {
	if p == "" || len(p) > 5 || p[0] == '0' {
		return false
	}
	for _, c := range p {
		if c < '0' || c > '9' {
			return false
		}
	}
	n, _ := strconv.Atoi(p)
	return n >= 1 && n <= 65535
}

func isIPv4(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if p == "" || len(p) > 3 || (len(p) > 1 && p[0] == '0') {
			return false
		}
		for _, c := range p {
			if c < '0' || c > '9' {
				return false
			}
		}
		if n, _ := strconv.Atoi(p); n > 255 {
			return false
		}
	}
	return true
}

func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}

func validLDH(l string) bool {
	if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
		return false
	}
	for _, c := range []byte(l) {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

// normaliseName: one trailing dot removed, ASCII lower-cased, non-ASCII
// labels Punycode-encoded (upper-case non-ASCII letters refused), labels
// LDH or "*" (when allowed), at most 253 bytes.
func normaliseName(host string, allowWildcard bool) (Host, error) {
	host = strings.TrimSuffix(host, ".")
	if host == "" {
		return Host{}, schemaErr("host: empty name")
	}
	host = asciiLower(host)
	if isIPv4(host) {
		return Host{Key: host, kind: kindIPv4}, nil
	}
	labels := strings.Split(host, ".")
	for i, l := range labels {
		if l == "*" {
			if !allowWildcard {
				return Host{}, schemaErr("host %q: wildcard", host)
			}
			continue
		}
		ascii := true
		for _, r := range l {
			if r >= 0x80 {
				ascii = false
				if unicode.IsUpper(r) {
					return Host{}, schemaErr("host %q: upper-case non-ASCII letter", host)
				}
			}
		}
		if !ascii {
			enc, err := punyEncode(l)
			if err != nil {
				return Host{}, schemaErr("host %q: punycode", host)
			}
			l = "xn--" + enc
			labels[i] = l
		}
		if !validLDH(l) {
			return Host{}, schemaErr("host %q: label %q", host, l)
		}
	}
	key := strings.Join(labels, ".")
	if len(key) > MaxHostLen {
		return Host{}, schemaErr("host: longer than %d bytes", MaxHostLen)
	}
	return Host{Key: key, kind: kindName}, nil
}

// listed reports whether host is covered by ingress.unprotected_sites: an
// exact name or "*.suffix" for one more label (caddymod.HostListed).
func listed(h string, list []string) bool {
	for _, e := range list {
		e = asciiLower(e)
		if e == h {
			return true
		}
		if suffix, ok := strings.CutPrefix(e, "*"); ok && strings.HasPrefix(suffix, ".") && strings.HasSuffix(h, suffix) {
			label := strings.TrimSuffix(h, suffix)
			if label != "" && !strings.Contains(label, ".") {
				return true
			}
		}
	}
	return false
}

type group struct {
	first     int // index of the earliest block
	hosts     []Host
	protected int
	listed    int
}

// Derive returns the websites of a gateway.
//
// Ingress: every site block that runs schild, or that proxies and is listed
// in ingress.unprotected_sites (all of its hosts), counts; a block that
// proxies without schild and is not listed is a config error (the MVP-19
// validator refuses it); other blocks (redirects, static files, probes)
// are no websites. Counting blocks that share a normalised host (scheme,
// port and path ignored) are one website. The id is derived from the first
// host of the earliest block. Websites are in the order of their earliest
// block; the first MaxTracked websites that schild sees are tracked.
//
// Proxy: one website; with upstream.site_hosts its id is derived from the
// first of them, else DefaultID.
func Derive(in Input) (*Set, error) {
	s := &Set{Mode: in.Mode, exact: map[string]int{}, any: -1}
	switch in.Mode {
	case ModeProxy:
		w := Website{ID: DefaultID, Label: DefaultID, Hosts: []string{}, Protection: Protected, Tracked: true}
		seen := map[string]bool{}
		for i, a := range in.SiteHosts {
			h, err := normaliseName(a, true)
			if err != nil {
				return nil, err
			}
			if i == 0 {
				w.ID, w.Label = h.ID(), h.Label()
			}
			if !seen[h.Key] {
				seen[h.Key] = true
				w.Hosts = append(w.Hosts, h.Key)
				s.index(h.Key, 0)
			}
		}
		s.Websites = []Website{w}
		return s, nil
	case ModeIngress:
	default:
		return nil, schemaErr("mode %q", in.Mode)
	}
	// Parse every address first, so a malformed address is a schema error
	// whatever block it is in.
	parsed := make([][]Host, len(in.Blocks))
	for i, b := range in.Blocks {
		for _, a := range b.Addresses {
			h, err := ParseAddress(a)
			if err != nil {
				return nil, err
			}
			parsed[i] = append(parsed[i], h)
		}
	}
	// Counting blocks; blocks that share a host are joined (union-find).
	counting := make([]bool, len(in.Blocks))
	parent := make([]int, len(in.Blocks))
	for i := range parent {
		parent[i] = i
	}
	var find func(int) int
	find = func(i int) int {
		for parent[i] != i {
			i = parent[i]
		}
		return i
	}
	owner := map[string]int{}
	for i, b := range in.Blocks {
		isListed := true
		for _, h := range parsed[i] {
			if h.kind == kindAny || !listed(h.Key, in.UnprotectedSites) {
				isListed = false
			}
		}
		switch {
		case b.Schild:
		case b.Proxies && isListed:
		case b.Proxies:
			return nil, configErr("block %d reaches a backend without schild and is not in ingress.unprotected_sites", i+1)
		default:
			continue // no website: redirects, static files, probe blocks
		}
		counting[i] = true
		for _, h := range parsed[i] {
			if j, ok := owner[h.Key]; ok {
				a, b := find(i), find(j)
				if a < b {
					a, b = b, a
				}
				parent[a] = b // the root is always the earliest block
			} else {
				owner[h.Key] = i
			}
		}
	}
	groups := map[int]*group{}
	var order []*group
	for i := range in.Blocks {
		if !counting[i] {
			continue
		}
		r := find(i)
		g := groups[r]
		if g == nil {
			g = &group{first: r}
			groups[r] = g
			order = append(order, g)
		}
		for _, h := range parsed[i] {
			g.hosts = appendHost(g.hosts, h)
		}
		if in.Blocks[i].Schild {
			g.protected++
		} else {
			g.listed++
		}
	}
	tracked := 0
	for _, g := range order {
		// Named by its first host; host-less addresses name it only when it
		// has no host at all.
		name := Host{kind: kindAny}
		for _, h := range g.hosts {
			if h.kind != kindAny {
				name = h
				break
			}
		}
		w := Website{ID: name.ID(), Label: name.Label(), Hosts: []string{}, Protection: Protected}
		switch {
		case g.protected == 0:
			w.Protection = Unprotected
		case g.listed > 0:
			w.Protection = Partial
		}
		if w.Protection != Unprotected && tracked < MaxTracked {
			w.Tracked = true
			tracked++
		}
		idx := len(s.Websites)
		for _, h := range g.hosts {
			if h.kind == kindAny {
				s.any = idx
				continue
			}
			w.Hosts = append(w.Hosts, h.Key)
			s.index(h.Key, idx)
		}
		s.Websites = append(s.Websites, w)
	}
	return s, nil
}

// index adds a normalised host of website idx to the lookup tables.
func (s *Set) index(key string, idx int) {
	if strings.Contains(key, "*") {
		s.wild = append(s.wild, wildHost{labels: strings.Split(key, "."), site: idx, stars: strings.Count(key, "*")})
		return
	}
	s.exact[key] = idx
}

// appendHost appends h unless hs has it (order of first appearance in the
// blocks of the website, in file order).
func appendHost(hs []Host, h Host) []Host {
	for _, x := range hs {
		if x.Key == h.Key {
			return hs
		}
	}
	return append(hs, h)
}

// Resolve maps the Host of a request to a website id ("" when none): in
// proxy mode always the one website; in ingress mode an exact host, else
// the matching wildcard host with the fewest "*" labels (earliest website
// on a tie), else the website of host-less blocks.
//
// In ingress mode the Host is read the way Caddy's host matcher reads it
// (D69), so a Host spelling Caddy routes to a site block never resolves to
// another website or to none: the port is cut off unchecked, brackets are
// stripped from any name, letters compare case-insensitively as Go's
// strings.EqualFold does, and a "*" label of a wildcard host matches any
// content (also "", "_" or "*").
func (s *Set) Resolve(hostHeader string) string {
	if s.Mode == ModeProxy {
		return s.Websites[0].ID
	}
	name := strings.TrimSuffix(foldHost(requestHost(hostHeader)), ".")
	if name == "" {
		return s.anyID()
	}
	if a, err := netip.ParseAddr(name); err == nil && a.Is6() {
		name = a.String()
	}
	if i, ok := s.exact[name]; ok {
		return s.Websites[i].ID
	}
	if i := s.matchWild(strings.Split(name, ".")); i >= 0 {
		return s.Websites[i].ID
	}
	return s.anyID()
}

// requestHost is the host of a request Host header as Caddy's host matcher
// takes it (caddyhttp.MatchHost): net.SplitHostPort with the port never
// checked, else the whole value with one "[" and one "]" stripped.
func requestHost(hostHeader string) string {
	if h, _, err := net.SplitHostPort(hostHeader); err == nil {
		return h
	}
	return strings.TrimSuffix(strings.TrimPrefix(hostHeader, "["), "]")
}

// hostFold maps the only non-ASCII runes that Go's strings.EqualFold or
// strings.ToLower (Caddy's host matcher with more than 100 hosts) take for
// an ASCII letter: the Kelvin sign, the long s and the capital I with dot.
var hostFold = strings.NewReplacer("K", "k", "ſ", "s", "İ", "i")

// foldHost lower-cases a request host for comparing it with the ASCII keys
// of the websites as Caddy compares it with the site addresses.
func foldHost(h string) string {
	for i := 0; i < len(h); i++ {
		if h[i] >= utf8.RuneSelf {
			h = hostFold.Replace(h)
			break
		}
	}
	return asciiLower(h)
}

// RouteWebsite returns the website of a Caddy route whose host matchers list
// hosts (as the adapted config writes them), "" when they name no website
// or more than one. In ingress mode the gate decides a request by the
// website of the route Caddy chose (D69), not by its Host header.
func (s *Set) RouteWebsite(hosts []string) string {
	id := ""
	for _, h := range hosts {
		i, ok := s.owner(h)
		if !ok || id != "" && s.Websites[i].ID != id {
			return ""
		}
		id = s.Websites[i].ID
	}
	return id
}

// owner returns the website that lists host (an exact or a wildcard site
// address, not a request host).
func (s *Set) owner(host string) (int, bool) {
	key := ""
	if a, err := netip.ParseAddr(strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")); err == nil && a.Is6() {
		key = a.String()
	} else if h, err := normaliseName(host, true); err == nil {
		key = h.Key
	} else {
		return -1, false
	}
	if i, ok := s.exact[key]; ok {
		return i, true
	}
	for _, w := range s.wild {
		if strings.Join(w.labels, ".") == key {
			return w.site, true
		}
	}
	return -1, false
}

// match returns the website whose exact host, else whose wildcard host with
// the fewest "*" labels (earliest website on a tie) matches h; -1 for none.
// The host-less catch-all never matches here.
func (s *Set) match(h Host) int {
	if i, ok := s.exact[h.Key]; ok {
		return i
	}
	if h.kind != kindName {
		return -1
	}
	return s.matchWild(strings.Split(h.Key, "."))
}

// matchWild returns the website whose wildcard host with the fewest "*"
// labels (earliest website on a tie) matches labels; -1 for none.
func (s *Set) matchWild(labels []string) int {
	best, bestStars := -1, 0
	for _, w := range s.wild {
		if len(w.labels) != len(labels) {
			continue
		}
		ok := true
		for i, l := range w.labels {
			if l != "*" && l != labels[i] {
				ok = false
				break
			}
		}
		if ok && (best < 0 || w.stars < bestStars || w.stars == bestStars && w.site < best) {
			best, bestStars = w.site, w.stars
		}
	}
	return best
}

// OwnHost reports whether a host (as in a Referer: name or IP literal, an
// optional port, case and one trailing dot ignored) is a host of any website
// of this gateway, protected or not: an exact host or a wildcard host of a
// website (ingress mode), or of upstream.site_hosts (proxy mode). The
// host-less catch-all (_any) and the proxy default without site_hosts own
// nothing. D36 amendment (2026-10-29): a Referer from such a host is the
// referrer key _intern (OpenAPI ReferrerKey), so moving between two apps on
// one gateway is internal traffic, not a referral.
func (s *Set) OwnHost(host string) bool {
	h, err := parseHostPort(host, false)
	if err != nil || h.kind == kindAny {
		return false
	}
	return s.match(h) >= 0
}

func (s *Set) anyID() string {
	if s.any >= 0 {
		return s.Websites[s.any].ID
	}
	return ""
}

// DeriveResult is the vector result of a website-derive vector.
type DeriveResult struct {
	Websites []Website `json:"websites"`
	Resolved []*string `json:"resolved,omitempty"`
	// Own (D36 amendment 2026-10-29): Set.OwnHost of each own_hosts entry.
	Own []bool `json:"own,omitempty"`
}

// RunDeriveVector parses and validates a website-derive vector input and
// returns the derived websites (and the resolved hosts when asked).
func RunDeriveVector(raw []byte) (DeriveResult, error) {
	v, err := parse(raw, SchemaDerive)
	if err != nil {
		return DeriveResult{}, err
	}
	in := Input{Mode: v["mode"].(string)}
	for _, x := range arr(v["blocks"]) {
		b := x.(map[string]any)
		blk := Block{Schild: b["schild"].(bool), Proxies: b["proxies"].(bool)}
		for _, a := range arr(b["addresses"]) {
			blk.Addresses = append(blk.Addresses, a.(string))
		}
		in.Blocks = append(in.Blocks, blk)
	}
	in.UnprotectedSites = strs(v["unprotected_sites"])
	in.SiteHosts = strs(v["site_hosts"])
	set, err := Derive(in)
	if err != nil {
		return DeriveResult{}, err
	}
	out := DeriveResult{Websites: set.Websites}
	if r, ok := v["resolve"]; ok {
		out.Resolved = []*string{}
		for _, h := range arr(r) {
			id := set.Resolve(h.(string))
			if id == "" {
				out.Resolved = append(out.Resolved, nil)
			} else {
				out.Resolved = append(out.Resolved, &id)
			}
		}
	}
	if r, ok := v["own_hosts"]; ok {
		out.Own = []bool{}
		for _, h := range arr(r) {
			out.Own = append(out.Own, set.OwnHost(h.(string)))
		}
	}
	return out, nil
}

func parse(raw []byte, name string) (map[string]any, error) {
	if len(raw) > MaxInputBytes {
		return nil, contract.Errf(contract.CodeOversize, "%d bytes > %d", len(raw), MaxInputBytes)
	}
	v, err := jsonx.ParseObject(raw)
	if err != nil {
		return nil, contract.Errf(contract.CodeMalformed, "%v", err)
	}
	if err := schema.Validate(name, v); err != nil {
		return nil, err
	}
	return v, nil
}

func arr(v any) []any {
	a, _ := v.([]any)
	return a
}

func strs(v any) []string {
	var out []string
	for _, x := range arr(v) {
		out = append(out, x.(string))
	}
	return out
}
