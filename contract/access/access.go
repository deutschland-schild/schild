// Package access is the contract of the access lock (D56, MVP-14 step 1): a
// website, or some of its paths, only for people with a shared password
// and/or from listed addresses or the own networks of the allowlist. Every
// condition set must hold (D58). Everyone else gets a maintenance page (scope
// site) or a login page (scope paths), and nothing of theirs reaches the app.
// A protection is on until it is removed.
//
// The rules are fixed by the access-gate vectors (Go and Python agree): how a
// request path is compared (CanonicalPath, Protected, Excepted) and who passes
// (Decide). The session cookie (session.go) and the file `schild front` reads
// while schild is down (active.go) have Go tests only.
package access

import (
	"net/netip"
	"regexp"
	"strings"

	"github.com/deutschland-schild/schild/contract"
)

// Scopes.
const (
	// ScopeSite: the whole website needs a way in, everyone else gets the
	// maintenance page.
	ScopeSite = "site"
	// ScopePaths: only the listed paths need a way in.
	ScopePaths = "paths"
)

// Limits.
const (
	MaxPaths      = 32
	MaxExcept     = 16
	MaxAddresses  = 64
	MaxPathLen    = 255
	MaxMessageLen = 500
	// MinIPv4Bits and MinIPv6Bits: the widest network one entry may name.
	MinIPv4Bits = 16
	MinIPv6Bits = 32
	// Password length in bytes.
	MinPasswordLen = 8
	MaxPasswordLen = 128
)

// Protection is the access lock of one website as the contract sees it. The
// password itself (its Argon2id hash) is not part of it, only whether one is
// set.
type Protection struct {
	Website     string   `json:"website"`
	Scope       string   `json:"scope"`
	Paths       []string `json:"paths,omitempty"`
	Except      []string `json:"except,omitempty"`
	Password    bool     `json:"password"`
	Addresses   []string `json:"addresses,omitempty"`
	OwnNetworks bool     `json:"own_networks"`
	Message     string   `json:"message,omitempty"`
}

// FieldError names the field a validation failed on.
type FieldError struct {
	Field string
	Msg   string
}

func (e *FieldError) Error() string { return e.Field + ": " + e.Msg }

func fieldErr(field, msg string) *FieldError { return &FieldError{Field: field, Msg: msg} }

// patternRe: a path as the operator writes it, optionally ending in /* for
// everything below. No percent escapes, no backslash, no other wildcard.
var patternRe = regexp.MustCompile(`^/[A-Za-z0-9._~!$&'()+,;=:@/-]*(/\*)?$`)

// exceptRe: an except path is plain: no escapes, no ';', no wildcard but a
// trailing /*.
var exceptRe = regexp.MustCompile(`^/[A-Za-z0-9._~!$&'()+,=:@/-]*(/\*)?$`)

// CheckShape checks p: scope and the fields it allows,
// paths, except paths, addresses, a way in, the message. The access-gate
// vectors fix it.
func (p Protection) CheckShape() error {
	switch p.Scope {
	case ScopeSite:
		if len(p.Paths) > 0 {
			return fieldErr("paths", "only with scope paths")
		}
	case ScopePaths:
		if len(p.Paths) == 0 {
			return fieldErr("paths", "at least one path")
		}
		if len(p.Except) > 0 {
			return fieldErr("except", "only with scope site")
		}
	default:
		return fieldErr("scope", "site or paths")
	}
	if len(p.Paths) > MaxPaths {
		return fieldErr("paths", "too many")
	}
	for _, s := range p.Paths {
		if err := checkPattern(s, patternRe); err != nil {
			return fieldErr("paths", err.Error())
		}
		if s == "/*" {
			return fieldErr("paths", "/* is the whole website: use scope site")
		}
	}
	if len(p.Except) > MaxExcept {
		return fieldErr("except", "too many")
	}
	for _, s := range p.Except {
		if err := checkPattern(s, exceptRe); err != nil {
			return fieldErr("except", err.Error())
		}
		if !plain(strings.TrimSuffix(s, "/*")) || s == "/*" || s == "/" {
			return fieldErr("except", "a plain path below the root")
		}
	}
	if len(p.Addresses) > MaxAddresses {
		return fieldErr("addresses", "too many")
	}
	for _, a := range p.Addresses {
		if _, err := ParseAddress(a); err != nil {
			return fieldErr("addresses", err.Error())
		}
	}
	if !p.Password && len(p.Addresses) == 0 && !p.OwnNetworks {
		return fieldErr("password", "a password, an address or own networks")
	}
	if len(p.Message) > MaxMessageLen {
		return fieldErr("message", "too long")
	}
	for _, r := range p.Message {
		if (r < 0x20 && r != '\n') || r == 0x7f {
			return fieldErr("message", "control character")
		}
	}
	return nil
}

func checkPattern(s string, re *regexp.Regexp) error {
	if len(s) > MaxPathLen {
		return contract.Errf(contract.CodeSchema, "path too long")
	}
	if !re.MatchString(s) {
		return contract.Errf(contract.CodeSchema, "path %q: starts with /, no escapes, * only as /* at the end", s)
	}
	return nil
}

// ParseAddress parses one address entry: an IP or a network with its host
// bits zero. IPv4 up to /16, IPv6 up to /32; no zone, no IPv4 in IPv6.
func ParseAddress(s string) (netip.Prefix, error) {
	bad := func(msg string) (netip.Prefix, error) {
		return netip.Prefix{}, contract.Errf(contract.CodeSchema, "address %q: %s", s, msg)
	}
	if strings.ContainsAny(s, "% ") || len(s) > 64 {
		return bad("not an IP or network")
	}
	var pf netip.Prefix
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return bad("not an IP or network")
		}
		if p.Masked() != p {
			return bad("host bits set")
		}
		pf = p
	} else {
		a, err := netip.ParseAddr(s)
		if err != nil {
			return bad("not an IP or network")
		}
		pf = netip.PrefixFrom(a, a.BitLen())
	}
	if pf.Addr().Is4In6() {
		return bad("IPv4 in IPv6")
	}
	if pf.Addr().Is4() && pf.Bits() < MinIPv4Bits || pf.Addr().Is6() && pf.Bits() < MinIPv6Bits {
		return bad("network too wide")
	}
	return pf, nil
}

// ---------------------------------------------------------------- paths

// maxDecode bounds how often a path is percent-decoded.
const maxDecode = 4

// CanonicalPath is the form a request path is compared in when it decides
// whether a path is protected. raw is the path as received, in its escaped
// form, without the query. When in doubt a path counts as protected, so the
// form folds every spelling an app might read as the same path:
//
//  1. percent-decode until nothing changes, at most 4 times (an invalid
//     escape stays as it is);
//  2. backslash is a slash;
//  3. per segment: a NUL ends it, a ';' starts parameters that are cut;
//     an empty segment and "." are dropped, ".." drops the one before
//     (never above the root); trailing dots and spaces are cut, and a
//     segment that is nothing else is dropped;
//  4. ASCII upper case to lower case;
//  5. bytes outside '!'..'~' and '%' are written as %XX (upper-case hex).
//
// The result starts with "/" and never ends with one, except the root.
func CanonicalPath(raw string) string {
	s := raw
	for i := 0; i < maxDecode; i++ {
		d := percentDecode(s)
		if d == s {
			break
		}
		s = d
	}
	s = strings.ReplaceAll(s, `\`, "/")
	var segs []string
	for _, seg := range strings.Split(s, "/") {
		if i := strings.IndexByte(seg, 0); i >= 0 {
			seg = seg[:i]
		}
		if i := strings.IndexByte(seg, ';'); i >= 0 {
			seg = seg[:i]
		}
		switch seg {
		case "", ".":
			continue
		case "..":
			if len(segs) > 0 {
				segs = segs[:len(segs)-1]
			}
			continue
		}
		seg = strings.TrimRight(seg, ". ")
		if seg == "" {
			continue
		}
		segs = append(segs, seg)
	}
	var b strings.Builder
	b.WriteByte('/')
	for i, seg := range segs {
		if i > 0 {
			b.WriteByte('/')
		}
		for j := 0; j < len(seg); j++ {
			c := seg[j]
			switch {
			case c >= 'A' && c <= 'Z':
				b.WriteByte(c + 32)
			case c < '!' || c > '~' || c == '%':
				const hex = "0123456789ABCDEF"
				b.WriteByte('%')
				b.WriteByte(hex[c>>4])
				b.WriteByte(hex[c&15])
			default:
				b.WriteByte(c)
			}
		}
	}
	return b.String()
}

func unhex(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// percentDecode decodes every valid %XX once; anything else stays.
func percentDecode(s string) string {
	if strings.IndexByte(s, '%') < 0 {
		return s
	}
	b := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			hi, ok1 := unhex(s[i+1])
			lo, ok2 := unhex(s[i+2])
			if ok1 && ok2 {
				b = append(b, hi<<4|lo)
				i += 2
				continue
			}
		}
		b = append(b, s[i])
	}
	return string(b)
}

// Protected reports whether the request path raw falls under one of the
// patterns: equal to a pattern or below it. A pattern covers what lies below
// it with or without /* (D70): PHP and CGI backends run /x.php for
// /x.php/anything (path info), so that is the same resource. Only the root
// "/" covers nothing below it; "/*" covers everything. Both sides are
// compared in the canonical form.
func Protected(raw string, patterns []string) bool {
	c := CanonicalPath(raw)
	for _, p := range patterns {
		base, below := strings.CutSuffix(p, "/*")
		cb := CanonicalPath(base)
		if c == cb || cb == "/" && below || cb != "/" && strings.HasPrefix(c, cb+"/") {
			return true
		}
	}
	return false
}

// plain reports whether a path has a single obvious reading: only the
// characters of exceptRe, no empty, "." or ".." segment and no segment ending
// in a dot.
func plain(raw string) bool {
	if !strings.HasPrefix(raw, "/") {
		return false
	}
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("._~!$&'()+,=:@/-", c) >= 0
		if !ok {
			return false
		}
	}
	if raw == "/" {
		return true
	}
	for _, seg := range strings.Split(raw[1:], "/") {
		if seg == "" || strings.HasSuffix(seg, ".") {
			return false
		}
	}
	return true
}

// Excepted reports whether the request path raw is one of the except paths
// of a site lock. An exception keeps the app reachable, so here nothing is
// folded: the path must be plain (see plain) and match case-sensitively, equal
// to an entry or below one ending in /*. Any other spelling stays locked.
func Excepted(raw string, except []string) bool {
	if !plain(raw) {
		return false
	}
	for _, e := range except {
		base, below := strings.CutSuffix(e, "/*")
		if raw == base || below && strings.HasPrefix(raw, base+"/") {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------- decision

// Session states of a request.
const (
	SessionNone    = "none"    // no cookie
	SessionValid   = "valid"   // a cookie of this website and epoch, not expired
	SessionInvalid = "invalid" // a cookie that does not verify
)

// Answers.
const (
	AnswerPass        = "pass"        // on to the WAF and the app as usual
	AnswerMaintenance = "maintenance" // 503, Retry-After, the maintenance page
	AnswerLogin       = "login"       // 403, the login page of a protected path
	AnswerDenied      = "denied"      // 403, "Kein Zugriff", no form
)

// Reasons of a pass, in the order they are checked.
const (
	ReasonNotProtected = "not_protected"
	ReasonExcept       = "except"
	// ReasonAddress, ReasonOwnNetwork: the client address matched and no
	// password is set.
	ReasonAddress    = "address"
	ReasonOwnNetwork = "own_network"
	// ReasonSession: a valid session, and the client address matched when
	// addresses or own networks are set.
	ReasonSession = "session"
	// ReasonLocked: a condition does not hold, the request is answered by
	// schild.
	ReasonLocked = "locked"
)

// Input is one request at a protected website.
type Input struct {
	Protection  Protection
	Path        string     // as received, escaped, without the query
	Client      netip.Addr // the client address as the gate resolved it; invalid = unknown
	Allowlisted bool       // the client is in the allowlist, at any level
	Session     string
}

// Result of Decide.
type Result struct {
	Answer    string `json:"answer"`
	Reason    string `json:"reason"`
	Status    int    `json:"status"`
	LoginForm bool   `json:"login_form"`
	Canonical string `json:"canonical_path"`
}

// Decide answers one request (D58). A path outside the protection passes.
// Otherwise every condition that is set must hold: the client address, when
// addresses or own networks are set (either list is enough), and a valid
// session, when a password is set. A client whose address does not match
// gets no login form: the password would not let it in.
func Decide(in Input) Result {
	p := in.Protection
	r := Result{Canonical: CanonicalPath(in.Path)}
	pass := func(reason string) Result {
		r.Answer, r.Reason, r.Status = AnswerPass, reason, 0
		return r
	}
	switch {
	case p.Scope == ScopePaths && !Protected(in.Path, p.Paths):
		return pass(ReasonNotProtected)
	case p.Scope == ScopeSite && Excepted(in.Path, p.Except):
		return pass(ReasonExcept)
	}
	addressOK, reason := true, ""
	if len(p.Addresses) > 0 || p.OwnNetworks {
		switch {
		case in.Client.IsValid() && inAddresses(in.Client.Unmap(), p.Addresses):
			reason = ReasonAddress
		case p.OwnNetworks && in.Allowlisted:
			reason = ReasonOwnNetwork
		default:
			addressOK = false
		}
	}
	if addressOK && p.Password && in.Session == SessionValid {
		return pass(ReasonSession)
	}
	if addressOK && !p.Password {
		return pass(reason)
	}
	r.Reason, r.LoginForm = ReasonLocked, p.Password && addressOK
	switch {
	case p.Scope == ScopeSite:
		r.Answer, r.Status = AnswerMaintenance, 503
	case r.LoginForm:
		r.Answer, r.Status = AnswerLogin, 403
	default:
		r.Answer, r.Status = AnswerDenied, 403
	}
	return r
}

// AddressAllowed reports whether client may log in at all: true without
// addresses and own networks, else when the address matches one (D58).
func (p Protection) AddressAllowed(client netip.Addr, allowlisted bool) bool {
	if len(p.Addresses) == 0 && !p.OwnNetworks {
		return true
	}
	return client.IsValid() && inAddresses(client.Unmap(), p.Addresses) || p.OwnNetworks && allowlisted
}

func inAddresses(ip netip.Addr, list []string) bool {
	for _, s := range list {
		if pf, err := ParseAddress(s); err == nil && pf.Contains(ip) {
			return true
		}
	}
	return false
}
