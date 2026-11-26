package audit

import (
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Forgotten names a person and the pseudonym that replaces the name.
type Forgotten struct{ Kind, Name, Pseudonym string }

// CutInput of Cut.
type CutInput struct {
	Entry     map[string]any
	Now       time.Time
	RawIPDays int
	Erased    []string // addresses erased on request
	Forgotten []Forgotten
}

// Cut returns what is left of an entry: a forgotten person is a pseudonym,
// an erased address is gone, and after RawIPDays an address is its network
// (IPv4 /24, IPv6 /48). The entry itself stays.
func Cut(in CutInput) map[string]any {
	e := clone(in.Entry).(map[string]any)
	actor := obj(e, "actor")
	for _, f := range in.Forgotten {
		k := map[string]string{"dashboard": "user", "integration": "on_behalf_of", "cli": "account"}[f.Kind]
		if str(actor, "kind") == f.Kind && str(actor, k) == f.Name && f.Name != "" {
			actor[k] = f.Pseudonym
		}
	}
	var gone []netip.Addr
	for _, s := range in.Erased {
		if x, ok := parseAddr(s); ok {
			gone = append(gone, x)
		}
	}
	if len(gone) > 0 {
		repl := map[string]string{}
		for _, x := range gone {
			repl[x.String()] = "erased"
			repl[single(x)] = "erased"
		}
		hit := func(s string) bool {
			for _, x := range gone {
				if names(s, x) {
					repl[s] = "erased"
					return true
				}
			}
			return false
		}
		if s := str(e, "address"); s != "" && hit(s) {
			delete(e, "address")
			e["address_cut"] = "erased"
		}
		for _, f := range fields(e) {
			found := false
			for _, s := range valuesOf(f) {
				found = hit(s) || found
			}
			if found {
				hide(f, HiddenErased)
			}
		}
		rewrite(e, repl)
	}
	t, err := time.Parse(time.RFC3339, str(e, "time"))
	if err != nil || in.Now.Sub(t) < time.Duration(in.RawIPDays)*24*time.Hour {
		return e
	}
	repl := map[string]string{}
	cut := func(s string) string {
		n := short(s)
		if n != s {
			repl[s] = n
			if x, bits, ok := parseNet(s); ok && bits == x.BitLen() {
				repl[x.String()] = n
				repl[single(x)] = n
			}
		}
		return n
	}
	if s := str(e, "address"); s != "" {
		if n := cut(s); n != s {
			e["address"] = n
			e["address_cut"] = "short"
		}
	}
	for _, f := range fields(e) {
		each(f, cut)
	}
	rewrite(e, repl)
	return e
}

// valuesOf returns the text values of a field.
func valuesOf(f map[string]any) []string {
	var out []string
	for _, k := range []string{"before", "after"} {
		if s, ok := f[k].(string); ok {
			out = append(out, s)
		}
	}
	for _, k := range []string{"added", "removed"} {
		l, _ := f[k].([]any)
		for _, x := range l {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
	}
	return out
}

// each maps every text value of a field; a list keeps each item once, in
// byte order.
func each(f map[string]any, fn func(string) string) {
	for _, k := range []string{"before", "after"} {
		if s, ok := f[k].(string); ok {
			f[k] = fn(s)
		}
	}
	for _, k := range []string{"added", "removed"} {
		l, ok := f[k].([]any)
		if !ok {
			continue
		}
		var ss []string
		seen := map[string]bool{}
		for _, x := range l {
			s, _ := x.(string)
			if s = fn(s); !seen[s] {
				seen[s] = true
				ss = append(ss, s)
			}
		}
		sort.Strings(ss)
		out := make([]any, len(ss))
		for i, s := range ss {
			out[i] = s
		}
		f[k] = out
	}
}

// rewrite replaces addresses in the texts of an entry: the reason, the label
// and id of the actor's token or portal, the subject's id and every recorded
// text value.
func rewrite(e map[string]any, repl map[string]string) {
	if len(repl) == 0 {
		return
	}
	keys := make([]string, 0, len(repl))
	for k := range repl {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if len(keys[i]) != len(keys[j]) {
			return len(keys[i]) > len(keys[j])
		}
		return keys[i] < keys[j]
	})
	fix := func(s string) string {
		for _, k := range keys {
			s = replaceAddr(s, k, repl[k])
		}
		return s
	}
	set := func(m map[string]any, k string, n int) {
		if s, ok := m[k].(string); ok {
			m[k], _ = clip(fix(s), n)
		}
	}
	set(e, "reason", 500)
	set(obj(e, "actor"), "label", 64)
	set(obj(e, "actor"), "on_behalf_of", 128)
	set(obj(e, "subject"), "id", 253)
	for _, f := range fields(e) {
		set(f, "before", MaxValueBytes)
		set(f, "after", MaxValueBytes)
		for _, k := range []string{"added", "removed"} {
			if l, ok := f[k].([]any); ok {
				for i := range l {
					if s, ok := l[i].(string); ok {
						l[i], _ = clip(fix(s), MaxItemBytes)
					}
				}
			}
		}
	}
}

// replaceAddr replaces the address or network old where it stands alone, not
// inside a longer one.
func replaceAddr(s, old, with string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		if strings.HasPrefix(s[i:], old) && !(i > 0 && addrByte(s[i-1])) && !goesOn(s[i+len(old):]) {
			b.WriteString(with)
			i += len(old)
			continue
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

func addrByte(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F' || c == '.' || c == ':'
}

// goesOn: the text after a match continues the address ("192.0.2.7" in
// "192.0.2.77"); a point or a colon at the end of a sentence does not.
func goesOn(rest string) bool {
	if rest == "" {
		return false
	}
	if rest[0] == '/' {
		return len(rest) > 1 && rest[1] >= '0' && rest[1] <= '9'
	}
	if !addrByte(rest[0]) {
		return false
	}
	if rest[0] == '.' || rest[0] == ':' {
		return len(rest) > 1 && addrByte(rest[1]) && rest[1] != '.' && rest[1] != ':'
	}
	return true
}

func parseAddr(s string) (netip.Addr, bool) {
	a, err := netip.ParseAddr(s)
	if err != nil || a.Zone() != "" {
		return netip.Addr{}, false
	}
	return a.Unmap(), true
}

// single is the address as a network of one.
func single(a netip.Addr) string { return a.String() + "/" + strconv.Itoa(a.BitLen()) }

// parseNet parses address/bits; without bits it is the single address.
func parseNet(s string) (netip.Addr, int, bool) {
	addr, bits, has := strings.Cut(s, "/")
	a, ok := parseAddr(addr)
	if !ok {
		return a, 0, false
	}
	if !has {
		return a, a.BitLen(), true
	}
	n, err := strconv.Atoi(bits)
	if err != nil || strconv.Itoa(n) != bits || n < 0 || n > a.BitLen() || strings.Contains(addr, ":") && a.Is4() {
		return a, 0, false
	}
	return a, n, true
}

// names reports whether s is the address x: the address itself, its /32, or
// an IPv6 network of /64 or longer around it (a client in IPv6 is its /64).
func names(s string, x netip.Addr) bool {
	a, n, ok := parseNet(s)
	if !ok || a.Is4() != x.Is4() || (a.Is4() && n != 32) || (!a.Is4() && n < 64) {
		return false
	}
	p, err := a.Prefix(n)
	return err == nil && p.Contains(x)
}

// short is the network of an address: IPv4 /24, IPv6 /48. What is no
// address, or a network that wide already, stays.
func short(s string) string {
	a, n, ok := parseNet(s)
	if !ok {
		return s
	}
	bits := 48
	if a.Is4() {
		bits = 24
	}
	if n <= bits {
		return s
	}
	p, err := a.Prefix(bits)
	if err != nil {
		return s
	}
	return p.String()
}

func clone(v any) any {
	switch t := v.(type) {
	case map[string]any:
		m := make(map[string]any, len(t))
		for k, x := range t {
			m[k] = clone(x)
		}
		return m
	case []any:
		l := make([]any, len(t))
		for i, x := range t {
			l[i] = clone(x)
		}
		return l
	}
	return v
}
