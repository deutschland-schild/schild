package gate

import (
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"sort"
	"strings"

	"github.com/corazawaf/coraza/v3/types"

	"github.com/deutschland-schild/schild/contract/events"
	"github.com/deutschland-schild/schild/contract/msg"
	"github.com/deutschland-schild/schild/gateway/internal/behaviour"
	"github.com/deutschland-schild/schild/gateway/internal/blockpage"
	"github.com/deutschland-schild/schild/gateway/internal/bots"
	"github.com/deutschland-schild/schild/gateway/internal/decide"
	"github.com/deutschland-schild/schild/gateway/internal/pathtpl"
	"github.com/deutschland-schild/schild/gateway/internal/waf"
)

// behaviourRequest builds the MVP-17 view of a request (local only).
func (g *Gate) behaviourRequest(r *http.Request, ri *reqInfo) *behaviour.Request {
	ip := ri.client.IP.Unmap()
	set := g.settings.Load()
	trustedProxy := ip.IsValid() && set.Resolver != nil && set.Resolver.Trusted(ip)
	method := strings.ToUpper(r.Method)
	if !methodRe.MatchString(method) {
		method = "OTHER"
	}
	ua := r.UserAgent()
	impersonator := false
	if ip.IsValid() && ua != "" {
		if g.Monitor != nil {
			impersonator = g.Monitor.ClassifyBot(ua, ip).Verification == bots.VerMismatch
		} else if g.Crawlers != nil && g.Crawlers.Engine() != nil {
			if id, _ := g.Crawlers.Engine().MatchUA(ua); id != 0 {
				impersonator = g.Crawlers.Engine().Verify(id, ip) == bots.VerMismatch
			}
		}
	}
	br := &behaviour.Request{
		Time: ri.start, IP: ip, Allowlisted: ri.allow != "", TrustedProxy: trustedProxy, BotImpersonator: impersonator,
		Client: events.Client{IP: ip.String(), Attribution: ri.client.Attribution, Allowlisted: ri.allow != "",
			Geo: events.Geo{Country: ri.geo.Country, City: trim(ri.geo.City, 128), ASN: ri.geo.ASN, ASOrg: trim(ri.geo.ASOrg, 256), NetClass: ri.geo.NetClass}},
		Method: method, Host: r.Host, Path: r.URL.Path, RawQuery: r.URL.RawQuery, UserAgent: ua,
		Except: func(src string) bool { return g.Exceptions.Has(ip, src, ri.start) },
	}
	g.fingerprint(r, ri, br)
	return br
}

// fingerprint fills the MVP-18 fields: JA4 only from the configured header
// of a trusted TLS terminator (concept 24 section 10), else the low-entropy
// header set; stage-0 inconsistency; the names of the cookies sent.
func (g *Gate) fingerprint(r *http.Request, ri *reqInfo, br *behaviour.Request) {
	set := g.settings.Load()
	trusted := ri.client.Peer.IsValid() && set.Resolver.Trusted(ri.client.Peer)
	if h := g.Behaviour.JA4Header(); h != "" && trusted {
		if v := r.Header.Get(h); behaviour.ValidJA4(v) {
			br.Fingerprint, br.FPKind, br.StrongFP = behaviour.FingerprintID(behaviour.FPJA4, v), behaviour.FPJA4, true
		}
	}
	if br.Fingerprint == "" {
		br.Fingerprint, br.FPKind = behaviour.FingerprintID(behaviour.FPHeaders, behaviour.HeaderFingerprint(r.Proto, r.Header)), behaviour.FPHeaders
	}
	https := r.TLS != nil || (trusted && strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https"))
	br.Inconsistent = behaviour.Inconsistent(r.UserAgent(), r.Header, https)
	for _, c := range r.Cookies() {
		if len(br.CookieNames) >= 16 {
			break
		}
		br.CookieNames = append(br.CookieNames, c.Name)
	}
}

// shapeStop answers a request whose shape is blocked by a running MVP-18
// shape_block (403, block page with the wave's incident number).
func (g *Gate) shapeStop(w http.ResponseWriter, r *http.Request, ri *reqInfo, incident string) {
	ri.stopped = true
	ri.incident = incident
	ri.status = http.StatusForbidden
	ri.decision = decide.Output{Outcome: decide.Blocked, Status: ri.status, Sources: []string{"distributed:shape"}}
	g.drain(w, r, ri)
	blockpage.Write(w, r, ri.status, incident, ri.start)
	g.finish(r, ri)
}

func sortedUnique(x []int) []int {
	x = append([]int(nil), x...)
	sort.Ints(x)
	out := x[:0]
	for i, v := range x {
		if i == 0 || v != x[i-1] {
			out = append(out, v)
		}
	}
	if len(out) > 32 {
		out = out[:32]
	}
	return out
}

// requestShapeSig is the request_sig of the signal shape (method, path
// template, parameter names, content type, rule ids); no values, no host.
func requestShapeSig(r *http.Request, params []string, rules []int) string {
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil {
		mt = ""
	}
	return msg.RequestSig(msg.RequestShape{Method: strings.ToUpper(r.Method), PathTemplate: pathtpl.Template(r.URL.EscapedPath()), ParamNames: params, ContentType: mt, RuleIDs: rules})
}

// behaviourStop answers a request of a blocked client key (403, calm page
// with the block's incident number and its end) or over a rate limit (429
// with Retry-After; problem details for API clients). The WAF is not run:
// the request never reaches the app.
func (g *Gate) behaviourStop(w http.ResponseWriter, r *http.Request, ri *reqInfo, v behaviour.Verdict) {
	ri.stopped = true
	g.drain(w, r, ri)
	if v.Block {
		ri.incident = v.Incident
		ri.status = http.StatusForbidden
		ri.decision = decide.Output{Outcome: decide.Blocked, Status: ri.status, Sources: []string{behaviour.BlockSource(v.Scenario)}}
		blockpage.WritePaused(w, r, v.Incident, v.Until, ri.start)
	} else {
		ri.status = http.StatusTooManyRequests
		ri.decision = decide.Output{Outcome: decide.Blocked, Status: ri.status, Sources: []string{"ratelimit:" + v.LimitID}}
		blockpage.WriteRateLimited(w, r, behaviour.RetryAfterSeconds(v.RetryAfter), ri.start)
	}
	g.finish(r, ri)
}

// cookieNames returns the names (never values) of cookies the app sets.
func cookieNames(h http.Header) []string {
	var out []string
	for _, c := range h.Values("Set-Cookie") {
		name, _, ok := strings.Cut(c, "=")
		if ok && len(out) < 16 {
			out = append(out, strings.TrimSpace(name))
		}
	}
	return out
}

// wafRuleIDs are the rules with blocking intent of this request for
// waf_repeat: CRS rules that added anomaly points and local rules; a CrowdSec
// Hub rule only when it really blocked
// (crowdsec.Effect.CountsAsHit, D39), so a rule in Erkannt can never lead to a
// block indirectly. CRS scoring rules (949xxx, 959xxx, 980xxx),
// schild's internal limit rules and local exceptions (ctl:, allow or nolog
// rules such as the runbook's Livewire and login exceptions; MVP-19
// measurement, finding 3b) do not count.
func wafRuleIDs(ri *reqInfo) []int {
	a := ri.analysis
	if a == nil || ri.limit != nil {
		return nil
	}
	var out []int
	for _, m := range a.Matches {
		if (m.ID >= 949000 && m.ID < 950000) || (m.ID >= 959000 && m.ID < 960000) || (m.ID >= 980000 && m.ID < 981000) {
			continue
		}
		switch {
		case !m.Counts:
		case m.Source == waf.SourceCRS && m.Points > 0, m.Source == waf.SourceLocal && !m.Exception, m.Source == waf.SourceCrowdsec:
			out = append(out, m.ID)
		}
		if len(out) >= 16 {
			break
		}
	}
	return out
}

// loginUserHash reads the user name of a login attempt from the body the
// WAF already buffered and returns its keyed hash. Only the named fields
// are looked at (never the password field); the name is dropped right away
// and neither it nor the hash is stored (MVP-17, concept 24).
func loginUserHash(r *http.Request, tx types.Transaction, fields []string) (uint64, bool) {
	rd, err := tx.RequestBodyReader()
	if err != nil || rd == nil {
		return 0, false
	}
	head, _ := io.ReadAll(io.LimitReader(rd, 64<<10))
	if len(head) == 0 {
		return 0, false
	}
	mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	var get func(string) string
	switch {
	case mt == "application/x-www-form-urlencoded":
		// Not url.ParseQuery: it refuses the whole form for one ';' or one
		// bad escape in any field, and the attempt would count for no user.
		// Of a field sent twice the last value counts, as in PHP, which
		// every preset with a name runs on (and as json.Unmarshal below does
		// for a key sent twice): "log=a&log=victim" is an attempt on victim.
		form := string(head)
		get = func(k string) string {
			if vs := behaviour.FormValues(form, k); len(vs) > 0 {
				return vs[len(vs)-1]
			}
			return ""
		}
	case mt == "application/json" || strings.HasSuffix(mt, "+json"):
		var obj map[string]json.RawMessage
		if json.Unmarshal(head, &obj) != nil {
			return 0, false
		}
		get = func(k string) string {
			var s string
			if raw, ok := obj[k]; ok && json.Unmarshal(raw, &s) == nil {
				return s
			}
			return ""
		}
	default:
		return 0, false
	}
	for _, f := range fields {
		if v := get(f); v != "" && len(v) <= 256 {
			return behaviour.HashUser(v), true
		}
	}
	return 0, false
}
