// Package humancheck enforces per-website browser verification ("Kurze Prüfung")
// and Under Attack mode in the gateway (MVP-12 v1_cut, contracts/human-check.md).
//
// Everything runs locally in schild: no third-party service, no fingerprinting,
// no persistent visitor identifier, no per-visitor storage. State (keys,
// per-instance endpoint prefix, and per-website policies) lives in schild.db
// under StoreKey.
package humancheck

import (
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	hc "github.com/deutschland-schild/schild/contract/humancheck"
)

// StoreKey is the schild.db row holding the human-check state.
const StoreKey = "human_check_v1"

// KeyRotationInterval is how often k_challenge and k_clear rotate (24 h).
const KeyRotationInterval = 24 * time.Hour

const (
	maxSpentSalts   = 65536
	maxRateBuckets  = 16384
	rateWindow      = time.Minute
	maxVerifyPerMin = 30
)

// Entry is the stored policy of one website.
type Entry struct {
	Policy    hc.Policy `json:"policy"`
	UpdatedAt time.Time `json:"updated_at"`
	Actor     string    `json:"actor"` // dashboard | agent | cli
	User      string    `json:"user,omitempty"`
}

// State is the persisted state of this gateway instance. Never mutate in place;
// Clone before modifying and swap with Store.
type State struct {
	Prefix           string            `json:"prefix"`
	PrevPrefix       string            `json:"prev_prefix,omitempty"`
	ChallengeKey     []byte            `json:"challenge_key"`
	PrevChallengeKey []byte            `json:"prev_challenge_key,omitempty"`
	ClearanceKey     []byte            `json:"clearance_key"`
	PrevClearanceKey []byte            `json:"prev_clearance_key,omitempty"`
	KeysRotatedAt    time.Time         `json:"keys_rotated_at"`
	Entries          map[string]*Entry `json:"entries"`
}

// NewState creates a fresh state with random 32-byte keys and a random prefix.
func NewState(now time.Time) *State {
	ck := make([]byte, hc.KeyLen)
	lk := make([]byte, hc.KeyLen)
	_, _ = rand.Read(ck)
	_, _ = rand.Read(lk)
	return &State{
		Prefix:        hc.NewPrefix(),
		ChallengeKey:  ck,
		ClearanceKey:  lk,
		KeysRotatedAt: now.UTC(),
		Entries:       map[string]*Entry{},
	}
}

// Clone deep-copies s so callers can mutate Entries safely.
func (s *State) Clone() *State {
	c := &State{
		Prefix:           s.Prefix,
		PrevPrefix:       s.PrevPrefix,
		ChallengeKey:     append([]byte(nil), s.ChallengeKey...),
		PrevChallengeKey: append([]byte(nil), s.PrevChallengeKey...),
		ClearanceKey:     append([]byte(nil), s.ClearanceKey...),
		PrevClearanceKey: append([]byte(nil), s.PrevClearanceKey...),
		KeysRotatedAt:    s.KeysRotatedAt,
		Entries:          make(map[string]*Entry, len(s.Entries)),
	}
	for k, e := range s.Entries {
		x := *e
		if len(e.Policy.Except) > 0 {
			x.Policy.Except = append([]string(nil), e.Policy.Except...)
		}
		c.Entries[k] = &x
	}
	return c
}

// RotateKeys rotates k_challenge and k_clear, keeping the previous keys valid
// for in-flight challenges and existing clearance cookies.
func (s *State) RotateKeys(now time.Time) {
	ck := make([]byte, hc.KeyLen)
	lk := make([]byte, hc.KeyLen)
	_, _ = rand.Read(ck)
	_, _ = rand.Read(lk)
	s.PrevChallengeKey = s.ChallengeKey
	s.ChallengeKey = ck
	s.PrevClearanceKey = s.ClearanceKey
	s.ClearanceKey = lk
	s.KeysRotatedAt = now.UTC()
}

func (s *State) challengeKeys() [][]byte {
	if len(s.PrevChallengeKey) > 0 {
		return [][]byte{s.ChallengeKey, s.PrevChallengeKey}
	}
	return [][]byte{s.ChallengeKey}
}

func (s *State) clearanceKeys() [][]byte {
	if len(s.PrevClearanceKey) > 0 {
		return [][]byte{s.ClearanceKey, s.PrevClearanceKey}
	}
	return [][]byte{s.ClearanceKey}
}

// Counters are aggregate-only challenge counts (never per-visitor).
type Counters struct {
	Served  uint64 `json:"served"`
	Passed  uint64 `json:"passed"`
	NoJS    uint64 `json:"nojs"`
	Invalid uint64 `json:"invalid"`
}

// Gate enforces browser verification and serves the verify/continue endpoints.
type Gate struct {
	cur atomic.Pointer[State]

	served  atomic.Uint64
	passed  atomic.Uint64
	nojs    atomic.Uint64
	invalid atomic.Uint64

	spentMu sync.Mutex
	spent   map[string]int64 // salt -> exp unix

	rateMu sync.Mutex
	rates  map[string][]time.Time
}

// New creates a Gate with an initial random state.
func New() *Gate {
	g := &Gate{
		spent: map[string]int64{},
		rates: map[string][]time.Time{},
	}
	g.cur.Store(NewState(time.Now()))
	return g
}

// Store swaps in a new immutable State.
func (g *Gate) Store(s *State) {
	if s == nil {
		return
	}
	if !hc.ValidPrefix(s.Prefix) {
		s.Prefix = hc.NewPrefix()
	}
	if len(s.ChallengeKey) == 0 || len(s.ClearanceKey) == 0 {
		fresh := NewState(time.Now())
		if len(s.ChallengeKey) == 0 {
			s.ChallengeKey = fresh.ChallengeKey
		}
		if len(s.ClearanceKey) == 0 {
			s.ClearanceKey = fresh.ClearanceKey
		}
	}
	if s.Entries == nil {
		s.Entries = map[string]*Entry{}
	}
	g.cur.Store(s)
}

// State returns the current State (do not mutate).
func (g *Gate) State() *State { return g.cur.Load() }

// Lookup returns the policy Entry for website, or nil.
func (g *Gate) Lookup(website string) *Entry {
	if g == nil {
		return nil
	}
	return g.cur.Load().Entries[website]
}

// Counts returns aggregate challenge counts since process start.
func (g *Gate) Counts() Counters {
	if g == nil {
		return Counters{}
	}
	return Counters{
		Served:  g.served.Load(),
		Passed:  g.passed.Load(),
		NoJS:    g.nojs.Load(),
		Invalid: g.invalid.Load(),
	}
}

// IsEndpoint reports whether path targets this instance's verify or continue endpoint.
func (g *Gate) IsEndpoint(path string) (action string, ok bool) {
	if g == nil {
		return "", false
	}
	st := g.cur.Load()
	for _, pfx := range []string{st.Prefix, st.PrevPrefix} {
		if pfx == "" {
			continue
		}
		if path == pfx+"verify" {
			return "verify", true
		}
		if path == pfx+"continue" {
			return "continue", true
		}
	}
	return "", false
}

// RequestSignals carries runtime signals from other gate stages.
type RequestSignals struct {
	Allowlisted        bool
	GoodBot            bool
	SharedScenarioHit  bool
	AggressiveCrawlHit bool
	DistributedWave    bool
}

// Verdict is the gate's decision for one request.
type Verdict struct {
	Result    hc.Result
	Policy    hc.Policy
	Prefix    string
	HadCookie bool
	Host      string
	IPPrefix  string
}

// Check evaluates the website's policy for r.
func (g *Gate) Check(r *http.Request, website string, clientIP netip.Addr, sig RequestSignals, now time.Time) (Verdict, bool) {
	if g == nil {
		return Verdict{}, false
	}
	st := g.cur.Load()
	entry := st.Entries[website]
	pol := hc.Policy{Website: website, Mode: hc.ModeOff}
	if entry != nil {
		pol = entry.Policy
	}
	if pol.Mode == hc.ModeOff && !pol.UnderAttack.Active(now) && !sig.DistributedWave {
		return Verdict{}, false
	}

	host := reqHost(r, website)
	ipPrefix := hc.IPPrefix(clientIP)
	ua := r.Header.Get("User-Agent")
	rawCookie := ""
	if c, err := r.Cookie(hc.CookieName); err == nil {
		rawCookie = c.Value
	}
	clearance := hc.VerifyClearance(st.clearanceKeys(), rawCookie, host, ipPrefix, ua, now)
	res := hc.Decide(hc.Input{
		Policy:             pol,
		Method:             r.Method,
		Path:               r.URL.Path,
		Accept:             r.Header.Get("Accept"),
		SecFetchMode:       r.Header.Get("Sec-Fetch-Mode"),
		Allowlisted:        sig.Allowlisted,
		GoodBot:            sig.GoodBot,
		Clearance:          clearance,
		SharedScenarioHit:  sig.SharedScenarioHit,
		AggressiveCrawlHit: sig.AggressiveCrawlHit,
		DistributedWave:    sig.DistributedWave,
		Now:                now,
	})
	return Verdict{
		Result:    res,
		Policy:    pol,
		Prefix:    st.Prefix,
		HadCookie: rawCookie != "",
		Host:      host,
		IPPrefix:  ipPrefix,
	}, true
}

// ServeInterstitial issues a signed challenge token and writes the "Kurze Prüfung"
// interstitial page. Returns false on an internal error (caller fails open).
func (g *Gate) ServeInterstitial(w http.ResponseWriter, r *http.Request, v Verdict, siteLabel string, now time.Time) bool {
	st := g.cur.Load()
	ret := r.URL.RequestURI()
	tok, payload, err := hc.IssueChallenge(st.ChallengeKey, v.Host, v.IPPrefix, r.Header.Get("User-Agent"), ret, v.Policy.EffectiveDifficulty(), now)
	if err != nil {
		return false
	}
	g.served.Add(1)
	writeInterstitial(w, r, interstitialData{
		SiteName:  siteLabel,
		Prefix:    st.Prefix,
		Token:     tok,
		Salt:      payload.Salt,
		Challenge: payload.Challenge,
		Max:       payload.Max,
		Return:    payload.Ret,
	})
	return true
}

// HandleEndpoint handles POST {prefix}verify and POST {prefix}continue.
func (g *Gate) HandleEndpoint(w http.ResponseWriter, r *http.Request, website string, clientIP netip.Addr, action string, now time.Time) int {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return http.StatusMethodNotAllowed
	}
	ipPrefix := hc.IPPrefix(clientIP)
	if !g.allowRate(ipPrefix, now) {
		g.invalid.Add(1)
		w.WriteHeader(http.StatusTooManyRequests)
		return http.StatusTooManyRequests
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, hc.MaxEndpointBodyLen+1))
	if err != nil || len(body) > hc.MaxEndpointBodyLen {
		g.invalid.Add(1)
		w.WriteHeader(http.StatusBadRequest)
		return http.StatusBadRequest
	}

	token, numStr, hasNum := parseVerifyBody(r.Header.Get("Content-Type"), body)
	if token == "" {
		g.invalid.Add(1)
		w.WriteHeader(http.StatusBadRequest)
		return http.StatusBadRequest
	}
	checkPoW := action == "verify"
	number := 0
	if checkPoW {
		if !hasNum {
			g.invalid.Add(1)
			w.WriteHeader(http.StatusBadRequest)
			return http.StatusBadRequest
		}
		n, err := strconv.Atoi(strings.TrimSpace(numStr))
		if err != nil {
			g.invalid.Add(1)
			w.WriteHeader(http.StatusBadRequest)
			return http.StatusBadRequest
		}
		number = n
	}

	st := g.cur.Load()
	host := reqHost(r, website)
	ua := r.Header.Get("User-Agent")
	payload, err := hc.VerifyChallenge(st.challengeKeys(), token, host, ipPrefix, ua, number, checkPoW, now)
	if err != nil {
		g.invalid.Add(1)
		w.WriteHeader(http.StatusBadRequest)
		return http.StatusBadRequest
	}
	if !g.markSaltSpent(payload.Salt, payload.Exp, now) {
		g.invalid.Add(1)
		w.WriteHeader(http.StatusBadRequest)
		return http.StatusBadRequest
	}

	kind := hc.ClearanceNoJS
	if checkPoW {
		kind = hc.ClearancePoW
		g.passed.Add(1)
	} else {
		g.nojs.Add(1)
	}
	ttl := time.Duration(hc.DefaultClearanceS) * time.Second
	if e := st.Entries[website]; e != nil {
		ttl = e.Policy.EffectiveTTL()
	}
	val := hc.ClearanceValue(st.ClearanceKey, host, kind, ipPrefix, ua, now.Add(ttl))
	http.SetCookie(w, &http.Cookie{
		Name:     hc.CookieName,
		Value:    val,
		Path:     "/",
		HttpOnly: true,
		Secure:   isHTTPS(r),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(ttl.Seconds()),
	})
	http.Redirect(w, r, payload.Ret, http.StatusSeeOther)
	return http.StatusSeeOther
}

// StripCookie removes __Host-schild_clr from r before forwarding to the app.
func StripCookie(r *http.Request) {
	raw := r.Header.Values("Cookie")
	if len(raw) == 0 {
		return
	}
	var kept []string
	for _, line := range raw {
		for _, part := range strings.Split(line, ";") {
			p := strings.TrimSpace(part)
			if p == "" {
				continue
			}
			name, _, _ := strings.Cut(p, "=")
			if strings.TrimSpace(name) == hc.CookieName {
				continue
			}
			kept = append(kept, p)
		}
	}
	if len(kept) == 0 {
		r.Header.Del("Cookie")
	} else {
		r.Header.Set("Cookie", strings.Join(kept, "; "))
	}
}

func (g *Gate) markSaltSpent(salt string, exp int64, now time.Time) bool {
	g.spentMu.Lock()
	defer g.spentMu.Unlock()
	nowU := now.Unix()
	if prev, ok := g.spent[salt]; ok && prev >= nowU {
		return false
	}
	if len(g.spent) >= maxSpentSalts {
		for k, e := range g.spent {
			if e < nowU {
				delete(g.spent, k)
			}
		}
		if len(g.spent) >= maxSpentSalts {
			// Bounded memory: evict arbitrary expired/oldest entries rather than grow unbounded.
			for k := range g.spent {
				delete(g.spent, k)
				if len(g.spent) < maxSpentSalts/2 {
					break
				}
			}
		}
	}
	g.spent[salt] = exp
	return true
}

func (g *Gate) allowRate(key string, now time.Time) bool {
	g.rateMu.Lock()
	defer g.rateMu.Unlock()
	cut := now.Add(-rateWindow)
	if len(g.rates) >= maxRateBuckets {
		for k, ts := range g.rates {
			if len(ts) == 0 || ts[len(ts)-1].Before(cut) {
				delete(g.rates, k)
			}
		}
	}
	cur := g.rates[key]
	keep := cur[:0]
	for _, t := range cur {
		if t.After(cut) {
			keep = append(keep, t)
		}
	}
	if len(keep) >= maxVerifyPerMin {
		g.rates[key] = keep
		return false
	}
	g.rates[key] = append(keep, now)
	return true
}

func parseVerifyBody(ct string, body []byte) (token, number string, hasNum bool) {
	if strings.Contains(strings.ToLower(ct), "application/json") {
		var j struct {
			Token  string          `json:"token"`
			Number json.RawMessage `json:"number"`
		}
		if json.Unmarshal(body, &j) == nil {
			s := strings.Trim(strings.TrimSpace(string(j.Number)), `"`)
			return j.Token, s, len(j.Number) > 0 && s != "" && s != "null"
		}
		return "", "", false
	}
	vals, err := url.ParseQuery(string(body))
	if err != nil {
		return "", "", false
	}
	_, ok := vals["number"]
	return vals.Get("token"), vals.Get("number"), ok && vals.Get("number") != ""
}

func reqHost(r *http.Request, fallback string) string {
	h := strings.TrimSpace(r.Host)
	if i := strings.LastIndexByte(h, ':'); i > 0 && !strings.Contains(h[i:], "]") {
		h = h[:i]
	}
	if h == "" {
		return strings.ToLower(fallback)
	}
	return strings.ToLower(h)
}

func isHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	return strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}
