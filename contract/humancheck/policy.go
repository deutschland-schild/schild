// Package humancheck implements the browser verification ("Kurze Prüfung") and
// Under Attack contract (MVP-12 v1_cut, contracts/human-check.md): per-website
// policy validation, pure request decision (Decide), stateless SHA-256
// proof-of-work challenge tokens, and identifier-free HMAC clearance cookies.
package humancheck

import (
	"fmt"
	"net/netip"
	"strings"
	"time"
)

// Modes for per-website browser verification.
const (
	ModeOff      = "off"
	ModeFindings = "findings"
	ModeAlways   = "always"
)

// Under Attack scopes.
const (
	UnderAttackOff   = "off"
	UnderAttackAdmin = "admin"
	UnderAttackAll   = "all"
)

// Clearance states.
const (
	ClearanceNone    = "none"
	ClearancePoW     = "pow"
	ClearanceNoJS    = "nojs"
	ClearanceInvalid = "invalid"
)

// Decision answers.
const (
	AnswerPass      = "pass"
	AnswerChallenge = "challenge"
)

// Decision reasons.
const (
	ReasonOff             = "off"
	ReasonNotNavigation   = "not_navigation"
	ReasonBypassPath      = "bypass_path"
	ReasonGoodBot         = "good_bot"
	ReasonAllowlisted     = "allowlisted"
	ReasonExcludedPath    = "excluded_path"
	ReasonClearanceValid  = "clearance_valid"
	ReasonUnderAttack     = "under_attack"
	ReasonDistributedWave = "distributed_wave"
	ReasonAlways          = "always"
	ReasonSharedScenario  = "shared_scenario"
	ReasonAggressiveCrawl = "aggressive_crawl"
	ReasonNoTrigger       = "no_trigger"
)

// Limits and defaults from contracts/human-check.md.
const (
	StatusChallenge    = 403
	MaxUnderAttack     = 24 * time.Hour
	MaxExcept          = 16
	MinClearanceTTLS   = 60
	MaxClearanceTTLS   = 3600
	DefaultClearanceS  = 1800
	MinDifficulty      = 1000
	MaxDifficulty      = 250000
	DefaultDifficulty  = 50000
	MaxChallengeTTL    = 5 * time.Minute
	MaxEndpointBodyLen = 2048
)

// UnderAttack is the time-bounded emergency verification switch for a website.
type UnderAttack struct {
	Scope string `json:"scope"`
	Until string `json:"until,omitempty"`
}

// Active reports whether u is active at now.
func (u UnderAttack) Active(now time.Time) bool {
	if u.Scope == "" || u.Scope == UnderAttackOff || u.Until == "" {
		return false
	}
	t, err := time.Parse(time.RFC3339, u.Until)
	if err != nil {
		return false
	}
	return now.Before(t)
}

// Policy is the browser verification policy of one website.
type Policy struct {
	Website       string      `json:"website"`
	Mode          string      `json:"mode"`
	UnderAttack   UnderAttack `json:"under_attack,omitempty"`
	Except        []string    `json:"except,omitempty"`
	ClearanceTTLS int         `json:"clearance_ttl_s,omitempty"`
	Difficulty    int         `json:"difficulty,omitempty"`
}

// EffectiveTTL returns the clearance cookie TTL, defaulting to 30m.
func (p Policy) EffectiveTTL() time.Duration {
	if p.ClearanceTTLS >= MinClearanceTTLS && p.ClearanceTTLS <= MaxClearanceTTLS {
		return time.Duration(p.ClearanceTTLS) * time.Second
	}
	return time.Duration(DefaultClearanceS) * time.Second
}

// EffectiveDifficulty returns the PoW upper bound, defaulting to 50000.
func (p Policy) EffectiveDifficulty() int {
	if p.Difficulty >= MinDifficulty && p.Difficulty <= MaxDifficulty {
		return p.Difficulty
	}
	return DefaultDifficulty
}

// FieldError describes one invalid policy field.
type FieldError struct {
	Field string
	Msg   string
}

func (e *FieldError) Error() string { return e.Field + ": " + e.Msg }

// CheckShape validates policy invariants beyond JSON Schema.
func (p Policy) CheckShape(now time.Time) error {
	if p.Website == "" {
		return &FieldError{Field: "website", Msg: "required"}
	}
	switch p.Mode {
	case ModeOff, ModeFindings, ModeAlways:
	default:
		return &FieldError{Field: "mode", Msg: "must be off, findings or always"}
	}
	switch p.UnderAttack.Scope {
	case "", UnderAttackOff:
		if p.UnderAttack.Until != "" {
			return &FieldError{Field: "under_attack.until", Msg: "must be empty when under_attack.scope is off"}
		}
	case UnderAttackAdmin, UnderAttackAll:
		if p.UnderAttack.Until == "" {
			return &FieldError{Field: "under_attack.until", Msg: "required when under_attack is active"}
		}
		t, err := time.Parse(time.RFC3339, p.UnderAttack.Until)
		if err != nil {
			return &FieldError{Field: "under_attack.until", Msg: "must be RFC3339 timestamp"}
		}
		if !now.IsZero() && t.Sub(now) > MaxUnderAttack {
			return &FieldError{Field: "under_attack.until", Msg: "at most 24 hours from now"}
		}
	default:
		return &FieldError{Field: "under_attack.scope", Msg: "must be off, admin or all"}
	}
	if len(p.Except) > MaxExcept {
		return &FieldError{Field: "except", Msg: fmt.Sprintf("at most %d paths", MaxExcept)}
	}
	for _, ex := range p.Except {
		if !validExceptPath(ex) {
			return &FieldError{Field: "except", Msg: "invalid path " + ex}
		}
	}
	if p.ClearanceTTLS != 0 && (p.ClearanceTTLS < MinClearanceTTLS || p.ClearanceTTLS > MaxClearanceTTLS) {
		return &FieldError{Field: "clearance_ttl_s", Msg: fmt.Sprintf("must be %d..%d", MinClearanceTTLS, MaxClearanceTTLS)}
	}
	if p.Difficulty != 0 && (p.Difficulty < MinDifficulty || p.Difficulty > MaxDifficulty) {
		return &FieldError{Field: "difficulty", Msg: fmt.Sprintf("must be %d..%d", MinDifficulty, MaxDifficulty)}
	}
	return nil
}

func validExceptPath(p string) bool {
	if p == "" || p[0] != '/' || p == "/*" {
		return false
	}
	body := strings.TrimSuffix(p, "/*")
	if strings.Contains(body, "*") || strings.Contains(body, "//") {
		return false
	}
	for _, seg := range strings.Split(body[1:], "/") {
		if seg == "." || seg == ".." {
			return false
		}
	}
	return true
}

// Input is one request evaluated against Policy.
type Input struct {
	Policy             Policy
	Method             string
	Path               string
	Accept             string
	SecFetchMode       string
	Allowlisted        bool
	GoodBot            bool
	Clearance          string // none | pow | nojs | invalid
	SharedScenarioHit  bool
	AggressiveCrawlHit bool
	DistributedWave    bool
	Now                time.Time
}

// Result is the output of Decide.
type Result struct {
	Answer string `json:"answer"`
	Reason string `json:"reason"`
	Status int    `json:"status"`
}

// Decide determines whether a request passes or gets the browser check.
func Decide(in Input) Result {
	if !IsTopLevelNavigation(in.Method, in.Accept, in.SecFetchMode) {
		return Result{Answer: AnswerPass, Reason: ReasonNotNavigation, Status: 0}
	}
	if IsBypassPath(in.Path) {
		return Result{Answer: AnswerPass, Reason: ReasonBypassPath, Status: 0}
	}
	if in.GoodBot {
		return Result{Answer: AnswerPass, Reason: ReasonGoodBot, Status: 0}
	}
	if in.Allowlisted {
		return Result{Answer: AnswerPass, Reason: ReasonAllowlisted, Status: 0}
	}
	if MatchesExcept(in.Path, in.Policy.Except) {
		return Result{Answer: AnswerPass, Reason: ReasonExcludedPath, Status: 0}
	}
	if in.Clearance == ClearancePoW || in.Clearance == ClearanceNoJS {
		return Result{Answer: AnswerPass, Reason: ReasonClearanceValid, Status: 0}
	}

	uaActive := in.Policy.UnderAttack.Active(in.Now)
	if uaActive {
		if in.Policy.UnderAttack.Scope == UnderAttackAll {
			return Result{Answer: AnswerChallenge, Reason: ReasonUnderAttack, Status: StatusChallenge}
		}
		if in.Policy.UnderAttack.Scope == UnderAttackAdmin && IsAdminPath(in.Path) {
			return Result{Answer: AnswerChallenge, Reason: ReasonUnderAttack, Status: StatusChallenge}
		}
	}
	if in.DistributedWave {
		return Result{Answer: AnswerChallenge, Reason: ReasonDistributedWave, Status: StatusChallenge}
	}
	if in.Policy.Mode == ModeAlways {
		return Result{Answer: AnswerChallenge, Reason: ReasonAlways, Status: StatusChallenge}
	}
	if in.Policy.Mode == ModeFindings {
		if in.SharedScenarioHit {
			return Result{Answer: AnswerChallenge, Reason: ReasonSharedScenario, Status: StatusChallenge}
		}
		if in.AggressiveCrawlHit {
			return Result{Answer: AnswerChallenge, Reason: ReasonAggressiveCrawl, Status: StatusChallenge}
		}
	}
	if in.Policy.Mode == ModeOff && !uaActive {
		return Result{Answer: AnswerPass, Reason: ReasonOff, Status: 0}
	}
	return Result{Answer: AnswerPass, Reason: ReasonNoTrigger, Status: 0}
}

// IsTopLevelNavigation reports whether a request is a browser page navigation.
func IsTopLevelNavigation(method, accept, secFetchMode string) bool {
	if method != "GET" && method != "HEAD" {
		return false
	}
	if strings.EqualFold(strings.TrimSpace(secFetchMode), "navigate") {
		return true
	}
	return strings.Contains(strings.ToLower(accept), "text/html")
}

// IsBypassPath reports whether path is never challenged.
func IsBypassPath(path string) bool {
	return path == "/robots.txt" || path == "/favicon.ico" || strings.HasPrefix(path, "/.well-known/")
}

var adminPrefixes = []string{
	"/admin",
	"/wp-admin",
	"/wp-login.php",
	"/login",
	"/signin",
	"/sign-in",
	"/auth",
	"/user/login",
	"/typo3",
	"/backend",
	"/manager",
	"/cms",
}

// IsAdminPath reports whether path is a common login or admin route.
func IsAdminPath(path string) bool {
	low := strings.ToLower(path)
	for _, p := range adminPrefixes {
		if low == p || strings.HasPrefix(low, p+"/") {
			return true
		}
	}
	return false
}

// MatchesExcept reports whether path matches any pattern in except.
func MatchesExcept(path string, except []string) bool {
	for _, pat := range except {
		if strings.HasSuffix(pat, "/*") {
			base := strings.TrimSuffix(pat, "/*")
			if path == base || strings.HasPrefix(path, base+"/") {
				return true
			}
			continue
		}
		if path == pat {
			return true
		}
	}
	return false
}

// IPPrefix returns the masked /24 (IPv4) or /56 (IPv6) prefix string used to
// bind challenge tokens and clearance cookies without storing a full IP.
func IPPrefix(ip netip.Addr) string {
	if !ip.IsValid() {
		return "unknown"
	}
	ip = ip.Unmap()
	if ip.Is4() {
		return netip.PrefixFrom(ip, 24).Masked().String()
	}
	return netip.PrefixFrom(ip, 56).Masked().String()
}
