// Package accesslock enforces the access lock of a website (D56, MVP-14
// step 1) in the gate: who passes is contract/access.Decide; this package
// holds the protections in force, answers locked requests with the
// maintenance, login or "Kein Zugriff" page, and serves the login form at
// LoginPath with its limits. The state lives in schild.db (StoreKey); the
// app loads it, changes it and swaps it in with Store.
package accesslock

import (
	"crypto/rand"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"
	"time"

	"github.com/deutschland-schild/schild/contract/access"
)

// StoreKey is the schild.db row of the protections.
const StoreKey = "access_protections_v1"

// LoginPath is answered by schild itself, below the prefix of the health
// checks; it never reaches the app or the WAF.
const LoginPath = "/.schild/access/login"

// Entry is the protection of one website as stored.
type Entry struct {
	Protection access.Protection `json:"protection"`
	// Hash is the Argon2id hash of the shared password; empty = none.
	Hash string `json:"hash,omitempty"`
	// Epoch changes with every change; a session cookie names it.
	Epoch     uint64    `json:"epoch"`
	UpdatedAt time.Time `json:"updated_at"`
	Actor     string    `json:"actor"` // dashboard | cli
	User      string    `json:"user,omitempty"`
}

// Maintenance is the maintenance mode of one website (D98): the whole
// website closed, the own networks of the allowlist as the only way in. It
// is a switch of its own next to the protection of the website: with both
// set, a visitor from an own network passes the maintenance mode and then
// meets the protection as usual.
type Maintenance struct {
	Message   string    `json:"message,omitempty"`
	UpdatedAt time.Time `json:"updated_at"`
	Actor     string    `json:"actor"` // dashboard | cli
	User      string    `json:"user,omitempty"`
}

// Protection is the maintenance mode as the contract decides it: scope
// site, own networks, nothing else.
func (m *Maintenance) Protection(website string) access.Protection {
	return access.Protection{Website: website, Scope: access.ScopeSite, OwnNetworks: true, Message: m.Message}
}

// IsMaintenance reports whether p is what the maintenance switch stored as a
// protection before D98: the whole website, no password, no addresses, no
// except path, own networks.
func IsMaintenance(p access.Protection) bool {
	return p.Scope == access.ScopeSite && !p.Password && len(p.Addresses) == 0 && len(p.Except) == 0 && p.OwnNetworks
}

// State is everything stored: the session key of this gateway, the
// protections and the maintenance modes by website id. A State in use is
// never changed; Clone it.
type State struct {
	Key         []byte                  `json:"key"`
	Entries     map[string]*Entry       `json:"entries"`
	Maintenance map[string]*Maintenance `json:"maintenance,omitempty"`
}

// NewState returns an empty state with a fresh session key.
func NewState() *State {
	k := make([]byte, access.KeyLen)
	_, _ = rand.Read(k)
	return &State{Key: k, Entries: map[string]*Entry{}}
}

// Clone copies s deep enough to change entries.
func (s *State) Clone() *State {
	c := &State{Key: append([]byte(nil), s.Key...), Entries: make(map[string]*Entry, len(s.Entries))}
	for k, e := range s.Entries {
		x := *e
		c.Entries[k] = &x
	}
	if len(s.Maintenance) > 0 {
		c.Maintenance = make(map[string]*Maintenance, len(s.Maintenance))
		for k, m := range s.Maintenance {
			x := *m
			c.Maintenance[k] = &x
		}
	}
	return c
}

// Active returns the record for the file `schild front` reads.
func (s *State) Active() access.Active {
	a := access.Active{Version: 1}
	for id, e := range s.Entries {
		a.Protections = append(a.Protections, access.ActiveRecord{Website: id, Scope: e.Protection.Scope})
	}
	for id := range s.Maintenance {
		a.Protections = append(a.Protections, access.ActiveRecord{Website: id, Scope: access.ScopeSite})
	}
	return a
}

// Lock is the access lock of the gate.
type Lock struct {
	cur     atomic.Pointer[State]
	limiter *limiter
	hashes  chan struct{}
	// HashWait is how long a login waits for a free hash slot.
	HashWait time.Duration

	// OnLogin, OnLockout and OnResult are called after a login attempt
	// (events and metrics); each may be nil. result: ok, wrong,
	// locked_out, busy.
	OnLogin   func(website string, prefix netip.Prefix, now time.Time)
	OnLockout func(website string, prefix netip.Prefix, until time.Time)
	OnResult  func(result string)
}

// Login limits (D56).
const (
	hashSlots   = 2
	defHashWait = 2 * time.Second
)

// New returns a lock without protections.
func New() *Lock {
	l := &Lock{limiter: newLimiter(), hashes: make(chan struct{}, hashSlots), HashWait: defHashWait}
	l.cur.Store(&State{Entries: map[string]*Entry{}})
	return l
}

// Store swaps the state in; it is in force for the next request.
func (l *Lock) Store(s *State) { l.cur.Store(s) }

// State returns the state in force. Do not change it.
func (l *Lock) State() *State { return l.cur.Load() }

// Lookup returns the protection of website, nil without one.
func (l *Lock) Lookup(website string) *Entry {
	if l == nil {
		return nil
	}
	s := l.cur.Load()
	if len(s.Entries) == 0 {
		return nil
	}
	return s.Entries[website]
}

// MaintenanceOf returns the maintenance mode of website, nil when it is off.
func (l *Lock) MaintenanceOf(website string) *Maintenance {
	if l == nil {
		return nil
	}
	return l.cur.Load().Maintenance[website]
}

// CheckMaintenance decides r against the maintenance mode of website (D98).
// stopped is true when the website is in maintenance and the client is not
// from an own network: the verdict is the maintenance page. It comes before
// the login form and the protection of the website.
func (l *Lock) CheckMaintenance(r *http.Request, website string, client netip.Addr, allowlisted bool) (v Verdict, stopped bool) {
	m := l.MaintenanceOf(website)
	if m == nil {
		return Verdict{}, false
	}
	e := &Entry{Protection: m.Protection(website)}
	in := access.Input{Protection: e.Protection, Client: client, Allowlisted: allowlisted, Session: access.SessionNone}
	for _, p := range requestPaths(r) {
		in.Path = p
		if res := access.Decide(in); res.Answer != access.AnswerPass {
			return Verdict{Result: res, Entry: e, Website: website}, true
		}
	}
	return Verdict{}, false
}

// Verdict is the decision for one request.
type Verdict struct {
	access.Result
	Entry   *Entry
	Website string
}

// Check decides r for website. ok is false when the website has no
// protection. A request passes only when every spelling of its path
// passes (the path as received and the path Caddy hands on, which differ
// after a rewrite).
func (l *Lock) Check(r *http.Request, website string, client netip.Addr, allowlisted bool, now time.Time) (Verdict, bool) {
	e := l.Lookup(website)
	if e == nil {
		return Verdict{}, false
	}
	session := access.SessionNone
	if e.Protection.Password {
		if c, err := r.Cookie(access.CookieName); err == nil {
			session = access.VerifySession(l.cur.Load().Key, c.Value, website, e.Epoch, now)
		}
	}
	in := access.Input{Protection: e.Protection, Client: client, Allowlisted: allowlisted, Session: session}
	var first access.Result
	for i, p := range requestPaths(r) {
		in.Path = p
		res := access.Decide(in)
		if res.Answer != access.AnswerPass {
			return Verdict{Result: res, Entry: e, Website: website}, true
		}
		if i == 0 {
			first = res
		}
	}
	return Verdict{Result: first, Entry: e, Website: website}, true
}

// requestPaths returns the path as received (RequestURI) and the escaped
// path of r.URL when it differs.
func requestPaths(r *http.Request) []string {
	esc := r.URL.EscapedPath()
	if esc == "" {
		esc = "/"
	}
	raw := r.RequestURI
	if i := strings.IndexByte(raw, '?'); i >= 0 {
		raw = raw[:i]
	}
	if !strings.HasPrefix(raw, "/") || raw == esc {
		return []string{esc}
	}
	return []string{raw, esc}
}

// StripCookie removes the session cookie from r before it goes to the app:
// the app has no use for it and should not log it.
func StripCookie(r *http.Request) {
	vals := r.Header.Values("Cookie")
	if len(vals) == 0 {
		return
	}
	found := false
	var keep []string
	for _, v := range vals {
		for _, part := range strings.Split(v, ";") {
			p := strings.TrimSpace(part)
			if p == "" {
				continue
			}
			if name, _, _ := strings.Cut(p, "="); name == access.CookieName {
				found = true
				continue
			}
			keep = append(keep, p)
		}
	}
	if !found {
		return
	}
	r.Header.Del("Cookie")
	if len(keep) > 0 {
		r.Header.Set("Cookie", strings.Join(keep, "; "))
	}
}
