package dashboard

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/deutschland-schild/schild/contract/msg"
	"github.com/deutschland-schild/schild/lab/internal/rules"
	"github.com/deutschland-schild/schild/lab/internal/store"
)

// Password hashing: PBKDF2-HMAC-SHA256 (stdlib, FIPS-approved). Iterations
// follow the OWASP 2023 recommendation; tests lower it.
var pbkdf2Iterations = 600_000

const (
	cookieName      = "schild_lab_session"
	csrfHeader      = "X-CSRF-Token"
	localhostUser   = rules.LocalhostUser
	maxLoginFails   = 5
	loginFailWindow = 15 * time.Minute
)

type user struct {
	Name       string `json:"name"`
	Salt       string `json:"salt"`
	Hash       string `json:"hash"`
	Iterations int    `json:"iterations"`
	CreatedAt  string `json:"created_at"`
}

type session struct {
	token   string
	user    string
	csrf    string
	via     string // localhost | password
	expires time.Time
}

// Auth manages dashboard users and sessions.
type Auth struct {
	DB        *store.DB
	TTL       time.Duration
	Now       func() time.Time
	SetupCode string // one-time code printed in the log, required from everywhere

	mu       sync.Mutex
	sessions map[string]*session
	fails    map[string][]time.Time
}

func newAuth(db *store.DB, ttl time.Duration, now func() time.Time) *Auth {
	return &Auth{DB: db, TTL: ttl, Now: now, sessions: map[string]*session{}, fails: map[string][]time.Time{}, SetupCode: randomToken(9)}
}

func randomToken(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func hashPassword(pw string, salt []byte, iter int) string {
	k, _ := pbkdf2.Key(sha256.New, pw, salt, iter, 32)
	return hex.EncodeToString(k)
}

// HasUsers reports whether any dashboard user exists.
func (a *Auth) HasUsers() bool {
	found := false
	_ = a.DB.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(store.Auth).Cursor()
		k, _ := c.Seek([]byte("user:"))
		found = k != nil && strings.HasPrefix(string(k), "user:")
		return nil
	})
	return found
}

// SetPassword creates or replaces a user.
func (a *Auth) SetPassword(name, pw string) error {
	if len(pw) < 12 || len(pw) > 256 {
		return errors.New("password needs 12 to 256 characters")
	}
	if !validUser(name) {
		return errors.New("user names are 1-64 characters a-z, 0-9, '.', '-', '_'")
	}
	salt := make([]byte, 16)
	_, _ = rand.Read(salt)
	u := user{Name: name, Salt: hex.EncodeToString(salt), Hash: hashPassword(pw, salt, pbkdf2Iterations), Iterations: pbkdf2Iterations, CreatedAt: msg.FormatTime(a.Now())}
	return a.DB.Update(func(tx *bolt.Tx) error { return store.PutJSON(tx, store.Auth, []byte("user:"+name), &u) })
}

func validUser(s string) bool {
	if s == "" || len(s) > 64 || s == localhostUser {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// Check verifies a password (constant-time compare) with a failure limit.
func (a *Auth) Check(name, pw string) (ok bool, limited bool) {
	now := a.Now()
	a.mu.Lock()
	recent := a.fails[name][:0:0]
	for _, t := range a.fails[name] {
		if now.Sub(t) < loginFailWindow {
			recent = append(recent, t)
		}
	}
	a.fails[name] = recent
	if len(recent) >= maxLoginFails {
		a.mu.Unlock()
		return false, true
	}
	a.mu.Unlock()
	var u user
	found := false
	_ = a.DB.View(func(tx *bolt.Tx) error {
		found, _ = store.GetJSON(tx, store.Auth, []byte("user:"+name), &u)
		return nil
	})
	salt, _ := hex.DecodeString(u.Salt)
	iter := u.Iterations
	if !found {
		salt, iter = []byte("schild-no-such-user"), pbkdf2Iterations // same work either way
	}
	got := hashPassword(pw, salt, iter)
	ok = found && hmac.Equal([]byte(got), []byte(u.Hash))
	if !ok {
		a.mu.Lock()
		a.fails[name] = append(a.fails[name], now)
		a.mu.Unlock()
	}
	return ok, false
}

func (a *Auth) create(userName, via string) *session {
	s := &session{token: randomToken(32), user: userName, csrf: randomToken(24), via: via, expires: a.Now().Add(a.TTL)}
	a.mu.Lock()
	a.sessions[s.token] = s
	a.mu.Unlock()
	return s
}

func (a *Auth) lookup(r *http.Request) *session {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	s := a.sessions[c.Value]
	if s == nil {
		return nil
	}
	if a.Now().After(s.expires) {
		delete(a.sessions, c.Value)
		return nil
	}
	return s
}

func (a *Auth) drop(s *session) {
	a.mu.Lock()
	delete(a.sessions, s.token)
	a.mu.Unlock()
}

func (a *Auth) setCookie(w http.ResponseWriter, r *http.Request, s *session) {
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: s.token, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode,
		Secure: !isLocal(r), Expires: s.expires})
}

// isLocal reports a request from this host to a loopback name: no proxy in
// between and no DNS-rebinding host name.
func isLocal(r *http.Request) bool {
	if r.TLS != nil || r.Header.Get("X-Forwarded-For") != "" || r.Header.Get("Forwarded") != "" {
		return false
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return false
	}
	h := r.Host
	if hh, _, err := net.SplitHostPort(h); err == nil {
		h = hh
	}
	h = strings.Trim(h, "[]")
	return h == "localhost" || h == "127.0.0.1" || h == "::1"
}

// sessionView is the API Session.
type sessionView struct {
	Authenticated bool    `json:"authenticated"`
	FirstRun      bool    `json:"first_run"`
	User          string  `json:"user,omitempty"`
	Role          string  `json:"role,omitempty"`
	CSRFToken     string  `json:"csrf_token,omitempty"`
	ExpiresAt     *string `json:"expires_at,omitempty"`
	Via           string  `json:"via,omitempty"`
}

func (a *Auth) view(s *session) sessionView {
	v := sessionView{FirstRun: !a.HasUsers()}
	if s != nil {
		exp := msg.FormatTime(s.expires)
		v.Authenticated, v.User, v.Role, v.CSRFToken, v.ExpiresAt, v.Via = true, s.user, "admin", s.csrf, &exp, s.via
	}
	return v
}

// NewAuthStore returns user management without a server (CLI).
func NewAuthStore(db *store.DB) *Auth { return newAuth(db, time.Hour, time.Now) }
