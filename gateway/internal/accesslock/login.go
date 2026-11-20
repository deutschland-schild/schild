package accesslock

import (
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/deutschland-schild/schild/contract/access"
	"github.com/deutschland-schild/schild/gateway/internal/passhash"
)

// Login limits (D56): 5 wrong guesses of one address prefix within 15
// minutes lock that prefix out of the website's login for 15 minutes.
const (
	FailLimit  = 5
	FailWindow = 15 * time.Minute
	Lockout    = 15 * time.Minute
	maxForm    = 4 << 10
	maxKeys    = 16384
)

// formWait bounds the read of the login form (a variable for tests).
var formWait = 10 * time.Second

// Results of a login attempt (schild_access_logins_total{result}).
const (
	ResultOK        = "ok"
	ResultWrong     = "wrong"
	ResultLockedOut = "locked_out"
	ResultBusy      = "busy"
)

// Login answers a request to LoginPath at website and returns the status
// written. Only a POST of the form of a protection with a password logs in,
// and only from an address the protection allows (D58: a password from
// elsewhere would not let the client in, so it is not even checked);
// everything else goes back to the website. A wrong and an empty password
// cost the same hash.
func (l *Lock) Login(w http.ResponseWriter, r *http.Request, website string, client netip.Addr, allowlisted bool, now time.Time) int {
	e := l.Lookup(website)
	if r.Method != http.MethodPost || e == nil || !e.Protection.Password || !e.Protection.AddressAllowed(client, allowlisted) {
		return redirect(w, "/")
	}
	// The form is read before any limit of the gate on bodies: without an end
	// a client sending it a byte now and then would keep a running request, a
	// place the limit of open connections never takes back.
	_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(formWait))
	body, err := io.ReadAll(io.LimitReader(r.Body, maxForm+1))
	if err != nil || len(body) > maxForm {
		return redirect(w, "/")
	}
	form, err := url.ParseQuery(string(body))
	if err != nil {
		return redirect(w, "/")
	}
	ret := returnPath(form.Get("return"))
	pw := form.Get("password")
	// The page to show again on failure: the one of the return path.
	again := func(note string, status int) int {
		v := Verdict{Entry: e, Website: website}
		v.Answer, v.LoginForm = access.AnswerLogin, true
		if e.Protection.Scope == access.ScopeSite {
			v.Answer = access.AnswerMaintenance
		}
		if status == 0 {
			status = http.StatusForbidden
			if v.Answer == access.AnswerMaintenance {
				status = http.StatusServiceUnavailable
			}
		}
		rr := r.Clone(r.Context())
		rr.URL, _ = url.Parse(ret)
		if rr.URL == nil {
			rr.URL = &url.URL{Path: "/"}
		}
		writeStatus(w, rr, v, status, note, now)
		return status
	}
	key := limitKey{website: website, prefix: Prefix(client)}
	if until, locked := l.limiter.locked(key, now); locked {
		l.result(ResultLockedOut)
		w.Header().Set("Retry-After", strconv.Itoa(int(until.Sub(now).Seconds())+1))
		return again(NoteLocked, http.StatusTooManyRequests)
	}
	if !l.acquire() {
		l.result(ResultBusy)
		w.Header().Set("Retry-After", "5")
		return again(NoteBusy, http.StatusTooManyRequests)
	}
	ok := len(pw) <= access.MaxPasswordLen && passhash.Check(e.Hash, pw)
	l.release()
	if !ok {
		l.result(ResultWrong)
		if until, newly := l.limiter.fail(key, now); newly && l.OnLockout != nil {
			l.OnLockout(website, key.prefix, until)
		}
		return again(NoteWrong, 0)
	}
	l.limiter.reset(key)
	l.result(ResultOK)
	if l.OnLogin != nil {
		l.OnLogin(website, key.prefix, now)
	}
	exp := now.Add(access.SessionTTL)
	http.SetCookie(w, &http.Cookie{
		Name: access.CookieName, Value: access.SessionValue(l.cur.Load().Key, website, e.Epoch, exp),
		Path: "/", MaxAge: int(exp.Sub(now).Seconds()), Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
	return redirect(w, ret)
}

func redirect(w http.ResponseWriter, to string) int {
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("X-Robots-Tag", "noindex")
	h.Set("Location", to)
	w.WriteHeader(http.StatusSeeOther)
	return http.StatusSeeOther
}

func (l *Lock) result(r string) {
	if l.OnResult != nil {
		l.OnResult(r)
	}
}

func (l *Lock) acquire() bool {
	select {
	case l.hashes <- struct{}{}:
		return true
	default:
	}
	t := time.NewTimer(l.HashWait)
	defer t.Stop()
	select {
	case l.hashes <- struct{}{}:
		return true
	case <-t.C:
		return false
	}
}

func (l *Lock) release() { <-l.hashes }

// Prefix is the address prefix a login is counted and logged under: /24
// for IPv4, /48 for IPv6; the zero prefix for an unknown address.
func Prefix(ip netip.Addr) netip.Prefix {
	if !ip.IsValid() {
		return netip.Prefix{}
	}
	ip = ip.Unmap()
	bits := 48
	if ip.Is4() {
		bits = 24
	}
	p, _ := ip.Prefix(bits)
	return p
}

type limitKey struct {
	website string
	prefix  netip.Prefix
}

type tries struct {
	n     int
	first time.Time
	until time.Time
}

// limiter counts wrong guesses per website and address prefix, bounded in
// keys: when full, keys whose window and lockout ended go first; a new key
// beyond that shares one overflow key per website, for counting and for the
// lockout alike.
type limiter struct {
	mu sync.Mutex
	m  map[limitKey]*tries
}

func newLimiter() *limiter { return &limiter{m: map[limitKey]*tries{}} }

func (l *limiter) locked(k limitKey, now time.Time) (time.Time, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	t := l.m[l.slot(k, now)]
	if t != nil && t.until.After(now) {
		return t.until, true
	}
	return time.Time{}, false
}

// fail counts a wrong guess; newly is true when it started a lockout.
func (l *limiter) fail(k limitKey, now time.Time) (time.Time, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	k = l.slot(k, now)
	t := l.m[k]
	if t == nil || now.Sub(t.first) >= FailWindow {
		t = &tries{first: now}
		l.m[k] = t
	}
	t.n++
	if t.n >= FailLimit && !t.until.After(now) {
		t.until = now.Add(Lockout)
		t.n, t.first = 0, now
		return t.until, true
	}
	return time.Time{}, false
}

// reset forgets the guesses of k after a login (a locked key never gets
// that far).
func (l *limiter) reset(k limitKey) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.m, k)
}

// slot returns the key to count and check under: locked must ask the key
// fail counts under, or guesses beyond maxKeys would never lock anything.
// Called with mu held.
func (l *limiter) slot(k limitKey, now time.Time) limitKey {
	if _, ok := l.m[k]; ok || len(l.m) < maxKeys {
		return k
	}
	for x, t := range l.m {
		if now.Sub(t.first) >= FailWindow && !t.until.After(now) {
			delete(l.m, x)
		}
	}
	if len(l.m) < maxKeys {
		return k
	}
	return limitKey{website: k.website}
}
