package gate

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/deutschland-schild/schild/contract/access"
	"github.com/deutschland-schild/schild/gateway/internal/accesslock"
	"github.com/deutschland-schild/schild/gateway/internal/allowlist"
	"github.com/deutschland-schild/schild/gateway/internal/decide"
	"github.com/deutschland-schild/schild/gateway/internal/passhash"
	"github.com/deutschland-schild/schild/gateway/internal/store"
)

const lockPassword = "korrekt-pferd-batterie"

// lockEnv is a gate in autoblock with one protected website (shop.example).
func lockEnv(t *testing.T, p access.Protection) (*tenv, *accesslock.Lock) {
	t.Helper()
	e := newEnv(t, decide.ModeAutoblock)
	e.g.siteID = func(string) string { return "shop.example" }
	l := accesslock.New()
	st := accesslock.NewState()
	p.Website = "shop.example"
	en := &accesslock.Entry{Protection: p, Epoch: 1, Actor: "cli"}
	if p.Password {
		en.Hash = passhash.Hash(lockPassword)
	}
	st.Entries["shop.example"] = en
	l.Store(st)
	e.g.Access = l
	return e, l
}

func TestAccessSiteLock(t *testing.T) {
	e, _ := lockEnv(t, access.Protection{Scope: access.ScopeSite, Password: true, Except: []string{"/hooks/*"}})
	for _, p := range []string{"/", "/wp-content/x.css", "/hooks/../wp-admin", "/HOOKS/x"} {
		for _, m := range []string{"GET", "HEAD", "POST", "OPTIONS", "DELETE"} {
			r := e.do(t, m, p, "", "", nil)
			if r.StatusCode != 503 || r.Header.Get("Retry-After") == "" || r.Header.Get("X-Robots-Tag") != "noindex" {
				t.Fatalf("%s %s: %d %v", m, p, r.StatusCode, r.Header)
			}
			if m == "GET" && !strings.Contains(r.Header.Get("X-Test-Body"), `action="/.schild/access/login"`) {
				t.Fatalf("%s %s: no login form", m, p)
			}
		}
	}
	r := e.do(t, "GET", "/api/x", "", "", map[string]string{"Accept": "application/json"})
	if r.StatusCode != 503 || !strings.Contains(r.Header.Get("Content-Type"), "problem+json") {
		t.Fatalf("json client: %d %s", r.StatusCode, r.Header.Get("Content-Type"))
	}
	if n := e.hits.Load(); n != 0 {
		t.Fatalf("%d requests reached the app while locked", n)
	}
	if r := e.do(t, "GET", "/hooks/paypal", "", "", nil); r.StatusCode != 200 {
		t.Fatalf("except path: %d", r.StatusCode)
	}
	// The WAF still runs behind an except path.
	if r := e.do(t, "GET", "/hooks/paypal"+sqli[1:], "", "", nil); r.StatusCode != 403 {
		t.Fatalf("waf behind except: %d", r.StatusCode)
	}
}

func TestAccessPathTricks(t *testing.T) {
	e, _ := lockEnv(t, access.Protection{Scope: access.ScopePaths, Paths: []string{"/wp-admin/*", "/wp-login.php"}, Password: true})
	for _, p := range []string{"/wp-admin", "/WP-ADMIN/", "//wp-admin//x", "/blog/../wp-admin/", "/blog/%2e%2e/wp-admin", "/wp-admin%2fx",
		"/wp-%61dmin/", "/blog/%252e%252e/wp-admin", "/wp-admin;x/y", "/blog/..;/wp-admin", "/wp-login.php.", "/wp-login.php%20", "/wp-login.php%00.jpg",
		// Path info (D70): PHP runs /wp-login.php for these.
		"/wp-login.php/x", "/wp-login.php%2fx", "/WP-LOGIN.PHP/x", "/wp-login.php;/x", "/wp-login.php/x?action=login"} {
		if r := e.do(t, "GET", p, "", "", nil); r.StatusCode != 403 {
			t.Errorf("%s: %d", p, r.StatusCode)
		}
	}
	if n := e.hits.Load(); n != 0 {
		t.Fatalf("%d requests reached the app", n)
	}
	if r := e.do(t, "GET", "/blog/hallo", "", "", nil); r.StatusCode != 200 {
		t.Fatalf("public path: %d", r.StatusCode)
	}
}

func login(t *testing.T, e *tenv, pw, ret, xff string) *http.Response {
	t.Helper()
	form := url.Values{"password": {pw}, "return": {ret}}.Encode()
	req, _ := http.NewRequest("POST", e.srv.URL+accesslock.LoginPath, strings.NewReader(form))
	req.Host = "shop.example"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "text/html")
	if xff != "" {
		req.Header.Set("X-Forwarded-For", xff)
	}
	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	r, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	return r
}

func TestAccessLogin(t *testing.T) {
	e, l := lockEnv(t, access.Protection{Scope: access.ScopeSite, Password: true})
	r := login(t, e, lockPassword, "/wp-admin/?x=1", "198.51.100.20")
	if r.StatusCode != 303 || r.Header.Get("Location") != "/wp-admin/?x=1" {
		t.Fatalf("login: %d %s", r.StatusCode, r.Header.Get("Location"))
	}
	var cookie *http.Cookie
	for _, c := range r.Cookies() {
		if c.Name == access.CookieName {
			cookie = c
		}
	}
	if cookie == nil || !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode || cookie.Path != "/" {
		t.Fatalf("cookie: %+v", cookie)
	}
	r = e.do(t, "GET", "/wp-admin/", "", "", map[string]string{"Cookie": "a=1; " + access.CookieName + "=" + cookie.Value})
	if r.StatusCode != 200 {
		t.Fatalf("with session: %d", r.StatusCode)
	}
	// Open redirects are refused.
	for _, ret := range []string{"//evil.example/", "https://evil.example/", `/\evil.example`} {
		if r := login(t, e, lockPassword, ret, "198.51.100.20"); r.Header.Get("Location") != "/" {
			t.Errorf("return %q: %s", ret, r.Header.Get("Location"))
		}
	}
	// A new epoch ends the session.
	st := l.State().Clone()
	st.Entries["shop.example"].Epoch++
	l.Store(st)
	if r := e.do(t, "GET", "/", "", "", map[string]string{"Cookie": access.CookieName + "=" + cookie.Value}); r.StatusCode != 503 {
		t.Fatalf("old epoch: %d", r.StatusCode)
	}
}

func TestAccessLockout(t *testing.T) {
	e, l := lockEnv(t, access.Protection{Scope: access.ScopePaths, Paths: []string{"/wp-admin/*"}, Password: true})
	results := map[string]int{}
	l.OnResult = func(r string) { results[r]++ }
	for i := 0; i < accesslock.FailLimit; i++ {
		if r := login(t, e, "falsch", "/wp-admin/", "198.51.100.20"); r.StatusCode != 403 {
			t.Fatalf("wrong %d: %d", i, r.StatusCode)
		}
	}
	r := login(t, e, lockPassword, "/wp-admin/", "198.51.100.77")
	if r.StatusCode != 429 {
		t.Fatalf("same /24 after lockout: %d", r.StatusCode)
	}
	if r := login(t, e, lockPassword, "/wp-admin/", "203.0.113.5"); r.StatusCode != 303 {
		t.Fatalf("other prefix: %d", r.StatusCode)
	}
	if results[accesslock.ResultWrong] != accesslock.FailLimit || results[accesslock.ResultLockedOut] != 1 || results[accesslock.ResultOK] != 1 {
		t.Fatalf("results %v", results)
	}
	if n := e.hits.Load(); n != 0 {
		t.Fatalf("%d logins reached the app", n)
	}
}

func TestAccessAddressesAndOwnNetworks(t *testing.T) {
	e, _ := lockEnv(t, access.Protection{Scope: access.ScopePaths, Paths: []string{"/wp-admin/*"}, Addresses: []string{"203.0.113.0/24"}, OwnNetworks: true})
	xff := func(ip string) map[string]string { return map[string]string{"X-Forwarded-For": ip} }
	r := e.do(t, "GET", "/wp-admin/", "", "", xff("198.51.100.20"))
	if r.StatusCode != 403 || strings.Contains(r.Header.Get("X-Test-Body"), "<form") {
		t.Fatalf("stranger: %d (no form without a password)", r.StatusCode)
	}
	if r := e.do(t, "GET", "/wp-admin/", "", "", xff("203.0.113.9")); r.StatusCode != 200 {
		t.Fatalf("listed network: %d", r.StatusCode)
	}
	e.g.Allow.Set([]store.AllowEntry{{ID: "a", IP: "198.51.100.20", Label: "büro", Level: allowlist.NoBlock, Expires: "never"}})
	if r := e.do(t, "GET", "/wp-admin/", "", "", xff("198.51.100.20")); r.StatusCode != 200 {
		t.Fatalf("own network: %d", r.StatusCode)
	}
}

// D58: password and addresses together. Only the listed network may log
// in, and a session from elsewhere does not open the path.
func TestAccessPasswordAndAddress(t *testing.T) {
	e, _ := lockEnv(t, access.Protection{Scope: access.ScopePaths, Paths: []string{"/wp-admin/*"}, Password: true, Addresses: []string{"203.0.113.0/24"}})
	xff := func(ip string, more map[string]string) map[string]string {
		m := map[string]string{"X-Forwarded-For": ip}
		for k, v := range more {
			m[k] = v
		}
		return m
	}
	if r := login(t, e, lockPassword, "/wp-admin/", "198.51.100.20"); r.StatusCode != 303 || r.Header.Get("Location") != "/" || len(r.Cookies()) != 0 {
		t.Fatalf("login from a stranger: %d %s %v", r.StatusCode, r.Header.Get("Location"), r.Cookies())
	}
	r := login(t, e, lockPassword, "/wp-admin/", "203.0.113.9")
	var cookie string
	for _, c := range r.Cookies() {
		if c.Name == access.CookieName {
			cookie = access.CookieName + "=" + c.Value
		}
	}
	if r.StatusCode != 303 || cookie == "" {
		t.Fatalf("login from the listed network: %d", r.StatusCode)
	}
	if r := e.do(t, "GET", "/wp-admin/", "", "", xff("203.0.113.9", nil)); r.StatusCode != 403 || !strings.Contains(r.Header.Get("X-Test-Body"), "<form") {
		t.Fatalf("listed network without session: %d, want the login form", r.StatusCode)
	}
	if r := e.do(t, "GET", "/wp-admin/", "", "", xff("198.51.100.20", map[string]string{"Cookie": cookie})); r.StatusCode != 403 || strings.Contains(r.Header.Get("X-Test-Body"), "<form") {
		t.Fatalf("session from a stranger: %d, want 403 without a form", r.StatusCode)
	}
	if r := e.do(t, "GET", "/wp-admin/", "", "", xff("203.0.113.9", map[string]string{"Cookie": cookie})); r.StatusCode != 200 {
		t.Fatalf("listed network with session: %d", r.StatusCode)
	}
}
