package behaviour

import (
	"net/url"
	"path"
	"regexp"
	"strings"

	"github.com/deutschland-schild/schild/contract/config"
)

// Response is what the scenarios may look at in an answer of the app:
// status, the redirect target and the names (never values) of cookies set.
type Response struct {
	Status      int
	Location    string
	CookieNames []string
}

// loginRoute is a known login form of a preset. Failure is decided from the
// response pattern of the preset only, never by reading a password.
type loginRoute struct {
	Preset string
	Path   string // exact path
	Query  string // required query parameter "k=v" ("" = none)
	// UserFields are body parameters that carry the user name (hashed into
	// a sketch for credential_stuffing, never stored).
	UserFields []string
	Failed     func(Response) bool
}

func statusIn(st int, codes ...int) bool {
	for _, c := range codes {
		if st == c {
			return true
		}
	}
	return false
}

func redirectTo(r Response, suffix string) bool {
	if r.Status < 300 || r.Status > 399 || r.Location == "" {
		return false
	}
	u, err := url.Parse(r.Location)
	if err != nil {
		return false
	}
	return strings.HasSuffix(strings.TrimSuffix(u.Path, "/"), suffix)
}

func setsCookie(r Response, name string) bool {
	for _, c := range r.CookieNames {
		if c == name {
			return true
		}
	}
	return false
}

// loginFailedOnPage: the form is shown again (200) or the app refuses (401/403).
func loginFailedOnPage(r Response) bool { return statusIn(r.Status, 200, 401, 403) }

// loginFailedGeneric: an explicit refusal (401/403/422/429) or a redirect
// back to the login form (Nextcloud, Laravel and most frameworks). A plain
// 200 is not counted: single-page apps answer 200 for success too.
func loginFailedGeneric(r Response) bool {
	return statusIn(r.Status, 401, 403, 422, 429) || redirectTo(r, "/login")
}

// Joomla answers 303 for success and failure; a successful login sets the
// cookie joomla_user_state (name only is checked).
func joomlaFailed(r Response) bool {
	if statusIn(r.Status, 401, 403) {
		return true
	}
	return r.Status >= 300 && r.Status <= 399 && !setsCookie(r, "joomla_user_state")
}

var loginRoutes = []loginRoute{
	// WordPress: a failed login renders the form again with 200 (CrowdSec
	// hub http-bf-wordpress_bf filters POST wp-login.php status 200); a
	// success redirects. xmlrpc.php always answers 200, so it is covered by
	// its rate limit, not by this scenario.
	{Preset: "wordpress", Path: "/wp-login.php", UserFields: []string{"log"}, Failed: loginFailedOnPage},
	{Preset: "joomla", Path: "/administrator/index.php", UserFields: []string{"username"}, Failed: joomlaFailed},
	{Preset: "joomla", Path: "/index.php", Query: "task=user.login", UserFields: []string{"username"}, Failed: joomlaFailed},
	{Preset: "drupal", Path: "/user/login", UserFields: []string{"name"}, Failed: loginFailedOnPage},
	{Preset: "nextcloud", Path: "/index.php/login", UserFields: []string{"user"}, Failed: loginFailedGeneric},
	{Preset: "typo3", Path: "/typo3/login", UserFields: []string{"username"}, Failed: loginFailedOnPage},
	{Preset: "typo3", Path: "/typo3/index.php", Query: "route=/login", UserFields: []string{"username"}, Failed: loginFailedOnPage},
	// /login is shared by Nextcloud, Laravel and the generic preset; their
	// failure patterns agree (redirect back to /login, or 401/403/422/429).
	// The generic entry comes first and names every user field of the three,
	// so a hit at /login is not called Nextcloud on every website; the other
	// two only matter when generic is switched off in behaviour.presets.
	{Preset: "generic", Path: "/login", UserFields: []string{"username", "user", "email", "login"}, Failed: loginFailedGeneric},
	{Preset: "nextcloud", Path: "/login", UserFields: []string{"user", "email", "username"}, Failed: loginFailedGeneric},
	{Preset: "laravel", Path: "/login", UserFields: []string{"email", "username"}, Failed: loginFailedGeneric},
	{Preset: "generic", Path: "/signin", UserFields: []string{"username", "user", "email", "login"}, Failed: loginFailedGeneric},
	{Preset: "generic", Path: "/api/login", UserFields: []string{"username", "user", "email", "login"}, Failed: loginFailedGeneric},
	{Preset: "generic", Path: "/auth/login", UserFields: []string{"username", "user", "email", "login"}, Failed: loginFailedGeneric},
}

// Form is what the gate knows of the form fields in a request body, once
// the body is buffered.
type Form struct {
	// Fields are the urlencoded fields ("" for a request without body).
	Fields string
	// Opaque: the body may carry fields that Fields does not show (multipart,
	// another or an unclear content type, more than the gate reads).
	Opaque bool
}

// matchLogin returns the login route for a POST to path with rawQuery among
// the enabled presets (first match wins). form is asked only for a route
// whose meaning hangs on a body field; nil stands for a body nobody read.
func matchLogin(enabled map[string]bool, method, p, rawQuery string, form func() Form) *loginRoute {
	if method != "POST" {
		return nil
	}
	canon := canonPath(p)
	for i := range loginRoutes {
		lr := &loginRoutes[i]
		if !enabled[lr.Preset] || !routeIs(lr.Path, p, canon) {
			continue
		}
		if lr.Query != "" && !hasQuery(rawQuery, lr.Query) {
			continue
		}
		if lr.Path == "/wp-login.php" && !wpLogin(rawQuery, form) {
			continue
		}
		return lr
	}
	return nil
}

// wpOtherActions are the actions of wp-login.php that are no login attempt:
// its $default_actions without "login". Every other value, a plugin's own
// action included, counts as a login, which is what wp-login.php does with
// a value it does not know.
var wpOtherActions = map[string]bool{
	"confirm_admin_email": true, "postpass": true, "logout": true, "lostpassword": true,
	"retrievepassword": true, "resetpass": true, "rp": true, "register": true,
	"checkemail": true, "confirmaction": true, "entered_recovery_mode": true,
}

// wpQueryVars: a query with more parameters than this never says "no login".
// PHP reads max_input_vars of them (1000 ab Werk) and drops the rest, so an
// action behind that many would be ours alone. WordPress sends a handful.
const wpQueryVars = 32

// wpLogin reports whether a POST to wp-login.php is a login attempt.
// WordPress takes the action from $_REQUEST, which it builds as the query
// overlaid by the body; an action it does not know and one that is no
// string ("action[]=x") fall back to "login". So the request is no login
// only in the form WordPress itself sends: the query names an action of
// wpOtherActions, and neither query nor body carry anything PHP could read
// as another one. Whatever is unclear counts as a login attempt: that costs
// an odd request a count, the other side would hide attempts from
// login_bruteforce, credential_stuffing and account_wave.
func wpLogin(rawQuery string, form func() Form) bool {
	other, odd := wpActions(rawQuery, wpQueryVars)
	if odd || other == 0 {
		return true
	}
	if form == nil {
		return true
	}
	f := form()
	if f.Opaque {
		return true
	}
	_, odd = wpActions(f.Fields, 0)
	return odd
}

// wpActions reads the action parameters of a query or a urlencoded body:
// other counts those that name an action of wpOtherActions, odd tells that
// PHP may read an action that is none of them. PHP drops leading spaces of
// a name, makes "action[...]" an array and may end a name at a NUL byte,
// so a name that only starts with "action" is odd; so is one behind a ';',
// which separates parameters where arg_separator.input says so. With
// limit > 0, more than limit parameters are odd as well.
func wpActions(raw string, limit int) (other int, odd bool) {
	isAction := func(k string) (bool, bool) {
		k = strings.TrimLeft(unescape(k), " ")
		return strings.HasPrefix(k, "action"), k == "action"
	}
	n := 0
	for raw != "" {
		var part string
		part, raw, _ = strings.Cut(raw, "&")
		if part == "" {
			continue
		}
		if n++; limit > 0 && n > limit {
			return other, true
		}
		k, v, _ := strings.Cut(part, "=")
		if is, exact := isAction(k); is {
			if !exact || !wpOtherActions[unescape(v)] {
				return other, true
			}
			other++
			continue
		}
		for _, piece := range strings.Split(part, ";")[1:] {
			k, _, _ := strings.Cut(piece, "=")
			if is, _ := isAction(k); is {
				return other, true
			}
		}
	}
	return other, false
}

// canonPath is the path a backend serves for the request path p when that
// is not p itself: repeated slashes and dot segments resolved, no trailing
// slash ("" when p is already canonical). PHP behind nginx or Caddy, Laravel
// and Symfony serve "//login/" or "/./wp-login.php" as the route itself. It
// allocates only for such a path.
func canonPath(p string) string {
	if len(p) < 2 || !strings.Contains(p, "//") && !strings.Contains(p, "/.") && p[len(p)-1] != '/' {
		return ""
	}
	if c := path.Clean(p); c != p {
		return c
	}
	return ""
}

// routeIs reports whether the request path p (canon is canonPath(p)) is the
// exact route: p itself, its canonical form, or for a PHP script the script
// with a PATH_INFO behind it ("/wp-login.php/x" runs /wp-login.php). Login
// presets and rate limits match through it, so a variant the backend treats
// as the same route does not slip past them.
func routeIs(route, p, canon string) bool {
	if p == route || canon == route {
		return true
	}
	if canon != "" {
		p = canon
	}
	return strings.HasSuffix(route, ".php") && len(p) > len(route) && p[len(route)] == '/' && strings.HasPrefix(p, route)
}

// hasQuery reports whether rawQuery has a parameter that matches kv: "k=v"
// for that value, "k" for any value that is not empty. Every occurrence of k
// counts: backends disagree on which of two wins (PHP the last, others the
// first), so a second "task=" in front of the real one must not hide it.
func hasQuery(rawQuery, kv string) bool {
	k, v, hasV := strings.Cut(kv, "=")
	for _, got := range FormValues(rawQuery, k) {
		if (hasV && got == v) || (!hasV && got != "") {
			return true
		}
	}
	return false
}

// FormValues returns every value of the parameter k in a query string or a
// urlencoded form, in order. Parameters are cut at '&' only, as PHP and the
// WAF do, and a bad escape stays as it stands: url.ParseQuery refuses the
// whole string for one ';' or one bad escape anywhere in it, which let an
// unrelated parameter switch the match off.
func FormValues(raw, k string) []string {
	var out []string
	for raw != "" {
		var part string
		part, raw, _ = strings.Cut(raw, "&")
		if part == "" {
			continue
		}
		rk, rv, _ := strings.Cut(part, "=")
		if unescape(rk) != k {
			continue
		}
		out = append(out, unescape(rv))
	}
	return out
}

// unescape decodes as PHP does: '+' is a space, "%XX" a byte, and a '%'
// without two hex digits stays as it stands (url.QueryUnescape refuses the
// whole string for it, and "%61ction=x%zz" would be no action).
func unescape(s string) string {
	if !strings.ContainsAny(s, "%+") {
		return s
	}
	b := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '+':
			c = ' '
		case c == '%' && i+2 < len(s) && unhex(s[i+1]) >= 0 && unhex(s[i+2]) >= 0:
			c = byte(unhex(s[i+1])<<4 | unhex(s[i+2]))
			i += 2
		}
		b = append(b, c)
	}
	return string(b)
}

func unhex(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	}
	return -1
}

// presetLimit is a rate limit that ships with a preset.
type presetLimit struct {
	Preset string
	Name   string
	Label  string
	config.RateLimit
	Query string // required query parameter "k" or "k=v" (presets only)
	// Recommended is the mode of the limit when schild.yaml sets none (D95).
	Recommended string
}

// presetKinds: what a preset limit is for, its label when several presets
// share the route, and its recommended mode (D95). Login, password reset and
// xmlrpc limit ab Werk: a person never reaches them. Search, contact forms and
// API writes observe: a shop search or an app that writes through its API on
// purpose gets there, the numbers show it first.
var presetKinds = map[string]struct{ label, recommended string }{
	"login":          {"Anmeldung", config.BehaviourBlock},
	"password-reset": {"Passwort vergessen", config.BehaviourBlock},
	"xmlrpc":         {"XML-RPC", config.BehaviourBlock},
	"search":         {"Suche", config.BehaviourObserve},
	"contact":        {"Kontaktformular", config.BehaviourObserve},
	"api-write":      {"API (schreibend)", config.BehaviourObserve},
}

func pl(preset, name, label, route string, methods []string, limit int, per string, burst int, query string) presetLimit {
	return presetLimit{Preset: preset, Name: name, Label: label, Query: query, Recommended: presetKinds[name].recommended,
		RateLimit: config.RateLimit{ID: "preset-" + preset + "-" + name, Label: label, Route: route, Methods: methods, Limit: limit, Per: per, Burst: burst}}
}

var (
	post   = []string{"POST"}
	get    = []string{"GET", "HEAD"}
	writes = []string{"POST", "PUT", "PATCH", "DELETE"}
)

// presetLimits: login, password reset, xmlrpc, search, contact forms and API
// writes. Generous on purpose: a person never reaches them, a script does.
var presetLimits = []presetLimit{
	pl("wordpress", "login", "WordPress Anmeldung", "/wp-login.php", post, 10, "1m", 10, ""),
	pl("wordpress", "password-reset", "WordPress Passwort vergessen", "/wp-login.php", post, 3, "10m", 3, "action=lostpassword"),
	pl("wordpress", "xmlrpc", "WordPress XML-RPC", "/xmlrpc.php", post, 10, "1m", 10, ""),
	pl("wordpress", "search", "WordPress Suche", "/", get, 30, "1m", 30, "s"),
	pl("wordpress", "contact", "WordPress Kontaktformular", "/wp-json/contact-form-7/v1/contact-forms/*/feedback", post, 5, "10m", 5, ""),
	pl("wordpress", "api-write", "WordPress REST-API (schreibend)", "/wp-json/**", writes, 60, "1m", 120, ""),
	pl("joomla", "login", "Joomla Anmeldung", "/administrator/index.php", post, 10, "1m", 10, ""),
	pl("joomla", "password-reset", "Joomla Passwort vergessen", "/index.php", post, 3, "10m", 3, "task=reset.request"),
	pl("joomla", "search", "Joomla Suche", "/index.php", get, 30, "1m", 30, "option=com_finder"),
	pl("joomla", "api-write", "Joomla Web-API (schreibend)", "/api/**", writes, 60, "1m", 120, ""),
	pl("drupal", "login", "Drupal Anmeldung", "/user/login", post, 10, "1m", 10, ""),
	pl("drupal", "password-reset", "Drupal Passwort vergessen", "/user/password", post, 3, "10m", 3, ""),
	pl("drupal", "search", "Drupal Suche", "/search/**", get, 30, "1m", 30, ""),
	pl("drupal", "contact", "Drupal Kontaktformular", "/contact/**", post, 5, "10m", 5, ""),
	pl("drupal", "api-write", "Drupal JSON:API (schreibend)", "/jsonapi/**", writes, 60, "1m", 120, ""),
	pl("nextcloud", "login", "Nextcloud Anmeldung", "/index.php/login", post, 10, "1m", 10, ""),
	pl("nextcloud", "password-reset", "Nextcloud Passwort vergessen", "/index.php/lostpassword/email", post, 3, "10m", 3, ""),
	pl("typo3", "login", "TYPO3 Anmeldung", "/typo3/login", post, 10, "1m", 10, ""),
	pl("typo3", "password-reset", "TYPO3 Passwort vergessen", "/typo3/login/password-reset/**", post, 3, "10m", 3, ""),
	pl("laravel", "login", "Laravel Anmeldung", "/login", post, 10, "1m", 10, ""),
	pl("laravel", "password-reset", "Laravel Passwort vergessen", "/forgot-password", post, 3, "10m", 3, ""),
	pl("laravel", "api-write", "Laravel API (schreibend)", "/api/**", writes, 60, "1m", 120, ""),
	pl("generic", "login", "Anmeldung", "/login", post, 10, "1m", 10, ""),
	pl("generic", "contact", "Kontaktformular", "/contact", post, 5, "10m", 5, ""),
	pl("generic", "search", "Suche", "/search", get, 30, "1m", 30, ""),
}

// PresetLimits returns the preset limits of the enabled presets. A route
// that several enabled presets share (/login, /api/**) is listed once and
// belongs to none of them (D95): preset generic, the label of its kind, id
// preset-generic-<kind>. Named after the first of them, the write limit of
// every /api/** was "Joomla" on any website.
func PresetLimits(presets []string) []presetLimit {
	on := map[string]bool{}
	for _, p := range presets {
		on[p] = true
	}
	key := func(l *presetLimit) string { return l.Route + "|" + strings.Join(l.Methods, ",") + "|" + l.Query }
	shared := map[string]int{}
	for i := range presetLimits {
		if l := &presetLimits[i]; on[l.Preset] {
			shared[key(l)]++
		}
	}
	seen := map[string]bool{}
	var out []presetLimit
	for _, l := range presetLimits {
		if !on[l.Preset] {
			continue
		}
		k := key(&l)
		if seen[k] {
			continue
		}
		seen[k] = true
		if shared[k] > 1 {
			l.Preset, l.Label = "generic", presetKinds[l.Name].label
			l.RateLimit.Label, l.ID = l.Label, "preset-generic-"+l.Name
		}
		out = append(out, l)
	}
	return out
}

// staticExt are assets that never count as probing or crawling.
var staticExt = map[string]bool{
	".css": true, ".js": true, ".mjs": true, ".map": true, ".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".svg": true, ".ico": true,
	".webp": true, ".avif": true, ".woff": true, ".woff2": true, ".ttf": true, ".otf": true, ".eot": true, ".mp4": true, ".webm": true, ".mp3": true,
	".pdf": true, ".txt": true, ".xml": true, ".json": true, ".webmanifest": true,
}

// IsStatic reports whether p looks like a static asset.
func IsStatic(p string) bool { return staticExt[strings.ToLower(path.Ext(p))] }

// probePaths are typical for scanners and weigh more (spec: .env, .git/,
// wp-config.php.bak, phpmyadmin, /vendor/phpunit).
var probePaths = []string{"/.env", "/.git/", "/.git/config", "wp-config.php.", "wp-config.php~", "wp-config.old", "phpmyadmin", "/pma/", "/vendor/phpunit",
	"/.aws/", "/.svn/", "/.ds_store", "/server-status", "/.htpasswd", "/actuator/", "/config.php.bak", "/backup.sql", "/dump.sql"}

// probeWeight is how much a known probe path counts towards path_probing.
const probeWeight = 5

// IsProbePath reports whether p is a known scanner target.
func IsProbePath(p string) bool {
	lp := strings.ToLower(p) + "/" // "/.git" counts like "/.git/"
	for _, s := range probePaths {
		if strings.Contains(lp, s) {
			return true
		}
	}
	return false
}

// searchBotRe matches user agents of large search engines. Without the
// FCrDNS / Web Bot Auth verification of MVP-12 they are unverified: counted
// by aggressive_crawl, never acted on (a forged one still meets the WAF and
// every other scenario).
var searchBotRe = regexp.MustCompile(`(?i)googlebot|bingbot|duckduckbot|yandex(bot)?|baiduspider|applebot|slurp|qwantify|ecosia|seznambot|petalbot`)

// ClaimsSearchBot reports whether ua names a search engine crawler.
func ClaimsSearchBot(ua string) bool { return searchBotRe.MatchString(ua) }

// routeRe compiles a route pattern: `*` within one segment, `**` across.
func routeRe(route string) *regexp.Regexp {
	var b strings.Builder
	b.WriteString("^")
	for i := 0; i < len(route); i++ {
		if route[i] == '*' {
			if i+1 < len(route) && route[i+1] == '*' {
				b.WriteString(".*")
				i++
				continue
			}
			b.WriteString("[^/]*")
			continue
		}
		b.WriteString(regexp.QuoteMeta(route[i : i+1]))
	}
	b.WriteString("$")
	return regexp.MustCompile(b.String())
}
