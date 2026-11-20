package behaviour

import (
	"fmt"
	"net/netip"
	"runtime"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/contract/config"
	"github.com/deutschland-schild/schild/contract/events"
)

func distBehaviour(mode string) config.Behaviour {
	b := modes(nil)
	b.Presets = []string{"wordpress"}
	for _, id := range config.DetectorIDs {
		b.Distributed.Detectors.Get(id).Mode = mode
	}
	b.Distributed.Responses = config.DistributedResponses{RouteTighten: config.RouteTighten{Minutes: 20, MaxMinutes: 120, LimitPerMinute: 10},
		AccountSlowdown: config.AccountSlowdown{StartS: 5, MaxS: 60}}
	return b
}

func newDistEngine(b config.Behaviour, installed time.Time, gatewayObserve bool) (*Engine, *rec, *clock) {
	e := New(Config{Behaviour: b, InstalledAt: installed, GatewayObserve: gatewayObserve})
	r := &rec{}
	e.Sink = r.sink()
	c := &clock{t: t0}
	e.Now = c.now
	return e, r, c
}

func (r *rec) waves() []events.DistributedDetectedData {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []events.DistributedDetectedData
	for _, e := range r.events {
		if d, ok := e.(events.DistributedDetectedData); ok {
			out = append(out, d)
		}
	}
	return out
}

func (r *rec) ended() []events.DistributedEndedData {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []events.DistributedEndedData
	for _, e := range r.events {
		if d, ok := e.(events.DistributedEndedData); ok {
			out = append(out, d)
		}
	}
	return out
}

var rotatingUAs = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15",
	"Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 Edg/128.0.0.0",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 17_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Mobile/15E148 Safari/604.1",
}

// stuffing sends one failed login per rotating sender: new IP, rotating
// user agent, same client stack (fingerprint), its own user name.
func stuffing(e *Engine, c *clock, n int, fp string, netClass string) {
	for i := 0; i < n; i++ {
		ip := fmt.Sprintf("198.18.%d.%d", i/250, i%250+1)
		rq := req(c, ip, netClass, "POST", "/wp-login.php")
		rq.UserAgent = rotatingUAs[i%len(rotatingUAs)]
		rq.Fingerprint, rq.FPKind, rq.Inconsistent = fp, FPHeaders, true
		if v := e.Check(rq); v.Block || v.RateLimited {
			c.add(50 * time.Millisecond)
			continue
		}
		e.Observe(rq, Outcome{Forwarded: true, Response: Response{Status: 200}, HasUser: true, UserHash: HashUser(fmt.Sprintf("victim%d@example.org", i))})
		c.add(50 * time.Millisecond)
	}
}

func TestRotatingCredentialStuffingOneStack(t *testing.T) {
	e, r, c := newDistEngine(distBehaviour(config.DistributedRespond), t0.Add(-30*24*time.Hour), false)
	// A real user loaded the form earlier: the app set its cookie.
	form := req(c, "192.0.2.77", "residential", "GET", "/wp-login.php")
	e.Observe(form, Outcome{Forwarded: true, Response: Response{Status: 200, CookieNames: []string{"wordpress_test_cookie"}}})

	stuffing(e, c, 300, "3f9a0c11b2d4", "residential")
	got := map[string]events.DistributedDetectedData{}
	for _, w := range r.waves() {
		got[w.Detector] = w
		if w.Action != config.DistributedRespond || w.Until == "" {
			t.Fatalf("wave not enforced: %+v", w)
		}
	}
	for _, d := range []string{config.DetectorRouteWave, config.DetectorFingerprintCluster, config.DetectorInconsistency} {
		if _, ok := got[d]; !ok {
			t.Fatalf("%s did not fire: %+v", d, r.waves())
		}
	}
	fc := got[config.DetectorFingerprintCluster]
	if fc.Fingerprint != "3f9a0c11b2d4" || fc.UserAgents < 3 || fc.Senders < 20 || fc.Response != RespRouteTighten {
		t.Fatalf("cluster: %+v", fc)
	}
	// route_tighten: senders without a session cookie share a strict limit...
	limited := 0
	for i := 0; i < 30; i++ {
		rq := req(c, fmt.Sprintf("198.18.9.%d", i+1), "residential", "POST", "/wp-login.php")
		if v := e.Check(rq); v.RateLimited && v.WaveID != "" && v.RetryAfter > 0 {
			limited++
		}
	}
	if limited < 15 {
		t.Fatalf("route not tightened: %d of 30 limited", limited)
	}
	// ...also behind CGNAT and Tor: not an address ban, a route rule.
	if v := e.Check(req(c, "100.64.0.9", "cgnat", "POST", "/wp-login.php")); !v.RateLimited {
		t.Fatal("route_tighten skips cgnat")
	}
	// The login form stays reachable, and a user with a session cookie logs in.
	if v := e.Check(req(c, "198.18.9.200", "residential", "GET", "/wp-login.php")); v.RateLimited {
		t.Fatal("form GET limited")
	}
	for i := 0; i < 20; i++ {
		u := req(c, "192.0.2.77", "residential", "POST", "/wp-login.php")
		u.CookieNames = []string{"wordpress_test_cookie"}
		u.Fingerprint, u.FPKind = "3f9a0c11b2d4", FPHeaders // same header set as the cluster: never overrides the cookie
		if v := e.Check(u); v.RateLimited || v.Block {
			t.Fatalf("legitimate user with session cookie stopped: %+v", v)
		}
	}
	// No address-based action: no behaviour block, no incident.
	if len(r.incidents) != 0 {
		t.Fatalf("incidents: %+v", r.incidents)
	}
}

func TestStrongFingerprintOverridesCookie(t *testing.T) {
	e, _, c := newDistEngine(distBehaviour(config.DistributedRespond), t0.Add(-30*24*time.Hour), false)
	e.LearnCookies("verein.example", []string{"wordpress_test_cookie"})
	for i := 0; i < 300; i++ {
		rq := req(c, fmt.Sprintf("198.18.%d.%d", i/250, i%250+1), "residential", "POST", "/wp-login.php")
		rq.UserAgent = rotatingUAs[i%len(rotatingUAs)]
		rq.Fingerprint, rq.FPKind, rq.StrongFP = "a1b2c3d4e5f6", FPJA4, true
		rq.CookieNames = []string{"wordpress_test_cookie"} // the bot replays the form cookie
		if v := e.Check(rq); v.RateLimited {
			c.add(50 * time.Millisecond)
			continue
		}
		e.Observe(rq, Outcome{Forwarded: true, Response: Response{Status: 200}})
		c.add(50 * time.Millisecond)
	}
	limited := 0
	for i := 0; i < 30; i++ {
		rq := req(c, fmt.Sprintf("198.18.8.%d", i+1), "residential", "POST", "/wp-login.php")
		rq.Fingerprint, rq.StrongFP, rq.CookieNames = "a1b2c3d4e5f6", true, []string{"wordpress_test_cookie"}
		if e.Check(rq).RateLimited {
			limited++
		}
	}
	if limited < 15 {
		t.Fatalf("JA4 cluster with a replayed cookie not limited: %d", limited)
	}
	u := req(c, "192.0.2.78", "residential", "POST", "/wp-login.php")
	u.Fingerprint, u.StrongFP, u.CookieNames = "ffffffffffff", true, []string{"wordpress_test_cookie"}
	if e.Check(u).RateLimited {
		t.Fatal("other stack with a session cookie limited")
	}
}

func TestAccountSlowdownNeverLocksOut(t *testing.T) {
	b := distBehaviour(config.DistributedRespond)
	b.Distributed.Responses.AccountSlowdown = config.AccountSlowdown{StartS: 5, MaxS: 300}
	e, r, c := newDistEngine(b, t0.Add(-30*24*time.Hour), false)
	e.LearnCookies("verein.example", []string{"wordpress_test_cookie"})
	victim := HashUser("anna@example.org")
	attempt := func(i int, session bool, status int) Verdict {
		rq := req(c, fmt.Sprintf("198.18.%d.%d", (i/250)%250, i%250+1), "residential", "POST", "/wp-login.php")
		if session {
			rq.CookieNames = []string{"wordpress_test_cookie"}
		}
		if v := e.Check(rq); v.RateLimited {
			return v
		}
		if v := e.AccountWait(rq, victim); v.RateLimited {
			return v
		}
		e.Observe(rq, Outcome{Forwarded: true, Response: Response{Status: status}, HasUser: true, UserHash: victim})
		return Verdict{}
	}
	for i := 0; i < 10; i++ {
		attempt(i, false, 200)
		c.add(10 * time.Second)
	}
	var aw bool
	for _, w := range r.waves() {
		aw = aw || (w.Detector == config.DetectorAccountWave && w.Response == RespAccountSlowdown)
	}
	if !aw {
		t.Fatalf("account_wave did not fire: %+v", r.waves())
	}
	// The attacker keeps hammering; waits grow and never pass 5 minutes.
	var waits []time.Duration
	for i := 10; i < 200; i++ {
		v := attempt(i, false, 200)
		if v.RateLimited {
			if v.RetryAfter > AccountWaitCap {
				t.Fatalf("wait %v above the cap", v.RetryAfter)
			}
			waits = append(waits, v.RetryAfter)
			c.add(v.RetryAfter)
			continue
		}
		c.add(time.Second)
	}
	if len(waits) == 0 || waits[len(waits)-1] < 4*time.Minute {
		t.Fatalf("wait did not grow: %v", waits)
	}
	// The real user (session cookie from the form) is never slowed down and
	// a successful login resets the account.
	if v := attempt(5000, true, 302); v.RateLimited {
		t.Fatalf("real user slowed down: %+v", v)
	}
	if v := e.AccountWait(req(c, "198.18.100.1", "residential", "POST", "/wp-login.php"), victim); v.RateLimited {
		t.Fatal("success did not reset the account")
	}
}

func TestDistributedLearningAndGatewayObserve(t *testing.T) {
	for _, tc := range []struct {
		name      string
		installed time.Time
		gwObserve bool
		reason    string
	}{
		{"fresh install", t0.Add(-13 * 24 * time.Hour), false, ReasonLearning},
		{"unknown install date", time.Time{}, false, ReasonLearning},
		{"gateway observe", t0.Add(-60 * 24 * time.Hour), true, ReasonGatewayObserve},
	} {
		e, r, c := newDistEngine(distBehaviour(config.DistributedRespond), tc.installed, tc.gwObserve)
		stuffing(e, c, 300, "3f9a0c11b2d4", "residential")
		ws := r.waves()
		if len(ws) == 0 {
			t.Fatalf("%s: no wave detected", tc.name)
		}
		for _, w := range ws {
			if w.Action != config.DistributedObserve || w.Reason != tc.reason || w.Until != "" {
				t.Fatalf("%s: enforced: %+v", tc.name, w)
			}
		}
		for i := 0; i < 50; i++ {
			rq := req(c, fmt.Sprintf("198.18.9.%d", i+1), "residential", "POST", "/wp-login.php")
			if e.Check(rq).RateLimited || e.AccountWait(rq, HashUser("x")).RateLimited {
				t.Fatalf("%s: something enforced", tc.name)
			}
		}
		if _, ok := e.ShapeBlocked("sha256:"+fmt.Sprintf("%064x", 1), c.t); ok {
			t.Fatal("shape blocked")
		}
	}
}

func TestShapeWaveBlocksShapeForAnySender(t *testing.T) {
	e, r, c := newDistEngine(distBehaviour(config.DistributedRespond), t0.Add(-30*24*time.Hour), false)
	sig := "sha256:" + fmt.Sprintf("%064x", 42)
	for i := 0; i < 25; i++ {
		rq := req(c, fmt.Sprintf("203.0.113.%d", i+1), "hosting", "POST", "/wp-json/gallery/v1/upload")
		e.Observe(rq, Outcome{Shape: sig, ShapeRules: []int{933100}})
	}
	inc, ok := e.ShapeBlocked(sig, c.t)
	if !ok || inc == "" {
		t.Fatalf("shape not blocked: %+v", r.waves())
	}
	if _, ok := e.ShapeBlocked("sha256:"+fmt.Sprintf("%064x", 43), c.t); ok {
		t.Fatal("other shape blocked")
	}
	if len(r.incidents) != 1 || r.incidents[0].IP != "" {
		t.Fatalf("shape incident must be address-free: %+v", r.incidents)
	}
	// Expiry: the response ends by itself.
	c.add(21 * time.Minute)
	e.Sweep()
	if _, ok := e.ShapeBlocked(sig, c.t); ok {
		t.Fatal("shape block did not expire")
	}
	if en := r.ended(); len(en) != 1 || en[0].Reason != "expired" || en[0].Stopped != 1 {
		t.Fatalf("ended: %+v", en)
	}
}

func TestEndWaveEarly(t *testing.T) {
	e, r, c := newDistEngine(distBehaviour(config.DistributedRespond), t0.Add(-30*24*time.Hour), false)
	stuffing(e, c, 300, "3f9a0c11b2d4", "residential")
	ws := r.waves()
	if len(ws) == 0 {
		t.Fatal("no wave")
	}
	for _, w := range ws {
		if _, known, active := e.EndWave(w.WaveID); !known || !active {
			t.Fatalf("end %s: %v %v", w.Detector, known, active)
		}
	}
	if _, _, active := e.EndWave(ws[0].WaveID); active {
		t.Fatal("ended twice")
	}
	if v := e.Check(req(c, "198.18.9.9", "residential", "POST", "/wp-login.php")); v.RateLimited {
		t.Fatal("still tightened after ending early")
	}
	for _, en := range r.ended() {
		if en.Reason != "operator" {
			t.Fatalf("ended: %+v", en)
		}
	}
}

// Wave records never carry an address, a user name or an account key.
func TestWaveEventsAddressFree(t *testing.T) {
	e, r, c := newDistEngine(distBehaviour(config.DistributedRespond), t0.Add(-30*24*time.Hour), false)
	stuffing(e, c, 300, "3f9a0c11b2d4", "residential")
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for i, ev := range r.events {
		if r.types[i] != events.DistributedDetected && r.types[i] != events.DistributedEnded {
			continue
		}
		n++
		s := fmt.Sprintf("%+v", ev)
		for _, bad := range []string{"198.18.", "victim", "example.org"} {
			if contains(s, bad) {
				t.Fatalf("wave record contains %q: %s", bad, s)
			}
		}
	}
	if n == 0 {
		t.Fatal("no wave records")
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestDistributedFloodBounded(t *testing.T) {
	if testing.Short() {
		t.Skip("flood")
	}
	b := distBehaviour(config.DistributedRespond)
	b.Distributed.Routes = []string{"/api/**"}
	e, _, c := newDistEngine(b, t0.Add(-30*24*time.Hour), false)
	e.Sink = Sink{}
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	for i := 0; i < 1_000_000; i++ {
		a := netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})
		p := "/wp-login.php"
		if i%3 == 0 {
			p = fmt.Sprintf("/api/x%d", i%5000)
		}
		rq := &Request{Time: c.t, IP: a, Method: "POST", Host: fmt.Sprintf("site%d.example", i%300), Path: p, UserAgent: rotatingUAs[i%5],
			Fingerprint: fmt.Sprintf("%012x", i), FPKind: FPHeaders, Client: events.Client{IP: a.String(), Attribution: "tcp_peer", Geo: events.Geo{Country: "ZZ", NetClass: "residential"}}}
		e.Check(rq)
		e.Observe(rq, Outcome{Forwarded: true, Response: Response{Status: 401}, HasUser: true, UserHash: uint64(i) * 0x9e3779b97f4a7c15,
			Shape: fmt.Sprintf("sha256:%064x", i), ShapeRules: []int{942100}})
		if i%1000 == 0 {
			c.add(time.Millisecond)
		}
	}
	routes, accounts, fps, shapes, waves := e.DistSizes()
	if routes > CapacityRoutes || accounts > CapacityAccounts || fps > CapacityFPs || shapes > CapacityShapes || waves > CapacityWaves {
		t.Fatalf("over capacity: %d %d %d %d %d", routes, accounts, fps, shapes, waves)
	}
	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	grown := int64(after.HeapAlloc) - int64(before.HeapAlloc)
	t.Logf("routes %d accounts %d fps %d shapes %d waves %d, heap grew %d MiB", routes, accounts, fps, shapes, waves, grown>>20)
	if grown > 160<<20 {
		t.Fatalf("heap grew %d MiB", grown>>20)
	}
}

func TestValidJA4(t *testing.T) {
	if !ValidJA4("t13d1516h2_8daaf6152771_e5627efa2ab1") {
		t.Fatal("JA4 of the FoxIO example rejected")
	}
	if ValidJA4("t13d1516h2_8daaf6152771_e5627efa2ab1_extra") || ValidJA4("") {
		t.Fatal("JA4+ or empty accepted")
	}
}

func TestHeaderFingerprintAndInconsistency(t *testing.T) {
	chrome := map[string][]string{"Accept": {"text/html"}, "Accept-Language": {"de-DE,de;q=0.9"}, "Accept-Encoding": {"gzip, br"},
		"Sec-Fetch-Mode": {"navigate"}, "Sec-Fetch-Dest": {"document"}, "Sec-Ch-Ua": {`"Chromium";v="129"`}}
	a := HeaderFingerprint("HTTP/1.1", chrome)
	withCookie := map[string][]string{"Cookie": {"a=b"}, "X-Forwarded-For": {"198.51.100.7"}}
	for k, v := range chrome {
		withCookie[k] = v
	}
	if HeaderFingerprint("HTTP/1.1", withCookie) != a {
		t.Fatal("cookie or forwarding headers change the fingerprint")
	}
	if FingerprintID(FPHeaders, a) == FingerprintID(FPJA4, a) || len(FingerprintID(FPHeaders, a)) != 12 {
		t.Fatal("fingerprint id")
	}
	ua := rotatingUAs[0]
	if Inconsistent(ua, chrome, true) {
		t.Fatal("consistent Chrome flagged")
	}
	if !Inconsistent(ua, map[string][]string{"Accept": {"*/*"}}, true) {
		t.Fatal("Chrome without Accept-Language and Sec-Fetch not flagged")
	}
	if !Inconsistent(rotatingUAs[2], chrome, true) {
		t.Fatal("Firefox with Chromium client hints not flagged")
	}
	if Inconsistent("curl/8.7.1", map[string][]string{}, true) {
		t.Fatal("tools say what they are")
	}
}
