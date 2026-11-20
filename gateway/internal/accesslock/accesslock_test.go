package accesslock

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/contract/access"
	"github.com/deutschland-schild/schild/gateway/internal/passhash"
)

func TestStripCookie(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Add("Cookie", "a=1; "+access.CookieName+"=secret; b=2")
	r.Header.Add("Cookie", "c=3")
	StripCookie(r)
	if got := r.Header.Values("Cookie"); len(got) != 1 || got[0] != "a=1; b=2; c=3" {
		t.Fatalf("%q", got)
	}
	r = httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Cookie", access.CookieName+"=secret")
	StripCookie(r)
	if r.Header.Get("Cookie") != "" {
		t.Fatal("cookie kept")
	}
}

func TestReturnPath(t *testing.T) {
	for in, want := range map[string]string{
		"/wp-admin/?a=1": "/wp-admin/?a=1", "": "/", "//evil.example": "/", `/\evil.example`: "/", "https://evil.example/": "/",
		"/x\r\nSet-Cookie: a=b": "/", LoginPath: "/", "/\t/evil.example": "/", "/\t\\evil.example": "/", "/\x7f": "/",
	} {
		if got := returnPath(in); got != want {
			t.Errorf("%q: %q", in, got)
		}
	}
}

func TestLimiter(t *testing.T) {
	l := newLimiter()
	now := time.Now()
	k := limitKey{website: "a", prefix: Prefix(netip.MustParseAddr("198.51.100.7"))}
	if k.prefix.String() != "198.51.100.0/24" || Prefix(netip.MustParseAddr("2001:db8:1:2::1")).String() != "2001:db8:1::/48" {
		t.Fatalf("prefix %s", k.prefix)
	}
	for i := 1; i < FailLimit; i++ {
		if _, newly := l.fail(k, now); newly {
			t.Fatalf("locked after %d", i)
		}
	}
	until, newly := l.fail(k, now)
	if !newly || !until.Equal(now.Add(Lockout)) {
		t.Fatalf("lockout %v %v", until, newly)
	}
	if _, locked := l.locked(k, now.Add(Lockout-time.Second)); !locked {
		t.Fatal("not locked")
	}
	if _, locked := l.locked(k, now.Add(Lockout)); locked {
		t.Fatal("lockout does not end")
	}
	// Guesses spread wider than the window do not add up.
	k2 := limitKey{website: "a", prefix: Prefix(netip.MustParseAddr("203.0.113.1"))}
	for i := 0; i < 2*FailLimit; i++ {
		if _, newly := l.fail(k2, now.Add(time.Duration(i)*FailWindow/4)); newly && i < FailLimit {
			t.Fatalf("locked at %d", i)
		}
	}
}

func TestLimiterBounded(t *testing.T) {
	l := newLimiter()
	now := time.Now()
	for i := 0; i < maxKeys+100; i++ {
		ip := netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i), 1}) // one /24 each
		l.fail(limitKey{website: "a", prefix: Prefix(ip)}, now)
	}
	if len(l.m) != maxKeys+1 {
		t.Fatalf("%d keys, want %d and the overflow key", len(l.m), maxKeys)
	}
}

// Past maxKeys new prefixes share the overflow key: its lockout holds for them
// too, else spreading guesses over many prefixes would never be locked.
func TestLimiterOverflowLocks(t *testing.T) {
	l := newLimiter()
	now := time.Now()
	for i := 0; i < maxKeys; i++ {
		ip := netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i), 1}) // one /24 each
		l.fail(limitKey{website: "a", prefix: Prefix(ip)}, now)
	}
	fresh := func(i int) limitKey {
		return limitKey{website: "a", prefix: Prefix(netip.AddrFrom4([4]byte{172, 16, byte(i), 1}))}
	}
	for i := 0; i < FailLimit; i++ {
		if _, locked := l.locked(fresh(i), now); locked {
			t.Fatalf("locked after %d guesses", i)
		}
		l.fail(fresh(i), now)
	}
	if _, locked := l.locked(fresh(FailLimit), now); !locked {
		t.Fatal("guesses beyond maxKeys are never locked out")
	}
	if _, locked := l.locked(limitKey{website: "b", prefix: fresh(0).prefix}, now); locked {
		t.Fatal("the overflow lockout of one website holds for another")
	}
	// Once the window of the full keys is over, a new prefix gets its own key.
	later := now.Add(Lockout)
	if _, locked := l.locked(fresh(FailLimit+1), later); locked {
		t.Fatal("still locked after the lockout")
	}
}

// A login form sent a byte now and then ends at formWait, not when the client
// likes: the request would hold its connection busy.
func TestLoginFormReadEnds(t *testing.T) {
	defer func(d time.Duration) { formWait = d }(formWait)
	formWait = 200 * time.Millisecond
	l := New()
	st := NewState()
	st.Entries["a"] = &Entry{Protection: access.Protection{Website: "a", Scope: access.ScopeSite, Password: true}, Hash: passhash.Hash("secret")}
	l.Store(st)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		l.Login(w, r, "a", netip.MustParseAddr("192.0.2.1"), false, time.Now())
	}))
	defer srv.Close()
	c, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	fmt.Fprintf(c, "POST %s HTTP/1.1\r\nHost: a\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 100\r\n\r\npassword=", LoginPath)
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	start := time.Now()
	res, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatalf("no answer to a stalled form: %v", err)
	}
	_ = res.Body.Close()
	if res.StatusCode != http.StatusSeeOther || time.Since(start) > 3*time.Second {
		t.Fatalf("status %d after %v", res.StatusCode, time.Since(start))
	}
}
