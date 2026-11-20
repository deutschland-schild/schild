package clientip

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestResolve(t *testing.T) {
	r, err := New([]string{"127.0.0.1/32", "::1/128", "10.66.1.0/24"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, remote, xff, want, attr string
	}{
		{"direct peer", "203.0.113.7:4444", "", "203.0.113.7", TCPPeer},
		{"untrusted peer ignores header", "203.0.113.7:4444", "192.0.2.1", "203.0.113.7", TCPPeer},
		{"trusted peer uses header", "127.0.0.1:5555", "198.51.100.23", "198.51.100.23", TrustedProxy},
		{"rightmost untrusted wins", "127.0.0.1:5555", "192.0.2.1, 198.51.100.23, 10.66.1.5", "198.51.100.23", TrustedProxy},
		{"malformed chain falls back to peer", "127.0.0.1:5555", "nonsense", "127.0.0.1", TCPPeer},
		// The client writes what stands left of its own address: garbage there
		// must not hand the attribution to the proxy.
		{"garbage left of the client is not read", "127.0.0.1:5555", "nonsense, 198.51.100.23", "198.51.100.23", TrustedProxy},
		{"garbage between proxies is no guess", "127.0.0.1:5555", "198.51.100.23, nonsense, 10.66.1.5", "127.0.0.1", TCPPeer},
		{"all trusted takes the leftmost", "127.0.0.1:5555", "10.66.1.7, 10.66.1.5", "10.66.1.7", TrustedProxy},
		{"zone is dropped", "127.0.0.1:5555", "[fe80::1%eth0]:80", "fe80::1", TrustedProxy},
		{"ipv6 peer", "[2001:db8::17]:443", "", "2001:db8::17", TCPPeer},
		{"trusted v6 loopback with port in header", "[::1]:1", "[2001:db8::5]:1234", "2001:db8::5", TrustedProxy},
		{"mapped v4", "[::ffff:203.0.113.9]:80", "", "203.0.113.9", TCPPeer},
	}
	for _, c := range cases {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = c.remote
		if c.xff != "" {
			req.Header.Set("X-Forwarded-For", c.xff)
		}
		got := r.Resolve(req)
		if got.IP.String() != c.want || got.Attribution != c.attr {
			t.Errorf("%s: got %s/%s want %s/%s", c.name, got.IP, got.Attribution, c.want, c.attr)
		}
	}
}

func TestForwardedHeader(t *testing.T) {
	r, _ := New([]string{"127.0.0.1/32"}, []string{"Forwarded"})
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "127.0.0.1:1"
	req.Header.Set("Forwarded", `for="[2001:db8::1]:4711";proto=https, for=198.51.100.4`)
	if got := r.Resolve(req); got.IP.String() != "198.51.100.4" {
		t.Fatalf("got %s", got.IP)
	}
}

// RFC 7239 allows obfuscated and unknown nodes; left of the client they do not
// matter, as the rightmost element is what the trusted proxy appended.
func TestForwardedObfuscatedLeft(t *testing.T) {
	r, _ := New([]string{"127.0.0.1/32"}, []string{"Forwarded"})
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "127.0.0.1:1"
	req.Header.Add("Forwarded", `for=unknown;proto=https, for="_hidden"`)
	req.Header.Add("Forwarded", "for=198.51.100.4")
	if got := r.Resolve(req); got.IP.String() != "198.51.100.4" || got.Attribution != TrustedProxy {
		t.Fatalf("got %+v", got)
	}
}

// Hops are walked in place: a header of many hops allocates nothing.
func TestManyHopsNoAllocation(t *testing.T) {
	r, _ := New([]string{"127.0.0.1/32"}, nil)
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "127.0.0.1:1"
	req.Header.Set("X-Forwarded-For", strings.Repeat(",", 1<<16)+"198.51.100.9")
	req.Header.Add("X-Forwarded-For", ", ")
	if got := r.Resolve(req); got.IP.String() != "198.51.100.9" {
		t.Fatalf("got %+v", got)
	}
	if n := testing.AllocsPerRun(20, func() { r.Resolve(req) }); n > 1 {
		t.Fatalf("%v allocations", n)
	}
}

func TestTooBroad(t *testing.T) {
	r, _ := New([]string{"0.0.0.0/0", "10.0.0.0/8", "::/0", "2001:db8::/32"}, nil)
	if got := r.TooBroad(); len(got) != 2 {
		t.Fatalf("got %v", got)
	}
}

// A too broad list never believes a forwarding header (D40): the spoofed
// address of a victim must not reach the gate, also not from a peer in the
// narrow part of the list.
func TestTooBroadIgnoresForwardingHeaders(t *testing.T) {
	r, _ := New([]string{"0.0.0.0/0", "10.0.0.0/8"}, []string{"X-Forwarded-For", "Forwarded"})
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.5:1234"
	req.Header.Set("X-Forwarded-For", "203.0.113.9")
	req.Header.Set("Forwarded", "for=203.0.113.9")
	got := r.Resolve(req)
	if got.IP.String() != "10.0.0.5" || got.Attribution != TCPPeer {
		t.Fatalf("got %+v", got)
	}
	if r.Trusted(netip.MustParseAddr("10.0.0.5")) {
		t.Fatal("trusted proxy behind a too broad list")
	}
}

func TestTruncateAndRange(t *testing.T) {
	if got := Truncate(netip.MustParseAddr("203.0.113.42")); got.String() != "203.0.113.0" {
		t.Fatal(got)
	}
	if got := Truncate(netip.MustParseAddr("2001:db8:1:2:3::4")); got.String() != "2001:db8:1::" {
		t.Fatal(got)
	}
	lo, hi := Range(netip.MustParsePrefix("203.0.113.0/24"))
	in, out := Key(netip.MustParseAddr("203.0.113.200")), Key(netip.MustParseAddr("203.0.114.1"))
	if !(lo <= in && in <= hi) || (lo <= out && out <= hi) {
		t.Fatalf("range %s..%s in=%s out=%s", lo, hi, in, out)
	}
	lo6, hi6 := Range(netip.MustParsePrefix("2001:db8::/32"))
	if k := Key(netip.MustParseAddr("2001:db8:ffff::1")); !(lo6 <= k && k <= hi6) {
		t.Fatal("v6 range")
	}
}

// D91: a forwarding header from a private peer outside the list is ignored
// and flagged, from a public peer or a trusted one it is not flagged.
func TestIgnoredForwardFromPrivatePeer(t *testing.T) {
	r, _ := New([]string{"127.0.0.1/32"}, nil)
	req := func(remote, xff string) *http.Request {
		q := httptest.NewRequest("GET", "/", nil)
		q.RemoteAddr = remote
		if xff != "" {
			q.Header.Set("X-Forwarded-For", xff)
		}
		return q
	}
	for _, c := range []struct {
		remote, xff string
		ignored     bool
	}{
		{"172.18.0.1:40000", "203.0.113.9", true},    // nginx on the Docker host
		{"10.0.0.5:40000", "203.0.113.9", true},      // a load balancer in a private network
		{"172.18.0.1:40000", "", false},              // no header: nothing to trust
		{"198.51.100.7:40000", "203.0.113.9", false}, // a public client sending the header itself
		{"127.0.0.1:40000", "203.0.113.9", false},    // trusted: the header counts
	} {
		res := r.Resolve(req(c.remote, c.xff))
		if res.Ignored != c.ignored {
			t.Errorf("%s with %q: ignored %v, want %v", c.remote, c.xff, res.Ignored, c.ignored)
		}
	}
	broad, _ := New([]string{"0.0.0.0/0"}, nil)
	if broad.Resolve(req("172.18.0.1:40000", "203.0.113.9")).Ignored {
		t.Error("a too broad list has its own hint")
	}
}

func TestWatchMissing(t *testing.T) {
	var w Watch
	now := time.Unix(1_800_000_000, 0)
	for range 19 {
		w.Note(now, true)
	}
	if w.Missing(now) {
		t.Fatal("19 requests are not enough")
	}
	w.Note(now, true)
	if !w.Missing(now) {
		t.Fatal("20 of 20 requests should count")
	}
	for range 21 {
		w.Note(now, false)
	}
	if w.Missing(now) {
		t.Fatal("20 of 41 is less than half")
	}
	// The previous slot still counts, the one before it no longer.
	later := now.Add(10 * time.Minute)
	if w.Missing(later) {
		t.Fatal("still less than half in the window")
	}
	var v Watch
	for range 30 {
		v.Note(now, true)
	}
	if !v.Missing(now.Add(10*time.Minute)) || v.Missing(now.Add(25*time.Minute)) {
		t.Fatal("the window is the current and the previous 10 minutes")
	}
}
