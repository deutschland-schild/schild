package dashboard

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestSessionCookieOverPlainHTTP: a browser that reached the dashboard over
// plain HTTP on a VPN or LAN address must get a cookie it keeps. A Secure
// cookie set over plain HTTP is dropped by every browser, so the login would
// succeed and the next request would be logged out again (D76).
func TestSessionCookieOverPlainHTTP(t *testing.T) {
	cases := []struct {
		name   string
		host   string
		origin string
		proto  string // X-Forwarded-Proto
		tls    bool
		want   bool
	}{
		{name: "loopback address", host: "127.0.0.1:8788", origin: "http://127.0.0.1:8788", want: false},
		{name: "localhost", host: "localhost:8788", origin: "http://localhost:8788", want: false},
		{name: "ipv6 loopback", host: "[::1]:8788", origin: "http://[::1]:8788", want: false},
		{name: "vpn address, plain http browser", host: "10.8.0.1:8788", origin: "http://10.8.0.1:8788", want: false},
		{name: "vpn name, plain http browser", host: "gateway.vpn.example:8788", origin: "http://gateway.vpn.example:8788", want: false},
		{name: "tls on the dashboard port", host: "10.8.0.1:8788", origin: "https://10.8.0.1:8788", tls: true, want: true},
		{name: "https origin behind a tls proxy", host: "schild.example", origin: "https://schild.example", want: true},
		{name: "proxy says https", host: "schild.example", origin: "http://schild.example", proto: "https", want: true},
		{name: "proxy says https on loopback", host: "127.0.0.1:8788", proto: "https", want: true},
		{name: "no origin, not loopback", host: "10.8.0.1:8788", want: true},
		{name: "no origin, loopback", host: "127.0.0.1:8788", want: false},
		{name: "foreign plain origin does not lower it", host: "10.8.0.1:8788", origin: "http://other.example", want: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "http://"+c.host+"/api/v0/auth/login", nil)
			r.Host = c.host
			if c.origin != "" {
				r.Header.Set("Origin", c.origin)
			}
			if c.proto != "" {
				r.Header.Set("X-Forwarded-Proto", c.proto)
			}
			if c.tls {
				r.TLS = &tls.ConnectionState{}
			}
			if got := secureCookie(r); got != c.want {
				t.Fatalf("Secure = %v, want %v", got, c.want)
			}
		})
	}
}
