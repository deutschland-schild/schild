package gate

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestDropTunnelUpgrades(t *testing.T) {
	for _, c := range []struct {
		name          string
		in            http.Header
		upgrade, conn string
	}{
		{"nothing", http.Header{"Connection": {"keep-alive"}}, "", "keep-alive"},
		{"h2c", http.Header{"Upgrade": {"h2c"}, "Connection": {"Upgrade, HTTP2-Settings"}, "Http2-Settings": {"AAMAAABkAAQCAAAAAAIAAAAA"}}, "", ""},
		{"h2c case", http.Header{"Upgrade": {"H2C"}, "Connection": {"upgrade"}}, "", ""},
		{"settings alone", http.Header{"Http2-Settings": {"x"}, "Connection": {"HTTP2-Settings, keep-alive"}}, "", "keep-alive"},
		{"other tunnel", http.Header{"Upgrade": {"tcp"}, "Connection": {"Upgrade"}}, "", ""},
		{"websocket", http.Header{"Upgrade": {"websocket"}, "Connection": {"Upgrade"}}, "websocket", "Upgrade"},
		{"websocket case", http.Header{"Upgrade": {"WebSocket"}, "Connection": {"keep-alive, Upgrade"}}, "WebSocket", "keep-alive, Upgrade"},
		{"h2c beside websocket", http.Header{"Upgrade": {"h2c, websocket"}, "Connection": {"Upgrade, HTTP2-Settings"}, "Http2-Settings": {"x"}}, "websocket", "Upgrade"},
		{"two header lines", http.Header{"Upgrade": {"h2c", "websocket"}, "Connection": {"Upgrade"}}, "websocket", "Upgrade"},
	} {
		t.Run(c.name, func(t *testing.T) {
			dropTunnelUpgrades(c.in)
			if got := strings.Join(c.in["Upgrade"], ","); got != c.upgrade {
				t.Fatalf("upgrade %q, want %q", got, c.upgrade)
			}
			if got := strings.Join(c.in["Connection"], ","); got != c.conn {
				t.Fatalf("connection %q, want %q", got, c.conn)
			}
			if _, ok := c.in["Http2-Settings"]; ok {
				t.Fatal("HTTP2-Settings stayed")
			}
		})
	}
}

// tunnelBackend answers 101 to any upgrade it is offered and then echoes what
// comes through the tunnel, as an h2c or WebSocket backend would.
func tunnelBackend(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") == "" {
			fmt.Fprintf(w, "plain upgrade=%q settings=%q", r.Header.Get("Upgrade"), r.Header.Get("Http2-Settings"))
			return
		}
		c, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer c.Close()
		fmt.Fprintf(rw, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: %s\r\n\r\n", r.Header.Get("Upgrade"))
		_ = rw.Flush()
		line, err := rw.ReadString('\n')
		if err == nil {
			fmt.Fprint(rw, "tunnel:"+line)
			_ = rw.Flush()
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// exchange sends a raw request through the gate in front of a reverse proxy.
func exchange(t *testing.T, g *Gate, backend, request string) (status int, conn net.Conn, br *bufio.Reader) {
	t.Helper()
	u, _ := url.Parse(backend)
	front := httptest.NewServer(g.Handler(httputil.NewSingleHostReverseProxy(u)))
	t.Cleanup(front.Close)
	conn, err := net.Dial("tcp", strings.TrimPrefix(front.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(conn, request); err != nil {
		t.Fatal(err)
	}
	br = bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, conn, br
}

// Finding 4: h2c never reaches the backend, the request itself does.
func TestH2CUpgradeNeverReachesTheBackend(t *testing.T) {
	g := newEnv(t, "autoblock").g
	status, _, _ := exchange(t, g, tunnelBackend(t).URL, "GET / HTTP/1.1\r\nHost: shop.test\r\nConnection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: AAMAAABkAAQCAAAAAAIAAAAA\r\n\r\n")
	if status != http.StatusOK {
		t.Fatalf("status %d: a tunnel opened", status)
	}
}

// A WebSocket upgrade still works end to end through the gate.
func TestWebSocketUpgradeStillWorks(t *testing.T) {
	g := newEnv(t, "autoblock").g
	status, conn, br := exchange(t, g, tunnelBackend(t).URL, "GET /app/key HTTP/1.1\r\nHost: shop.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\n\r\n")
	if status != http.StatusSwitchingProtocols {
		t.Fatalf("status %d", status)
	}
	if _, err := io.WriteString(conn, "ping\n"); err != nil {
		t.Fatal(err)
	}
	line, err := br.ReadString('\n')
	if err != nil || line != "tunnel:ping\n" {
		t.Fatalf("%q %v", line, err)
	}
}
