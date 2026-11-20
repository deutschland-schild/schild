package caddymod

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// upgradeBackend answers 101 to any upgrade it gets, as an h2c or WebSocket
// backend would, and echoes one line through the tunnel.
func upgradeBackend(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") == "" {
			_, _ = io.WriteString(w, "plain")
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
		if line, err := rw.ReadString('\n'); err == nil {
			fmt.Fprint(rw, "tunnel:"+line)
			_ = rw.Flush()
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// D41: a refused request is drained for at most 2 s, also behind the real
// Caddy server, whose body reader sets its own read deadline on every read
// (idle timeouts since Caddy 2.11.6). The client stalls after one byte; both
// the proxy listener and an ingress server have that reader.
func TestDrainIsBoundedBehindCaddy(t *testing.T) {
	back := upgradeBackend(t)
	dir := caddyDir(t)
	addr := freePort(t)
	p := port(addr)
	cf := writeFile(t, dir, "Caddyfile", fmt.Sprintf("{\n\tauto_https off\n\thttp_port %[1]s\n}\n\nhttp://app.example.test:%[1]s {\n\tschild\n\treverse_proxy %[2]s\n}\n",
		p, strings.TrimPrefix(back.URL, "http://")))
	ing, err := PrepareIngress(IngressOptions{Caddyfile: cf, DefaultStorage: filepath.Join(dir, "caddy")})
	if err != nil {
		t.Fatal(err)
	}
	bind(t, testGate(t))
	if err := Load(ing.JSON); err != nil {
		t.Fatal(err)
	}
	defer Stop()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	start := time.Now()
	_ = c.SetDeadline(start.Add(10 * time.Second))
	if _, err := io.WriteString(c, "POST /upload HTTP/1.1\r\nHost: app.example.test:"+p+"\r\nContent-Type: text/plain\r\nContent-Length: 100000000\r\n\r\na"); err != nil {
		t.Fatal(err)
	}
	r, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatalf("no answer after %v: %v", time.Since(start), err)
	}
	if r.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status %d", r.StatusCode)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("answered after %v", d)
	}
}

// D43, MVP-26 finding 4: with the real Caddy reverse_proxy, `Upgrade: h2c`
// never opens a tunnel, and a WebSocket upgrade still does.
func TestIngressUpgrades(t *testing.T) {
	back := upgradeBackend(t)
	dir := caddyDir(t)
	addr := freePort(t)
	p := port(addr)
	cf := writeFile(t, dir, "Caddyfile", fmt.Sprintf("{\n\tauto_https off\n\thttp_port %[1]s\n}\n\nhttp://app.example.test:%[1]s {\n\tschild\n\treverse_proxy %[2]s\n}\n",
		p, strings.TrimPrefix(back.URL, "http://")))
	ing, err := PrepareIngress(IngressOptions{Caddyfile: cf, DefaultStorage: filepath.Join(dir, "caddy")})
	if err != nil {
		t.Fatal(err)
	}
	bind(t, testGate(t))
	if err := Load(ing.JSON); err != nil {
		t.Fatal(err)
	}
	defer Stop()
	send := func(request string) (*http.Response, net.Conn, *bufio.Reader) {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := io.WriteString(c, request); err != nil {
			t.Fatal(err)
		}
		br := bufio.NewReader(c)
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			t.Fatal(err)
		}
		return resp, c, br
	}
	host := "Host: app.example.test:" + p + "\r\n"
	if r, _, _ := send("GET / HTTP/1.1\r\n" + host + "Connection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: AAMAAABkAAQCAAAAAAIAAAAA\r\n\r\n"); r.StatusCode != http.StatusOK {
		t.Fatalf("h2c: status %d", r.StatusCode)
	}
	if r, _, _ := send("GET / HTTP/1.1\r\n" + host + "Connection: Upgrade\r\nUpgrade: H2C\r\n\r\n"); r.StatusCode != http.StatusOK {
		t.Fatalf("h2c in capitals: status %d", r.StatusCode)
	}
	r, c, br := send("GET /app/key HTTP/1.1\r\n" + host + "Connection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\n\r\n")
	if r.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("websocket: status %d", r.StatusCode)
	}
	if _, err := io.WriteString(c, "ping\n"); err != nil {
		t.Fatal(err)
	}
	if line, err := br.ReadString('\n'); err != nil || line != "tunnel:ping\n" {
		t.Fatalf("%q %v", line, err)
	}
}
