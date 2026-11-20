package caddymod

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/deutschland-schild/schild/contract/bodylimit"
	"github.com/deutschland-schild/schild/gateway/internal/connlimit"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) jump() {
	c.mu.Lock()
	c.t = c.t.Add(time.Hour)
	c.mu.Unlock()
}

func wrappersOf(t *testing.T, server map[string]any) []string {
	t.Helper()
	var out []string
	for _, w := range server["listener_wrappers"].([]any) {
		m := w.(map[string]any)
		name := m["wrapper"].(string)
		if m["proxied"] == true {
			name += "+proxied"
		}
		out = append(out, name)
	}
	return out
}

// The wrapper stands before TLS, wherever the operator put the other ones.
func TestLimitConnsOrder(t *testing.T) {
	for _, c := range []struct {
		name string
		in   []any
		want string
	}{
		{"nothing", nil, "schild_conns tls"},
		{"after tls by default", []any{map[string]any{"wrapper": "http_redirect"}}, "schild_conns tls http_redirect"},
		{"tls written out", []any{map[string]any{"wrapper": "http_redirect"}, map[string]any{"wrapper": "tls"}}, "schild_conns http_redirect tls"},
		{"proxy protocol", []any{map[string]any{"wrapper": "proxy_protocol"}, map[string]any{"wrapper": "tls"}}, "schild_conns+proxied proxy_protocol tls"},
	} {
		s := map[string]any{}
		if c.in != nil {
			s["listener_wrappers"] = c.in
		}
		limitConns(s)
		if got := strings.Join(wrappersOf(t, s), " "); got != c.want {
			t.Errorf("%s: %s", c.name, got)
		}
	}
}

func TestRedirectListeners(t *testing.T) {
	site := func(listen ...any) map[string]any {
		return map[string]any{"listen": listen, "routes": []any{map[string]any{"match": []any{map[string]any{"host": []any{"a.example"}}}}}}
	}
	cases := []struct {
		name    string
		http    map[string]any
		servers map[string]any
		want    string
	}{
		{"https site", nil, map[string]any{"srv0": site(":443")}, ":80"},
		{"a server has the port", nil, map[string]any{"srv0": site(":443"), "srv1": site(":80")}, ""},
		{"own ports", map[string]any{"https_port": float64(8443), "http_port": float64(8080)}, map[string]any{"srv0": site(":8443")}, ":8080"},
		{"a site on another port", nil, map[string]any{"srv0": site(":9443")}, ":80"},
		{"http only", nil, map[string]any{"srv0": site(":80")}, ""},
		{"bound address", nil, map[string]any{"srv0": site("127.0.0.1:443")}, "127.0.0.1:80"},
		{"redirects off", nil, map[string]any{"srv0": func() map[string]any {
			s := site(":443")
			s["automatic_https"] = map[string]any{"disable_redirects": true}
			return s
		}()}, ""},
		{"automatic https off", nil, map[string]any{"srv0": func() map[string]any {
			s := site(":443")
			s["automatic_https"] = map[string]any{"disable": true}
			return s
		}()}, ""},
		{"no host", nil, map[string]any{"srv0": map[string]any{"listen": []any{":443"}}}, ""},
		{"unix socket", nil, map[string]any{"srv0": site("unix//run/x.sock")}, ""},
	}
	for _, c := range cases {
		h := c.http
		if h == nil {
			h = map[string]any{}
		}
		if got := strings.Join(redirectListeners(h, c.servers), " "); got != c.want {
			t.Errorf("%s: %q", c.name, got)
		}
	}
}

// liveConns runs a Caddyfile behind a limiter.
func liveConns(t *testing.T, lim bodylimit.ConnLimits, caddyfile string) (*connlimit.Limiter, *clock) {
	t.Helper()
	dir := caddyDir(t)
	cf := writeFile(t, dir, "Caddyfile", caddyfile)
	ing, err := PrepareIngress(IngressOptions{Caddyfile: cf, DefaultStorage: filepath.Join(dir, "caddy")})
	if err != nil {
		t.Fatal(err)
	}
	c := &clock{t: time.Now()}
	l := connlimit.New(connlimit.Options{Limits: lim, Now: c.now})
	bind(t, testGate(t))
	t.Cleanup(BindConns(l))
	if err := Load(ing.JSON); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = Stop() })
	return l, c
}

// A refused connection is closed before any TLS: no record comes back.
func TestConnRefusedBeforeTLS(t *testing.T) {
	addr := freePort(t)
	p := port(addr)
	l, _ := liveConns(t, bodylimit.ConnLimits{MaxPerClient: 1, MaxPerNetwork: 8, Max: 8},
		fmt.Sprintf("{\n\tservers {\n\t\tprotocols h1 h2\n\t}\n\tauto_https disable_redirects\n\tskip_install_trust\n\thttps_port %[1]s\n\thttp_port %[2]s\n}\n\nhttps://app.example.test:%[1]s {\n\ttls internal\n\tschild\n\trespond 200\n}\n", p, port(freePort(t))))
	first, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	waitOpen(t, l, 1)
	second, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, ServerName: "app.example.test"})
	if err == nil {
		second.Close()
		t.Fatal("handshake with a connection over the limit")
	}
	if l.Open() != 1 {
		t.Fatalf("open %d", l.Open())
	}
}

func waitOpen(t *testing.T, l *connlimit.Limiter, n int) {
	t.Helper()
	for i := 0; i < 400 && l.Open() != n; i++ {
		time.Sleep(5 * time.Millisecond)
	}
	if l.Open() != n {
		t.Fatalf("open %d, want %d", l.Open(), n)
	}
}

// Through the real server, on every shape of connection Caddy wraps differently:
// a connection with a running request keeps its place, one without gives it up.
func TestConnStateBehindCaddy(t *testing.T) {
	cases := []struct {
		name      string
		protocols string
		https     bool
		h2        bool
	}{
		{"plain h1 only", "h1", false, false},
		{"plain h1 h2", "h1 h2", false, false},
		{"tls h1", "h1 h2", true, false},
		{"tls h2", "h1 h2", true, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			release := make(chan struct{})
			var once sync.Once
			free := func() { once.Do(func() { close(release) }) }
			entered := make(chan struct{}, 8)
			back := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				entered <- struct{}{}
				<-release
				_, _ = io.WriteString(w, "ok")
			}))
			t.Cleanup(func() { free(); back.Close() })
			addr := freePort(t)
			p := port(addr)
			scheme, tlsLine, ports := "http", "", fmt.Sprintf("http_port %s", p)
			if c.https {
				scheme, tlsLine, ports = "https", "\ttls internal\n", fmt.Sprintf("https_port %s\n\thttp_port %s", p, port(freePort(t)))
			}
			l, clk := liveConns(t, bodylimit.ConnLimits{MaxPerClient: 1, MaxPerNetwork: 8, Max: 8}, fmt.Sprintf(
				"{\n\tservers {\n\t\tprotocols %s\n\t}\n\tauto_https disable_redirects\n\tskip_install_trust\n\t%s\n}\n\n%s://app.example.test:%s {\n%s\tschild\n\treverse_proxy %s\n}\n",
				c.protocols, ports, scheme, p, tlsLine, strings.TrimPrefix(back.URL, "http://")))
			for i := 0; c.https && i < 400; i++ { // the certificate comes a moment after the load
				tc, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, ServerName: "app.example.test"})
				if err == nil {
					_ = tc.Close()
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			waitOpen(t, l, 0)
			tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: "app.example.test"}, ForceAttemptHTTP2: c.h2,
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, "tcp", addr)
				}}
			if !c.h2 {
				tr.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
			}
			defer tr.CloseIdleConnections()
			cl := &http.Client{Transport: tr, Timeout: 20 * time.Second}
			url := fmt.Sprintf("%s://app.example.test:%s/", scheme, p)
			done := make(chan error, 1)
			go func() {
				r, err := cl.Get(url + "slow")
				if err == nil {
					defer r.Body.Close()
					if _, err = io.ReadAll(r.Body); err == nil && (r.StatusCode != 200 || (c.h2 && r.ProtoMajor != 2)) {
						err = fmt.Errorf("status %d proto %d", r.StatusCode, r.ProtoMajor)
					}
				}
				done <- err
			}()
			select {
			case <-entered:
			case err := <-done:
				t.Fatalf("the request ended before the backend saw it: %v", err)
			}
			clk.jump()
			second, err := net.Dial("tcp", addr)
			if err != nil {
				t.Fatal(err)
			}
			defer second.Close()
			_ = second.SetReadDeadline(time.Now().Add(5 * time.Second))
			if _, err := second.Read(make([]byte, 1)); err == nil || isTimeout(err) {
				t.Fatalf("a connection over the limit stayed open: %v", err)
			}
			free()
			if err := <-done; err != nil {
				t.Fatalf("the running request lost its connection: %v", err)
			}
			// Now the first connection is idle, and gives way after the minimum age.
			waitIdle(t, tr, clk, addr)
		})
	}
}

// proxyProtocolCaddyfile is a plain HTTP site behind the proxy protocol: the
// header is read for every peer of 127.0.0.1, within timeout.
func proxyProtocolCaddyfile(p, backend string) string {
	return fmt.Sprintf("{\n\tservers {\n\t\tlistener_wrappers {\n\t\t\tproxy_protocol {\n\t\t\t\ttimeout 3s\n\t\t\t\tallow 127.0.0.1/32\n\t\t\t}\n\t\t}\n\t}\n\tauto_https disable_redirects\n\tskip_install_trust\n\thttp_port %s\n}\n\nhttp://app.example.test:%s {\n\tschild\n\treverse_proxy %s\n}\n", p, p, backend)
}

// proxied writes a proxy protocol header and an HTTP request on a new connection.
func proxied(t *testing.T, addr, path string) net.Conn {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	fmt.Fprintf(c, "PROXY TCP4 198.51.100.7 127.0.0.1 40000 %s\r\nGET %s HTTP/1.1\r\nHost: app.example.test:%s\r\n\r\n", port(addr), path, port(addr))
	return c
}

// A client that connects and sends nothing must not hold up the accept loop: the
// proxy protocol header of a connection is read when the connection is served,
// and the hooks of the limiter never wait for it.
func TestProxyProtocolSilentClientBlocksNobody(t *testing.T) {
	back := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") }))
	defer back.Close()
	addr := freePort(t)
	l, _ := liveConns(t, bodylimit.ConnLimits{MaxPerClient: 8, MaxPerNetwork: 8, Max: 8}, proxyProtocolCaddyfile(port(addr), strings.TrimPrefix(back.URL, "http://")))
	silent, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer silent.Close()
	waitOpen(t, l, 1)
	c := proxied(t, addr, "/")
	_ = c.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
	b := make([]byte, 64)
	n, err := c.Read(b)
	if err != nil || !strings.HasPrefix(string(b[:n]), "HTTP/1.1 200") {
		t.Fatalf("a request waited for a silent connection: %q %v", b[:n], err)
	}
}

// Behind the proxy protocol the server's connection names the client, not the
// counted connection under it: a connection with a running request still keeps
// its place.
func TestProxyProtocolBusyKeepsItsPlace(t *testing.T) {
	release := make(chan struct{})
	var once sync.Once
	free := func() { once.Do(func() { close(release) }) }
	entered := make(chan struct{}, 8)
	back := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		entered <- struct{}{}
		<-release
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(func() { free(); back.Close() })
	addr := freePort(t)
	l, clk := liveConns(t, bodylimit.ConnLimits{MaxPerClient: 8, MaxPerNetwork: 8, Max: 1}, proxyProtocolCaddyfile(port(addr), strings.TrimPrefix(back.URL, "http://")))
	first := proxied(t, addr, "/slow")
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the request did not reach the backend")
	}
	clk.jump()
	second, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	_ = second.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := second.Read(make([]byte, 1)); err == nil || isTimeout(err) {
		t.Fatalf("a connection over the limit stayed open: %v", err)
	}
	free()
	_ = first.SetReadDeadline(time.Now().Add(5 * time.Second))
	b := make([]byte, 64)
	n, err := first.Read(b)
	if err != nil || !strings.HasPrefix(string(b[:n]), "HTTP/1.1 200") {
		t.Fatalf("the running request lost its connection: %q %v", b[:n], err)
	}
	if l.Open() != 1 {
		t.Fatalf("open %d", l.Open())
	}
}

// An HTTP/2 PING moves bytes without a request, so it keeps no place.
func TestPingKeepsNoPlace(t *testing.T) {
	addr := freePort(t)
	l, clk := liveConns(t, bodylimit.ConnLimits{MaxPerClient: 1, MaxPerNetwork: 8, Max: 8}, fmt.Sprintf(
		"{\n\tservers {\n\t\tprotocols h1 h2\n\t}\n\tauto_https disable_redirects\n\tskip_install_trust\n\thttps_port %s\n\thttp_port %s\n}\n\nhttps://app.example.test:%s {\n\ttls internal\n\tschild\n\trespond ok\n}\n",
		port(addr), port(freePort(t)), port(addr)))
	dial := func() (*tls.Conn, error) {
		return tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, ServerName: "app.example.test", NextProtos: []string{"h2"}})
	}
	var first *tls.Conn
	for i := 0; i < 400; i++ { // the certificate comes a moment after the load
		var err error
		if first, err = dial(); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if first == nil {
		t.Fatal("no TLS connection")
	}
	defer first.Close()
	_ = first.SetReadDeadline(time.Now().Add(5 * time.Second))
	ping := func() {
		t.Helper()
		if _, err := io.WriteString(first, "\x00\x00\x08\x06\x00\x00\x00\x00\x00schild!!"); err != nil {
			t.Fatal(err)
		}
		for { // other frames come first
			var head [9]byte
			if _, err := io.ReadFull(first, head[:]); err != nil {
				t.Fatalf("no ack of the ping: %v", err)
			}
			if _, err := io.CopyN(io.Discard, first, int64(head[0])<<16|int64(head[1])<<8|int64(head[2])); err != nil {
				t.Fatal(err)
			}
			if head[3] == 6 && head[4]&1 == 1 {
				return
			}
		}
	}
	if _, err := io.WriteString(first, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\x00\x00\x00\x04\x00\x00\x00\x00\x00"); err != nil {
		t.Fatal(err)
	}
	ping() // the server has read the preface, and reported the connection idle once
	clk.jump()
	ping()
	second, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	_ = second.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	if _, err := second.Read(make([]byte, 1)); !isTimeout(err) {
		t.Fatalf("the new connection lost to one that only pings: %v", err)
	}
	_ = first.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.Copy(io.Discard, first); err != nil && isTimeout(err) {
		t.Fatal("the connection that only pings stayed open")
	}
	if n := l.Open(); n != 1 {
		t.Fatalf("open %d, want 1", n)
	}
}

// A HEADERS frame the server refuses before any handler runs makes the connection
// active and idle, and keeps no place either (round 6 of the measurement before
// the live test).
func TestRefusedStreamKeepsNoPlace(t *testing.T) {
	addr := freePort(t)
	l, clk := liveConns(t, bodylimit.ConnLimits{MaxPerClient: 1, MaxPerNetwork: 8, Max: 8}, fmt.Sprintf(
		"{\n\tservers {\n\t\tprotocols h1 h2\n\t}\n\tauto_https disable_redirects\n\tskip_install_trust\n\thttps_port %s\n\thttp_port %s\n}\n\nhttps://app.example.test:%s {\n\ttls internal\n\tschild\n\trespond ok\n}\n",
		port(addr), port(freePort(t)), port(addr)))
	var first *tls.Conn
	for i := 0; i < 400; i++ { // the certificate comes a moment after the load
		var err error
		if first, err = tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, ServerName: "app.example.test", NextProtos: []string{"h2"}}); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if first == nil {
		t.Fatal("no TLS connection")
	}
	defer first.Close()
	_ = first.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(first, http2.ClientPreface); err != nil {
		t.Fatal(err)
	}
	fr := http2.NewFramer(first, first)
	if err := fr.WriteSettings(); err != nil {
		t.Fatal(err)
	}
	var block strings.Builder
	enc := hpack.NewEncoder(&block)
	for _, f := range []hpack.HeaderField{{Name: ":method", Value: "GET"}, {Name: ":scheme", Value: "https"}, {Name: ":authority", Value: "app.example.test"}} {
		_ = enc.WriteField(f)
	}
	refused := func(stream uint32) {
		t.Helper()
		if err := fr.WriteHeaders(http2.HeadersFrameParam{StreamID: stream, BlockFragment: []byte(block.String()), EndStream: true, EndHeaders: true}); err != nil {
			t.Fatal(err)
		}
		for { // settings and their ack come first
			f, err := fr.ReadFrame()
			if err != nil {
				t.Fatalf("no reset of stream %d: %v", stream, err)
			}
			if rst, ok := f.(*http2.RSTStreamFrame); ok && rst.StreamID == stream {
				return
			}
		}
	}
	refused(1)
	clk.jump()
	refused(3)
	time.Sleep(50 * time.Millisecond) // the server reports the connection idle after the reset
	second, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	_ = second.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	if _, err := second.Read(make([]byte, 1)); !isTimeout(err) {
		t.Fatalf("the new connection lost to one with refused streams only: %v", err)
	}
	_ = first.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.Copy(io.Discard, first); err != nil && isTimeout(err) {
		t.Fatal("the connection with refused streams only stayed open")
	}
	if n := l.Open(); n != 1 {
		t.Fatalf("open %d, want 1", n)
	}
}

// The server allows H2MaxStreams streams per HTTP/2 connection, not Go's 250 (D60).
func TestH2StreamsPerConnection(t *testing.T) {
	addr := freePort(t)
	liveConns(t, bodylimit.ConnLimits{MaxPerClient: 8, MaxPerNetwork: 8, Max: 8}, fmt.Sprintf(
		"{\n\tservers {\n\t\tprotocols h1 h2\n\t}\n\tauto_https disable_redirects\n\tskip_install_trust\n\thttps_port %s\n\thttp_port %s\n}\n\nhttps://app.example.test:%s {\n\ttls internal\n\trespond ok\n}\n",
		port(addr), port(freePort(t)), port(addr)))
	var c *tls.Conn
	for i := 0; i < 400; i++ { // the certificate comes a moment after the load
		var err error
		if c, err = tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, ServerName: "app.example.test", NextProtos: []string{"h2"}}); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if c == nil {
		t.Fatal("no TLS connection")
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(c, http2.ClientPreface); err != nil {
		t.Fatal(err)
	}
	fr := http2.NewFramer(c, c)
	if err := fr.WriteSettings(); err != nil {
		t.Fatal(err)
	}
	for {
		f, err := fr.ReadFrame()
		if err != nil {
			t.Fatal(err)
		}
		if sf, ok := f.(*http2.SettingsFrame); ok && !sf.IsAck() {
			if v, ok := sf.Value(http2.SettingMaxConcurrentStreams); !ok || v != bodylimit.H2MaxStreams {
				t.Fatalf("max concurrent streams %d (sent %v), want %d", v, ok, bodylimit.H2MaxStreams)
			}
			return
		}
	}
}

func isTimeout(err error) bool {
	ne, ok := err.(net.Error)
	return ok && ne.Timeout()
}

// waitIdle opens a new connection until it stays open: the first one has to be
// reported idle by the server, which comes just after the answer.
func waitIdle(t *testing.T, _ *http.Transport, clk *clock, addr string) {
	t.Helper()
	for i := 0; i < 100; i++ {
		clk.jump()
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		_ = c.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		_, err = c.Read(make([]byte, 1))
		c.Close()
		if isTimeout(err) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("an idle connection did not give way")
}

// Neither a proxied answer, an answer of Caddy, an error nor a redirect names the
// server (D47). The backend's own Server goes too.
func TestServerHeadersHidden(t *testing.T) {
	back := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "backend/1.2.3")
		_, _ = io.WriteString(w, "ok")
	}))
	defer back.Close()
	gone := freePort(t)
	addr := freePort(t)
	p := port(addr)
	liveConns(t, bodylimit.ConnLimits{MaxPerClient: 64, MaxPerNetwork: 64, Max: 64}, fmt.Sprintf(
		"{\n\thttp_port %s\n\tauto_https disable_redirects\n\tskip_install_trust\n}\n\nhttp://app.example.test:%s {\n\tschild\n\thandle /caddy {\n\t\trespond ok\n\t}\n\thandle /down {\n\t\treverse_proxy %s\n\t}\n\thandle /moved {\n\t\tredir * /caddy\n\t}\n\treverse_proxy %s\n}\n",
		p, p, gone, strings.TrimPrefix(back.URL, "http://")))
	for path, status := range map[string]int{"/": 200, "/caddy": 200, "/down": 502, "/moved": 302} {
		req, err := http.NewRequest("GET", "http://"+addr+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Host = "app.example.test:" + p
		r, err := http.DefaultTransport.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = r.Body.Close()
		if r.StatusCode != status || r.Header.Get("Server") != "" || r.Header.Get("Via") != "" {
			t.Errorf("%s: status %d, Server %q, Via %q", path, r.StatusCode, r.Header.Get("Server"), r.Header.Get("Via"))
		}
	}
}

func TestExposeServerHeaders(t *testing.T) {
	dir := caddyDir(t)
	cf := writeFile(t, dir, "Caddyfile", "http://app.example.test {\n\tschild\n\trespond ok\n}\n")
	for expose, want := range map[bool]bool{false: true, true: false} {
		ing, err := PrepareIngress(IngressOptions{Caddyfile: cf, DefaultStorage: filepath.Join(dir, "caddy"), ExposeServerHeaders: expose})
		if err != nil {
			t.Fatal(err)
		}
		if got := strings.Contains(string(ing.JSON), `"Via"`); got != want {
			t.Errorf("expose %v: Via in the config %v", expose, got)
		}
	}
}

// The redirects of automatic HTTPS come from a server Caddy makes on its own, which
// takes no wrappers. Written out, it is counted, and the redirect still works.
func TestRedirectServerCounts(t *testing.T) {
	httpAddr, httpsAddr := freePort(t), freePort(t)
	l, _ := liveConns(t, bodylimit.ConnLimits{MaxPerClient: 2, MaxPerNetwork: 8, Max: 8},
		fmt.Sprintf("{\n\tservers {\n\t\tprotocols h1 h2\n\t}\n\tskip_install_trust\n\thttp_port %s\n\thttps_port %s\n}\n\napp.example.test {\n\ttls internal\n\tschild\n\trespond 200\n}\n", port(httpAddr), port(httpsAddr)))
	c, err := net.Dial("tcp", httpAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	waitOpen(t, l, 1)
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprint(c, "GET /x HTTP/1.1\r\nHost: app.example.test\r\n\r\n")
	b := make([]byte, 256)
	n, err := c.Read(b)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(b[:n]), "HTTP/1.1 308") || !strings.Contains(strings.ToLower(string(b[:n])), "location: https://app.example.test") {
		t.Fatalf("%s", b[:n])
	}
}

// A validation has no limiter, and the JSON stays a valid config for it.
func TestValidateWithTheWrapper(t *testing.T) {
	dir := caddyDir(t)
	cf := writeFile(t, dir, "Caddyfile", "{\n\tskip_install_trust\n}\n\napp.example.test {\n\ttls internal\n\tschild\n\trespond 200\n}\n")
	ing, err := PrepareIngress(IngressOptions{Caddyfile: cf, DefaultStorage: filepath.Join(dir, "caddy")})
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateIngress(ing); err != nil {
		t.Fatal(err)
	}
	var m struct {
		Apps struct {
			HTTP struct {
				Servers map[string]map[string]any `json:"servers"`
			} `json:"http"`
		} `json:"apps"`
	}
	if err := json.Unmarshal(ing.JSON, &m); err != nil {
		t.Fatal(err)
	}
	if len(m.Apps.HTTP.Servers) != 2 {
		t.Fatalf("%d servers: %v", len(m.Apps.HTTP.Servers), m.Apps.HTTP.Servers)
	}
	for name, s := range m.Apps.HTTP.Servers {
		if w := wrappersOf(t, s); w[0] != connWrapperName {
			t.Fatalf("%s: %v", name, w)
		}
	}
}
