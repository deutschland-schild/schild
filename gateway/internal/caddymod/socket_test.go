package caddymod

import (
	"context"
	"net"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
)

func caddyListener(t *testing.T, addr string) net.Listener {
	t.Helper()
	na, err := caddy.ParseNetworkAddress(addr)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := na.Listen(context.Background(), 0, net.ListenConfig{})
	if err != nil {
		t.Fatal(err)
	}
	return ln.(net.Listener)
}

// TestTCPListenerBelowCaddy: the TCP listener is found below what this
// version of Caddy puts around it. When it fails after a Caddy update, a
// reload costs connections again (socket.go).
func TestTCPListenerBelowCaddy(t *testing.T) {
	ln := caddyListener(t, "127.0.0.1:0")
	defer ln.Close()
	if tcpListenerOf(ln) == nil {
		t.Fatalf("no TCP listener in %T", ln)
	}
}

// TestKeepSocket: the connections of an address go to its newest config, the
// first socket stays open while any config listens, and the last one closes
// it.
func TestKeepSocket(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux only")
	}
	first := caddyListener(t, "127.0.0.1:0")
	addr := first.Addr().String()
	var fresh, fresh2 atomic.Int64
	g1 := keepSocket(first, net.KeepAliveConfig{Enable: true}, &fresh)
	g2 := keepSocket(caddyListener(t, addr), net.KeepAliveConfig{Enable: true}, &fresh2)
	if _, ok := g1.(*generation); !ok {
		t.Fatalf("not kept: %T", g1)
	}
	dial := func() net.Conn {
		t.Helper()
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	accepted := make(chan string, 64)
	for name, ln := range map[string]net.Listener{"g1": g1, "g2": g2} {
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					accepted <- name + " closed"
					return
				}
				accepted <- name
				c.Close()
			}
		}()
	}
	// A connection the old config accepted and has not read holds it back.
	fresh.Store(1)
	time.AfterFunc(300*time.Millisecond, func() { fresh.Store(0) })
	start := time.Now()
	takeOver()
	if d := time.Since(start); d < 300*time.Millisecond || d > takeOverWait {
		t.Fatalf("took over after %s", d)
	}
	for range 20 {
		c := dial()
		if who := <-accepted; who != "g2" {
			t.Fatalf("a connection went to %s", who)
		}
		c.Close()
	}
	g1.Close()
	if who := <-accepted; who != "g1 closed" {
		t.Fatal(who)
	}
	c := dial()
	if who := <-accepted; who != "g2" {
		t.Fatal(who)
	}
	c.Close()
	g2.Close()
	<-accepted
	if c, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
		c.Close()
		t.Fatal("the socket is still open")
	}
}
