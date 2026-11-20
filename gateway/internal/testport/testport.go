// Package testport hands out TCP ports to tests that give the port to a
// server which binds it later (the embedded Caddy, `schild run`).
//
// Asking the kernel for a free port (":0"), closing it and letting the
// server bind it afterwards is a race. Until the server has bound it, the
// kernel hands the same port out again: to another listener, or as the
// source port of an outgoing connection, in this process or in a test
// binary that runs next to it. The server then fails with "address already
// in use", or the test reaches somebody else.
//
// The ports here lie below the ranges kernels take such ports from (Linux
// from 32768, macOS from 49152), and each process hands out its own block
// of them, so test binaries that run at the same time do not meet.
package testport

import (
	"net"
	"os"
	"strconv"
	"sync"
	"testing"
)

const (
	first  = 10000 // first port handed out
	blocks = 200   // blocks of ports, one per process (by process id)
	size   = 100   // ports of a block
)

var (
	mu   sync.Mutex
	next int
)

// Free returns 127.0.0.1:port for a port nothing listens on, neither on
// TCP nor on UDP (HTTP/3 binds the UDP port of the same number). Two calls
// in a row never return the same port. A server that was given the port has
// to be up, or gone, before the block of this process comes round again
// (size calls later).
func Free(t testing.TB) string {
	t.Helper()
	mu.Lock()
	defer mu.Unlock()
	base := first + os.Getpid()%blocks*size
	for range size {
		port := strconv.Itoa(base + next%size)
		next++
		if unused(port) {
			return net.JoinHostPort("127.0.0.1", port)
		}
	}
	t.Fatalf("testport: no unused port in %d-%d", base, base+size-1)
	return ""
}

// unused binds the port the ways a server may: on every address (Caddy
// listens on ":port"), on loopback, and on UDP.
func unused(port string) bool {
	for _, addr := range []string{":" + port, "127.0.0.1:" + port} {
		l, err := net.Listen("tcp", addr)
		if err != nil {
			return false
		}
		_ = l.Close()
	}
	pc, err := net.ListenPacket("udp", ":"+port)
	if err != nil {
		return false
	}
	_ = pc.Close()
	return true
}
