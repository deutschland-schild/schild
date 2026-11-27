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
// of them, so test binaries that run at the same time do not meet: the block
// follows from the process id, or from BlockEnv when a runner sets it.
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
	blocks = 200   // blocks of ports, one per process (block)
	size   = 100   // ports of a block
)

var (
	mu   sync.Mutex
	next int
	// held are the ports of tests that still run. Tests that run in parallel
	// draw from one block, and a server of one test may be down for a while
	// (a node that restarts, a node that starts late): its port must not go
	// to another test in between.
	held = map[string]bool{}
)

// Free returns 127.0.0.1:port for a port nothing listens on, neither on
// TCP nor on UDP (HTTP/3 binds the UDP port of the same number). Two calls
// in a row never return the same port, and a port stays with its test until
// the test ended, as long as the block has another one. When every port of
// the block is held, the oldest way applies: a server that was given the
// port has to be up, or gone, before the block of this process comes round
// again (size calls later).
func Free(t testing.TB) string {
	t.Helper()
	mu.Lock()
	defer mu.Unlock()
	base := first + block(t)*size
	for _, skipHeld := range []bool{true, false} {
		for range size {
			port := strconv.Itoa(base + next%size)
			next++
			if skipHeld && held[port] {
				continue
			}
			if unused(port) {
				if !held[port] {
					held[port] = true
					t.Cleanup(func() {
						mu.Lock()
						delete(held, port)
						mu.Unlock()
					})
				}
				return net.JoinHostPort("127.0.0.1", port)
			}
		}
	}
	t.Fatalf("testport: no unused port in %d-%d", base, base+size-1)
	return ""
}

// BlockEnv gives this process one of the blocks no process id leads to: a
// number, the same for no two processes that run at the same time. A runner
// that starts several test binaries side by side sets it
// (internal/tools/splittest); process ids alone may fall into one block.
const BlockEnv = "SCHILD_TESTPORT_BLOCK"

// given is how many blocks are kept for BlockEnv, the last ones.
const given = 16

// block is the block of this process: by BlockEnv, else by the process id.
func block(t testing.TB) int {
	s := os.Getenv(BlockEnv)
	if s == "" {
		return os.Getpid() % (blocks - given)
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 || n >= given {
		t.Fatalf("testport: %s=%q, want a number from 0 to %d", BlockEnv, s, given-1)
	}
	return blocks - given + n
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
