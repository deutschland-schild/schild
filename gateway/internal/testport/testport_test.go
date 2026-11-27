package testport

import (
	"net"
	"strconv"
	"testing"
)

func TestFree(t *testing.T) {
	seen := map[string]bool{}
	for range size {
		addr := Free(t)
		if seen[addr] {
			t.Fatalf("%s handed out twice within one round", addr)
		}
		seen[addr] = true
		_, p, _ := net.SplitHostPort(addr)
		if n, _ := strconv.Atoi(p); n < first || n >= first+blocks*size {
			t.Fatalf("port %d outside %d-%d", n, first, first+blocks*size-1)
		}
	}
	// A port somebody listens on is skipped, on TCP and on UDP.
	addr := Free(t)
	_, p, _ := net.SplitHostPort(addr)
	l, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	if unused(p) {
		t.Error("a port with a TCP listener counts as unused")
	}
	_ = l.Close()
	pc, err := net.ListenPacket("udp", ":"+p)
	if err != nil {
		t.Fatal(err)
	}
	if unused(p) {
		t.Error("a port with a UDP socket counts as unused")
	}
	_ = pc.Close()
	if !unused(p) {
		t.Error("a released port counts as used")
	}
}

// Two processes whose process ids lead to one block do not share it: the
// second one takes the next block.
func TestClaimSkipsABlockThatIsTaken(t *testing.T) {
	a, la := claim(7)
	if la == nil {
		t.Skip("no lock port can be bound here")
	}
	defer la.Close()
	b, lb := claim(a)
	if lb != nil {
		defer lb.Close()
	}
	if b == a {
		t.Fatalf("the block %d was claimed twice", a)
	}
	// The last block before the ones of BlockEnv wraps to the first.
	c, lc := claim(blocks - given - 1)
	if lc != nil {
		defer lc.Close()
	}
	if c < 0 || c >= blocks-given {
		t.Fatalf("claimed the block %d, which is kept for %s", c, BlockEnv)
	}
}
