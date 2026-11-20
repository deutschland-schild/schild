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
