package caddymod

import (
	"net"

	"golang.org/x/sys/unix"
)

// firstTakesAll makes the kernel send every connection of the address of ln
// to the first socket of its SO_REUSEPORT group: a classic BPF program that
// returns 0, the index of the socket. It needs no capability.
func firstTakesAll(ln *net.TCPListener) error {
	rc, err := ln.SyscallConn()
	if err != nil {
		return err
	}
	prog := []unix.SockFilter{{Code: unix.BPF_RET | unix.BPF_K, K: 0}}
	var serr error
	if err := rc.Control(func(fd uintptr) {
		serr = unix.SetsockoptSockFprog(int(fd), unix.SOL_SOCKET, unix.SO_ATTACH_REUSEPORT_CBPF, &unix.SockFprog{Len: 1, Filter: &prog[0]})
	}); err != nil {
		return err
	}
	return serr
}
