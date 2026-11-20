package main

// Hold many TCP sockets open (sampler budget with 50 000 sockets): a
// loopback listener plus N client connections, so /proc/net/tcp lists 2N+1
// entries (ESTABLISHED on both ends).

import (
	"flag"
	"fmt"
	"net"
	"os"
	"time"
)

func cmdSockets(args []string) error {
	fs := flag.NewFlagSet("sockets", flag.ExitOnError)
	n := fs.Int("n", 25000, "client connections")
	hold := fs.Duration("hold", 5*time.Minute, "")
	addr := fs.String("listen", "127.0.0.1:17777", "")
	_ = fs.Parse(args)
	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		return err
	}
	var accepted []net.Conn
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted = append(accepted, c)
		}
	}()
	var conns []net.Conn
	for i := 0; i < *n; i++ {
		c, err := net.Dial("tcp", *addr)
		if err != nil {
			return fmt.Errorf("after %d: %w", i, err)
		}
		conns = append(conns, c)
	}
	fmt.Fprintf(os.Stderr, "holding %d connections for %s\n", len(conns), *hold)
	time.Sleep(*hold)
	_ = accepted
	return nil
}
