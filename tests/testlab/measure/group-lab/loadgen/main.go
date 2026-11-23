// Command loadgen is the load client of the throughput scenario of the MVP-27 lab measurement. TEST ONLY.
//
// It opens kept connections straight to the web port of every gateway, speaks the PROXY protocol v1 on each
// (as a balancer would, naming a visitor address of the documentation ranges) and sends GET requests at a
// fixed rate, or as fast as the answers come (-rate 0). It prints one JSON object: what was sent to each
// target, the answers by status, the latency and how much CPU the client itself used, so a run can say
// whether the client was the limit. Standard library only; it imports nothing of schild.
//
//	loadgen -targets 10.0.0.1,10.0.0.2 -host www.example.org -conns 32 -rate 3000 -seconds 60 -tag run1
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

type result struct {
	sent   int64
	codes  map[int]int64
	failed int64
	lat    []float64 // milliseconds, one of every `sample` requests
}

func main() {
	targets := flag.String("targets", "", "addresses of the gateways, comma separated")
	port := flag.Int("port", 80, "web port")
	host := flag.String("host", "app.sg27.test", "Host header")
	conns := flag.Int("conns", 16, "kept connections per target")
	rate := flag.Float64("rate", 0, "requests a second over all targets; 0: as fast as the answers come")
	seconds := flag.Float64("seconds", 30, "how long")
	tag := flag.String("tag", "t", "first path element of every request")
	clients := flag.Int("clients", 200, "visitor addresses named in the PROXY header (198.51.100.1 and up)")
	flag.Parse()
	ips := strings.Split(*targets, ",")
	if *targets == "" {
		fmt.Fprintln(os.Stderr, "loadgen: -targets is needed")
		os.Exit(2)
	}
	var seq int64
	res := make([]*result, len(ips)**conns)
	end := time.Now().Add(time.Duration(*seconds * float64(time.Second)))
	start := time.Now()
	var wg sync.WaitGroup
	workers := len(ips) * *conns
	gap := time.Duration(0)
	if *rate > 0 {
		gap = time.Duration(float64(workers) / *rate * float64(time.Second))
	}
	for w := 0; w < workers; w++ {
		r := &result{codes: map[int]int64{}}
		res[w] = r
		wg.Add(1)
		go func(w int, r *result) {
			defer wg.Done()
			ip := ips[w%len(ips)]
			visitor := fmt.Sprintf("198.51.100.%d", 1+w%*clients%250)
			var c net.Conn
			var br *bufio.Reader
			next := start.Add(time.Duration(float64(gap) * float64(w) / float64(workers)))
			for time.Now().Before(end) {
				if gap > 0 {
					if d := time.Until(next); d > 0 {
						time.Sleep(d)
					}
					next = next.Add(gap)
					if late := time.Since(next); late > 5*gap {
						next = time.Now()
					}
				}
				if c == nil {
					var err error
					c, err = net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, *port), 3*time.Second)
					if err != nil {
						r.failed++
						r.sent++
						c = nil
						time.Sleep(50 * time.Millisecond)
						continue
					}
					fmt.Fprintf(c, "PROXY TCP4 %s %s %d %d\r\n", visitor, ip, 40000+w%20000, *port)
					br = bufio.NewReaderSize(c, 16384)
				}
				n := atomic.AddInt64(&seq, 1)
				t0 := time.Now()
				c.SetDeadline(t0.Add(10 * time.Second))
				_, err := fmt.Fprintf(c, "GET /%s/%d HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0 (measure MVP-27 lab, loadgen)\r\n\r\n", *tag, n, *host)
				r.sent++
				if err != nil {
					r.failed++
					c.Close()
					c = nil
					continue
				}
				resp, err := http.ReadResponse(br, nil)
				if err != nil {
					r.failed++
					c.Close()
					c = nil
					continue
				}
				_, _ = br.Discard(int(resp.ContentLength))
				if resp.ContentLength < 0 || resp.Close {
					resp.Body.Close()
					c.Close()
					c = nil
				}
				r.codes[resp.StatusCode]++
				if n%20 == 0 {
					r.lat = append(r.lat, float64(time.Since(t0).Microseconds())/1000)
				}
			}
			if c != nil {
				c.Close()
			}
		}(w, r)
	}
	wg.Wait()
	wall := time.Since(start).Seconds()
	var ru syscall.Rusage
	_ = syscall.Getrusage(syscall.RUSAGE_SELF, &ru)
	cpu := float64(ru.Utime.Sec+ru.Stime.Sec) + float64(ru.Utime.Usec+ru.Stime.Usec)/1e6
	perTarget := map[string]int64{}
	codes := map[string]int64{}
	var lat []float64
	var sent, failed int64
	for w, r := range res {
		ok := int64(0)
		for code, n := range r.codes {
			codes[fmt.Sprint(code)] += n
			ok += n
		}
		perTarget[ips[w%len(ips)]] += ok
		sent += r.sent
		failed += r.failed
		lat = append(lat, r.lat...)
	}
	sort.Float64s(lat)
	q := func(p float64) float64 {
		if len(lat) == 0 {
			return 0
		}
		return lat[int(p*float64(len(lat)-1))]
	}
	out := map[string]any{
		"sent": sent, "failed": failed, "codes": codes, "answered_per_target": perTarget, "seconds": wall,
		"requests_per_s": float64(sent) / wall, "latency_ms": map[string]float64{"p50": q(0.5), "p95": q(0.95), "p99": q(0.99), "max": q(1)},
		"client_cpu_s": cpu, "client_cpus": runtime.NumCPU(), "client_cpu_share": cpu / wall / float64(runtime.NumCPU()),
		"started_unix": float64(start.UnixMilli()) / 1000, "ended_unix": float64(time.Now().UnixMilli()) / 1000,
	}
	_ = json.NewEncoder(os.Stdout).Encode(out)
}
