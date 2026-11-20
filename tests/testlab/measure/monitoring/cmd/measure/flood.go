package main

// Load and cardinality floods: fixed-rate GETs with distinct paths, client
// addresses, user agents and referrer hosts; prints rate, status counts and
// client-side latency quantiles as JSON.

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

func cmdFlood(args []string) error {
	fs := flag.NewFlagSet("flood", flag.ExitOnError)
	target := fs.String("target", "http://127.0.0.1:18090", "")
	host := fs.String("host", "shop.test", "")
	n := fs.Int("n", 10000, "requests (0: run for -duration)")
	dur := fs.Duration("duration", 0, "")
	rps := fs.Int("rps", 0, "0 = as fast as the workers go")
	workers := fs.Int("workers", 32, "")
	paths := fs.Int("paths", 0, "distinct paths (0: always /)")
	pathLen := fs.Int("pathlen", 0, "pad each distinct path to this length")
	addrs := fs.Int("addrs", 0, "distinct client addresses via X-Forwarded-For (0: none)")
	uas := fs.Int("uas", 0, "distinct user agents")
	refs := fs.Int("refs", 0, "distinct referrer hosts")
	offset := fs.Int("offset", 0, "start number for distinct values")
	spread := fs.Bool("spread", false, "vary path length by k%16 (spreads the keys over the 16 stripes of a length-hashed cache)")
	delay := fs.Int("delay", 0, "X-Delay-Ms for the backend")
	_ = fs.Parse(args)
	tr := &http.Transport{DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext, MaxIdleConns: 2 * *workers, MaxIdleConnsPerHost: 2 * *workers, DisableCompression: true}
	hc := &http.Client{Transport: tr, Timeout: 30 * time.Second}
	var idx atomic.Int64
	var mu sync.Mutex
	status := map[int]int{}
	var lats []float64
	errs := 0
	start := time.Now()
	deadline := time.Time{}
	if *dur > 0 {
		deadline = start.Add(*dur)
	}
	work := make(chan int, 1024)
	go func() {
		for i := 0; ; i++ {
			if *n > 0 && i >= *n || !deadline.IsZero() && time.Now().After(deadline) {
				close(work)
				return
			}
			if *rps > 0 {
				// open-loop pacing by elapsed time (a ticker loses ticks below 1 ms)
				for due := int(time.Since(start).Seconds() * float64(*rps)); i >= due; due = int(time.Since(start).Seconds() * float64(*rps)) {
					time.Sleep(200 * time.Microsecond)
				}
			}
			work <- i
		}
	}()
	var wg sync.WaitGroup
	for w := 0; w < *workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var local []float64
			lst := map[int]int{}
			le := 0
			for i := range work {
				k := i + *offset
				p := "/"
				if *paths > 0 {
					p = fmt.Sprintf("/f/p%d", k%*paths)
					if *pathLen > len(p) {
						l := *pathLen - len(p) - 1
						if *spread {
							l -= k % 16
						}
						p += "/" + strings.Repeat("x", l)
					}
				}
				req, _ := http.NewRequest("GET", *target+p, nil)
				req.Host = *host
				if *addrs > 0 {
					a := uint32(k % *addrs)
					ip := netip.AddrFrom4([4]byte{10, byte(a >> 16), byte(a >> 8), byte(a)})
					req.Header.Set("X-Forwarded-For", ip.String())
				}
				ua := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
				if *uas > 0 {
					ua = fmt.Sprintf("FloodAgent/%d (+https://example.org/bot-%d)", k%*uas, k%*uas)
				}
				req.Header.Set("User-Agent", ua)
				if *refs > 0 {
					req.Header.Set("Referer", fmt.Sprintf("https://r%d.example-%d.org/x", k%*refs, k%*refs))
				}
				req.Header.Set("Accept", "text/html")
				if *delay > 0 {
					req.Header.Set("X-Delay-Ms", fmt.Sprint(*delay))
				}
				t0 := time.Now()
				resp, err := hc.Do(req)
				if err != nil {
					le++
					continue
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				local = append(local, float64(time.Since(t0).Microseconds())/1000)
				lst[resp.StatusCode]++
				idx.Add(1)
			}
			mu.Lock()
			lats = append(lats, local...)
			for k, v := range lst {
				status[k] += v
			}
			errs += le
			mu.Unlock()
		}()
	}
	wg.Wait()
	el := time.Since(start).Seconds()
	sort.Float64s(lats)
	q := func(x float64) float64 {
		if len(lats) == 0 {
			return 0
		}
		return lats[min(len(lats)-1, int(x*float64(len(lats))))]
	}
	out := map[string]any{"requests": len(lats), "errors": errs, "seconds": el, "rps": float64(len(lats)) / el, "status": status,
		"p50_ms": q(0.5), "p90_ms": q(0.9), "p99_ms": q(0.99), "p999_ms": q(0.999), "max_ms": q(1)}
	return json.NewEncoder(os.Stdout).Encode(out)
}
