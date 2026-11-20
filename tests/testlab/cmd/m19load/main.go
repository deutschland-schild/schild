// Command m19load is the TEST ONLY open-loop load and latency driver of the
// independent MVP-19 measurement: fixed request rate against one URL with a
// Host/SNI name, dialing a fixed address (so example names need no DNS),
// optional custom CA. Prints status counts, errors, hangs (no answer within
// -timeout) and p50/p95/p99 as JSON.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sort"
	"sync"
	"time"
)

func main() {
	url := flag.String("url", "", "URL (host part is Host and SNI)")
	connect := flag.String("connect", "", "dial this host:port instead of the URL's host")
	caFile := flag.String("ca", "", "PEM CA bundle for TLS")
	rps := flag.Int("rps", 200, "requests per second (open loop)")
	n := flag.Int("n", 3000, "number of requests")
	warm := flag.Int("warmup", 200, "warm-up requests (not counted)")
	timeout := flag.Duration("timeout", 30*time.Second, "per-request timeout; longer counts as a hang")
	method := flag.String("method", "GET", "method")
	body := flag.String("body", "", "request body (or @file)")
	ctype := flag.String("ctype", "", "Content-Type")
	label := flag.String("label", "", "label in the output")
	conns := flag.Int("conns", 64, "max idle conns per host")
	flag.Parse()
	var bodyBytes []byte
	if len(*body) > 0 && (*body)[0] == '@' {
		b, err := os.ReadFile((*body)[1:])
		if err != nil {
			panic(err)
		}
		bodyBytes = b
	} else {
		bodyBytes = []byte(*body)
	}
	tlsCfg := &tls.Config{}
	if *caFile != "" {
		pem, err := os.ReadFile(*caFile)
		if err != nil {
			panic(err)
		}
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(pem)
		tlsCfg.RootCAs = pool
	}
	d := &net.Dialer{Timeout: 5 * time.Second}
	tr := &http.Transport{TLSClientConfig: tlsCfg, MaxIdleConnsPerHost: *conns, MaxIdleConns: *conns, IdleConnTimeout: time.Minute,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if *connect != "" {
				addr = *connect
			}
			return d.DialContext(ctx, network, addr)
		}}
	cl := &http.Client{Transport: tr, Timeout: *timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	do := func() (int, time.Duration, error) {
		var rd io.Reader
		if len(bodyBytes) > 0 {
			rd = bytes.NewReader(bodyBytes)
		}
		req, _ := http.NewRequest(*method, *url, rd)
		if *ctype != "" {
			req.Header.Set("Content-Type", *ctype)
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux aarch64) m19load")
		t0 := time.Now()
		resp, err := cl.Do(req)
		if err != nil {
			return 0, time.Since(t0), err
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return resp.StatusCode, time.Since(t0), nil
	}
	for i := 0; i < *warm; i++ {
		_, _, _ = do()
	}
	var mu sync.Mutex
	lat := make([]float64, 0, *n)
	status := map[string]int{}
	errs := map[string]int{}
	hangs := 0
	var wg sync.WaitGroup
	tick := time.NewTicker(time.Second / time.Duration(*rps))
	start := time.Now()
	for i := 0; i < *n; i++ {
		<-tick.C
		wg.Add(1)
		go func() {
			defer wg.Done()
			code, dur, err := do()
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				var ne net.Error
				if e, ok := err.(net.Error); ok {
					ne = e
				}
				if ne != nil && ne.Timeout() {
					hangs++
				}
				errs[fmt.Sprintf("%.80s", err.Error())]++
				return
			}
			status[fmt.Sprint(code)]++
			lat = append(lat, float64(dur.Microseconds())/1000)
		}()
	}
	wg.Wait()
	elapsed := time.Since(start)
	sort.Float64s(lat)
	pct := func(p float64) float64 {
		if len(lat) == 0 {
			return 0
		}
		i := int(p*float64(len(lat))+0.5) - 1
		if i < 0 {
			i = 0
		}
		if i >= len(lat) {
			i = len(lat) - 1
		}
		return lat[i]
	}
	out := map[string]any{"label": *label, "url": *url, "rps": *rps, "n": *n, "answered": len(lat), "elapsed_s": elapsed.Seconds(),
		"status": status, "errors": errs, "hangs": hangs,
		"p50_ms": pct(0.50), "p95_ms": pct(0.95), "p99_ms": pct(0.99)}
	if len(lat) > 0 {
		out["max_ms"] = lat[len(lat)-1]
	}
	b, _ := json.Marshal(out)
	fmt.Println(string(b))
}
