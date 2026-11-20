package main

// agentflood (TEST ONLY, MVP-21 re-measurement): floods the agent API with
// read-only tokens to check that the call log never pushes out events.

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

func cmdAgentFlood(args []string) error {
	fs := flag.NewFlagSet("agentflood", flag.ExitOnError)
	target := fs.String("target", "http://127.0.0.1:18189", "agent API base URL")
	tokFile := fs.String("tokens", "tokens", "file with one token per line")
	path := fs.String("path", "/agent/v0/status", "")
	dur := fs.Duration("duration", 10*time.Second, "")
	n := fs.Int("n", 0, "stop after n requests (0: duration only)")
	workers := fs.Int("workers", 32, "")
	_ = fs.Parse(args)
	raw, err := os.ReadFile(*tokFile)
	if err != nil {
		return err
	}
	var toks []string
	for _, l := range strings.Split(string(raw), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			toks = append(toks, l)
		}
	}
	if len(toks) == 0 {
		return fmt.Errorf("no tokens")
	}
	tr := &http.Transport{DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext, MaxIdleConns: 2 * *workers, MaxIdleConnsPerHost: 2 * *workers}
	hc := &http.Client{Transport: tr, Timeout: 30 * time.Second}
	var mu sync.Mutex
	status := map[int]int{}
	var cnt atomic.Int64
	errs := 0
	start := time.Now()
	deadline := start.Add(*dur)
	var wg sync.WaitGroup
	for w := 0; w < *workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			loc := map[int]int{}
			le := 0
			for i := w; time.Now().Before(deadline); i += *workers {
				if *n > 0 && cnt.Add(1) > int64(*n) {
					break
				}
				req, _ := http.NewRequest(http.MethodGet, *target+*path, nil)
				req.Header.Set("Authorization", "Bearer "+toks[i%len(toks)])
				resp, err := hc.Do(req)
				if err != nil {
					le++
					continue
				}
				var sink [4096]byte
				for {
					if _, e := resp.Body.Read(sink[:]); e != nil {
						break
					}
				}
				resp.Body.Close()
				loc[resp.StatusCode]++
			}
			mu.Lock()
			for k, v := range loc {
				status[k] += v
			}
			errs += le
			mu.Unlock()
		}(w)
	}
	wg.Wait()
	total := 0
	st := map[string]int{}
	for k, v := range status {
		total += v
		st[fmt.Sprint(k)] = v
	}
	el := time.Since(start).Seconds()
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"requests": total, "errors": errs, "seconds": el, "rps": float64(total) / el, "status": st, "tokens": len(toks)})
}
