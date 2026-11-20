// Command floodtool holds the load shapes of the D40 replay. TEST ONLY: local instances, documentation addresses.
//
//	floodtool slots -target URL -attack 2001:db8:a -workers 24 -victim 2001:db8:b -duration 20s -kib 128
//	floodtool blocks -target URL -clients 70000 -rps 5000 -stall "sqlite3 lock file"     two passes within one minute
//	floodtool setup -target URL -keys 12000                                             login keys from 127.a.b.c (Linux only)
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

func client(workers int) *http.Client {
	return &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{MaxIdleConns: workers * 2, MaxIdleConnsPerHost: workers * 2, DisableCompression: true}}
}

func post(hc *http.Client, url, host, ip string, body []byte) (int, float64) {
	t0 := time.Now()
	rq, _ := http.NewRequest("POST", url, bytes.NewReader(body))
	rq.Host = host
	rq.Header.Set("X-Forwarded-For", ip)
	rq.Header.Set("Content-Type", "application/json")
	rq.Header.Set("User-Agent", "Mozilla/5.0 m26")
	r, err := hc.Do(rq)
	if err != nil {
		return 0, 0
	}
	_, _ = io.Copy(io.Discard, r.Body)
	r.Body.Close()
	return r.StatusCode, time.Since(t0).Seconds() * 1000
}

func cmdSlots(args []string) {
	fs := flag.NewFlagSet("slots", flag.ExitOnError)
	target := fs.String("target", "", "")
	host := fs.String("host", "shop.test", "")
	attack := fs.String("attack", "2001:db8:a", "")
	victim := fs.String("victim", "2001:db8:b", "")
	workers := fs.Int("workers", 24, "")
	dur := fs.Duration("duration", 20*time.Second, "")
	kib := fs.Int("kib", 128, "")
	pause := fs.Duration("pause", 300*time.Millisecond, "wait after a refused request")
	_ = fs.Parse(args)
	b, _ := json.Marshal(map[string]string{"text": strings.Repeat("lorem ipsum ", *kib*1024/12)})
	hc := client(*workers * 2)
	end := time.Now().Add(*dur)
	var mu sync.Mutex
	st := map[string]map[int]int{"attack": {}, "victim": {}, "cheap": {}}
	var wg sync.WaitGroup
	var attackOK atomic.Int64
	inflightMax := atomic.Int64{}
	inflight := atomic.Int64{}
	for w := 0; w < *workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for time.Now().Before(end) {
				inflight.Add(1)
				c, _ := post(hc, *target+"/api/items", *host, fmt.Sprintf("%s:%x::%x", *attack, w+1, w+1), b)
				inflight.Add(-1)
				if c == 200 {
					attackOK.Add(1)
				} else {
					time.Sleep(*pause)
				}
				mu.Lock()
				st["attack"][c]++
				mu.Unlock()
			}
		}(w)
	}
	time.Sleep(2 * time.Second)
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for time.Now().Before(end) {
				c, _ := post(hc, *target+"/api/items", *host, fmt.Sprintf("%s:%x::%x", *victim, w+1, w+1), b)
				mu.Lock()
				st["victim"][c]++
				mu.Unlock()
				time.Sleep(50 * time.Millisecond)
			}
		}(w)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for time.Now().Before(end) {
			c, _ := post(hc, *target+"/contact", *host, "2001:db8:e:1::1", []byte(`{"a":1}`))
			mu.Lock()
			st["cheap"][c]++
			mu.Unlock()
			time.Sleep(20 * time.Millisecond)
		}
	}()
	wg.Wait()
	_ = inflightMax
	o, _ := json.Marshal(st)
	fmt.Println(string(o))
}

func cmdBlocks(args []string) {
	fs := flag.NewFlagSet("blocks", flag.ExitOnError)
	target := fs.String("target", "", "")
	host := fs.String("host", "shop.test", "")
	clients := fs.Int("clients", 70000, "")
	workers := fs.Int("workers", 128, "")
	marker := fs.String("marker", "", "file created between the passes; the stall starts then")
	gofile := fs.String("go", "", "wait for this file before the second pass")
	_ = fs.Parse(args)
	hc := client(*workers)
	pass := func() (map[int]int, float64) {
		t0 := time.Now()
		var next atomic.Int64
		var mu sync.Mutex
		st := map[int]int{}
		var wg sync.WaitGroup
		for w := 0; w < *workers; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				local := map[int]int{}
				for {
					i := next.Add(1)
					if int(i) > *clients {
						break
					}
					ip := fmt.Sprintf("10.%d.%d.%d", i>>16, (i>>8)&255, i&255)
					rq, _ := http.NewRequest("GET", *target+"/?q=%3Cscript%3Ealert(1)%3C/script%3E", nil)
					rq.Host = *host
					rq.Header.Set("X-Forwarded-For", ip)
					rq.Header.Set("User-Agent", "Mozilla/5.0 m26")
					r, err := hc.Do(rq)
					if err != nil {
						local[0]++
						continue
					}
					_, _ = io.Copy(io.Discard, r.Body)
					r.Body.Close()
					local[r.StatusCode]++
				}
				mu.Lock()
				for k, v := range local {
					st[k] += v
				}
				mu.Unlock()
			}()
		}
		wg.Wait()
		return st, time.Since(t0).Seconds()
	}
	// start at the top of a minute: both passes must fall into one
	time.Sleep(time.Until(time.Now().Truncate(time.Minute).Add(time.Minute)))
	a, ta := pass()
	fmt.Println("pass1", a, ta)
	if *marker != "" {
		_ = os.WriteFile(*marker, []byte("x"), 0o644)
		for *gofile != "" {
			if _, err := os.Stat(*gofile); err == nil {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	b, tb := pass()
	fmt.Println("pass2", b, tb)
}

func cmdSetup(args []string) {
	fs := flag.NewFlagSet("setup", flag.ExitOnError)
	port := fs.Int("port", 8788, "")
	keys := fs.Int("keys", 12000, "")
	_ = fs.Parse(args)
	do := func(a, b, c byte) (int, float64) {
		d := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.IPv4(127, a, b, c)}}
		tr := &http.Transport{DialContext: func(ctx context.Context, n, ad string) (net.Conn, error) { return d.DialContext(ctx, n, ad) }, DisableKeepAlives: true}
		hc := &http.Client{Transport: tr, Timeout: 20 * time.Second}
		defer tr.CloseIdleConnections()
		t0 := time.Now()
		r, err := hc.Post("http://127.0.0.1:"+strconv.Itoa(*port)+"/api/v0/auth/setup", "application/json", strings.NewReader(`{"password":"schild-m26-TESTONLY-pw","setup_code":"000000"}`))
		if err != nil {
			fmt.Println("err", err)
			return 0, 0
		}
		_, _ = io.Copy(io.Discard, r.Body)
		r.Body.Close()
		return r.StatusCode, time.Since(t0).Seconds() * 1000
	}
	// the victim: a client close to its limit
	var vs []int
	for i := 0; i < 20; i++ {
		c, _ := do(9, 9, 9)
		vs = append(vs, c)
		if c == 429 {
			break
		}
	}
	fmt.Println("victim until limited:", vs)
	var lat []float64
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 16)
	st := map[int]int{}
	t0 := time.Now()
	for i := 0; i < *keys; i++ {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			c, l := do(byte(10+i>>16), byte(i>>8), byte(i))
			mu.Lock()
			lat = append(lat, l)
			st[c]++
			mu.Unlock()
		}(i)
	}
	wg.Wait()
	sort.Float64s(lat)
	fmt.Println("flood", *keys, st, "seconds", time.Since(t0).Seconds(), "p50 ms", lat[len(lat)/2], "p99", lat[len(lat)*99/100], "max", lat[len(lat)-1])
	c, _ := do(9, 9, 9)
	fmt.Println("victim after flood:", c)
	// the first keys of the flood had one failure each: are they gone?
	c2, _ := do(10, 0, 1)
	fmt.Println("early key after flood:", c2)
}

func main() {
	switch os.Args[1] {
	case "slots":
		cmdSlots(os.Args[2:])
	case "blocks":
		cmdBlocks(os.Args[2:])
	case "setup":
		cmdSetup(os.Args[2:])
	}
}
