// Command flip is the TEST ONLY hot-reload check of the MVP-29 measurement. While an open-loop load of browser and
// GPTBot requests runs against one website, it switches the crawler policy of that website between the preset
// block_ai_training and an empty policy through the dashboard API, and right after each answer sends one GPTBot probe.
// It reports: browser requests answered with the crawler block (must be 0), errors and 5xx under the switching, and
// probes whose outcome is not the policy just set ("in force for the next request").
//
//	flip -dir /tmp/m29/i/d -host shop.test -rps 500 -flips 200
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	gptbot  = "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.2; +https://openai.com/gptbot)"
	firefox = "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0"
	chrome  = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
	body403 = "This website does not allow this crawler.\n"
)

func read(p string) string { b, _ := os.ReadFile(p); return strings.TrimSpace(string(b)) }

func session(dir string) string {
	f, err := os.Open(dir + "/cj")
	if err != nil {
		panic(err)
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	v := ""
	for s.Scan() {
		x := strings.Split(s.Text(), "\t")
		if len(x) == 7 && x[5] == "schild_session" {
			v = x[6]
		}
	}
	return v
}

func main() {
	dir := flag.String("dir", "/tmp/m29/i/d", "")
	host := flag.String("host", "shop.test", "")
	rps := flag.Int("rps", 500, "")
	flips := flag.Int("flips", 200, "")
	flag.Parse()
	port := read(*dir + "/port")
	ingress := "http://127.0.0.1:" + port + "90/"
	dash := "http://127.0.0.1:" + port + "88/api/v0/websites/" + *host + "/crawlers"
	csrf, sess := read(*dir+"/csrf"), session(*dir)
	hc := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{MaxIdleConnsPerHost: 256}}
	send := func(ua, ip string) (int, bool, error) {
		rq, _ := http.NewRequest("GET", ingress+"blog/x", nil)
		rq.Host = *host
		rq.Header.Set("User-Agent", ua)
		rq.Header.Set("X-Forwarded-For", ip)
		r, err := hc.Do(rq)
		if err != nil {
			return 0, false, err
		}
		b, _ := io.ReadAll(r.Body)
		r.Body.Close()
		return r.StatusCode, r.StatusCode == 403 && string(b) == body403, nil
	}
	put := func(body string) (int, time.Duration) {
		rq, _ := http.NewRequest("PUT", dash, bytes.NewBufferString(body))
		rq.Header.Set("Content-Type", "application/json")
		rq.Header.Set("X-CSRF-Token", csrf)
		rq.AddCookie(&http.Cookie{Name: "schild_session", Value: sess})
		t0 := time.Now()
		r, err := hc.Do(rq)
		if err != nil {
			return 0, 0
		}
		io.Copy(io.Discard, r.Body)
		r.Body.Close()
		return r.StatusCode, time.Since(t0)
	}
	var stop atomic.Bool
	var n, browserBlocked, gptBlocked, gptPassed, errs, s5xx, other atomic.Int64
	var wg sync.WaitGroup
	sem := make(chan struct{}, 256)
	go func() {
		t := time.NewTicker(time.Second / time.Duration(*rps))
		defer t.Stop()
		i := 0
		for !stop.Load() {
			<-t.C
			i++
			sem <- struct{}{}
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				defer func() { <-sem }()
				ua := []string{firefox, chrome, gptbot}[i%3]
				st, blk, err := send(ua, fmt.Sprintf("198.51.100.%d", 1+i%250))
				n.Add(1)
				switch {
				case err != nil:
					errs.Add(1)
				case st >= 500:
					s5xx.Add(1)
				case ua != gptbot && blk:
					browserBlocked.Add(1)
				case ua == gptbot && blk:
					gptBlocked.Add(1)
				case ua == gptbot && st == 200:
					gptPassed.Add(1)
				case st != 200:
					other.Add(1)
				}
			}(i)
		}
	}()
	time.Sleep(time.Second)
	probeWrong, putFail := 0, 0
	var putMax, putSum time.Duration
	for f := 0; f < *flips; f++ {
		on := f%2 == 0
		body := `{}`
		if on {
			body = `{"preset":"block_ai_training"}`
		}
		code, d := put(body)
		if code != 200 {
			putFail++
			continue
		}
		putSum += d
		if d > putMax {
			putMax = d
		}
		_, blk, err := send(gptbot, "203.0.113.9")
		if err != nil || blk != on {
			probeWrong++
		}
		time.Sleep(20 * time.Millisecond)
	}
	time.Sleep(500 * time.Millisecond)
	stop.Store(true)
	wg.Wait()
	out := map[string]any{"load_requests": n.Load(), "browser_crawler_blocked": browserBlocked.Load(), "gptbot_blocked": gptBlocked.Load(),
		"gptbot_passed": gptPassed.Load(), "errors": errs.Load(), "status_5xx": s5xx.Load(), "other_status": other.Load(),
		"flips": *flips, "put_failed": putFail, "probe_wrong": probeWrong,
		"put_ms_mean": float64(putSum.Microseconds()) / float64(max(1, *flips-putFail)) / 1000, "put_ms_max": float64(putMax.Microseconds()) / 1000}
	b, _ := json.MarshalIndent(out, "", "  ")
	fmt.Println(string(b))
}
