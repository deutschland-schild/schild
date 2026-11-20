// Command load is the TEST ONLY open-loop load tool of the MVP-26 measurement. It sends one deterministic request
// stream (fixed seed) at a fixed rate and writes latency per class plus a per-second timeline, so that a stall during
// a rule swap shows up. Mixes: body (Laravel and Livewire shaped bodies), light (ordinary pages and small posts).
// Addresses are documentation ranges, hosts are test names.
//
//	load -target http://127.0.0.1:29190 -host shop.test -mix body -rps 200 -duration 60s -seed 26 -out run.json
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand/v2"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type req struct {
	class, method, path, ctype string
	body                       []byte
	ip                         string
	ua                         string
}

var uas = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0",
}

func words(r *rand.Rand, n int) string {
	var b strings.Builder
	for b.Len() < n {
		l := 3 + r.IntN(8)
		for i := 0; i < l; i++ {
			b.WriteByte(byte('a' + r.IntN(26)))
		}
		b.WriteByte(' ')
	}
	return b.String()[:n]
}

// livewire is a /livewire/update body as Livewire 3 sends it, with made-up components and values.
func livewire(r *rand.Rand, size int) []byte {
	snap := map[string]any{
		"data":     map[string]any{"title": words(r, 40), "body": words(r, size/2), "email": "person@shop.example", "page": r.IntN(20), "items": []int{1, 2, 3}},
		"memo":     map[string]any{"id": "abcDEF123xyz", "name": "contact-form", "path": "contact", "method": "GET", "children": []any{}, "errors": []any{}, "locale": "de"},
		"checksum": strings.Repeat("a1b2c3d4", 8),
	}
	sb, _ := json.Marshal(snap)
	o := map[string]any{"_token": "TESTONLY0123456789abcdefTESTONLY01234567", "components": []any{map[string]any{
		"snapshot": string(sb), "updates": map[string]any{"title": words(r, 30)}, "calls": []any{map[string]any{"path": "", "method": "save", "params": []any{}}}}}}
	b, _ := json.Marshal(o)
	return b
}

func form(r *rand.Rand, n int) []byte {
	v := url.Values{}
	v.Set("_token", "TESTONLY0123456789abcdefTESTONLY01234567")
	for i := 0; i < n; i++ {
		v.Set("field"+strconv.Itoa(i), words(r, 20+r.IntN(40)))
	}
	return []byte(v.Encode())
}

func manyKeys(r *rand.Rand, n int) []byte {
	o := map[string]any{}
	for i := 0; i < n; i++ {
		o["k"+strconv.Itoa(i)] = map[string]any{"id": i, "name": words(r, 40), "on": i%2 == 0}
	}
	b, _ := json.Marshal(o)
	return b
}

func upload(r *rand.Rand, size int) ([]byte, string) {
	var b bytes.Buffer
	w := multipart.NewWriter(&b)
	_ = w.WriteField("_token", "TESTONLY0123456789abcdefTESTONLY01234567")
	f, _ := w.CreateFormFile("files[]", "photo-"+strconv.Itoa(r.IntN(1000))+".jpg")
	data := make([]byte, size)
	for i := range data {
		data[i] = byte(r.Uint32())
	}
	_, _ = f.Write(data)
	_ = w.Close()
	return b.Bytes(), w.FormDataContentType()
}

func next(r *rand.Rand, mix string) req {
	q := req{ip: "198.51.100." + strconv.Itoa(1+r.IntN(250)), ua: uas[r.IntN(len(uas))]}
	if r.IntN(2) == 0 {
		q.ip = "203.0.113." + strconv.Itoa(1+r.IntN(250))
	}
	x := r.IntN(100)
	switch mix {
	case "body":
		switch {
		case x < 45:
			q.class, q.method, q.path, q.ctype, q.body = "livewire_2k", "POST", "/livewire/update", "application/json", livewire(r, 2<<10)
		case x < 65:
			q.class, q.method, q.path, q.ctype, q.body = "form_100args", "POST", "/contact", "application/x-www-form-urlencoded", form(r, 100)
		case x < 80:
			var ct string
			q.class, q.method, q.path = "upload_256k", "POST", "/livewire/upload-file"
			q.body, ct = upload(r, 256<<10)
			q.ctype = ct
		case x < 90:
			q.class, q.method, q.path, q.ctype, q.body = "json_500keys", "POST", "/api/items/bulk", "application/json", manyKeys(r, 500)
		case x < 95:
			q.class, q.method, q.path, q.ctype, q.body = "livewire_64k", "POST", "/livewire/update", "application/json", livewire(r, 64<<10)
		default:
			q.class, q.method, q.path = "get", "GET", "/products/"+strconv.Itoa(r.IntN(500))
		}
	default:
		switch {
		case x < 80:
			q.class, q.method, q.path = "get", "GET", []string{"/", "/about", "/products/blue-shirt", "/blog/my-first-post/", "/search?q=schuhe"}[r.IntN(5)]
		default:
			q.class, q.method, q.path, q.ctype, q.body = "post", "POST", "/contact", "application/x-www-form-urlencoded", form(r, 8)
		}
	}
	return q
}

type sample struct {
	class  string
	status int
	lat    float64
	at     float64
	err    string
}

func pct(a []float64, p float64) float64 {
	if len(a) == 0 {
		return 0
	}
	i := int(p * float64(len(a)-1))
	return a[i]
}

func main() {
	target := flag.String("target", "http://127.0.0.1:29190", "")
	host := flag.String("host", "shop.test", "")
	mix := flag.String("mix", "body", "body | light")
	rps := flag.Int("rps", 200, "")
	dur := flag.Duration("duration", 60*time.Second, "")
	seed := flag.Uint64("seed", 26, "")
	workers := flag.Int("workers", 64, "")
	out := flag.String("out", "run.json", "")
	pregen := flag.Int("pregen", 2000, "requests prepared in advance and cycled, so the client stays out of the measurement")
	flag.Parse()
	r := rand.New(rand.NewPCG(*seed, 0x26))
	pool := make([]req, *pregen)
	for i := range pool {
		pool[i] = next(r, *mix)
	}
	tr := &http.Transport{DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext, MaxIdleConns: 4 * *workers, MaxIdleConnsPerHost: 4 * *workers, DisableCompression: true}
	hc := &http.Client{Transport: tr, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	jobs := make(chan req, 8192)
	res := make(chan sample, 1<<16)
	var wg sync.WaitGroup
	t0 := time.Now()
	for w := 0; w < *workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for q := range jobs {
				start := time.Now()
				var body io.Reader
				if q.body != nil {
					body = bytes.NewReader(q.body)
				}
				rq, _ := http.NewRequest(q.method, *target+q.path, body)
				rq.Host = *host
				rq.Header.Set("X-Forwarded-For", q.ip)
				rq.Header.Set("User-Agent", q.ua)
				rq.Header.Set("Accept", "text/html,application/json")
				if q.ctype != "" {
					rq.Header.Set("Content-Type", q.ctype)
				}
				s := sample{class: q.class, at: start.Sub(t0).Seconds()}
				resp, err := hc.Do(rq)
				if err != nil {
					s.err = err.Error()
				} else {
					_, _ = io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
					s.status = resp.StatusCode
				}
				s.lat = time.Since(start).Seconds() * 1000
				res <- s
			}
		}()
	}
	var all []sample
	done := make(chan struct{})
	go func() {
		for s := range res {
			all = append(all, s)
		}
		close(done)
	}()
	interval := time.Second / time.Duration(*rps)
	nxt := time.Now()
	end := nxt.Add(*dur)
	i := 0
	dropped := 0
	for time.Now().Before(end) {
		select {
		case jobs <- pool[i%len(pool)]:
		default:
			dropped++
		}
		i++
		nxt = nxt.Add(interval)
		if d := time.Until(nxt); d > 0 {
			time.Sleep(d)
		}
	}
	close(jobs)
	wg.Wait()
	close(res)
	<-done

	type row struct {
		N                  int
		P50, P95, P99, Max float64
		Status             map[string]int
	}
	by := map[string][]float64{}
	st := map[string]map[string]int{}
	errs := map[string]int{}
	type sec struct {
		N, Err, Non2xx int
		Max            float64
	}
	tl := map[int]*sec{}
	for _, s := range all {
		k := s.class
		for _, c := range []string{k, "_all"} {
			by[c] = append(by[c], s.lat)
			if st[c] == nil {
				st[c] = map[string]int{}
			}
			st[c][strconv.Itoa(s.status)]++
		}
		t := tl[int(s.at)]
		if t == nil {
			t = &sec{}
			tl[int(s.at)] = t
		}
		t.N++
		if s.lat > t.Max {
			t.Max = s.lat
		}
		if s.err != "" {
			t.Err++
			e := s.err
			if len(e) > 80 {
				e = e[len(e)-80:]
			}
			errs[e]++
		} else if s.status >= 300 {
			t.Non2xx++
		}
	}
	rows := map[string]row{}
	for k, v := range by {
		sort.Float64s(v)
		rows[k] = row{N: len(v), P50: pct(v, .5), P95: pct(v, .95), P99: pct(v, .99), Max: v[len(v)-1], Status: st[k]}
	}
	var keys []int
	for k := range tl {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	timeline := make([]map[string]any, 0, len(keys))
	for _, k := range keys {
		t := tl[k]
		timeline = append(timeline, map[string]any{"s": k, "n": t.N, "err": t.Err, "non2xx": t.Non2xx, "max_ms": t.Max})
	}
	b, _ := json.MarshalIndent(map[string]any{"mix": *mix, "rps": *rps, "seed": *seed, "duration_s": dur.Seconds(), "dropped": dropped, "errors": errs, "classes": rows, "timeline": timeline}, "", " ")
	if err := os.WriteFile(*out, b, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	a := rows["_all"]
	fmt.Printf("%s %d rps: n=%d p50=%.2f p95=%.2f p99=%.2f max=%.1f dropped=%d errors=%d\n", *mix, *rps, a.N, a.P50, a.P95, a.P99, a.Max, dropped, len(errs))
}
