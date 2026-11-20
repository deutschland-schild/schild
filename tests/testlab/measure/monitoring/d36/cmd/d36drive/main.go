// Command d36drive replays labelled per-website traffic against a schild
// ingress instance for the D36 measurement and writes the ground truth per
// minute and website (TEST ONLY, own loopback instances).
//
// The plan is a JSON file: one entry per wall-clock minute (aligned to the
// minute, requests sent between second 3 and 50), each with streams of
// requests for one Host. The class of every request is read from the answer
// (X-Backend of the app stub, X-Schild-Incident, status), as in spec21 replay.
//
//	d36drive -plan plan.json -target http://127.0.0.1:19190 -out truth.json
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand/v2"
	"net/http"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Stream is one kind of request to one host within a minute.
type Stream struct {
	Host string `json:"host"`
	// Kind: normal, err500, attack, ratelimit, slow, busy, scan.
	Kind string `json:"kind"`
	N    int    `json:"n"`
	// Clients: number of distinct client addresses (default N/5, at least 1).
	Clients int `json:"clients,omitempty"`
	// Net: second octet base of the client addresses 10.<net+i%nets>.x.y.
	Net  int `json:"net"`
	Nets int `json:"nets,omitempty"`
	// Client: one fixed address (scanner).
	Client string `json:"client,omitempty"`
	// DelayMS of the app stub (slow kind).
	DelayMS int `json:"delay_ms,omitempty"`
	// Burst: send the requests of this stream in groups of Burst at the
	// same instant (busy kind, to fill the WAF evaluation slots).
	Burst int `json:"burst,omitempty"`
}

// Minute of the plan.
type Minute struct {
	Streams []Stream `json:"streams"`
}

// Plan of a run.
type Plan struct {
	Seed    uint64   `json:"seed"`
	Minutes []Minute `json:"minutes"`
}

// Counts per website and minute.
type Counts struct {
	Requests         int64            `json:"requests"`
	Forwarded        int64            `json:"forwarded"`
	Stopped          int64            `json:"stopped"`
	BlockedWAF       int64            `json:"blocked_waf"`
	RateLimited      int64            `json:"rate_limited"`
	RejectedLimit    int64            `json:"rejected_limit"`
	FailClosed       int64            `json:"fail_closed"`
	UpstreamErrors   int64            `json:"upstream_errors"`
	UpstreamTimeouts int64            `json:"upstream_timeouts"`
	Detections       int64            `json:"detections"`
	BytesIn          int64            `json:"bytes_in"`
	BytesOut         int64            `json:"bytes_out"`
	Status           map[string]int64 `json:"status"`
	Kinds            map[string]int64 `json:"kinds"`
	Unknown          map[string]int64 `json:"unknown,omitempty"`
	Clients          int              `json:"clients"`
	LatP50MS         float64          `json:"lat_p50_ms"`
	LatP95MS         float64          `json:"lat_p95_ms"`
	clientSet        map[string]bool
	lats             []float64
}

// MinuteTruth is the truth of one minute.
type MinuteTruth struct {
	Start string             `json:"start"`
	Sites map[string]*Counts `json:"sites"`
}

// Truth of the run.
type Truth struct {
	Started string         `json:"started"`
	Minutes []*MinuteTruth `json:"minutes"`
	// Clients per host over the run (distinct addresses).
	ClientsRun map[string]int `json:"clients_run"`
	// ScanClients: the scanner addresses and the hosts they attacked.
	Scans map[string][]string `json:"scans,omitempty"`
}

type job struct {
	at     time.Time
	minute int
	burst  int
	host   string
	kind   string
	method string
	target string
	body   []byte
	hdr    http.Header
	client netip.Addr
}

var attacks = []struct{ method, target, body string }{
	{"GET", "/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E", ""},
	{"GET", "/products/123?id=1%27%20OR%20%271%27%3D%271%27--", ""},
	{"GET", "/index.php?page=../../../../etc/passwd", ""},
	{"POST", "/login", "user=admin&pass=%27%20OR%201%3D1--"},
}

func repeatQuery(n int) string {
	var b strings.Builder
	b.WriteString("/search?q=")
	for b.Len() < n {
		b.WriteString("lorem-ipsum-dolor-sit-amet-")
	}
	return b.String()
}

func main() {
	planPath := flag.String("plan", "plan.json", "")
	target := flag.String("target", "http://127.0.0.1:19190", "")
	out := flag.String("out", "truth.json", "")
	workers := flag.Int("workers", 96, "")
	noAlign := flag.Bool("no-align", false, "start at once (smoke tests)")
	flag.Parse()
	raw, err := os.ReadFile(*planPath)
	if err != nil {
		log.Fatal(err)
	}
	var plan Plan
	if err := json.Unmarshal(raw, &plan); err != nil {
		log.Fatal(err)
	}
	r := rand.New(rand.NewPCG(plan.Seed, 36))
	now := time.Now()
	start := now.Truncate(time.Minute).Add(time.Minute)
	if *noAlign {
		start = now.Add(-3 * time.Second)
	}
	truth := &Truth{Started: start.UTC().Format(time.RFC3339), ClientsRun: map[string]int{}, Scans: map[string][]string{}}
	runClients := map[string]map[string]bool{}
	var jobs []job
	for mi, m := range plan.Minutes {
		ms := start.Add(time.Duration(mi) * time.Minute)
		truth.Minutes = append(truth.Minutes, &MinuteTruth{Start: ms.UTC().Format(time.RFC3339), Sites: map[string]*Counts{}})
		var mj []job
		for _, s := range m.Streams {
			nc := s.Clients
			if nc == 0 {
				nc = max(s.N/5, 1)
			}
			nets := max(s.Nets, 1)
			for i := 0; i < s.N; i++ {
				ci := r.IntN(nc)
				a := netip.AddrFrom4([4]byte{10, byte(s.Net + ci%nets), byte(ci >> 8), byte(ci)})
				if s.Client != "" {
					a = netip.MustParseAddr(s.Client)
					truth.Scans[s.Client] = appendU(truth.Scans[s.Client], s.Host)
				}
				j := job{minute: mi, host: s.Host, kind: s.Kind, method: "GET", hdr: http.Header{}, client: a, burst: s.Burst}
				j.hdr.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0")
				j.hdr.Set("Accept", "text/html,application/xhtml+xml")
				j.hdr.Set("X-Size", strconv.Itoa(1000+r.IntN(20000)))
				j.target = fmt.Sprintf("/page/%d", r.IntN(50))
				switch s.Kind {
				case "normal":
					j.hdr.Set("X-Delay-Ms", strconv.Itoa(r.IntN(5)))
				case "err500":
					j.hdr.Set("X-Status", "500")
				case "attack", "scan":
					at := attacks[r.IntN(len(attacks))]
					j.method, j.target = at.method, at.target
					if at.body != "" {
						j.body = []byte(at.body)
						j.hdr.Set("Content-Type", "application/x-www-form-urlencoded")
					}
				case "ratelimit":
					j.target = "/api/limited"
				case "slow":
					j.hdr.Set("X-Delay-Ms", strconv.Itoa(s.DelayMS))
				case "busy":
					j.target = repeatQuery(5 * 1024)
				}
				mj = append(mj, j)
			}
		}
		r.Shuffle(len(mj), func(a, b int) { mj[a], mj[b] = mj[b], mj[a] })
		var paced, bursts []job
		for _, j := range mj {
			if j.burst > 0 {
				bursts = append(bursts, j)
			} else {
				paced = append(paced, j)
			}
		}
		for i := range paced {
			off := 3*time.Second + time.Duration(float64(47*time.Second)*float64(i)/float64(max(len(paced), 1)))
			paced[i].at = ms.Add(off)
		}
		if len(bursts) > 0 {
			groups := (len(bursts) + bursts[0].burst - 1) / bursts[0].burst
			for i := range bursts {
				g := i / bursts[0].burst
				bursts[i].at = ms.Add(3*time.Second + time.Duration(float64(47*time.Second)*float64(g)/float64(groups)))
			}
		}
		mj = append(paced, bursts...)
		sort.SliceStable(mj, func(a, b int) bool { return mj[a].at.Before(mj[b].at) })
		jobs = append(jobs, mj...)
	}
	hc := &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{MaxIdleConnsPerHost: *workers, MaxConnsPerHost: 0, DisableCompression: true},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	var mu sync.Mutex
	ch := make(chan job, 4096)
	var wg sync.WaitGroup
	for w := 0; w < *workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range ch {
				res := do(hc, *target, j)
				mu.Lock()
				mt := truth.Minutes[j.minute]
				c := mt.Sites[j.host]
				if c == nil {
					c = &Counts{Status: map[string]int64{}, Kinds: map[string]int64{}, Unknown: map[string]int64{}, clientSet: map[string]bool{}}
					mt.Sites[j.host] = c
				}
				add(c, j, res)
				if runClients[j.host] == nil {
					runClients[j.host] = map[string]bool{}
				}
				runClients[j.host][j.client.String()] = true
				mu.Unlock()
			}
		}()
	}
	log.Printf("start %s, %d minutes, %d requests", start.UTC().Format(time.RFC3339), len(plan.Minutes), len(jobs))
	for _, j := range jobs {
		if d := time.Until(j.at); d > 0 {
			time.Sleep(d)
		}
		ch <- j
	}
	close(ch)
	wg.Wait()
	for _, mt := range truth.Minutes {
		for _, c := range mt.Sites {
			c.Clients = len(c.clientSet)
			sort.Float64s(c.lats)
			c.LatP50MS, c.LatP95MS = q(c.lats, 0.5), q(c.lats, 0.95)
			if len(c.Unknown) == 0 {
				c.Unknown = nil
			}
		}
	}
	for h, m := range runClients {
		truth.ClientsRun[h] = len(m)
	}
	b, _ := json.MarshalIndent(truth, "", " ")
	if err := os.WriteFile(*out, b, 0o644); err != nil {
		log.Fatal(err)
	}
	log.Printf("done, truth in %s", *out)
}

func appendU(l []string, s string) []string {
	for _, x := range l {
		if x == s {
			return l
		}
	}
	return append(l, s)
}

func q(s []float64, p float64) float64 {
	if len(s) == 0 {
		return 0
	}
	i := int(p*float64(len(s))+0.999999) - 1
	return s[max(0, min(i, len(s)-1))]
}

type result struct {
	class    string
	status   int
	bytesOut int64
	latMS    float64
}

func do(hc *http.Client, target string, j job) result {
	var body io.Reader
	if j.body != nil {
		body = bytes.NewReader(j.body)
	}
	req, _ := http.NewRequest(j.method, target+j.target, body)
	req.Host = j.host
	req.Header = j.hdr.Clone()
	req.Header.Set("X-Forwarded-For", j.client.String())
	t0 := time.Now()
	resp, err := hc.Do(req)
	if err != nil {
		return result{class: "transport_error"}
	}
	n, _ := io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	res := result{status: resp.StatusCode, bytesOut: n, latMS: float64(time.Since(t0).Microseconds()) / 1000}
	inc := resp.Header.Get("X-Schild-Incident") != ""
	backend := resp.Header.Get("X-Backend") == "1"
	switch {
	case backend:
		res.class = "forwarded"
	case !inc && (res.status == 502 || res.status == 503):
		res.class = "upstream_error"
	case !inc && res.status == 504:
		res.class = "upstream_timeout"
	case res.status == 429:
		res.class = "rate_limited"
	case inc && res.status == 403:
		res.class = "blocked_waf"
	case inc && (res.status == 400 || res.status == 413 || res.status == 415):
		res.class = "rejected_limit"
	case inc && res.status == 503:
		res.class = "fail_closed"
	default:
		res.class = "unknown:" + j.kind + ":" + strconv.Itoa(res.status)
	}
	return res
}

func add(c *Counts, j job, r result) {
	c.Kinds[j.kind]++
	if strings.HasPrefix(r.class, "unknown") || r.class == "transport_error" {
		c.Unknown[r.class]++
		return
	}
	c.Requests++
	c.clientSet[j.client.String()] = true
	c.lats = append(c.lats, r.latMS)
	c.BytesIn += int64(len(j.body))
	c.BytesOut += r.bytesOut
	c.Status[strconv.Itoa(r.status/100)+"xx"]++
	switch r.class {
	case "forwarded":
		c.Forwarded++
	case "upstream_error":
		c.Forwarded++
		c.UpstreamErrors++
	case "upstream_timeout":
		c.Forwarded++
		c.UpstreamTimeouts++
	case "blocked_waf":
		c.Stopped++
		c.BlockedWAF++
		c.Detections++
	case "rate_limited":
		c.Stopped++
		c.RateLimited++
	case "rejected_limit":
		c.Stopped++
		c.RejectedLimit++
	case "fail_closed":
		c.FailClosed++
	}
}
