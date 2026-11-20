package main

// Replay with known ground truth (MVP-21 measurement). Every request is
// built from labelled parts (client address, user agent, referrer, path with
// its expected template, method, kind); the answer tells the class
// (X-Backend from the app, X-Schild-Incident from schild, status). The
// ground truth is counted per wall-clock minute; requests are only sent
// between second 3 and 56 of a minute, so each one falls into a known 1 min
// bucket of schild.

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"math/rand/v2"
	"net"
	"net/http"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type uaLabel struct {
	UA                                   string
	Class, Browser, OS, Device, Category string
	W                                    int
	Safe                                 bool // usable for the no_block clients (no CRS hit)
}

var uaCorpus = []uaLabel{
	{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36", "browser", "chrome", "windows", "desktop", "likely_browser", 30, true},
	{"Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1", "browser", "safari", "ios", "mobile", "likely_browser", 15, true},
	{"Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0", "browser", "firefox", "linux", "desktop", "likely_browser", 6, true},
	{"Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/26.0 Chrome/122.0.0.0 Mobile Safari/537.36", "browser", "samsung", "android", "mobile", "likely_browser", 4, true},
	{"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0", "browser", "edge", "macos", "desktop", "likely_browser", 5, true},
	{"Mozilla/5.0 (iPad; CPU OS 17_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.7 Mobile/15E148 Safari/604.1", "browser", "safari", "ios", "tablet", "likely_browser", 2, true},
	{"Mozilla/5.0 (Linux; Android 13; SM-X710) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36", "browser", "chrome", "android", "tablet", "likely_browser", 2, true},
	{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 OPR/116.0.0.0", "browser", "opera", "windows", "desktop", "likely_browser", 1, true},
	{"Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36", "browser", "chrome", "chromeos", "desktop", "likely_browser", 1, true},
	{"Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko", "browser", "ie", "windows", "desktop", "likely_browser", 1, true},
	{"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15", "browser", "safari", "macos", "desktop", "likely_browser", 4, true},
	{"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", "bot_unverified", "none", "none", "unknown", "search_engine", 4, false},
	{"Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm) Chrome/116.0.1938.76 Safari/537.36", "bot_unverified", "none", "none", "unknown", "search_engine", 2, false},
	{"Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.2; +https://openai.com/gptbot)", "bot_unverified", "none", "none", "unknown", "ai_training", 3, false},
	{"Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; ClaudeBot/1.0; +claudebot@anthropic.com)", "bot_unverified", "none", "none", "unknown", "ai_training", 2, false},
	{"Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; ChatGPT-User/1.0; +https://openai.com/bot", "bot_unverified", "none", "none", "unknown", "ai_assistant", 1, false},
	{"Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; PerplexityBot/1.0; +https://perplexity.ai/perplexitybot)", "bot_unverified", "none", "none", "unknown", "ai_search", 1, false},
	{"facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)", "bot_unverified", "none", "none", "unknown", "preview_social", 1, false},
	{"Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)", "bot_unverified", "none", "none", "unknown", "seo_tool", 2, false},
	{"Mozilla/5.0 (compatible; MJ12bot/v1.4.8; http://mj12bot.com/)", "bot_unverified", "none", "none", "unknown", "seo_tool", 1, false},
	{"Mozilla/5.0+(compatible; UptimeRobot/2.0; http://www.uptimerobot.com/)", "bot_unverified", "none", "none", "unknown", "monitoring", 1, false},
	{"Feedly/1.0 (+http://www.feedly.com/fetcher.html; 5 subscribers)", "bot_unverified", "none", "none", "unknown", "feed_reader", 1, false},
	{"ia_archiver (+http://www.alexa.com/site/help/webmasters; crawler@alexa.com)", "bot_unverified", "none", "none", "unknown", "archive_research", 1, false},
	{"curl/8.7.1", "tool", "none", "none", "unknown", "tool_library", 3, false},
	{"python-requests/2.32.3", "tool", "none", "none", "unknown", "tool_library", 2, false},
	{"Go-http-client/1.1", "tool", "none", "none", "unknown", "tool_library", 1, false},
	{"", "none", "none", "none", "unknown", "likely_automated", 2, false},
	{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/131.0.0.0 Safari/537.36", "other", "none", "none", "unknown", "likely_automated", 1, false},
	{"SomeRandomAgent/1.0", "other", "none", "none", "unknown", "likely_automated", 1, false},
	{"Nuclei - Open-source project (github.com/projectdiscovery/nuclei)", "tool", "none", "none", "unknown", "security_scanner", 1, false},
}

type refLabel struct {
	Ref, Key string
	W        int
}

var refCorpus = []refLabel{
	{"", "_direct", 40},
	{"https://www.google.com/search?q=schild", "google.com", 15},
	{"https://www.google.co.uk/", "google.co.uk", 2},
	{"https://chatgpt.com/", "ai:chatgpt", 3},
	{"https://chat.openai.com/c/abc", "ai:chatgpt", 1},
	{"https://www.perplexity.ai/search?q=x", "ai:perplexity", 1},
	{"https://claude.ai/chat/1", "ai:claude", 1},
	{"SAME", "_intern", 20},
	{"https://news.ycombinator.com/item?id=1", "ycombinator.com", 2},
	{"https://m.facebook.com/", "facebook.com", 3},
	{"https://www.bbc.co.uk/news", "bbc.co.uk", 1},
	{"https://WWW.Example.ORG/Path", "example.org", 1},
	{"http://203.0.113.250/page", "_other", 1},
	{"https://[2001:db8::99]/x", "_other", 1},
	{"not a url", "_other", 1},
}

type pathLabel struct {
	Path, Tpl string
	W         int
}

var pathCorpus = []pathLabel{
	{"/", "/", 25},
	{"/about", "/about", 5},
	{"/kontakt", "/kontakt", 3},
	{"/products/blue-shirt", "/products/{slug}", 10},
	{"/products/123", "/products/{n}", 8},
	{"/blog/my-first-post/", "/blog/{slug}/", 6},
	{"/api/items/550e8400-e29b-41d4-a716-446655440000", "/api/items/{uuid}", 5},
	{"/static/app.js", "/static/app.js", 10},
	{"/search?q=schuhe", "/search", 5},
	{"/user/deadbeefcafe1234/settings", "/user/{hex}/settings", 2},
	{"/index.php", "/index.php", 2},
	{"/lookup/100.64.77.88", "/lookup/100.64.77.88", 1},
}

var statusCorpus = []struct{ S, W int }{{200, 70}, {201, 3}, {204, 3}, {301, 4}, {302, 3}, {304, 2}, {404, 8}, {410, 1}, {418, 1}, {500, 3}, {503, 2}}

// Truth is the ground truth of one wall-clock minute.
type Truth struct {
	Minute   int64                           `json:"minute"`
	Counters map[string]int64                `json:"counters"`
	Dims     map[string]map[string]*[3]int64 `json:"dims"`
	Unique   int                             `json:"unique"`
	New      int                             `json:"new"`
	// D36 amendment (re-measurement): visitors are browser requests schild
	// forwarded (contract/monitoring.Visitor); every other request is a bot client.
	Visitors    int                                    `json:"visitors"`
	VisitorsNew int                                    `json:"visitors_new"`
	BotClients  int                                    `json:"bot_clients"`
	vis         map[string]bool                        `json:"-"`
	visNew      map[string]bool                        `json:"-"`
	bots        map[string]bool                        `json:"-"`
	LatMS       map[string]float64                     `json:"latency_ms"`
	UpMS        map[string]float64                     `json:"upstream_delay_ms"`
	Unknown     map[string]int64                       `json:"unknown"`
	clients     map[string]bool                        `json:"-"`
	newSet      map[string]bool                        `json:"-"`
	lat         []float64                              `json:"-"`
	up          []float64                              `json:"-"`
	Extra       map[string]map[string]int64            `json:"extra,omitempty"`
	_           map[string]map[string]map[string]int64 `json:"-"`
}

type result struct {
	minute                          int64
	client                          string // client key
	class                           string
	status                          int
	wouldBlock, detection, pageView bool
	waitingPage                     bool // D37 waiting page (fail_closed without incident)
	upstream                        string
	bytesIn, bytesOut               int64
	rejectedBody                    int64
	dims                            map[string]string
	latMS                           float64
	delayMS                         int
	timed                           bool
}

type job struct {
	minute    int64
	host      string
	method    string
	target    string
	hdr       http.Header
	body      []byte
	client    netip.Addr
	kind      string // normal, attack, ratelimit, reject, down, slow, zipf, busy
	noBlock   bool
	ua        uaLabel
	ref       refLabel
	tpl       string
	pageDoc   bool
	delayMS   int
	expensive bool
}

func clientKey(a netip.Addr) string {
	if a.Is6() {
		p, _ := a.Prefix(64)
		return p.String()
	}
	return a.String()
}

type picker[T any] struct {
	items []T
	cum   []int
}

func newPicker[T any](items []T, w func(T) int) *picker[T] {
	p := &picker[T]{items: items}
	s := 0
	for _, it := range items {
		s += w(it)
		p.cum = append(p.cum, s)
	}
	return p
}

func (p *picker[T]) pick(r *rand.Rand) T {
	x := r.IntN(p.cum[len(p.cum)-1])
	i := sort.SearchInts(p.cum, x+1)
	return p.items[i]
}

// clientAddr maps a client number to an address: mostly the 256 synthetic
// networks (Zipf over the networks), the documentation ranges, IPv6 hosts
// (four per /64) and 172.20.0.0/16 (not in the geo table: ZZ).
func clientAddr(i int, z *rand.Zipf, r *rand.Rand) netip.Addr {
	switch i % 20 {
	case 0, 1:
		return netip.AddrFrom4([4]byte{198, 51, 100, byte(1 + (i/20)%250)})
	case 2, 3:
		return netip.AddrFrom4([4]byte{203, 0, 113, byte(1 + (i/20)%249)})
	case 4:
		b := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, byte(i >> 16), byte(i >> 8 & 0xff), 0}
		// four clients per /64: i/4 picks the /64, i%4 the host
		k := i / 4
		b[5], b[6], b[7] = byte(k>>16), byte(k>>8), byte(k)
		b[15] = byte(1 + i%4)
		return netip.AddrFrom16(b)
	case 5:
		return netip.AddrFrom4([4]byte{172, 20, byte(i >> 8), byte(i)})
	}
	n := i * 2654435761
	// skewed but stable network per client: u^3 puts most clients into the
	// first networks (top-K of ASNs has a clear ranking)
	u := float64(uint32(n)) / float64(1<<32)
	return netip.AddrFrom4([4]byte{10, byte(int(256 * u * u * u)), byte(n >> 8), byte(n >> 16)})
}

// noBlockAddr: 192.0.2.0/24 is allowlisted with level no_block in the config.
func noBlockAddr(i int) netip.Addr { return netip.AddrFrom4([4]byte{192, 0, 2, byte(1 + i%250)}) }

var attacks = []struct{ method, target, body, tpl string }{
	{"GET", "/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E", "", "/search"},
	{"GET", "/products/123?id=1%27%20OR%20%271%27%3D%271%27--", "", "/products/{n}"},
	{"GET", "/index.php?page=../../../../etc/passwd", "", "/index.php"},
	{"POST", "/login", "user=admin&pass=%27%20OR%201%3D1--", "/login"},
	{"GET", "/kontakt?a=%3Cscript%3Ealert(1)%3C/script%3E&b=1%27%20UNION%20SELECT%20password%20FROM%20users--&c=../../../../etc/passwd&d=%3Bcat%20/etc/passwd&e=%3C%3Fphp%20system(%24_GET%5B%27x%27%5D)%3B%20%3F%3E&f=%24%7Bjndi%3Aldap%3A//x/a%7D&g=%3Ciframe%20src%3Djavascript%3Aalert(1)%3E&h=1%20AND%20SLEEP(5)", "", "/kontakt"},
}

func repeatQuery(n int) string {
	var b strings.Builder
	b.WriteString("/search?q=")
	for b.Len() < n {
		b.WriteString("lorem-ipsum-dolor-sit-amet-")
	}
	return b.String()
}

func cmdReplay(args []string) error {
	fs := flag.NewFlagSet("replay", flag.ExitOnError)
	target := fs.String("target", "http://127.0.0.1:18090", "")
	host := fs.String("host", "shop.test", "")
	seed := fs.Uint64("seed", 21, "")
	rps := fs.Int("rps", 250, "")
	workers := fs.Int("workers", 24, "")
	phase := fs.String("phase", "mix", "mix | zipf")
	minutes := fs.Int("minutes", 5, "")
	out := fs.String("out", "truth.json", "")
	clientOff := fs.Int("clientoffset", 0, "added to every client number")
	_ = fs.Parse(args)
	r := rand.New(rand.NewPCG(*seed, 0x5c41d))
	geo := geoTable()
	uaP := newPicker(uaCorpus, func(u uaLabel) int { return u.W })
	var safeUA []uaLabel
	for _, u := range uaCorpus {
		if u.Safe {
			safeUA = append(safeUA, u)
		}
	}
	safeP := newPicker(safeUA, func(u uaLabel) int { return u.W })
	refP := newPicker(refCorpus, func(x refLabel) int { return x.W })
	pathP := newPicker(pathCorpus, func(x pathLabel) int { return x.W })
	stP := newPicker(statusCorpus, func(x struct{ S, W int }) int { return x.W })
	zipfASN := rand.NewZipf(r, 1.3, 2, 255)
	zipfPath := rand.NewZipf(r, 1.15, 1, 199999)
	words := make([]string, 200000)
	for i := range words {
		var b [10]byte
		for j := range b {
			b[j] = byte('a' + r.IntN(26))
		}
		words[i] = string(b[:])
	}

	tr := &http.Transport{DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext, MaxIdleConns: 4 * *workers, MaxIdleConnsPerHost: 4 * *workers,
		DisableCompression: true, TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	hc := &http.Client{Transport: tr, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	truths := map[int64]*Truth{}
	var mu sync.Mutex
	seenEver := map[string]bool{}
	jobs := make(chan job, 4096)
	var wg sync.WaitGroup
	for w := 0; w < *workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				res := do(hc, *target, j)
				mu.Lock()
				t := truths[res.minute]
				if t == nil {
					t = newTruth(res.minute)
					truths[res.minute] = t
				}
				t.add(res, seenEver)
				mu.Unlock()
			}
		}()
	}

	// schedule of active clients per minute (unique / new ground truth)
	type span struct{ lo, hi int }
	sched := [][]span{{{0, 2000}}, {{1000, 3000}}, {{0, 3500}}, {{3500, 4000}, {0, 100}}, {{0, 4000}}}
	for m := 0; m < *minutes; m++ {
		// wait for second 3 of the next minute
		now := time.Now()
		start := now.Truncate(time.Minute).Add(time.Minute)
		time.Sleep(time.Until(start.Add(3 * time.Second)))
		end := start.Add(56 * time.Second)
		minute := start.Unix()
		var active []int
		for _, s := range sched[m%len(sched)] {
			for i := s.lo; i < s.hi; i++ {
				active = append(active, i)
			}
		}
		r.Shuffle(len(active), func(i, j int) { active[i], active[j] = active[j], active[i] })
		interval := time.Second / time.Duration(*rps)
		next := time.Now()
		n := 0
		fmt.Fprintf(os.Stderr, "minute %d (%s): %d clients\n", m, start.UTC().Format(time.RFC3339), len(active))
		for time.Now().Before(end) {
			var ci int
			if n < len(active) {
				ci = active[n]
			} else {
				ci = active[r.IntN(len(active))]
			}
			n++
			ci += *clientOff
			var j job
			if *phase == "zipf" {
				j = zipfJob(r, zipfASN, zipfPath, words, ci)
			} else {
				j = mixJob(r, ci, zipfASN, uaP, safeP, refP, pathP, stP)
			}
			j.minute = minute
			if j.host == "" {
				j.host = *host
			}
			if j.ref.Ref == "SAME" {
				j.hdr.Set("Referer", "https://"+j.host+"/products")
			} else if j.ref.Ref != "" {
				j.hdr.Set("Referer", j.ref.Ref)
			}
			_ = geo
			jobs <- j
			next = next.Add(interval)
			if d := time.Until(next); d > 0 {
				time.Sleep(d)
			}
		}
	}
	close(jobs)
	wg.Wait()
	var list []*Truth
	for _, t := range truths {
		t.finish(geo)
		list = append(list, t)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Minute < list[j].Minute })
	b, _ := json.MarshalIndent(list, "", " ")
	return os.WriteFile(*out, b, 0o644)
}

func zipfJob(r *rand.Rand, za, zp *rand.Zipf, words []string, ci int) job {
	a := netip.AddrFrom4([4]byte{10, byte(za.Uint64()), byte(ci >> 8), byte(ci)})
	w := words[zp.Uint64()]
	j := job{method: "GET", target: "/w/" + w, hdr: http.Header{}, client: a, kind: "zipf", ua: uaCorpus[0], ref: refCorpus[0], tpl: "/w/" + w}
	j.hdr.Set("User-Agent", j.ua.UA)
	j.hdr.Set("Accept", "image/webp")
	return j
}

func mixJob(r *rand.Rand, ci int, za *rand.Zipf, uaP, safeP *picker[uaLabel], refP *picker[refLabel], pathP *picker[pathLabel], stP *picker[struct{ S, W int }]) job {
	j := job{hdr: http.Header{}, kind: "normal"}
	x := r.IntN(1000)
	nb := ci%25 == 7 // no_block clients
	if nb {
		j.client = noBlockAddr(ci)
		j.noBlock = true
		j.ua = safeP.pick(r)
	} else {
		j.client = clientAddr(ci, za, r)
		j.ua = uaP.pick(r)
	}
	j.ref = refP.pick(r)
	p := pathP.pick(r)
	j.method, j.target, j.tpl = "GET", p.Path, p.Tpl
	switch {
	case x < 60: // attack
		a := attacks[r.IntN(len(attacks))]
		j.kind, j.method, j.target, j.tpl = "attack", a.method, a.target, a.tpl
		if a.body != "" {
			j.body = []byte(a.body)
			j.hdr.Set("Content-Type", "application/x-www-form-urlencoded")
		}
	case x < 90 && !nb: // rate limited route (block, 2 per minute and client)
		j.kind, j.target, j.tpl = "ratelimit", "/api/limited", "/api/limited"
	case x < 110 && !nb: // hard limits
		j.kind = "reject"
		switch r.IntN(4) {
		case 0:
			j.target, j.tpl = repeatQuery(33*1024), "/search"
		case 1:
			for i := 0; i < 101; i++ {
				j.hdr.Add("X-Pad-"+strconv.Itoa(i), "v")
			}
		case 2:
			var c strings.Builder
			for i := 0; i < 151; i++ {
				if i > 0 {
					c.WriteString("; ")
				}
				fmt.Fprintf(&c, "c%d=v", i)
			}
			j.hdr.Set("Cookie", c.String())
		case 3:
			j.method = "POST"
			j.body = []byte("payload-gzip-not-really-0123456789")
			j.hdr.Set("Content-Type", "application/octet-stream")
			j.hdr.Set("Content-Encoding", "gzip")
		}
	case x < 130 && !nb:
		j.kind, j.host = "down", "down.test"
	case x < 140 && !nb:
		j.kind, j.host = "slow", "slow.test"
		j.delayMS = 1500
	case x < 180 && !nb: // expensive but benign (cost class), may meet waf_busy
		j.kind, j.target, j.tpl = "expensive", repeatQuery(5*1024), "/search"
	default:
		if !nb {
			switch y := r.IntN(100); {
			case y < 6:
				j.method = "POST"
			case y < 11:
				j.method = "HEAD"
			case y < 13:
				j.method = "PUT"
			case y < 15:
				j.method = "DELETE"
			case y < 17:
				j.method = "OPTIONS"
			case y < 18:
				j.method = "PATCH"
			case y < 19:
				j.method = "PROPFIND"
			}
		} else if y := r.IntN(100); y < 6 {
			j.method = "POST"
		} else if y < 11 {
			j.method = "HEAD"
		}
		if j.method == "POST" || j.method == "PUT" || j.method == "PATCH" {
			if nb {
				j.body = []byte("comment=" + strings.Repeat("hallo+welt+", r.IntN(700)))
				j.hdr.Set("Content-Type", "application/x-www-form-urlencoded")
			} else {
				j.body = bytes.Repeat([]byte("b"), r.IntN(8000))
				j.hdr.Set("Content-Type", "application/octet-stream")
			}
		}
		st := stP.pick(r).S
		j.hdr.Set("X-Status", strconv.Itoa(st))
		j.hdr.Set("X-Size", strconv.Itoa(r.IntN(40000)))
		switch y := r.IntN(100); {
		case y < 70:
			j.delayMS = r.IntN(5)
		case y < 95:
			j.delayMS = 10 + r.IntN(40)
		default:
			j.delayMS = 100 + r.IntN(200)
		}
	}
	if j.delayMS > 0 {
		j.hdr.Set("X-Delay-Ms", strconv.Itoa(j.delayMS))
	}
	if j.ua.UA != "" {
		j.hdr.Set("User-Agent", j.ua.UA)
	} else {
		j.hdr["User-Agent"] = []string{""}
	}
	switch y := r.IntN(10); {
	case y < 3:
		j.hdr.Set("Sec-Fetch-Dest", "document")
		j.hdr.Set("Accept", "text/html,application/xhtml+xml")
	case y < 4:
		j.hdr.Set("Sec-Fetch-Dest", "image")
		j.hdr.Set("Accept", "text/html,image/webp")
	case y < 7:
		j.hdr.Set("Accept", "text/html,application/xhtml+xml,*/*;q=0.8")
	default:
		j.hdr.Set("Accept", "*/*")
	}
	d := j.hdr.Get("Sec-Fetch-Dest")
	j.pageDoc = d == "document" || d == "" && strings.Contains(j.hdr.Get("Accept"), "text/html")
	return j
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
	if j.body != nil {
		req.ContentLength = int64(len(j.body))
	}
	t0 := time.Now()
	resp, err := hc.Do(req)
	res := result{minute: j.minute, client: clientKey(j.client), dims: map[string]string{}, delayMS: j.delayMS}
	if err != nil {
		res.class = "transport_error"
		return res
	}
	n, _ := io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	res.latMS = float64(time.Since(t0).Microseconds()) / 1000
	res.timed = true
	res.status = resp.StatusCode
	res.bytesOut = n
	res.bytesIn = int64(len(j.body))
	inc := resp.Header.Get("X-Schild-Incident") != ""
	backend := resp.Header.Get("X-Backend") == "1"
	switch {
	case backend:
		res.class = "forwarded"
		if j.kind == "attack" && j.noBlock {
			res.wouldBlock, res.detection = true, true
		}
	case !inc && isWaitingPage(resp):
		// D37: a browser navigation under overload (waf_busy, waf_timeout)
		// gets the waiting page, without an incident number; the outcome
		// stays fail_closed. Checked before the upstream errors: a down
		// backend's 502/503 never carries these headers.
		res.class, res.waitingPage = "fail_closed", true
	case j.kind == "down" && (res.status == 502 || res.status == 503) && !inc:
		res.class, res.upstream = "forwarded", "error"
	case j.kind == "slow" && res.status == 504 && !inc:
		res.class, res.upstream = "forwarded", "timeout"
	case res.status == 429:
		res.class = "rate_limited"
	case inc && res.status == 403:
		res.class, res.detection = "blocked_waf", true
	case inc && (res.status == 400 || res.status == 413 || res.status == 415):
		res.class = "rejected_limit"
		res.rejectedBody = int64(len(j.body)) // included in bytesIn (drained by the gate)
	case inc && res.status == 503:
		res.class = "fail_closed"
	default:
		res.class = "unknown:" + j.kind + ":" + strconv.Itoa(res.status)
	}
	if res.class == "forwarded" && j.method == "GET" && res.status/100 == 2 && j.ua.Category == "likely_browser" && j.pageDoc {
		res.pageView = true
	}
	method := j.method
	switch method {
	case "GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "CONNECT", "TRACE":
	default:
		method = "OTHER"
	}
	a := j.client
	g := lookup(geoTable(), a)
	country, nc, asn := "ZZ", "unknown", ""
	if g != nil {
		country, nc, asn = g.Country, g.NetClass, strconv.FormatUint(uint64(g.ASN), 10)
	}
	res.dims["country"] = country
	res.dims["net_class"] = nc
	if asn != "" {
		res.dims["asn"] = asn
	}
	res.dims["ua_class"] = j.ua.Class
	res.dims["browser"] = j.ua.Browser
	res.dims["os"] = j.ua.OS
	res.dims["device"] = j.ua.Device
	res.dims["bot_category"] = j.ua.Category
	res.dims["method"] = method
	res.dims["referrer"] = j.ref.Key
	res.dims["path"] = j.tpl
	res.dims["status_class"] = strconv.Itoa(res.status/100) + "xx"
	return res
}

// The waiting page marker (D37 amendment 2026-10-29, contract/waitingpage
// MarkerHeader, MarkerValue). Kept here so the replay tool needs no
// dependency on the contract module.
const (
	waitingMarkerHeader = "Schild-Waiting"
	waitingMarkerValue  = "1"
)

// isWaitingPage reports whether an answer without an incident number is
// schild's waiting page (D37, contracts/waiting-page.md section 4). The
// primary signal is the marker Schild-Waiting: 1 on a 503 that is not the
// problem-JSON variant (that one carries the marker too, but it is no page
// and is not counted as waiting_page_shown). The gateway strips the marker
// from backend answers, so it cannot come from the app.
//
// Fallback for gateways from before the marker: 503, HTML, Retry-After 5
// to 8, no-store and the waiting page's Vary; these headers together are
// what no upstream 503 of the replay backend sends.
func isWaitingPage(resp *http.Response) bool {
	if resp.StatusCode != http.StatusServiceUnavailable || resp.Header.Get("X-Backend") != "" {
		return false
	}
	if resp.Header.Get(waitingMarkerHeader) == waitingMarkerValue {
		return !strings.HasPrefix(resp.Header.Get("Content-Type"), "application/problem+json")
	}
	ra, err := strconv.Atoi(resp.Header.Get("Retry-After"))
	if err != nil || ra < 5 || ra > 8 {
		return false
	}
	return strings.HasPrefix(resp.Header.Get("Content-Type"), "text/html") &&
		resp.Header.Get("Cache-Control") == "no-store" &&
		strings.Contains(resp.Header.Get("Vary"), "Sec-Fetch-Dest")
}

var timedQuantiles = map[string]float64{"p50": 0.5, "p95": 0.95, "p99": 0.99}

func newTruth(m int64) *Truth {
	return &Truth{Minute: m, Counters: map[string]int64{}, Dims: map[string]map[string]*[3]int64{}, Unknown: map[string]int64{},
		clients: map[string]bool{}, newSet: map[string]bool{}, vis: map[string]bool{}, visNew: map[string]bool{}, bots: map[string]bool{}, Extra: map[string]map[string]int64{}}
}

// seenVisitor: clients already counted as visitors in this replay (new visitors).
var seenVisitor = map[string]bool{}

func (t *Truth) add(r result, seen map[string]bool) {
	c := t.Counters
	if strings.HasPrefix(r.class, "unknown") || r.class == "transport_error" {
		t.Unknown[r.class]++
		return
	}
	c["requests"]++
	stopped := int64(0)
	switch r.class {
	case "forwarded":
		c["forwarded"]++
	case "blocked_waf", "rate_limited", "rejected_limit":
		c["stopped"]++
		c[r.class]++
		stopped = 1
	case "fail_closed":
		c["fail_closed"]++
		if r.waitingPage {
			c["waiting_page_shown"]++
		}
	}
	would := int64(0)
	if r.wouldBlock {
		c["would_block"]++
		would = 1
	}
	if r.detection {
		c["detections"]++
	}
	if r.pageView {
		c["page_views"]++
	}
	c["status_"+strconv.Itoa(r.status/100)+"xx"]++
	switch r.upstream {
	case "error":
		c["upstream_errors"]++
	case "timeout":
		c["upstream_timeouts"]++
	}
	c["bytes_in"] += r.bytesIn
	c["bytes_out"] += r.bytesOut
	c["rejected_body_bytes"] += r.rejectedBody
	for d, k := range r.dims {
		m := t.Dims[d]
		if m == nil {
			m = map[string]*[3]int64{}
			t.Dims[d] = m
		}
		v := m[k]
		if v == nil {
			v = &[3]int64{}
			m[k] = v
		}
		v[0]++
		v[1] += stopped
		v[2] += would
	}
	if d := r.dims["path"]; d != "" && r.detection {
		if t.Extra["path_detections"] == nil {
			t.Extra["path_detections"] = map[string]int64{}
		}
		t.Extra["path_detections"][d]++
	}
	t.clients[r.client] = true
	if r.dims["ua_class"] == "browser" && r.dims["bot_category"] == "likely_browser" {
		if r.class == "forwarded" {
			t.vis[r.client] = true
			if !seenVisitor[r.client] {
				seenVisitor[r.client] = true
				t.visNew[r.client] = true
			}
		}
	} else {
		t.bots[r.client] = true
	}
	if !seen[r.client] {
		seen[r.client] = true
		t.newSet[r.client] = true
	}
	if r.timed {
		t.lat = append(t.lat, r.latMS)
		if r.class == "forwarded" && r.upstream == "" {
			t.up = append(t.up, float64(r.delayMS))
		}
	}
}

func quantile(xs []float64, q float64) float64 {
	if len(xs) == 0 {
		return math.NaN()
	}
	s := append([]float64(nil), xs...)
	sort.Float64s(s)
	i := int(math.Ceil(q*float64(len(s)))) - 1
	return s[max(0, i)]
}

func (t *Truth) finish(_ []geoEntry) {
	t.Unique, t.New = len(t.clients), len(t.newSet)
	t.Visitors, t.VisitorsNew, t.BotClients = len(t.vis), len(t.visNew), len(t.bots)
	t.LatMS, t.UpMS = map[string]float64{}, map[string]float64{}
	for k, q := range timedQuantiles {
		t.LatMS[k] = quantile(t.lat, q)
		t.UpMS[k] = quantile(t.up, q)
	}
}
