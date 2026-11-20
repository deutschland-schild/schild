package bots

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"math/rand"
	"net"
	"net/http"
	"net/netip"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/contract/bots"
	"github.com/deutschland-schild/schild/contract/config"
	cm "github.com/deutschland-schild/schild/contract/monitoring"
	"github.com/deutschland-schild/schild/contract/msg"
	"github.com/deutschland-schild/schild/contract/vectors"
)

func boolp(b bool) *bool { return &b }

func shipped(t testing.TB) *bots.Catalogue {
	t.Helper()
	c, err := bots.Parse(catalogueJSON)
	if err != nil {
		t.Fatalf("shipped catalogue: %v", err)
	}
	return c
}

func catOf(e *Engine, id uint16, cat int) (string, string) {
	name := ""
	if b := e.Bot(id); b != nil {
		name = b.ID
	}
	return name, cm.BotCategories[cat]
}

// ---------------------------------------------------------------- catalogue

func TestShippedCatalogue(t *testing.T) {
	c := shipped(t)
	if len(c.Bots) < 200 || len(c.Ranges) < 10 {
		t.Fatalf("catalogue too small: %d bots, %d range sets", len(c.Bots), len(c.Ranges))
	}
	srcAI := false
	for _, s := range c.Sources {
		srcAI = srcAI || s.ID == "ai-robots-txt" && s.License == "MIT"
	}
	if !srcAI {
		t.Error("ai.robots.txt attribution missing")
	}
	e := Default()
	if e.NumBots() != len(c.Bots) || e.CatalogueVersion() != c.Version {
		t.Fatal("engine and catalogue disagree")
	}
	for _, want := range []string{"googlebot", "bingbot", "gptbot", "oai-searchbot", "chatgpt-user", "perplexitybot", "perplexity-user", "applebot", "duckduckgo"} {
		found := false
		for _, r := range e.Ranges() {
			found = found || r.ID == want && r.Source == "release"
		}
		if !found {
			t.Errorf("range snapshot %s missing", want)
		}
	}
	// Every bot of a category; every robots token is unique.
	robots := map[string]string{}
	for i := range c.Bots {
		b := &c.Bots[i]
		if b.RobotsToken != "" {
			if o := robots[strings.ToLower(b.RobotsToken)]; o != "" {
				t.Errorf("robots token %s used by %s and %s", b.RobotsToken, o, b.ID)
			}
			robots[strings.ToLower(b.RobotsToken)] = b.ID
		}
	}
	s := e.Settings()
	if !s.Ranges || s.FCrDNS || s.RangesFetch {
		t.Errorf("default settings %+v", s)
	}
}

// New, matching and verification with the default switches never touch the
// network: no HTTP request, no DNS lookup.
func TestOfflineByDefault(t *testing.T) {
	var calls atomic.Int32
	oldT := http.DefaultTransport
	http.DefaultTransport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return nil, errors.New("no network in this test")
	})
	oldR := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		calls.Add(1)
		return nil, errors.New("no DNS in this test")
	}}
	t.Cleanup(func() { http.DefaultTransport, net.DefaultResolver = oldT, oldR })

	e, err := New(config.Bots{}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	e.Start(ctx)
	for _, ua := range browserUAs {
		id, _ := e.MatchUA(ua)
		e.Verify(id, netip.MustParseAddr("203.0.113.9"))
	}
	g, _ := e.MatchUA("Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)")
	e.Verify(g, netip.MustParseAddr("66.249.66.1"))
	time.Sleep(50 * time.Millisecond)
	cancel()
	e.Close()
	if n := calls.Load(); n != 0 {
		t.Fatalf("%d network calls with the default switches", n)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// ---------------------------------------------------------------- vectors

type matchInput struct {
	Catalogue json.RawMessage `json:"catalogue"`
	Request   struct {
		IP     string `json:"ip"`
		UA     string `json:"user_agent"`
		FCrDNS string `json:"fcrdns_name"`
	} `json:"request"`
	Options *struct {
		Ranges *bool `json:"ranges"`
		FCrDNS *bool `json:"fcrdns"`
	} `json:"options"`
}

// engineResult classifies one request with the engine (FCrDNS answers are
// put into the cache as the background worker would).
func engineResult(t testing.TB, e *Engine, ua string, a netip.Addr, fcName string) bots.Result {
	t.Helper()
	if e.fc != nil && fcName != "" {
		e.fc.lookupAddr = func(context.Context, string) ([]string, error) { return []string{fcName}, nil }
		e.fc.lookupIP = func(context.Context, string, string) ([]netip.Addr, error) { return []netip.Addr{a.Unmap()}, nil }
		e.fc.store(a.Unmap(), e.fc.resolve(context.Background(), a.Unmap()))
	}
	id, cat := e.MatchUA(ua)
	r := bots.Result{Category: cm.BotCategories[cat]}
	if id != 0 {
		name := e.Bot(id).ID
		v := VerificationName(e.Verify(id, a))
		r.Bot, r.Verification = &name, &v
	}
	return r
}

// Every valid bot-match vector gives the expected result through the
// engine, and the same as the contract.
func TestBotMatchVectors(t *testing.T) {
	files, _ := filepath.Glob("../../../contracts/vectors/bot-match/valid/*.json")
	if len(files) == 0 {
		t.Skip("vectors not present")
	}
	for _, f := range files {
		v, err := vectors.Load(f)
		if err != nil {
			t.Fatal(err)
		}
		now, err := msg.ParseTime(v.Context.Now)
		if err != nil {
			t.Fatal(err)
		}
		var in matchInput
		if err := json.Unmarshal([]byte(v.InputRaw), &in); err != nil {
			t.Fatal(err)
		}
		c, err := bots.Parse(in.Catalogue)
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		var cfg config.Bots
		if in.Options != nil {
			cfg.Verify.Ranges, cfg.Verify.FCrDNS = in.Options.Ranges, in.Options.FCrDNS
		}
		e, err := NewFromCatalogue(c, cfg, func() time.Time { return now })
		if err != nil {
			t.Fatal(err)
		}
		a := netip.MustParseAddr(in.Request.IP)
		got := engineResult(t, e, in.Request.UA, a, in.Request.FCrDNS)
		want, err := bots.RunVector([]byte(v.InputRaw), now)
		if err != nil {
			t.Fatal(err)
		}
		gj, _ := json.Marshal(got)
		wj, _ := json.Marshal(want)
		if !bytes.Equal(gj, wj) || !vectors.SameJSON(gj, v.Expect.Result) {
			t.Errorf("%s: engine %s, contract %s, expected %s", filepath.Base(f), gj, wj, v.Expect.Result)
		}
	}
}

// ---------------------------------------------------------------- matching

var browserUAs = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0",
	"Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/25.0 Chrome/121.0.0.0 Mobile Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0",
	"Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/130.0 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36 OPR/114.0.0.0",
	"Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Mobile Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 14.7; rv:132.0) Gecko/20100101 Firefox/132.0",
}

var botUAs = []string{
	"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
	"Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.69 Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
	"Googlebot-Image/1.0",
	"Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.2; +https://openai.com/gptbot)",
	"Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; ChatGPT-User/1.0; +https://openai.com/bot",
	"Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; OAI-SearchBot/1.0; +https://openai.com/searchbot)",
	"Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; PerplexityBot/1.0; +https://perplexity.ai/perplexitybot)",
	"Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; ClaudeBot/1.0; +claudebot@anthropic.com)",
	"Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.1.1 Safari/605.1.15 (Applebot/0.1; +http://www.apple.com/go/applebot)",
	"DuckDuckBot/1.1; (+http://duckduckgo.com/duckduckbot.html)",
	"Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)",
	"Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)",
	"Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)",
	"Mozilla/5.0 (compatible; SemrushBot/7~bl; +http://www.semrush.com/bot.html)",
	"facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)",
	"Twitterbot/1.0", "Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)",
	"Mozilla/5.0+(compatible; UptimeRobot/2.0; http://www.uptimerobot.com/)",
	"Feedly/1.0 (+http://www.feedly.com/fetcher.html; 42 subscribers)",
	"curl/8.5.0", "Wget/1.21.4", "python-requests/2.32.3", "Go-http-client/1.1", "okhttp/4.12.0",
	"sqlmap/1.8#stable (https://sqlmap.org)", "Mozilla/5.0 zgrab/0.x",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (compatible; SomeNewCrawler/1.0)", "", "x", "Mozilla/", "MOZILLA/5.0 GOOGLEBOT",
}

// matchCorpus: real user agents, every catalogue and automation token
// alone, upper case and embedded in noise, overlong user agents (tokens
// around the 512 byte cut) and random strings over a small alphabet that
// makes partial token matches likely.
func matchCorpus(c *bots.Catalogue, rng *rand.Rand) []string {
	out := append(append([]string{}, browserUAs...), botUAs...)
	var toks []string
	for _, b := range c.Bots {
		toks = append(toks, b.UAMatch...)
	}
	toks = append(toks, c.AutomationTokens...)
	for _, tk := range toks {
		out = append(out, tk, strings.ToUpper(tk), "Mozilla/5.0 (compatible; "+tk+"/1.0)", "x"+tk[:len(tk)-1], tk[1:]+"/2",
			browserUAs[rng.Intn(len(browserUAs))]+" "+tk, strings.Repeat("a", 512-len(tk)/2)+tk, strings.Repeat("b", 512-len(tk))+tk)
	}
	alpha := "abcdeghilmnoprstuyzABGMOPSTU/-_. ;()0123456789"
	for i := 0; i < 20000; i++ {
		n := rng.Intn(80)
		b := make([]byte, n)
		for j := range b {
			b[j] = alpha[rng.Intn(len(alpha))]
		}
		s := string(b)
		switch rng.Intn(4) {
		case 0:
			s = "Mozilla/" + s
		case 1:
			tk := toks[rng.Intn(len(toks))]
			p := rng.Intn(len(s) + 1)
			s = s[:p] + tk + s[p:]
		case 2:
			tk, tk2 := toks[rng.Intn(len(toks))], toks[rng.Intn(len(toks))]
			s = "Mozilla/5.0 " + tk + s + tk2
		}
		out = append(out, s)
	}
	for i := 0; i < 2000; i++ { // arbitrary bytes, also non-ASCII
		b := make([]byte, rng.Intn(600))
		rng.Read(b)
		out = append(out, string(b))
	}
	return out
}

func sameMatch(t *testing.T, e *Engine, c *bots.Catalogue, ua string) {
	t.Helper()
	wb, wc := c.Match(ua)
	id, cat := e.MatchUA(ua)
	want := ""
	if wb != nil {
		want = wb.ID
	}
	got, gc := catOf(e, id, cat)
	if got != want || gc != wc {
		t.Fatalf("%q: engine %s/%s, contract %s/%s", ua, got, gc, want, wc)
	}
}

// The matcher gives exactly the contract's answer on the shipped catalogue
// and on every vector catalogue.
func TestMatchEqualsContract(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	cats := []*bots.Catalogue{shipped(t)}
	files, _ := filepath.Glob("../../../contracts/vectors/bot-match/valid/*.json")
	if len(files) > 0 {
		v, err := vectors.Load(files[0])
		if err != nil {
			t.Fatal(err)
		}
		var in matchInput
		_ = json.Unmarshal([]byte(v.InputRaw), &in)
		c, err := bots.Parse(in.Catalogue)
		if err != nil {
			t.Fatal(err)
		}
		cats = append(cats, c)
	}
	for _, c := range cats {
		e, err := NewFromCatalogue(c, config.Bots{}, time.Now)
		if err != nil {
			t.Fatal(err)
		}
		corpus := matchCorpus(c, rng)
		for _, ua := range corpus {
			sameMatch(t, e, c, ua)
		}
	}
}

// Ties of equally long tokens go to the earlier entry, as in the contract's
// loop; the second entry wins only with a longer token.
func TestMatchTies(t *testing.T) {
	raw := `{"schema":"schild.bot_catalogue/0.1","version":"2026-10-29.1","generated_at":"2026-10-29T00:00:00Z",
	"sources":[{"id":"own","license":"MIT","url":"https://example.org"}],"automation_tokens":["bot"],"ranges":[],
	"bots":[{"id":"aa","name":"A","operator":"A","category":"seo_tool","ua_match":["xyzw","longertoken"],"verify":{}},
	        {"id":"bb","name":"B","operator":"B","category":"monitoring","ua_match":["abcd"],"verify":{}}]}`
	c, err := bots.Parse([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	e, _ := NewFromCatalogue(c, config.Bots{}, time.Now)
	for _, ua := range []string{"abcd xyzw", "xyzw abcd", "abcd", "ABCD longertoken", "Mozilla/5.0 bot", "Mozilla/5.0 x"} {
		sameMatch(t, e, c, ua)
	}
}

func FuzzMatchEqualsContract(f *testing.F) {
	for _, s := range append(append([]string{}, browserUAs...), botUAs...) {
		f.Add(s)
	}
	c := shipped(f)
	e := Default()
	f.Fuzz(func(t *testing.T, ua string) {
		sameMatch(t, e, c, ua)
	})
}

// ---------------------------------------------------------------- verification

// A spoofed User-Agent of any bot with published ranges, from an address
// outside them (IPv4, IPv6, IPv4-mapped), is never verified; it is a
// mismatch while the snapshot is fresh.
func TestSpoofedNeverVerified(t *testing.T) {
	c := shipped(t)
	gen, _ := msg.ParseTime(c.GeneratedAt)
	now := gen.Add(24 * time.Hour)
	e, err := NewFromCatalogue(c, config.Bots{}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	foreign := []netip.Addr{netip.MustParseAddr("192.0.2.66"), netip.MustParseAddr("198.51.100.7"), netip.MustParseAddr("203.0.113.200"),
		netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8:4860::7"), netip.MustParseAddr("::ffff:192.0.2.66"),
		netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("::1")}
	checked := 0
	for i := range c.Bots {
		b := &c.Bots[i]
		if b.Verify.Ranges == "" {
			continue
		}
		for _, tk := range b.UAMatch {
			id, _ := e.MatchUA("Mozilla/5.0 (compatible; " + tk + "/2.1)")
			if e.Bot(id) == nil {
				t.Fatalf("%s: token %s does not match", b.ID, tk)
			}
			for _, a := range foreign {
				if v := e.Verify(id, a); v != VerMismatch {
					t.Errorf("%s from %s: %s, want mismatch", e.Bot(id).ID, a, VerificationName(v))
				}
				checked++
			}
		}
	}
	if checked == 0 {
		t.Fatal("no bot with ranges")
	}
	// The named spoofs of the spec.
	for _, ua := range []string{"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.2; +https://openai.com/gptbot)"} {
		id, _ := e.MatchUA(ua)
		for _, a := range []string{"185.220.101.1", "2a0b:f4c0::1"} {
			if v := e.Verify(id, netip.MustParseAddr(a)); v == VerVerified {
				t.Errorf("%q from %s verified", ua, a)
			}
		}
	}
}

// Random addresses and the published prefixes themselves: the engine gives
// the contract's verification for every bot with ranges.
func TestVerifyEqualsContract(t *testing.T) {
	c := shipped(t)
	gen, _ := msg.ParseTime(c.GeneratedAt)
	rng := rand.New(rand.NewSource(7))
	for _, off := range []time.Duration{time.Hour, 29 * 24 * time.Hour, 31 * 24 * time.Hour} {
		now := gen.Add(off)
		for _, cfg := range []config.Bots{{}, {Verify: config.BotsVerify{Ranges: boolp(false)}}} {
			e, _ := NewFromCatalogue(c, cfg, func() time.Time { return now })
			opt := bots.Options{Ranges: cfg.RangesOn()}
			var addrs []netip.Addr
			for _, r := range c.Ranges {
				for _, s := range r.Prefixes {
					p := netip.MustParsePrefix(s)
					addrs = append(addrs, p.Addr(), lastAddr(p), lastAddr(p).Next(), p.Addr().Prev())
				}
			}
			for i := 0; i < 5000; i++ {
				var b4 [4]byte
				var b16 [16]byte
				rng.Read(b4[:])
				rng.Read(b16[:])
				addrs = append(addrs, netip.AddrFrom4(b4), netip.AddrFrom16(b16))
			}
			for i := range c.Bots {
				b := &c.Bots[i]
				id := uint16(i + 1)
				for j, a := range addrs {
					if b.Verify.Ranges == "" && j > 50 {
						break
					}
					if !a.IsValid() {
						continue
					}
					want := c.VerifyAddr(b, a, "", opt, now)
					if got := VerificationName(e.Verify(id, a)); got != want {
						t.Fatalf("%s %s at +%s: engine %s, contract %s", b.ID, a, off, got, want)
					}
				}
			}
		}
	}
}

func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Addr().AsSlice()
	for i := p.Bits(); i < len(b)*8; i++ {
		b[i/8] |= 1 << (7 - i%8)
	}
	a, _ := netip.AddrFromSlice(b)
	return a
}

// A snapshot older than 30 days is unknown_stale, also for an address in
// it; at exactly 30 days it is still fresh.
func TestStaleSnapshot(t *testing.T) {
	c := shipped(t)
	var fetched time.Time
	var inside netip.Addr
	for _, r := range c.Ranges {
		if r.ID == "googlebot" {
			fetched, _ = msg.ParseTime(r.FetchedAt)
			for _, s := range r.Prefixes {
				if p := netip.MustParsePrefix(s); p.Addr().Is4() {
					inside = p.Addr()
					break
				}
			}
		}
	}
	if !inside.IsValid() {
		t.Fatal("no googlebot IPv4 prefix")
	}
	var now time.Time
	e, _ := NewFromCatalogue(c, config.Bots{}, func() time.Time { return now })
	id, _ := e.MatchUA("Mozilla/5.0 (compatible; Googlebot/2.1)")
	for _, tc := range []struct {
		age  time.Duration
		addr netip.Addr
		want uint8
	}{
		{time.Hour, inside, VerVerified},
		{time.Hour, netip.MustParseAddr("192.0.2.1"), VerMismatch},
		{bots.StaleAfter, inside, VerVerified},
		{bots.StaleAfter + time.Second, inside, VerUnknownStale},
		{bots.StaleAfter + time.Second, netip.MustParseAddr("192.0.2.1"), VerUnknownStale},
	} {
		now = fetched.Add(tc.age)
		if got := e.Verify(id, tc.addr); got != tc.want {
			t.Errorf("age %s, %s: %s, want %s", tc.age, tc.addr, VerificationName(got), VerificationName(tc.want))
		}
	}
	now = fetched.Add(bots.StaleAfter + time.Hour)
	for _, r := range e.Ranges() {
		if !r.Stale {
			t.Errorf("range %s not stale", r.ID)
		}
	}
	// Ranges off: claimed.
	off, _ := NewFromCatalogue(c, config.Bots{Verify: config.BotsVerify{Ranges: boolp(false)}}, func() time.Time { return fetched })
	if got := off.Verify(id, inside); got != VerClaimed {
		t.Errorf("ranges off: %s", VerificationName(got))
	}
	if off.Verify(0, inside) != VerNone {
		t.Error("id 0 must be no bot")
	}
}

// ---------------------------------------------------------------- FCrDNS

func TestFCrDNSAsyncCache(t *testing.T) {
	c := shipped(t)
	gen, _ := msg.ParseTime(c.GeneratedAt)
	now := gen.Add(time.Hour)
	e, err := NewFromCatalogue(c, config.Bots{Verify: config.BotsVerify{FCrDNS: boolp(true)}}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	var lookups atomic.Int32
	e.fc.interval = time.Millisecond
	e.fc.lookupAddr = func(_ context.Context, a string) ([]string, error) {
		lookups.Add(1)
		switch a {
		case "192.0.2.10":
			return []string{"crawl-192-0-2-10.googlebot.com."}, nil
		case "192.0.2.11":
			return []string{"evil.example.net."}, nil
		case "192.0.2.12":
			return []string{"fake.googlebot.com."}, nil // forward lookup does not confirm
		}
		return nil, errors.New("nxdomain")
	}
	e.fc.lookupIP = func(_ context.Context, _ string, host string) ([]netip.Addr, error) {
		switch host {
		case "crawl-192-0-2-10.googlebot.com.":
			return []netip.Addr{netip.MustParseAddr("192.0.2.10")}, nil
		case "evil.example.net.":
			return []netip.Addr{netip.MustParseAddr("192.0.2.11")}, nil
		case "fake.googlebot.com.":
			return []netip.Addr{netip.MustParseAddr("198.51.100.1")}, nil
		}
		return nil, errors.New("nxdomain")
	}
	id, _ := e.MatchUA("Mozilla/5.0 (compatible; Googlebot/2.1)")
	addrs := map[string]uint8{"192.0.2.10": VerVerified, "192.0.2.11": VerMismatch, "192.0.2.12": VerMismatch, "192.0.2.13": VerMismatch}
	// Before the worker ran: what the ranges say (all outside: mismatch),
	// no lookup on the request path.
	for a := range addrs {
		if got := e.Verify(id, netip.MustParseAddr(a)); got != VerMismatch {
			t.Fatalf("%s before lookup: %s", a, VerificationName(got))
		}
	}
	if lookups.Load() != 0 {
		t.Fatal("lookup on the request path")
	}
	ctx, cancel := context.WithCancel(context.Background())
	e.Start(ctx)
	deadline := time.Now().Add(5 * time.Second)
	for e.fc.size() < len(addrs) && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	e.Close()
	for a, want := range addrs {
		if got := e.Verify(id, netip.MustParseAddr(a)); got != want {
			t.Errorf("%s: %s, want %s", a, VerificationName(got), VerificationName(want))
		}
	}
	// A bot without rdns suffixes never queues a lookup.
	before := lookups.Load()
	g, _ := e.MatchUA("GPTBot/1.2")
	e.Verify(g, netip.MustParseAddr("192.0.2.50"))
	if len(e.fc.q) != 0 || lookups.Load() != before {
		t.Error("lookup queued for a bot without rdns_suffixes")
	}
	// The cache is bounded.
	for i := 0; i < fcMaxEntry*2; i++ {
		var b [4]byte
		b[0], b[1], b[2], b[3] = 10, byte(i>>16), byte(i>>8), byte(i)
		e.fc.store(netip.AddrFrom4(b), fcEntry{exp: now.Add(time.Hour).Unix()})
	}
	if n := e.fc.size(); n > fcMaxEntry {
		t.Errorf("cache holds %d > %d", n, fcMaxEntry)
	}
}

// ---------------------------------------------------------------- allocation and speed

func TestHotPathDoesNotAllocate(t *testing.T) {
	e := Default()
	uas := append(append([]string{}, browserUAs...), botUAs...)
	uas = append(uas, strings.Repeat("x", 2000)+"Googlebot")
	g, _ := e.MatchUA(botUAs[0])
	a4, a6 := netip.MustParseAddr("66.249.66.1"), netip.MustParseAddr("2001:4860:4801:10::1")
	i := 0
	if n := testing.AllocsPerRun(2000, func() {
		e.MatchUA(uas[i%len(uas)])
		i++
	}); n != 0 {
		t.Errorf("MatchUA allocates %v", n)
	}
	if n := testing.AllocsPerRun(2000, func() { e.Verify(g, a4); e.Verify(g, a6) }); n != 0 {
		t.Errorf("Verify allocates %v", n)
	}
	fc, _ := New(config.Bots{Verify: config.BotsVerify{FCrDNS: boolp(true)}}, time.Now)
	fc.fc.store(a4, fcEntry{exp: time.Now().Add(time.Hour).Unix(), n: 1, names: [fcKeepNames]string{"crawl.googlebot.com"}})
	if n := testing.AllocsPerRun(2000, func() { fc.Verify(g, a4); fc.Verify(g, a6) }); n != 0 {
		t.Errorf("Verify with FCrDNS allocates %v", n)
	}
}

func BenchmarkMatchUABrowser(b *testing.B) {
	e := Default()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		e.MatchUA(browserUAs[i%len(browserUAs)])
	}
}

func BenchmarkMatchUABot(b *testing.B) {
	e := Default()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		e.MatchUA(botUAs[i%len(botUAs)])
	}
}

func BenchmarkMatchContract(b *testing.B) {
	c := shipped(b)
	for i := 0; i < b.N; i++ {
		c.Match(browserUAs[i%len(browserUAs)])
	}
}

func BenchmarkVerify(b *testing.B) {
	e := Default()
	g, _ := e.MatchUA(botUAs[0])
	addrs := []netip.Addr{netip.MustParseAddr("66.249.66.1"), netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:4860:4801:10::1"), netip.MustParseAddr("2001:db8::1")}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		e.Verify(g, addrs[i%len(addrs)])
	}
}
