package monitoring

import (
	"net/netip"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/contract/config"
	cm "github.com/deutschland-schild/schild/contract/monitoring"
	"github.com/deutschland-schild/schild/contract/websites"
	"github.com/deutschland-schild/schild/gateway/internal/sites"
)

// outcomeOf maps a request class to the contract's RequestOutcome
// (Challenged has none: it is stopped, so never a visitor).
func outcomeOf(c Class, would bool) string {
	switch c {
	case Forwarded:
		if would {
			return "would_block"
		}
		return "passed"
	case BlockedWAF:
		return "blocked_waf"
	case BlockedBehaviour:
		return "blocked_behaviour"
	case RateLimited:
		return "rate_limited"
	case RejectedLimit:
		return "rejected_limit"
	case Challenged:
		return "challenged"
	}
	return "fail_closed"
}

// TestVisitorRuleMatchesContract: for every user agent of the corpus (and
// none) and every class, the recorder adds the client to the visitor
// sketches exactly when contract/monitoring.Visitor says so and to the bot
// client sketch exactly when BotClient says so, gateway-wide and per
// website.
func TestVisitorRuleMatchesContract(t *testing.T) {
	uas := append([]string{"", "curl/8.5", "python-requests/2.31"}, uaCorpus...)
	classes := []Class{Forwarded, BlockedWAF, BlockedBehaviour, RateLimited, RejectedLimit, Challenged, FailTimeout, FailBusy, FailNotReady, FailPanic}
	reg := testSites(t)
	for _, ua := range uas {
		for _, c := range classes {
			for _, would := range []bool{false, true} {
				if would && c != Forwarded {
					continue
				}
				rc := newRecorder(time.Now())
				rc.sites = reg
				r := siteReq("shop.example.org", "/")
				r.Header.Set("User-Agent", ua)
				rc.record(&Req{R: r, Class: c, WouldBlock: would, Status: 200, Client: netip.MustParseAddr("198.51.100.7")})
				info := rc.ua.classify(ua)
				uaClass, cat := cm.UAClasses[info.class], cm.BotCategories[info.bot]
				out := outcomeOf(c, would)
				wantV, wantB := cm.Visitor(uaClass, cat, out), cm.BotClient(uaClass, cat)
				var a accum
				for i := range rc.shards {
					a.merge(rc.shards[i].cur)
				}
				_, slot := reg.Resolve("shop.example.org")
				st := a.sites[slot]
				gotV, gotB := !a.unique.empty(), !a.bots.empty()
				if gotV != wantV || gotB != wantB || st == nil || !st.unique.empty() != wantV || !st.bots.empty() != wantB {
					t.Errorf("ua %q (%s/%s) %s: visitor %v bot %v, want %v %v", ua, uaClass, cat, out, gotV, gotB, wantV, wantB)
				}
				if !a.fresh.empty() && !wantV {
					t.Errorf("ua %q %s: new client without being a visitor", ua, out)
				}
			}
		}
	}
}

// TestRecordBotDoesNotAllocate: the bot client path stays allocation-free.
func TestRecordBotDoesNotAllocate(t *testing.T) {
	rc := newRecorder(time.Now())
	rc.sites = testSites(t)
	r := siteReq("shop.example.org", "/robots.txt")
	r.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)")
	q := Req{R: r, Class: Forwarded, Status: 200, Client: netip.MustParseAddr("192.0.2.66"), Country: "US", ASN: 15169, NetClass: "hosting"}
	for i := 0; i < len(rc.shards)*2; i++ {
		rc.record(&q)
	}
	if n := testing.AllocsPerRun(1000, func() { rc.record(&q) }); n != 0 {
		t.Errorf("Record of a bot allocates %.1f times per request", n)
	}
}

// TestVisitorEstimates: 3 browser clients, 2 bots, 1 tool and 1 browser
// client whose every request was blocked give 3 visitors and 3 bot clients
// in the buckets (gateway-wide and per website), the KPI row, Echtzeit and
// TrafficNow.
func TestVisitorEstimates(t *testing.T) {
	now := time.Now().UTC().Truncate(10 * time.Minute).Add(-30 * time.Minute)
	// Exact counts need the three visitors and the three bot clients in
	// different sketch registers; with the random seed of a monitor they
	// share one in about 0.6 % of the monitors, so the test takes another.
	var m *Monitor
	for {
		var err error
		m, err = New(Config{StoragePath: t.TempDir(), Keep: config.MonitoringKeep{TenSecondsHours: 6, MinuteHours: 48, TenMinuteDays: 14},
			Sampler: SamplerConfig{Root: fixtureRoot(t), Linux: true, Host: true, Started: now, Version: "test"}, Sites: testSites(t)}, now.Add(-time.Second))
		if err != nil {
			t.Fatal(err)
		}
		if m.distinctRegisters("198.51.100.1", "198.51.100.2", "2001:db8:1:2::5") && m.distinctRegisters("192.0.2.10", "192.0.2.11", "192.0.2.12") {
			break
		}
		m.Close()
	}
	defer m.Close()
	m.Sample(now.Add(-5 * time.Second))
	rec := func(ua, ip string, c Class) {
		r := siteReq("shop.example.org", "/produkt")
		r.Header.Set("User-Agent", ua)
		m.Record(&Req{R: r, Class: c, Status: 200, Client: netip.MustParseAddr(ip), Country: "DE", NetClass: "residential"})
	}
	for s := 1; s <= 600; s++ {
		at := now.Add(time.Duration(s) * time.Second)
		m.flushWrites()
		if s%10 == 1 {
			rec(chromeUA, "198.51.100.1", Forwarded)
			rec(uaCorpus[1], "198.51.100.2", Forwarded)
			rec(uaCorpus[4], "2001:db8:1:2::5", Forwarded)
			rec(chromeUA, "203.0.113.50", BlockedWAF)
			rec(uaCorpus[5], "192.0.2.10", Forwarded) // Googlebot
			rec(uaCorpus[6], "192.0.2.11", Forwarded) // GPTBot
			rec("curl/8.5", "192.0.2.12", RateLimited)
		}
		m.Tick(at)
	}
	m.flushWrites()
	end := now.Add(600 * time.Second)
	page, err := m.Buckets("10m", now, "", 10, end)
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("%v %d buckets", err, len(page.Items))
	}
	b := page.Items[0]
	is := func(p *int64, want int64) bool { return p != nil && *p == want }
	if !is(b.Clients.Unique, 3) || !is(b.Clients.Bots, 3) || !is(b.Clients.UniqueDay, 3) {
		t.Errorf("gateway clients %+v", b.Clients)
	}
	if len(b.Sites) != 1 || b.Sites[0].Clients == nil || !is(b.Sites[0].Clients.Unique, 3) || !is(b.Sites[0].Clients.Bots, 3) || !is(b.Sites[0].Clients.UniqueDay, 3) {
		t.Errorf("site clients %+v", b.Sites)
	}
	k, err := m.Kpis("shop.example.org", now, end, nil, end)
	if err != nil || k.Visitors.Value == nil || *k.Visitors.Value != 3 {
		t.Errorf("kpi visitors %+v %v", k.Visitors, err)
	}
	rt, err := m.Realtime("shop.example.org", end)
	if err != nil || !is(rt.Visitors5m, 3) {
		t.Errorf("realtime visitors_5m %v %v", rt.Visitors5m, err)
	}
	for _, p := range rt.Points[len(rt.Points)-6 : len(rt.Points)-1] {
		if !is(p.Visitors, 3) {
			t.Errorf("realtime point %+v", p)
		}
	}
	if n := m.Site(0, end); n.Now == nil || !is(n.Now.ClientsUnique, 3) {
		t.Errorf("site now %+v", n.Now)
	}
	whole, err := m.Now("", end)
	if err != nil || !is(whole.Traffic.ClientsUnique, 3) {
		t.Errorf("now %+v %v", whole.Traffic.ClientsUnique, err)
	}
}

// ownSites: four websites, one of them a wildcard, two IP literals.
func ownSites(t *testing.T) *sites.Registry {
	t.Helper()
	v := sites.NewView(websites.Input{Mode: websites.ModeIngress, Blocks: []websites.Block{
		{Addresses: []string{"shop.example.org"}, Schild: true, Proxies: true},
		{Addresses: []string{"*.kunden.example.org"}, Schild: true, Proxies: true},
		{Addresses: []string{"192.0.2.10"}, Schild: true, Proxies: true},
		{Addresses: []string{"[2001:db8::1]"}, Schild: true, Proxies: true},
		{Addresses: []string{"legacy.example.net"}, Proxies: true},
		{Addresses: []string{":8080"}, Schild: true, Proxies: true},
	}, UnprotectedSites: []string{"legacy.example.net"}})
	if v.Err != nil {
		t.Fatal(v.Err)
	}
	return sites.NewRegistry(v)
}

// TestReferrerOwnHosts: a Referer from a host of any website of this
// gateway is _intern (D36 amendment, websites.Set.OwnHost), never through
// the catch-all.
func TestReferrerOwnHosts(t *testing.T) {
	own := ownSites(t)
	var d domainCache
	d.init()
	for ref, want := range map[string]string{
		"https://shop.example.org/warenkorb": "_intern",
		"https://Shop.Example.org.:443/":     "_intern",
		"https://a.kunden.example.org/":      "_intern",
		"https://kunden.example.org/":        "example.org",
		"https://legacy.example.net/":        "_intern", // unprotected websites are own hosts too
		"http://192.0.2.10/":                 "_intern",
		"http://192.0.2.10:8080/x":           "_intern",
		"http://192.0.2.11/":                 "_other",
		"http://[2001:db8::1]/":              "_intern",
		"http://[2001:db8::2]/":              "_other",
		"https://www.google.com/":            "google.com",
		"https://chatgpt.com/":               "ai:chatgpt",
		"https://verein.example/":            "_intern", // the request's own host
		"https://other.example/":             "other.example",
	} {
		if k, _ := referrerKey(ref, "verein.example", d.registrable, own); k != want {
			t.Errorf("%s: %s, want %s", ref, k, want)
		}
	}
	if k, _ := referrerKey("https://shop.example.org/", "verein.example", d.registrable, nil); k != "example.org" {
		t.Errorf("without websites: %s", k)
	}
}

// TestRecordOwnReferrerDoesNotAllocate: the own-host check is cached.
func TestRecordOwnReferrerDoesNotAllocate(t *testing.T) {
	rc := newRecorder(time.Now())
	rc.sites = ownSites(t)
	for _, ref := range []string{"https://a.kunden.example.org/start", "https://www.google.com/search"} {
		r := newReq("/produkt", chromeUA, ref)
		r.Host = "shop.example.org"
		q := Req{R: r, Class: Forwarded, Status: 200, Client: netip.MustParseAddr("192.0.2.50"), Country: "DE", NetClass: "residential"}
		for i := 0; i < len(rc.shards)*2; i++ {
			rc.record(&q)
		}
		if n := testing.AllocsPerRun(1000, func() { rc.record(&q) }); n != 0 {
			t.Errorf("%s: %.1f allocations per request", ref, n)
		}
	}
}
