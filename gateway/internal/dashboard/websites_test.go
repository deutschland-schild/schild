//go:build !release

package dashboard_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/contract/events"
	"github.com/deutschland-schild/schild/contract/websites"
	"github.com/deutschland-schild/schild/gateway/internal/apptest"
	"github.com/deutschland-schild/schild/gateway/internal/dashboard"
	"github.com/deutschland-schild/schild/gateway/internal/sites"
)

// visitHost sends one request through the proxy with a Host header.
func visitHost(t *testing.T, h *apptest.Harness, host, path, ip string) int {
	t.Helper()
	req, _ := http.NewRequest("GET", h.Proxy.URL+path, nil)
	req.Host = host
	req.Header.Set("X-Forwarded-For", ip)
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0")
	req.Header.Set("Accept", "text/html")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.StatusCode
}

// TestWebsites: the website-first operations (v0.5, D36) on a gateway with
// two protected websites and one unprotected one.
func TestWebsites(t *testing.T) {
	h := apptest.New(t, apptest.Options{})
	h.Login()
	h.App.Sites.Store(sites.NewView(websites.Input{Mode: websites.ModeIngress, Blocks: []websites.Block{
		{Addresses: []string{"shop.example", "www.shop.example"}, Schild: true},
		{Addresses: []string{"verein.example"}, Schild: true},
		{Addresses: []string{"legacy.example"}, Proxies: true},
	}, UnprotectedSites: []string{"legacy.example"}}))
	for i := 0; i < 3; i++ {
		if c := visitHost(t, h, "shop.example", "/produkte/1", "198.51.100.23"); c != 200 {
			t.Fatalf("shop: %d", c)
		}
	}
	if c := visitHost(t, h, "verein.example", "/termine", "203.0.113.5"); c != 200 {
		t.Fatalf("verein: %d", c)
	}
	if c := visitHost(t, h, "www.shop.example", "/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E", "203.0.113.5"); c != 403 {
		t.Fatalf("xss: %d", c)
	}
	h.Flush()
	// Websites and one website.
	l := decode[websites.List](t, expect(t, h, "GET", "/websites", nil, 200, "WebsiteList"))
	if len(l.Websites) != 3 || l.Websites[0].ID != "shop.example" || l.Websites[2].Status != websites.StatusUnknown || l.Websites[2].Reasons[0].Code != websites.ReasonUnprotected ||
		l.Server == nil || !l.Server.This || l.Other != nil {
		t.Fatalf("list: %+v", l)
	}
	d := decode[websites.Detail](t, expect(t, h, "GET", "/websites/shop.example", nil, 200, "WebsiteDetail"))
	if d.Incidents24h != 1 || d.Website.ID != "shop.example" {
		t.Fatalf("detail: %+v", d)
	}
	// A schild started just now counts from its start (D36 open items).
	if d.Traffic24h == nil || !d.Traffic24hPartial || d.Traffic24hSince == "" {
		t.Fatalf("traffic_24h of a fresh start: %+v partial %v since %q", d.Traffic24h, d.Traffic24hPartial, d.Traffic24hSince)
	}
	expect(t, h, "GET", "/websites/legacy.example", nil, 200, "WebsiteDetail")
	expect(t, h, "GET", "/websites/nope.example", nil, 404, "Problem")
	// Events and incidents carry their website; the site filter.
	ev := decode[dashboard.EventPage](t, expect(t, h, "GET", "/events?site=shop.example", nil, 200, "EventPage"))
	if len(ev.Items) == 0 {
		t.Fatal("no events of shop.example")
	}
	for _, e := range ev.Items {
		if e.Site != "shop.example" {
			t.Fatalf("event of %q in the shop list", e.Site)
		}
	}
	ev = decode[dashboard.EventPage](t, expect(t, h, "GET", "/events?site=verein.example", nil, 200, "EventPage"))
	for _, e := range ev.Items {
		if e.Site != "verein.example" {
			t.Fatalf("event of %q in the verein list", e.Site)
		}
	}
	expect(t, h, "GET", "/events?site=nope.example", nil, 400, "Problem")
	expect(t, h, "GET", "/behaviour/hits?site=shop.example", nil, 200, "BehaviourHitPage")
	expect(t, h, "GET", "/distributed/waves?site=shop.example", nil, 200, "WavePage")
	ip := decode[dashboard.IncidentPage](t, expect(t, h, "GET", "/incidents?site=shop.example", nil, 200, "IncidentPage"))
	if len(ip.Items) != 1 || ip.Items[0].Site != "shop.example" || ip.Items[0].SitesAffected == nil || ip.Items[0].SitesAffected.Count != 2 ||
		ip.Items[0].SitesAffected.Total != 2 || ip.Items[0].SitesAffected.Sites[0] != "shop.example" {
		t.Fatalf("incidents: %+v", ip.Items)
	}
	if p := decode[dashboard.IncidentPage](t, expect(t, h, "GET", "/incidents?site=verein.example&status=blocked", nil, 200, "IncidentPage")); len(p.Items) != 0 {
		t.Fatalf("verein incidents: %+v", p.Items)
	}
	inc := decode[dashboard.Incident](t, expect(t, h, "GET", "/incidents/"+ip.Items[0].Incident, nil, 200, "Incident"))
	if inc.Site != "shop.example" || inc.Block != nil {
		t.Fatalf("incident site %q block %+v (a WAF block has no duration)", inc.Site, inc.Block)
	}
	// Overview of one website.
	now := time.Now().UTC()
	rng := "from=" + url.QueryEscape(now.Add(-time.Hour).Format(time.RFC3339)) + "&to=" + url.QueryEscape(now.Add(time.Minute).Format(time.RFC3339))
	expect(t, h, "GET", "/websites/shop.example/kpis?"+rng, nil, 200, "WebsiteKpis")
	expect(t, h, "GET", "/websites/shop.example/kpis?"+rng+"&filter=country:DE", nil, 200, "WebsiteKpis")
	// MVP-22: two filters come from the request ring within its window
	// (D66: up to 30 days here), older ranges stay 409 filter_unavailable.
	k2 := decode[websites.Kpis](t, expect(t, h, "GET", "/websites/shop.example/kpis?"+rng+"&filter=country:DE&filter=path:/a", nil, 200, "WebsiteKpis"))
	if k2.Source != "requests" {
		t.Fatalf("kpis source %q", k2.Source)
	}
	old := "from=" + url.QueryEscape(now.Add(-800*time.Hour).Format(time.RFC3339)) + "&to=" + url.QueryEscape(now.Add(-798*time.Hour).Format(time.RFC3339))
	expect(t, h, "GET", "/websites/shop.example/kpis?"+old+"&filter=country:DE&filter=path:/a", nil, 409, "Problem")
	expect(t, h, "GET", "/websites/shop.example/kpis", nil, 400, "Problem")
	rt := decode[websites.Realtime](t, expect(t, h, "GET", "/websites/shop.example/realtime", nil, 200, "WebsiteRealtime"))
	if len(rt.Points) != 31 || !rt.Points[30].Partial {
		t.Fatalf("realtime points %d", len(rt.Points))
	}
	al := decode[websites.AnnotationList](t, expect(t, h, "GET", "/websites/shop.example/annotations?"+rng, nil, 200, "AnnotationList"))
	kinds := map[string]bool{}
	for _, a := range al.Items {
		kinds[a.Kind] = true
	}
	if !kinds[websites.AnnIncident] || !kinds[websites.AnnRestart] || !kinds[websites.AnnConfigChanged] {
		t.Fatalf("annotations: %+v", al.Items)
	}
	feed := decode[websites.AlertFeed](t, expect(t, h, "GET", "/websites/shop.example/alerts?"+rng, nil, 200, "AlertFeed"))
	if len(feed.Items) != 1 || feed.Items[0].Kind != "waf" || feed.Items[0].Outcome != "blocked" || feed.Items[0].Category != "xss" ||
		!strings.HasPrefix(feed.Items[0].ClientPseudonym, "p1-") || strings.Contains(string(mustJSON(feed)), "203.0.113.5") {
		t.Fatalf("alerts: %+v", feed.Items)
	}
	if f := decode[websites.AlertFeed](t, expect(t, h, "GET", "/websites/verein.example/alerts?"+rng, nil, 200, "AlertFeed")); len(f.Items) != 0 {
		t.Fatalf("verein alerts: %+v", f.Items)
	}
	expect(t, h, "GET", "/websites/shop.example/alerts?filter=country:XX", nil, 200, "AlertFeed")
	// MVP-22: the request ring answers (requests_off only with it off,
	// TestRequestsOff).
	expect(t, h, "GET", "/requests?"+rng, nil, 200, "RequestPage")
	expect(t, h, "GET", "/requests/alerts/hints?site=shop.example", nil, 200, "FalsePositiveHintList")
	expect(t, h, "GET", "/websites/shop.example/alerts?filter=browser:chrome", nil, 400, "Problem")
	// Monitoring with a site and the agent API call log.
	expect(t, h, "GET", "/monitoring/now?site=verein.example", nil, 200, "MonitoringNow")
	expect(t, h, "GET", "/monitoring/series?metric=traffic.requests&site=shop.example&"+rng, nil, 200, "SeriesResult")
	expect(t, h, "GET", "/monitoring/traffic/breakdown?by=path&site=shop.example&"+rng, nil, 200, "TrafficBreakdown")
	cl := decode[dashboard.AgentCallLog](t, expect(t, h, "GET", "/agent-api/calls", nil, 200, "AgentCallLog"))
	// D103: the agent API is on by default.
	if !cl.Enabled || len(cl.Tokens) != 0 {
		t.Fatalf("call log: %+v", cl)
	}
}

// TestWouldBlockReason: a request the gateway in mode observe passes
// carries would_block_reason gateway_observe on its event (EventSummary)
// and its alert; other events carry none (D36 open items).
func TestWouldBlockReason(t *testing.T) {
	h := apptest.New(t, apptest.Options{Mode: "observe"})
	h.Login()
	h.App.Sites.Store(sites.NewView(websites.Input{Mode: websites.ModeIngress, Blocks: []websites.Block{
		{Addresses: []string{"shop.example"}, Schild: true},
	}}))
	if c := visitHost(t, h, "shop.example", "/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E", "203.0.113.5"); c != 200 {
		t.Fatalf("observe: %d", c)
	}
	if c := visitHost(t, h, "shop.example", "/produkte/1", "198.51.100.23"); c != 200 {
		t.Fatalf("clean: %d", c)
	}
	h.Flush()
	ev := decode[dashboard.EventPage](t, expect(t, h, "GET", "/events", nil, 200, "EventPage"))
	n := 0
	for _, e := range ev.Items {
		switch {
		case e.Outcome == "would_block" && e.WouldBlockReason == "gateway_observe":
			n++
		case e.WouldBlockReason != "":
			t.Fatalf("reason %q on %s/%s", e.WouldBlockReason, e.Type, e.Outcome)
		}
	}
	if n != 1 {
		t.Fatalf("would_block events with reason: %d (%+v)", n, ev.Items)
	}
	now := time.Now().UTC()
	rng := "from=" + url.QueryEscape(now.Add(-time.Hour).Format(time.RFC3339)) + "&to=" + url.QueryEscape(now.Add(time.Minute).Format(time.RFC3339))
	feed := decode[websites.AlertFeed](t, expect(t, h, "GET", "/websites/shop.example/alerts?"+rng, nil, 200, "AlertFeed"))
	if len(feed.Items) != 1 || feed.Items[0].Outcome != "would_block" || feed.Items[0].WouldBlockReason != "gateway_observe" {
		t.Fatalf("alerts: %+v", feed.Items)
	}
}

// TestBlockLongCount: a block_long annotation carries the ladder step as
// count (D36 open items: "wiederholt" = count >= 2).
func TestBlockLongCount(t *testing.T) {
	h := apptest.New(t, apptest.Options{})
	h.Login()
	h.App.Sites.Store(sites.NewView(websites.Input{Mode: websites.ModeIngress, Blocks: []websites.Block{
		{Addresses: []string{"shop.example"}, Schild: true},
	}}))
	now := time.Now().UTC().Truncate(time.Second)
	for i, lv := range []int{1, 3} {
		since := now.Add(-time.Duration(i+1) * time.Minute)
		if err := h.App.Store.PutBlock(context.Background(), events.ActiveBlock{ClientKey: fmt.Sprintf("203.0.113.%d", 70+i), KeyBits: 32, NetClass: "hosting",
			Source: "behaviour:login_bruteforce", Level: lv, DurationS: 86400 * 2, Since: since.Format(time.RFC3339),
			Until: since.Add(48 * time.Hour).Format(time.RFC3339), Incident: fmt.Sprintf("K7QM-4XB%d", 2+i)}); err != nil {
			t.Fatal(err)
		}
	}
	rng := "from=" + url.QueryEscape(now.Add(-time.Hour).Format(time.RFC3339)) + "&to=" + url.QueryEscape(now.Add(time.Minute).Format(time.RFC3339))
	al := decode[websites.AnnotationList](t, expect(t, h, "GET", "/websites/shop.example/annotations?"+rng, nil, 200, "AnnotationList"))
	got := map[string]int64{}
	for _, a := range al.Items {
		if a.Kind == websites.AnnBlockLong {
			got[a.Ref] = a.Count
		}
	}
	if len(got) != 2 || got["K7QM-4XB2"] != 1 || got["K7QM-4XB3"] != 3 {
		t.Fatalf("block_long counts: %v", got)
	}
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

// TestEventBreakdownFilters: listEvents net_class, method (OTHER) and
// ua_class (D36 amendment), the filters a breakdown row links to.
func TestEventBreakdownFilters(t *testing.T) {
	h := apptest.New(t, apptest.Options{})
	h.Login()
	send := func(method, ua, ip string) {
		req, _ := http.NewRequest(method, h.Proxy.URL+"/seite?x=%3Cscript%3Ealert(1)%3C%2Fscript%3E", nil)
		req.Host = "shop.example"
		req.Header.Set("X-Forwarded-For", ip)
		req.Header.Set("User-Agent", ua)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	const firefox = "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0"
	send("GET", firefox, "198.51.100.23")
	send("PROPFIND", firefox, "198.51.100.24")
	send("POST", "curl/8.5.0", "198.51.100.25")
	h.Flush()
	list := func(q string) []dashboard.EventSummary {
		t.Helper()
		return decode[dashboard.EventPage](t, expect(t, h, "GET", "/events?"+q, nil, 200, "EventPage")).Items
	}
	all := list("")
	if len(all) < 3 {
		t.Fatalf("events: %d", len(all))
	}
	if ev := list("method=OTHER"); len(ev) != 1 || ev[0].Method != "PROPFIND" {
		t.Fatalf("method OTHER: %+v", ev)
	}
	if ev := list("method=POST"); len(ev) != 1 || ev[0].Method != "POST" {
		t.Fatalf("method POST: %+v", ev)
	}
	if ev := list("ua_class=tool"); len(ev) != 1 || ev[0].Method != "POST" {
		t.Fatalf("ua_class tool: %+v", ev)
	}
	if ev := list("ua_class=browser"); len(ev) != 2 {
		t.Fatalf("ua_class browser: %+v", ev)
	}
	page := decode[dashboard.EventPage](t, expect(t, h, "GET", "/events?ua_class=browser&limit=1", nil, 200, "EventPage"))
	if len(page.Items) != 1 || page.NextCursor == nil {
		t.Fatalf("ua_class browser page: %+v", page)
	}
	if ev := list("ua_class=browser&cursor=" + *page.NextCursor); len(ev) != 1 || ev[0].ID == page.Items[0].ID {
		t.Fatalf("ua_class browser next page: %+v", ev)
	}
	nc := ""
	for _, e := range all {
		if e.Geo != nil && e.Geo.NetClass != "" {
			nc = e.Geo.NetClass
		}
	}
	if nc == "" {
		t.Fatal("no net class in the events")
	}
	if ev := list("net_class=" + nc); len(ev) < 3 {
		t.Fatalf("net_class %s: %d", nc, len(ev))
	}
	other := "tor"
	if nc == "tor" {
		other = "vpn"
	}
	if ev := list("net_class=" + other); len(ev) != 0 {
		t.Fatalf("net_class %s: %+v", other, ev)
	}
	expect(t, h, "GET", "/events?net_class=moon", nil, 400, "Problem")
	expect(t, h, "GET", "/events?ua_class=robot", nil, 400, "Problem")
	expect(t, h, "GET", "/events?method=get", nil, 400, "Problem")
}
