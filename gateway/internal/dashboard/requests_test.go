//go:build !release

package dashboard_test

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	cr "github.com/deutschland-schild/schild/contract/requests"
	"github.com/deutschland-schild/schild/contract/websites"
	"github.com/deutschland-schild/schild/gateway/internal/apptest"
	"github.com/deutschland-schild/schild/gateway/internal/monitoring"
	"github.com/deutschland-schild/schild/gateway/internal/reqring"
)

func rangeQ(from, to time.Time) string {
	return "from=" + url.QueryEscape(from.UTC().Format(time.RFC3339)) + "&to=" + url.QueryEscape(to.UTC().Format(time.RFC3339))
}

// TestRequestsTag: the MVP-22 operations end to end in observe mode. Five
// normal visitors browse and send a contact form whose field trips a CRS
// rule (a seeded false positive); a scanner sends only attacks. The hint
// flags the form rule on /kontakt with a narrow, website-scoped exception,
// the context of an alert shows the visitor's normal requests around it,
// and no ring file contains a replayed address.
func TestRequestsTag(t *testing.T) {
	h := apptest.New(t, apptest.Options{Mode: "observe"})
	h.Login()
	form := "nachricht=" + url.QueryEscape("Ich komme am Montag; bitte ' OR 1=1 -- nicht vergessen")
	var normal []string
	for i := 1; i <= 5; i++ {
		ip := fmt.Sprintf("198.51.100.%d", 10+i)
		normal = append(normal, ip)
		h.Visit("GET", "/", ip, "", "")
		h.Visit("GET", "/kontakt", ip, "", "")
		if r := h.Visit("POST", "/kontakt", ip, "application/x-www-form-urlencoded", form); r.StatusCode != 200 {
			t.Fatalf("observe mode answered %d", r.StatusCode)
		}
		h.Visit("GET", "/danke", ip, "", "")
	}
	scanner := "203.0.113.66"
	for _, p := range []string{"/?id=1%27%20OR%20%271%27=%271", "/admin?x=%3Cscript%3Ealert(1)%3C/script%3E", "/etc/passwd?f=../../../../etc/passwd"} {
		h.Visit("GET", p, scanner, "", "")
	}
	h.Flush()
	now := time.Now()
	rng := rangeQ(now.Add(-time.Hour), now.Add(time.Minute))

	// queryRequests: every request, newest first; filters.
	all := decode[cr.Page](t, expect(t, h, "GET", "/requests?"+rng+"&limit=500", nil, 200, "RequestPage"))
	if len(all.Items) != 23 || all.SampleRate != 1 {
		t.Fatalf("requests: %d %+v", len(all.Items), all.SampleRate)
	}
	wb := decode[cr.Page](t, expect(t, h, "GET", "/requests?"+rng+"&outcome=would_block&limit=500", nil, 200, "RequestPage"))
	if len(wb.Items) < 6 {
		t.Fatalf("would_block: %d", len(wb.Items))
	}
	var formAlert *cr.Record
	for i := range wb.Items {
		it := &wb.Items[i]
		if it.Path == "/kontakt" && it.Method == "POST" && it.EventID != "" {
			formAlert = it
		}
	}
	if formAlert == nil {
		t.Fatalf("no form alert: %+v", wb.Items)
	}
	expect(t, h, "GET", "/requests?"+rangeQ(now.Add(-7*time.Hour), now), nil, 400, "Problem")
	// D49: one address, over the whole ring, also from before its start.
	if all.Items[0].IP == "" {
		t.Fatal("a record without its address")
	}
	ip := all.Items[0].IP
	wide := decode[cr.Page](t, expect(t, h, "GET", "/requests?"+rangeQ(now.Add(-72*time.Hour), now.Add(time.Minute))+"&ip="+url.QueryEscape(ip)+"&limit=500", nil, 200, "RequestPage"))
	if len(wide.Items) == 0 {
		t.Fatal("no request of the address")
	}
	for _, x := range wide.Items {
		if x.IP != ip {
			t.Fatalf("%s in the list of %s", x.IP, ip)
		}
	}
	expect(t, h, "GET", "/requests?"+rng+"&ip=nope", nil, 400, "Problem")

	// Kontext of the form alert: the visitor's browsing around it.
	c := decode[cr.Context](t, expect(t, h, "GET", "/requests/context/"+formAlert.EventID, nil, 200, "RequestContext"))
	if c.State != "complete" || c.Anchor == nil || c.Anchor.EventID != formAlert.EventID || len(c.VisitorRequests) != 4 ||
		c.VisitorSummary == nil || c.VisitorSummary.Pattern != "in_session" || len(c.SiteStrip) == 0 {
		t.Fatalf("context: %+v", c)
	}
	if c.VisitorRequests[0].Path != "/" || c.VisitorRequests[3].Path != "/danke" {
		t.Fatalf("order: %+v", c.VisitorRequests)
	}
	expect(t, h, "GET", "/requests/context/00000000-0000-4000-8000-000000000000", nil, 404, "Problem")

	// Hints: the form rule on /kontakt, not the scanner's rules.
	hl := decode[cr.FalsePositiveHintList](t, expect(t, h, "GET", "/requests/alerts/hints", nil, 200, "FalsePositiveHintList"))
	var hint *cr.FalsePositiveHint
	for i := range hl.Items {
		x := &hl.Items[i]
		if x.Path != "/kontakt" {
			t.Fatalf("hint outside the form page: %+v", x)
		}
		hint = x
	}
	if hint == nil || hint.ClientsHit != 5 || hint.ClientsInSession != 5 || hint.Exception.Language != "seclang" ||
		!strings.Contains(hint.Exception.Snippet, "ctl:ruleRemove") || !strings.HasPrefix(hint.Exception.File, "rules.d/") {
		t.Fatalf("hints: %+v", hl.Items)
	}
	if hint.Target != "" && !strings.HasPrefix(hint.Target, "ARGS") {
		t.Fatalf("target %q", hint.Target)
	}
	ra := decode[cr.RuleAlerts](t, expect(t, h, "GET", "/requests/alerts/rules?"+rng, nil, 200, "RuleAlerts"))
	flagged := 0
	for _, it := range ra.Items {
		if it.PossibleFalsePositive {
			flagged++
		}
	}
	if ra.RingFrom == nil || len(ra.Items) == 0 || flagged == 0 {
		t.Fatalf("rule alerts: %+v", ra)
	}
	pa := decode[cr.PageAlerts](t, expect(t, h, "GET", "/requests/alerts/pages?"+rng, nil, 200, "PageAlerts"))
	review := false
	for _, it := range pa.Items {
		review = review || it.Path == "/kontakt" && it.Review
	}
	if !review {
		t.Fatalf("page alerts: %+v", pa.Items)
	}
	expect(t, h, "GET", "/requests/bots?"+rng, nil, 200, "BotOverview")

	// Combined filters within 48 h come from the ring.
	bd := decode[monitoring.TrafficBreakdown](t, expect(t, h, "GET", "/monitoring/traffic/breakdown?by=path&"+rng+"&filter=status_class:2xx&filter=method:POST", nil, 200, "TrafficBreakdown"))
	if bd.Source != "requests" || len(bd.Items) != 1 || bd.Items[0].Key != "/kontakt" || bd.Items[0].Requests != 5 {
		t.Fatalf("breakdown: %+v", bd)
	}
	k := decode[websites.Kpis](t, expect(t, h, "GET", "/websites/default/kpis?"+rng+"&filter=path:/kontakt&filter=method:POST", nil, 200, "WebsiteKpis"))
	if k.Source != "requests" || k.Current.Requests.Value == nil || *k.Current.Requests.Value != 5 || *k.Current.WouldBlock.Value != 5 {
		t.Fatalf("kpis: %+v", k.Current)
	}
	expect(t, h, "GET", "/monitoring/series?metric=traffic.requests&"+rng+"&filter=path:/kontakt&filter=method:POST", nil, 200, "SeriesResult")

	// Privacy: no replayed address, /24 or /64 in any ring file.
	h.App.Requests.Flush()
	dir := filepath.Join(h.Dir, "data", reqring.Dir)
	files, _ := filepath.Glob(filepath.Join(dir, "*"))
	if len(files) == 0 {
		t.Fatal("no ring files in " + dir)
	}
	needles := []string{scanner, "203.0.113.", "198.51.100.", "/24", "/64"}
	needles = append(needles, normal...)
	for _, f := range files {
		b, _ := os.ReadFile(f)
		for _, n := range needles {
			if bytes.Contains(b, []byte(n)) {
				t.Fatalf("%s contains %q", filepath.Base(f), n)
			}
		}
	}
}

// TestRequestsOff: without the ring every operation answers 409
// requests_off (never 404) and combined filters 409 filter_unavailable.
func TestRequestsOff(t *testing.T) {
	h := apptest.New(t, apptest.Options{Extra: "monitoring:\n  requests:\n    enabled: false\n"})
	h.Login()
	now := time.Now()
	rng := rangeQ(now.Add(-time.Hour), now)
	for _, p := range []string{"/requests?" + rng, "/requests/context/00000000-0000-4000-8000-000000000000", "/requests/bots", "/requests/alerts/hints"} {
		if b := expect(t, h, "GET", p, nil, 409, "Problem"); !strings.Contains(string(b), `"requests_off"`) {
			t.Fatalf("%s: %s", p, b)
		}
	}
	expect(t, h, "GET", "/monitoring/traffic/breakdown?by=path&"+rng+"&filter=status_class:2xx", nil, 409, "Problem")
}

// TestSpoofedBotNeverVerified: a Googlebot user agent from an address
// outside Google's published ranges is "mismatch" in the ring and the bot
// overview ("gibt sich als ... aus"), never verified.
func TestSpoofedBotNeverVerified(t *testing.T) {
	h := apptest.New(t, apptest.Options{})
	h.Login()
	for _, ip := range []string{"203.0.113.99", "2001:db8::99"} {
		req, _ := http.NewRequest("GET", h.Proxy.URL+"/produkte", nil)
		req.Host = "shop.example"
		req.Header.Set("X-Forwarded-For", ip)
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	h.Flush()
	now := time.Now()
	rng := rangeQ(now.Add(-time.Hour), now.Add(time.Minute))
	p := decode[cr.Page](t, expect(t, h, "GET", "/requests?"+rng+"&bot=googlebot", nil, 200, "RequestPage"))
	if len(p.Items) != 2 {
		t.Fatalf("googlebot requests: %+v", p.Items)
	}
	for _, it := range p.Items {
		if it.Verification != "mismatch" || it.BotCategory != "search_engine" {
			t.Fatalf("spoofed googlebot: %+v", it)
		}
	}
	o := decode[cr.BotOverview](t, expect(t, h, "GET", "/requests/bots?"+rng, nil, 200, "BotOverview"))
	found := false
	for _, b := range o.Bots {
		if b.ID == "googlebot" {
			found = true
			if b.Verification.Verified != 0 || b.Verification.Mismatch != 2 {
				t.Fatalf("overview: %+v", b)
			}
		}
	}
	if !found || !o.Verification.Ranges || o.Verification.FCrDNS || !o.Verification.RangesFetch || len(o.Ranges) == 0 { // fetch on by default (D67)
		t.Fatalf("overview: %+v", o)
	}
	bd := decode[monitoring.TrafficBreakdown](t, expect(t, h, "GET", "/monitoring/traffic/breakdown?by=bot_category&"+rng, nil, 200, "TrafficBreakdown"))
	if bd.BotVerification == nil || !*bd.BotVerification {
		t.Fatalf("bot_verification: %+v", bd.BotVerification)
	}
}
