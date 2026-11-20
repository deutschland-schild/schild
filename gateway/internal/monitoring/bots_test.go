package monitoring

import (
	"net/netip"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/contract/config"
	cm "github.com/deutschland-schild/schild/contract/monitoring"
	"github.com/deutschland-schild/schild/contract/msg"
	"github.com/deutschland-schild/schild/gateway/internal/bots"
)

// googleAddr returns an address inside the shipped googlebot snapshot.
func googleAddr(t *testing.T) netip.Addr {
	t.Helper()
	for _, r := range bots.Default().Catalogue().Ranges {
		if r.ID == "googlebot" {
			for _, s := range r.Prefixes {
				if p := netip.MustParsePrefix(s); p.Addr().Is4() {
					return p.Addr().Next()
				}
			}
		}
	}
	t.Fatal("no googlebot prefix")
	return netip.Addr{}
}

const googlebotUA = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"

func uaClassCounts(rc *recorder) [6]int64 {
	var out [6]int64
	for i := range rc.shards {
		for c := range out {
			out[c] += rc.shards[i].cur.dims.uaClass[c][0]
		}
	}
	return out
}

// A Googlebot from Google's published range counts as bot_verified, the
// same User-Agent from elsewhere as bot_unverified; the bot category stays
// search_engine either way. The monitor's engine is the one UseBots set.
func TestRecordBotVerification(t *testing.T) {
	cat := bots.Default().Catalogue()
	gen, err := msg.ParseTime(cat.GeneratedAt)
	if err != nil {
		t.Fatal(err)
	}
	now := gen.Add(time.Hour)
	e, err := bots.NewFromCatalogue(cat, config.Bots{}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	m := &Monitor{rec: newRecorder(now)}
	m.UseBots(e)
	if m.Bots() != e {
		t.Fatal("UseBots")
	}
	rc := m.rec
	in, out := googleAddr(t), netip.MustParseAddr("192.0.2.10")
	q := Req{R: newReq("/", googlebotUA, ""), Class: Forwarded, Status: 200, Client: in}
	rc.record(&q)
	q.Client = out
	rc.record(&q)
	q.Client = in
	q.R = newReq("/", chromeUA, "")
	rc.record(&q)
	got := uaClassCounts(rc)
	if got[uaBotVerified] != 1 || got[uaBotUnverified] != 1 || got[uaBrowser] != 1 {
		t.Errorf("ua_class counts %v", got)
	}
	bi := m.ClassifyBot(googlebotUA, in)
	if b := e.Bot(bi.ID); b == nil || b.ID != "googlebot" || cm.BotCategories[bi.Category] != "search_engine" || bi.Verification != bots.VerVerified {
		t.Errorf("ClassifyBot from the range: %+v", bi)
	}
	if bi := m.ClassifyBot(googlebotUA, netip.MustParseAddr("2001:db8::1")); bi.Verification != bots.VerMismatch {
		t.Errorf("ClassifyBot spoofed IPv6: %+v", bi)
	}
	if bi := m.ClassifyBot(chromeUA, in); bi.ID != 0 || bi.Verification != bots.VerNone || cm.BotCategories[bi.Category] != "likely_browser" {
		t.Errorf("ClassifyBot browser: %+v", bi)
	}
}

// Recording a verified bot request (address in the range) does not allocate.
func TestRecordVerifiedBotDoesNotAllocate(t *testing.T) {
	rc := newRecorder(time.Now())
	q := Req{R: newReq("/robots.txt", googlebotUA, ""), Class: Forwarded, Status: 200, Timed: true, Client: googleAddr(t), Country: "US", ASN: 15169, ASOrg: "Google LLC", NetClass: "hosting"}
	for i := 0; i < len(rc.shards)*2; i++ {
		rc.record(&q)
	}
	if n := testing.AllocsPerRun(1000, func() { rc.record(&q) }); n != 0 {
		t.Errorf("Record of a bot allocates %.1f times per request", n)
	}
}
