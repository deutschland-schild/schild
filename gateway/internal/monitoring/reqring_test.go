package monitoring

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/contract/msg"
	"github.com/deutschland-schild/schild/gateway/internal/reqring"
)

// The MVP-22 request ring on the request path: building the entry and the
// non-blocking send allocate nothing; a full channel drops.
func TestRecordWithRingDoesNotAllocate(t *testing.T) {
	ring, err := reqring.New(reqring.Config{StoragePath: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer ring.Close()
	rc := newRecorder(time.Now())
	rc.ring = ring
	r := newReq("/blog/my-post", chromeUA, "https://www.google.com/search")
	q := Req{R: r, Class: Forwarded, Status: 200, Timed: true, Total: 3 * time.Millisecond, UpstreamDur: 2 * time.Millisecond,
		Client: netip.MustParseAddr("192.0.2.10"), Country: "DE", ASN: 3320, ASOrg: "Deutsche Telekom", NetClass: "residential",
		EventID: msg.NewID(), Start: time.Now(), RingRules: [3]string{"942100"}, NRingRules: 1, Score: 5, WouldBlock: true, WBReason: "gateway_observe"}
	for i := 0; i < len(rc.shards)*2; i++ {
		rc.record(&q)
	}
	if n := testing.AllocsPerRun(20000, func() { rc.record(&q) }); n != 0 {
		t.Errorf("Record with the request ring allocates %.1f times per request", n)
	}
	if ring.Dropped() == 0 {
		t.Fatal("the channel never filled without a writer")
	}
}

// The ring sees what the counters see: outcome, site, template, visitor.
func TestRecordFeedsRing(t *testing.T) {
	ring, err := reqring.New(reqring.Config{StoragePath: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer ring.Close()
	rc := newRecorder(time.Now())
	rc.ring = ring
	now := time.Now()
	ev := msg.NewID()
	q := Req{R: newReq("/user/12345/edit", chromeUA, "https://chatgpt.com/"), Class: BlockedWAF, Status: 403, Total: time.Millisecond,
		Client: netip.MustParseAddr("192.0.2.10"), Country: "AT", ASN: 1, EventID: ev, Start: now, RingRules: [3]string{"941100", "942100"}, NRingRules: 2, Score: 10, Detection: true}
	rc.record(&q)
	ring.Flush()
	p, err := ring.Query(context.Background(), reqring.QueryParams{From: now.Add(-time.Minute), To: now.Add(time.Minute), Filter: reqring.AnyFilter()}, now)
	if err != nil || len(p.Items) != 1 {
		t.Fatalf("%+v %v", p, err)
	}
	it := p.Items[0]
	if it.Outcome != "blocked_waf" || it.EventID != ev || it.Path != "/user/{n}/edit" || it.Country != "AT" || it.Referrer != "ai:chatgpt" ||
		it.AnomalyScore != 10 || len(it.Rules) != 2 || it.Browser != "chrome" || it.PageView {
		t.Fatalf("%+v", it)
	}
}

func BenchmarkRecordWithRing(b *testing.B) {
	ring, err := reqring.New(reqring.Config{StoragePath: b.TempDir()})
	if err != nil {
		b.Fatal(err)
	}
	ring.Start(context.Background())
	defer ring.Close()
	for _, on := range []bool{false, true} {
		name := "ring_off"
		if on {
			name = "ring_on"
		}
		b.Run(name, func(b *testing.B) {
			rc := newRecorder(time.Now())
			if on {
				rc.ring = ring
			}
			r := newReq("/blog/my-post", chromeUA, "https://www.google.com/search")
			q := Req{R: r, Class: Forwarded, Status: 200, Timed: true, Total: 3 * time.Millisecond, Client: netip.MustParseAddr("192.0.2.10"),
				Country: "DE", ASN: 3320, NetClass: "residential", Start: time.Now()}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				rc.record(&q)
			}
		})
	}
}

// D64: ip and user_agent filter the request ring like any dimension, and
// only the request ring answers them.
func TestRingFiltersIPAndUserAgent(t *testing.T) {
	ring, err := reqring.New(reqring.Config{StoragePath: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer ring.Close()
	rc := newRecorder(time.Now())
	rc.ring = ring
	now := time.Now()
	add := func(path, ua, ip string) {
		q := Req{R: newReq(path, ua, ""), Class: Forwarded, Status: 200, Total: time.Millisecond,
			Client: netip.MustParseAddr(ip), Country: "DE", Start: now}
		rc.record(&q)
	}
	add("/a", chromeUA, "192.0.2.10")
	add("/b", chromeUA, "192.0.2.10")
	add("/a", "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)", "198.51.100.7")
	ring.Flush()

	fs, err := ParseFilters([]string{"ip:::ffff:192.0.2.10", "user_agent:BingBot"})
	if err != nil || fs[0].Value != "192.0.2.10" || fs[1].Value != "bingbot" || !ringOnly(fs[:1]) {
		t.Fatalf("%+v %v", fs, err)
	}
	if _, err := ParseFilters([]string{"ip:nope"}); err == nil {
		t.Fatal("ip:nope parsed")
	}
	ctx := context.Background()
	from, to := now.Add(-time.Minute), now.Add(time.Minute)
	for _, c := range []struct {
		f    []Filter
		want float64
	}{
		{fs[:1], 2},
		{fs[1:], 1},
		{fs, 0},
		{[]Filter{{"ip", "192.0.2.10"}, {"path", "/a"}}, 1},
	} {
		k, err := ring.Kpis(ctx, "", from, to, dimFilters(c.f))
		if err != nil || k.Requests.Value == nil || *k.Requests.Value != c.want {
			t.Errorf("%+v: %+v %v", c.f, k.Requests, err)
		}
	}
	b, err := ring.Breakdown(ctx, "path", "", from, to, dimFilters(fs[:1]), 10)
	if err != nil || len(b.Items) != 2 {
		t.Fatalf("%+v %v", b, err)
	}

	// D65: addresses and User-Agents as breakdowns; a key filters again.
	b, err = ring.Breakdown(ctx, "ip", "", from, to, dimFilters([]Filter{{"path", "/a"}}), 10)
	if err != nil || len(b.Items) != 2 || b.Items[0].Key != "192.0.2.10" || b.Items[0].Requests != 1 || b.Total[0] != 2 {
		t.Fatalf("by ip: %+v %v", b, err)
	}
	b, err = ring.Breakdown(ctx, "user_agent", "", from, to, nil, 10)
	if err != nil || len(b.Items) != 2 || b.Items[0].Key != chromeUA || b.Items[0].Requests != 2 {
		t.Fatalf("by user_agent: %+v %v", b, err)
	}
	ua, err := ParseFilters([]string{"user_agent:" + b.Items[1].Key})
	if err != nil {
		t.Fatal(err)
	}
	if k, err := ring.Kpis(ctx, "", from, to, dimFilters(ua)); err != nil || *k.Requests.Value != 1 {
		t.Errorf("filter from key: %+v %v", k.Requests, err)
	}
}
