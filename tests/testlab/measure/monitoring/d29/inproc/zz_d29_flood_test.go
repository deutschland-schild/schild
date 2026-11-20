// TEST ONLY, measurement (D29 amendment). Copied by run-inproc.sh into a
// scratch copy of gateway/internal/behaviour (never into the repo's
// client module). A hosting client is driven up to the 7-day block with a
// fake clock, then 1M distinct addresses and 200k blocking addresses flood
// the engine. It reports whether the 7-day key's entry left the block table
// (eviction) and whether Check still blocks it, plus heap use.
package behaviour

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/contract/config"
	"github.com/deutschland-schild/schild/contract/events"
)

func d29req(t time.Time, ip, nc string) *Request {
	a := netip.MustParseAddr(ip)
	return &Request{Time: t, IP: a, Method: "GET", Host: "shop.test", Path: "/", UserAgent: "Mozilla/5.0",
		Client: events.Client{IP: ip, Attribution: "trusted_proxy", Geo: events.Geo{Country: "DE", ASN: 64601, NetClass: nc}}}
}

func d29offend(e *Engine, t time.Time, ip, nc string) {
	e.Observe(d29req(t, ip, nc), Outcome{Forwarded: true, WAFRules: []int{941100}})
	e.Observe(d29req(t.Add(time.Second), ip, nc), Outcome{Forwarded: true, WAFRules: []int{942100}})
}

func heapMB() float64 {
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return float64(m.HeapAlloc) / (1 << 20)
}

func TestD29FloodKeepsLongBlocks(t *testing.T) {
	b := config.Behaviour{PresetLimits: config.BehaviourOff}
	for _, id := range config.ScenarioIDs {
		b.Scenarios.Get(id).Mode = config.BehaviourObserve
	}
	b.Scenarios.Get(config.ScenarioWAFRepeat).Mode = config.BehaviourBlock
	now := time.Now()
	e := New(Config{Behaviour: b, InstalledAt: now.Add(-60 * 24 * time.Hour)})
	clk := now
	e.Now = func() time.Time { return clk }
	persisted := 0
	e.Sink.Persist = func(events.ActiveBlock) { persisted++ }
	const long, short = "10.1.0.80", "10.0.0.80"
	for step := 1; step <= 4; step++ {
		d29offend(e, clk, long, "hosting")
		bi, ok := e.ActiveBlock(netip.MustParseAddr(long))
		if !ok {
			t.Fatalf("step %d not blocked", step)
		}
		if step < 4 {
			clk = bi.Until.Add(time.Minute)
		}
	}
	d29offend(e, clk, short, "residential")
	key, _ := KeyOf(netip.MustParseAddr(long))
	inTable := func(k Key) bool {
		found := false
		e.blocks.with(k, false, func(b *blockState) { found = b != nil && b.until > clk.UnixNano() })
		return found
	}
	skey, _ := KeyOf(netip.MustParseAddr(short))
	res := map[string]any{"heap_mb_before": heapMB(), "long_in_table_before": inTable(key), "short_in_table_before": inTable(skey)}
	ip4 := func(base uint32, i int) string {
		x := base + uint32(i)
		return fmt.Sprintf("%d.%d.%d.%d", x>>24, x>>16&255, x>>8&255, x&255)
	}
	t0 := time.Now()
	for i := 0; i < 1_000_000; i++ { // 1M distinct addresses (crawl counting only)
		e.Observe(d29req(clk, ip4(10<<24|128<<16, i), "residential"), Outcome{Forwarded: true})
	}
	for i := 0; i < 200_000; i++ { // 200k blocking addresses
		d29offend(e, clk, ip4(10<<24|64<<16, i), "hosting")
	}
	c, bk, bl := e.Sizes()
	res["flood_seconds"] = time.Since(t0).Seconds()
	res["heap_mb_after"] = heapMB()
	res["sizes_clients_buckets_blocks"] = []int{c, bk, bl}
	res["block_table_evictions"] = e.blocks.evictions()
	res["client_table_evictions"] = e.clients.evictions()
	res["long_in_table_after"] = inTable(key)
	res["long_blocked_after"] = e.Check(d29req(clk, long, "hosting")).Block
	bi, ok := e.ActiveBlock(netip.MustParseAddr(long))
	res["long_active_block_after"] = ok
	res["long_duration_s_after"] = int(bi.Duration / time.Second)
	res["long_persisted_after"] = bi.Persisted
	res["short_in_table_after"] = inTable(skey)
	res["short_blocked_after"] = e.Check(d29req(clk, short, "residential")).Block
	res["kept_blocks_in_memory"] = len(e.LongBlocks())
	res["persist_calls"] = persisted
	out, _ := json.MarshalIndent(res, "", " ")
	t.Logf("%s", out)
	if p := os.Getenv("D29_FLOOD_OUT"); p != "" {
		_ = os.WriteFile(p, out, 0o644)
	}
}
