package monitoring

import (
	"fmt"
	"math/rand/v2"
	"net/netip"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	cm "github.com/deutschland-schild/schild/contract/monitoring"

	"github.com/deutschland-schild/schild/gateway/internal/pathtpl"
)

// checkBound: requests - error <= truth <= requests (TopEntry.error is the
// maximum overcount).
func checkBound(t *testing.T, what string, e cm.TopEntry, truth int64) {
	t.Helper()
	if truth > e.Requests || truth < e.Requests-e.Error {
		t.Errorf("%s %s: truth %d outside [%d, %d] (requests %d, error %d)", what, e.Key, truth, e.Requests-e.Error, e.Requests, e.Requests, e.Error)
	}
}

// Space-saving tables keep their bound through shard merges, also when the
// merged tables were full (MVP-21 measurement finding 3b).
func TestTopTableBoundAcrossMerges(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	z := rand.NewZipf(rng, 1.1, 1, 4999)
	truth := map[string]int64{}
	minute := newTopTable(2 * cm.TopK)
	for sec := 0; sec < 60; sec++ {
		var shards [nShards]*topTable
		for i := range shards {
			shards[i] = newTopTable(2 * cm.TopK)
		}
		for i := 0; i < 4000; i++ {
			k := fmt.Sprintf("/w/%d", z.Uint64())
			truth[k]++
			shards[i%nShards].add(k, "", 1, 0, 0, 0, 0)
		}
		for _, s := range shards {
			minute.merge(s)
		}
	}
	for _, e := range minute.top(cm.TopK, false) {
		checkBound(t, "minute", e, truth[e.Key])
	}
	// A key that is not listed counted at most the floor.
	listed := map[string]bool{}
	for _, e := range minute.entries {
		listed[e.key] = true
	}
	for k, n := range truth {
		if !listed[k] && n > minute.floor {
			t.Fatalf("unlisted %s counted %d > floor %d", k, n, minute.floor)
		}
	}
}

// getTrafficBreakdown over several 1 min buckets: every entry keeps its
// bound, also keys that a bucket's list did not name; the top 10 match.
func TestBreakdownBoundAcrossBuckets(t *testing.T) {
	now := time.Now().UTC().Truncate(10 * time.Minute).Add(-30 * time.Minute)
	m := newTestMonitor(t, now.Add(-time.Second))
	rng := rand.New(rand.NewPCG(3, 4))
	zp := rand.NewZipf(rng, 1.05, 1, 4999)
	za := rand.NewZipf(rng, 1.01, 1, 255)
	truthPath := map[string]int64{}
	truthASN := map[string]int64{}
	ip := netip.MustParseAddr("198.51.100.4")
	const minutes = 4
	for s := 1; s <= minutes*60; s++ {
		at := now.Add(time.Duration(s) * time.Second)
		for i := 0; i < 400; i++ {
			p := fmt.Sprintf("/w/k%dx", zp.Uint64())
			asn := uint32(64512 + za.Uint64())
			truthPath[pathtpl.Template(p)]++
			truthASN[asnKey(asn)]++
			m.Record(&Req{R: newReq(p, chromeUA, ""), Class: Forwarded, Status: 200, Client: ip, Country: "DE", ASN: asn, NetClass: "residential"})
		}
		m.Tick(at)
		m.flushWrites()
	}
	end := now.Add(minutes * 60 * time.Second)
	for _, by := range []string{"path", "asn"} {
		truth := truthPath
		if by == "asn" {
			truth = truthASN
		}
		bd, err := m.Breakdown(by, now, end, "", nil, 64, end)
		if err != nil {
			t.Fatal(err)
		}
		if bd.Exact || len(bd.Items) == 0 {
			t.Fatalf("%s: %+v", by, bd)
		}
		for _, e := range bd.Items {
			checkBound(t, by, e, truth[e.Key])
		}
		// Top 10 by truth vs the shown top 10.
		top := topKeys(truth, 10)
		shown := map[string]bool{}
		for _, e := range bd.Items[:10] {
			shown[e.Key] = true
		}
		overlap := 0
		for _, k := range top {
			if shown[k] {
				overlap++
			}
		}
		if overlap < 9 {
			t.Errorf("%s: top-10 overlap %d", by, overlap)
		}
	}
}

// Memory stays flat with millions of distinct long paths, user agents and
// referrers (MVP-21 measurement finding 4: raw paths as cache keys reached
// 1.2 GB and an OOM kill).
func TestMemoryFlatWithDistinctLongInputs(t *testing.T) {
	n := 1_000_000
	if testing.Short() {
		n = 200_000
	}
	now := time.Now().UTC().Truncate(10 * time.Minute).Add(-30 * time.Minute)
	m := newTestMonitor(t, now.Add(-time.Second))
	long := strings.Repeat("a", 1200)
	r := newReq("/", chromeUA, "")
	q := Req{R: r, Class: Forwarded, Status: 200, Timed: true, Client: netip.MustParseAddr("198.51.100.4"), Country: "DE", NetClass: "residential"}
	heap := func() uint64 {
		runtime.GC()
		var ms runtime.MemStats
		runtime.ReadMemStats(&ms)
		return ms.HeapAlloc
	}
	base := heap()
	var warm, peak uint64
	sec := 0
	for i := 0; i < n; i++ {
		is := strconv.Itoa(i)
		if i%2 == 0 {
			// long (lengths and last bytes vary, so every cache stripe is
			// hit): template of the first bytes, never a cache key
			r.URL.Path = "/p" + is + "x/" + long[:1100+i%61] + string(rune('a'+i%26))
		} else {
			r.URL.Path = "/s/" + is + "q/x" // short and distinct: cached, bounded
		}
		r.URL.RawPath = ""
		r.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/131."+is+" "+long[:200])
		r.Header.Set("Referer", "https://h"+is+".example"+strconv.Itoa(i%7)+".org/"+long[:100])
		q.ASN = uint32(64512 + i%100000)
		q.Client = netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})
		m.Record(&q)
		if i%5000 == 4999 {
			sec++
			m.Tick(now.Add(time.Duration(sec) * time.Second))
			m.flushWrites()
		}
		if i%(n/10) == n/10-1 {
			h := heap()
			peak = max(peak, h)
			if warm == 0 {
				warm = h
			}
		}
	}
	end := heap()
	t.Logf("heap: base %.1f MiB, after %d %.1f MiB, peak %.1f MiB, after %d %.1f MiB", float64(base)/(1<<20), n/10, float64(warm)/(1<<20), float64(peak)/(1<<20), n, float64(end)/(1<<20))
	// The caches are bounded at 2 MiB each and the top tables hold short
	// templates: far below the 32 MiB budget of the spec.
	if peak > base+8<<20 {
		t.Errorf("monitoring heap grew by %.1f MiB (expected < 8 MiB, budget 32 MiB)", float64(peak-base)/(1<<20))
	}
	if end > warm+4<<20 {
		t.Errorf("heap not flat: %.1f MiB after %d, %.1f MiB after %d", float64(warm)/(1<<20), n/10, float64(end)/(1<<20), n)
	}
}

// The first bucket after a start covers only the time since the start; its
// rate divides by that span, not by the full step (MVP-21 measurement
// finding 9).
func TestPartialBucketRateUsesCoveredSpan(t *testing.T) {
	minute := time.Now().UTC().Truncate(time.Hour).Add(-2 * time.Hour)
	started := minute.Add(45 * time.Second) // 15 s of the minute are covered
	m := newTestMonitor(t, started)
	for s := 46; s <= 120; s++ {
		for i := 0; i < 10; i++ { // 10 requests per second
			m.Record(&Req{R: newReq("/", chromeUA, ""), Class: Forwarded, Status: 200})
		}
		m.Tick(minute.Add(time.Duration(s) * time.Second))
		m.flushWrites()
	}
	res, err := m.Series(SeriesQuery{Metrics: []string{"traffic.requests:rate", "traffic.requests:sum"}, From: minute, To: minute.Add(2 * time.Minute), Resolution: "1m"}, minute.Add(2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	rate, sum := res.Series[0].Values, res.Series[1].Values
	if len(rate) != 2 || rate[0] == nil || rate[1] == nil {
		t.Fatalf("series %+v", res.Series[0])
	}
	// 15 s x 10 requests in the partial minute, 60 s x 10 in the full one.
	if *sum[0] != 150 || *rate[0] != 10 || *rate[1] != 10 {
		t.Errorf("partial minute: sum %v rate %v, full minute rate %v (want 150, 10, 10)", *sum[0], *rate[0], *rate[1])
	}
	if len(res.Restarts) != 1 {
		t.Errorf("restarts %v", res.Restarts)
	}
}

func topKeys(m map[string]int64, k int) []string {
	type kv struct {
		k string
		v int64
	}
	var all []kv
	for key, v := range m {
		all = append(all, kv{key, v})
	}
	for i := 0; i < len(all) && i < k; i++ {
		b := i
		for j := i + 1; j < len(all); j++ {
			if all[j].v > all[b].v || (all[j].v == all[b].v && all[j].k < all[b].k) {
				b = j
			}
		}
		all[i], all[b] = all[b], all[i]
	}
	out := []string{}
	for i := 0; i < len(all) && i < k; i++ {
		out = append(out, all[i].k)
	}
	return out
}

// One answer holds at most maxSeries series (SeriesResult.series maxItems),
// however many objects the per-object metrics have.
func TestSeriesCapped(t *testing.T) {
	minute := time.Now().UTC().Truncate(time.Hour).Add(-2 * time.Hour)
	m := newTestMonitor(t, minute)
	s := &sample{at: minute}
	for i := 0; i < 40; i++ {
		s.objects = append(s.objects, objectSample{object: fmt.Sprintf("/m%02d", i), kind: "mount"},
			objectSample{object: fmt.Sprintf("eth%02d", i), kind: "interface"})
	}
	m.last.Store(s)
	metrics := []string{"server.disk_used", "server.disk_used_ratio", "server.disk_inodes_used_ratio",
		"server.net_rx_bytes", "server.net_tx_bytes", "server.net_errors", "server.net_drops"}
	res, err := m.Series(SeriesQuery{Metrics: metrics, From: minute, To: minute.Add(2 * time.Minute), Resolution: "1m"}, minute.Add(2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Series) != maxSeries {
		t.Fatalf("%d series, want %d", len(res.Series), maxSeries)
	}
}

// A range reaching far into the past or future walks no more than the
// buckets the 1 min ring can refill (getWebsiteKpis only checks from < to).
func TestFillFarRangeIsCheap(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Hour)
	m := newTestMonitor(t, now)
	from := time.Date(1, 1, 1, 0, 0, 0, 0, time.UTC)
	to := time.Date(9999, 12, 31, 0, 0, 0, 0, time.UTC)
	start := time.Now()
	if _, err := m.Kpis("", from, to, nil, now); err != nil {
		t.Fatal(err)
	}
	var cov coverage
	if err := m.readFilled(from, to, now, readParts{}, true, &cov, func(time.Time, *cm.MetricBucket) {}); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("reads over years 1 to 9999 took %v", d)
	}
}
