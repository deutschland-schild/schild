//go:build spec21measure

// MVP-21 measurement (TEST ONLY): in-process numbers of the monitoring
// package. Not part of the product; run.sh copies this file into a scratch
// copy of gateway/internal/monitoring and runs it there with
// -tags spec21measure.
package monitoring

import (
	"database/sql"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/contract/config"
	cm "github.com/deutschland-schild/schild/contract/monitoring"
	"github.com/deutschland-schild/schild/contract/websites"
	"github.com/deutschland-schild/schild/gateway/internal/sites"
)

// measureSites: the website registry the gateway has in ingress mode (D36);
// shop.example is the website of every simulated request.
func measureSites(t testing.TB) *sites.Registry {
	v := sites.NewView(websites.Input{Mode: websites.ModeIngress, Blocks: []websites.Block{
		{Addresses: []string{"shop.example"}, Schild: true},
		{Addresses: []string{"blog.example"}, Schild: true},
	}})
	if v.Err != nil {
		t.Fatal(v.Err)
	}
	return sites.NewRegistry(v)
}

func mreq(path, ua, ref string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "http://shop.example"+path, nil)
	r.Header.Set("User-Agent", ua)
	r.Header.Set("Referer", ref)
	r.Header.Set("Accept", "text/html,application/xhtml+xml")
	return r
}

func commonReq() Req {
	return Req{R: mreq("/products/123", chromeUA, "https://www.google.com/search?q=x"), Class: Forwarded, Status: 200, Timed: true,
		Total: 3 * time.Millisecond, UpstreamDur: 2 * time.Millisecond, BytesOut: 12000,
		Client: netip.MustParseAddr("198.51.100.10"), Country: "DE", ASN: 3320, ASOrg: "Deutsche Telekom AG", NetClass: "residential"}
}

func BenchmarkMeasureRecordCommon(b *testing.B) {
	rc := newRecorder(time.Now())
	q := commonReq()
	for i := 0; i < 64; i++ {
		rc.record(&q)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rc.record(&q)
	}
}

func BenchmarkMeasureRecordParallel(b *testing.B) {
	rc := newRecorder(time.Now())
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		q := commonReq()
		for i := 0; i < 64; i++ {
			rc.record(&q)
		}
		for pb.Next() {
			rc.record(&q)
		}
	})
}

// Distinct client addresses (new for the Bloom filters and HLL), same path.
func BenchmarkMeasureRecordDistinctClients(b *testing.B) {
	rc := newRecorder(time.Now())
	q := commonReq()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		q.Client = netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})
		rc.record(&q)
	}
}

// Distinct paths: template cache miss and top-K eviction on every request.
func BenchmarkMeasureRecordDistinctPaths(b *testing.B) {
	rc := newRecorder(time.Now())
	reqs := make([]*http.Request, 4096)
	for i := range reqs {
		reqs[i] = mreq("/w/p"+strconv.Itoa(i)+"x", chromeUA, "")
	}
	q := commonReq()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		q.R = reqs[i%len(reqs)]
		rc.record(&q)
	}
}

func TestMeasureAllocs(t *testing.T) {
	rc := newRecorder(time.Now())
	q := commonReq()
	for i := 0; i < 64; i++ {
		rc.record(&q)
	}
	t.Logf("allocs/op common (warm): %.2f", testing.AllocsPerRun(5000, func() { rc.record(&q) }))
	i := 0
	t.Logf("allocs/op new client each time: %.2f", testing.AllocsPerRun(5000, func() {
		i++
		q.Client = netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})
		rc.record(&q)
	}))
	det := commonReq()
	det.WouldBlock, det.Detection, det.Rules = true, true, []string{"941100", "941110", "941160", "949110", "980170"}
	for k := 0; k < 64; k++ {
		rc.record(&det)
	}
	t.Logf("allocs/op detection with 5 rules (warm): %.2f", testing.AllocsPerRun(5000, func() { rc.record(&det) }))
	paths := make([]*http.Request, 20000)
	for k := range paths {
		paths[k] = mreq("/w/q"+strconv.Itoa(k)+"z", chromeUA, "")
	}
	j := 0
	t.Logf("allocs/op distinct path each time: %.2f", testing.AllocsPerRun(5000, func() {
		j++
		q.R = paths[j%len(paths)]
		rc.record(&q)
	}))
	refs := make([]*http.Request, 20000)
	for k := range refs {
		refs[k] = mreq("/", chromeUA, "https://r"+strconv.Itoa(k)+".example.org/")
	}
	t.Logf("allocs/op distinct referrer each time: %.2f", testing.AllocsPerRun(5000, func() {
		j++
		q.R = refs[j%len(refs)]
		rc.record(&q)
	}))
}

func heapMiB() float64 {
	runtime.GC()
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return float64(ms.HeapInuse) / (1 << 20)
}

func newMeasureMonitor(t *testing.T, dir string, now time.Time) *Monitor {
	t.Helper()
	m, err := New(Config{StoragePath: dir, Keep: config.MonitoringKeep{TenSecondsHours: 6, MinuteHours: 48, TenMinuteDays: 14},
		Sampler: SamplerConfig{Root: fixtureRoot(t), Linux: true, Host: true, Started: now, Version: "test"},
		Sites:   measureSites(t),
		Internals: func(bool) Internals {
			return Internals{EventQueueUsed: 3, EventQueueCapacity: 8192, EvalSlotsUsed: 1, EvalSlotsMax: 16, StoreBytes: 1 << 20, StoreMaxBytes: 500 << 20}
		},
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// Memory under floods: 1 million distinct paths, addresses, user agents
// and referrer hosts at 10 000 requests per simulated second, then long
// distinct paths (the template cache keeps raw paths as keys).
func TestMeasureMemoryFlood(t *testing.T) {
	base := heapMiB()
	now := time.Date(2026, 10, 29, 0, 0, 0, 0, time.UTC)
	m := newMeasureMonitor(t, t.TempDir(), now)
	defer m.Close()
	afterNew := heapMiB()
	t.Logf("heap before New %.1f MiB, after New %.1f MiB (monitor baseline %.1f MiB)", base, afterNew, afterNew-base)
	const n = 1_000_000
	q := commonReq()
	peak := 0.0
	sec := now
	for i := 0; i < n; i++ {
		r := httptest.NewRequest(http.MethodGet, "http://shop.example/f/p"+strconv.Itoa(i)+"q", nil)
		r.Header.Set("User-Agent", "FloodAgent/"+strconv.Itoa(i))
		r.Header.Set("Referer", "https://r"+strconv.Itoa(i)+".example-"+strconv.Itoa(i)+".org/")
		q.R = r
		q.Client = netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})
		q.ASN = uint32(100000 + i)
		q.ASOrg = "Flood AS " + strconv.Itoa(i)
		m.Record(&q)
		if i%10000 == 9999 {
			sec = sec.Add(time.Second)
			m.Tick(sec)
			m.flushWrites()
		}
		if i%100000 == 99999 {
			h := heapMiB()
			peak = max(peak, h)
			t.Logf("after %d distinct: heap %.1f MiB (monitor %.1f MiB)", i+1, h, h-base)
		}
	}
	for k := 0; k < 700; k++ { // close the 10 min bucket
		sec = sec.Add(time.Second)
		m.Tick(sec)
		m.flushWrites()
	}
	t.Logf("after 1M distinct and bucket close: heap %.1f MiB (monitor %.1f MiB), peak monitor %.1f MiB", heapMiB(), heapMiB()-base, peak-base)
	for _, L := range []int{1024, 8192, 32768} {
		cnt := 40000
		for i := 0; i < cnt; i++ {
			p := "/long/" + strconv.Itoa(i) + "/" + strings.Repeat("y", L)
			r := httptest.NewRequest(http.MethodGet, "http://shop.example"+p, nil)
			r.Header.Set("User-Agent", chromeUA)
			q.R = r
			m.Record(&q)
			if i%10000 == 9999 {
				sec = sec.Add(time.Second)
				m.Tick(sec)
				m.flushWrites()
			}
		}
		h := heapMiB()
		t.Logf("after %d distinct paths of %d bytes: heap %.1f MiB (monitor %.1f MiB)", cnt, L, h, h-base)
	}
	// MVP-21 fix round 1: millions of distinct long paths, user agents and
	// referrers at once (2 KiB path, 1 KiB UA, 1 KiB referrer host part).
	nLong := 2_000_000
	if v, _ := strconv.Atoi(os.Getenv("MVP21_LONG_N")); v > 0 {
		nLong = v
	}
	padP, padU, padR := strings.Repeat("p", 2048), strings.Repeat("u", 1024), strings.Repeat("r", 1000)
	for i := 0; i < nLong; i++ {
		is := strconv.Itoa(i)
		r := httptest.NewRequest(http.MethodGet, "http://shop.example/l/"+is+"/"+padP, nil)
		r.Header.Set("User-Agent", "Mozilla/5.0 LongAgent/"+is+" "+padU)
		r.Header.Set("Referer", "https://"+padR[:60]+is+"."+padR[:60]+".example/"+padR)
		q.R = r
		q.Client = netip.AddrFrom4([4]byte{11, byte(i >> 16), byte(i >> 8), byte(i)})
		m.Record(&q)
		if i%10000 == 9999 {
			sec = sec.Add(time.Second)
			m.Tick(sec)
			m.flushWrites()
		}
		if i%250000 == 249999 {
			h := heapMiB()
			t.Logf("long distinct path+UA+referrer %d: heap %.1f MiB (monitor %.1f MiB)", i+1, h, h-base)
		}
	}
	runtime.KeepAlive(m)
}

// Fourteen simulated days at 1 s ticks with high-cardinality traffic and
// a host sample every 10 s: metrics.db size once every ring is full.
func TestMeasureFourteenDays(t *testing.T) {
	dir := os.Getenv("MVP21_SIM_DIR")
	if dir == "" {
		dir = t.TempDir()
	}
	perSec, _ := strconv.Atoi(os.Getenv("MVP21_SIM_PER_SEC"))
	if perSec == 0 {
		perSec = 20
	}
	pathLen, _ := strconv.Atoi(os.Getenv("MVP21_SIM_PATHLEN"))
	if pathLen == 0 {
		pathLen = 500
	}
	days, _ := strconv.Atoi(os.Getenv("MVP21_SIM_DAYS"))
	if days == 0 {
		days = 14
	}
	end := time.Now().UTC().Truncate(10 * time.Minute)
	if v := os.Getenv("MVP21_SIM_END"); v != "" {
		e, _ := time.Parse(time.RFC3339, v)
		end = e.UTC()
	}
	start := end.Add(-time.Duration(days)*24*time.Hour - time.Hour)
	m := newMeasureMonitor(t, dir, start)
	defer m.Close()
	uas := []string{chromeUA, "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", "curl/8.7.1", "",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1"}
	methods := []string{"GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "PATCH", "PROPFIND"}
	k := 0
	t0 := time.Now()
	sizes := map[string]int{}
	for sec := start.Add(time.Second); !sec.After(end); sec = sec.Add(time.Second) {
		for i := 0; i < perSec; i++ {
			k++
			seg := strconv.Itoa(k)
			p := "/" + strings.Repeat("abcdefghij", 5) + "/" + "w" + strings.Map(func(r rune) rune { return 'a' + (r - '0') }, seg)
			for len(p) < pathLen {
				p += "/" + strings.Repeat("seg", 20)[:min(60, pathLen-len(p))] + "x"
			}
			r := httptest.NewRequest(methods[k%len(methods)], "http://shop.example"+p, nil)
			r.Header.Set("User-Agent", uas[k%len(uas)])
			r.Header.Set("Referer", "https://www."+strings.Repeat("r", 40)+strconv.Itoa(k)+".example.org/x")
			cls := Class(k % 10)
			q := Req{R: r, Class: cls, Status: []int{200, 301, 404, 403, 429, 413, 500, 503, 204, 200}[k%10], Timed: true,
				Total: time.Duration(k%5000) * 37 * time.Microsecond, UpstreamDur: time.Duration(k%4000) * 30 * time.Microsecond,
				Client:  netip.AddrFrom4([4]byte{10, byte(k >> 16), byte(k >> 8), byte(k)}),
				Country: string([]byte{byte('A' + k%26), byte('A' + (k/26)%26)}), ASN: uint32(70000 + k), ASOrg: strings.Repeat("Org ", 20) + strconv.Itoa(k),
				NetClass: netClasses[k%len(netClasses)], BytesIn: int64(k % 9000), BytesOut: int64(k % 90000)}
			if cls == BlockedWAF || k%7 == 0 {
				if cls == Forwarded {
					q.WouldBlock = true
				}
				q.Detection = cls == BlockedWAF || q.WouldBlock
				q.Rules = []string{strconv.Itoa(900000 + k%997), strconv.Itoa(910000 + k%991), "949110", "980170", strconv.Itoa(920000 + k%983)}
			}
			m.Record(&q)
		}
		if sec.Unix()%10 == 5 {
			m.Sample(sec)
		}
		m.Tick(sec)
		m.flushWrites()
	}
	t.Logf("simulated %s .. %s (%d requests) in %s", start.Format(time.RFC3339), end.Format(time.RFC3339), k, time.Since(t0).Round(time.Second))
	_ = m.Close()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(dir, "metrics.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, tbl := range []string{"ring_10s", "ring_1m", "ring_10m"} {
		var n, sum, mx int64
		_ = db.QueryRow("SELECT COUNT(*), COALESCE(SUM(LENGTH(bucket)),0), COALESCE(MAX(LENGTH(bucket)),0) FROM "+tbl).Scan(&n, &sum, &mx)
		t.Logf("%s: rows %d, blob bytes %.1f MiB, avg %.0f B, max %d B", tbl, n, float64(sum)/(1<<20), float64(sum)/float64(max(1, n)), mx)
		sizes[tbl] = int(sum)
	}
	for _, f := range []string{"metrics.db", "metrics.db-wal", "metrics.db-shm"} {
		if st, err := os.Stat(filepath.Join(dir, f)); err == nil {
			t.Logf("%s: %.2f MiB", f, float64(st.Size())/(1<<20))
		}
	}
	fmt.Println("rings", cm.Rings(6, 48, 14))
}

// HyperLogLog accuracy of the package's sketch with the package's keyed
// hash over IPv4 client keys: relative error distribution per cardinality.
func TestMeasureHLL(t *testing.T) {
	for _, n := range []int{100, 500, 1000, 1750, 2500, 3000, 3500, 5000, 10000, 50000, 200000} {
		const trials = 300
		var sum, sum2, maxAbs float64
		over33, over5 := 0, 0
		for tr := 0; tr < trials; tr++ {
			rc := newRecorder(time.Now()) // fresh random seed per trial
			var h hll
			for i := 0; i < n; i++ {
				x, _ := rc.clientHash(netip.AddrFrom4([4]byte{byte(10 + tr%50), byte(i >> 16), byte(i >> 8), byte(i)}))
				h.add(x)
			}
			e := (float64(h.estimate()) - float64(n)) / float64(n)
			sum += e
			sum2 += e * e
			maxAbs = max(maxAbs, abs(e))
			if abs(e) > 0.033 {
				over33++
			}
			if abs(e) > 0.05 {
				over5++
			}
		}
		mean := sum / trials
		sd := sqrt(sum2/trials - mean*mean)
		t.Logf("n=%6d mean %+.2f%% sd %.2f%% max|e| %.2f%% beyond 3.3%%: %d/%d beyond 5%%: %d/%d", n, 100*mean, 100*sd, 100*maxAbs, over33, trials, over5, trials)
	}
}

func abs(x float64) float64 {
	if x < 0 {
		return -x
	}
	return x
}

func sqrt(x float64) float64 {
	if x <= 0 {
		return 0
	}
	z := x
	for i := 0; i < 50; i++ {
		z = (z + x/z) / 2
	}
	return z
}
