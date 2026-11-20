//go:build d36measure

// D36 measurement (TEST ONLY): size of the per-website parts of the 10 min
// ring (MetricBucket.sites[], top lists) and of metrics.db over 14 simulated
// days with 32 tracked websites. Runs in a scratch copy of
// client/internal/monitoring (never in the product tree):
//
//	cp zz_d36_sites_test.go <scratch>/gateway/internal/monitoring/
//	cd <scratch>/gateway && go test -tags d36measure -run TestD36SiteBucketSizes -v ./internal/monitoring/
//	D36_SIM_DIR=... D36_SIM_DAYS=15 go test -tags d36measure -timeout 3h -run TestD36FourteenDays -v ./internal/monitoring/
package monitoring

import (
	"database/sql"
	"fmt"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/contract/config"
	"github.com/deutschland-schild/schild/contract/websites"
	"github.com/deutschland-schild/schild/gateway/internal/sites"
)

func d36Registry(n int) *sites.Registry {
	if n == 0 {
		return nil
	}
	in := websites.Input{Mode: websites.ModeIngress}
	for i := 0; i < n; i++ {
		in.Blocks = append(in.Blocks, websites.Block{Addresses: []string{fmt.Sprintf("site%02d.example.org", i)}, Schild: true, Proxies: true})
	}
	return sites.NewRegistry(sites.NewView(in))
}

func d36Monitor(t *testing.T, dir string, now time.Time, n int) *Monitor {
	t.Helper()
	m, err := New(Config{StoragePath: dir, Keep: config.MonitoringKeep{TenSecondsHours: 6, MinuteHours: 48, TenMinuteDays: 14},
		Sampler: SamplerConfig{Root: fixtureRoot(t), Linux: true, Host: true, Started: now, Version: "test"},
		Internals: func(bool) Internals {
			return Internals{EventQueueUsed: 3, EventQueueCapacity: 8192, EvalSlotsUsed: 1, EvalSlotsMax: 16, StoreBytes: 1 << 20, StoreMaxBytes: 500 << 20}
		},
		Sites: d36Registry(n),
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

var d36UAs = []string{chromeUA, "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", "curl/8.7.1", "",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1"}

// d36Req builds request k of a profile: "real" (a shop: 300 Zipf paths of
// ~30 bytes, 60 ASNs, 12 countries, 8 referrers, 6 rules) or "high" (every
// path, ASN, referrer, country pair and rule distinct, 500-byte paths).
func d36Req(r *rand.Rand, z *rand.Zipf, profile string, k, nsites int) *Req {
	host := "shop.example"
	if nsites > 0 {
		host = fmt.Sprintf("site%02d.example.org", k%nsites)
	}
	var p, ref, country, asorg string
	var asn uint32
	var rules []string
	cls := Forwarded
	status := 200
	switch profile {
	case "real":
		i := z.Uint64()
		p = fmt.Sprintf("/produkte/kategorie-%d/artikel-%s", i%40, strings.Repeat("x", int(i%9)))
		if i%5 == 0 {
			p = "/blog/" + strconv.Itoa(int(i)) // numeric segment: one template
		}
		ref = []string{"", "https://www.google.com/", "https://www.bing.com/", "https://duckduckgo.com/", "https://t.co/x", "https://www.facebook.com/", "https://news.example.net/a", "https://partner.example.com/"}[r.IntN(8)]
		country = []string{"DE", "DE", "DE", "DE", "AT", "CH", "NL", "US", "FR", "PL", "GB", "IT"}[r.IntN(12)]
		asn = uint32(3320 + r.IntN(60))
		asorg = "Example Carrier " + strconv.Itoa(int(asn))
		if r.IntN(100) < 3 {
			cls, status = BlockedWAF, 403
			rules = []string{strconv.Itoa(941100 + r.IntN(6)), "949110"}
		}
	case "worst":
		// random lower-case letters: compresses far worse than repeated text
		rnd := func(n int) string {
			b := make([]byte, n)
			for i := range b {
				b[i] = byte('a' + r.IntN(26))
			}
			return string(b)
		}
		p = ""
		for len(p) < 500 {
			p += "/" + rnd(min(40, 499-len(p)))
		}
		ref = "https://" + rnd(50) + ".example.org/x"
		country = string([]byte{byte('A' + r.IntN(26)), byte('A' + r.IntN(26))})
		asn = uint32(70000 + r.IntN(1<<20))
		asorg = rnd(100)
		cls = Class(k % 10)
		status = []int{200, 301, 404, 403, 429, 413, 500, 503, 204, 200}[k%10]
		if cls == BlockedWAF || k%7 == 0 {
			rules = []string{strconv.Itoa(900000 + r.IntN(99999)), strconv.Itoa(900000 + r.IntN(99999)), "949110", "980170", strconv.Itoa(900000 + r.IntN(99999))}
		}
	default:
		seg := strings.Map(func(c rune) rune { return 'a' + (c - '0') }, strconv.Itoa(k))
		p = "/" + strings.Repeat("abcdefghij", 5) + "/w" + seg
		for len(p) < 500 {
			p += "/" + strings.Repeat("seg", 20)[:min(60, 500-len(p))] + "x"
		}
		ref = "https://www." + strings.Repeat("r", 40) + strconv.Itoa(k) + ".example.org/x"
		country = string([]byte{byte('A' + k%26), byte('A' + (k/26)%26)})
		asn = uint32(70000 + k)
		asorg = strings.Repeat("Org ", 20) + strconv.Itoa(k)
		cls = Class(k % 10)
		status = []int{200, 301, 404, 403, 429, 413, 500, 503, 204, 200}[k%10]
		if cls == BlockedWAF || k%7 == 0 {
			rules = []string{strconv.Itoa(900000 + k%997), strconv.Itoa(910000 + k%991), "949110", "980170", strconv.Itoa(920000 + k%983)}
		}
	}
	req := httptest.NewRequest(http.MethodGet, "http://"+host+p, nil)
	req.Host = host
	req.Header.Set("User-Agent", d36UAs[k%len(d36UAs)])
	if ref != "" {
		req.Header.Set("Referer", ref)
	}
	q := &Req{R: req, Class: cls, Status: status, Timed: true,
		Total: time.Duration(k%5000) * 37 * time.Microsecond, UpstreamDur: time.Duration(k%4000) * 30 * time.Microsecond,
		Client:  netip.AddrFrom4([4]byte{10, byte(k >> 16), byte(k >> 8), byte(k)}),
		Country: country, ASN: asn, ASOrg: asorg, NetClass: netClasses[k%len(netClasses)], BytesIn: int64(k % 9000), BytesOut: int64(k % 90000)}
	if len(rules) > 0 {
		q.Detection = true
		if cls == Forwarded {
			q.WouldBlock = true
		}
		q.Rules = rules
	}
	return q
}

// d36Blobs: rows, bytes (core + top) and max bytes of the 10 min ring.
func d36Blobs(t *testing.T, dir string) (n, sum, mx int64) {
	db, err := sql.Open("sqlite", "file:"+filepath.Join(dir, "metrics.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.QueryRow("SELECT COUNT(*), COALESCE(SUM(LENGTH(core)+COALESCE(LENGTH(top),0)),0), COALESCE(MAX(LENGTH(core)+COALESCE(LENGTH(top),0)),0) FROM ring_10m").Scan(&n, &sum, &mx); err != nil {
		t.Fatal(err)
	}
	return
}

// TestD36SiteBucketSizes: bytes of a 10 min bucket blob for 0 (no
// registry), 1, 4, 16, 32 and 40 websites, two traffic profiles, rate per
// website fixed (so every website has the same traffic); the increment per
// tracked website is (blob(n) - blob(0)) / tracked.
func TestD36SiteBucketSizes(t *testing.T) {
	perSite, _ := strconv.Atoi(os.Getenv("D36_PER_SITE_PER_SEC"))
	if perSite == 0 {
		perSite = 2
	}
	profiles := []string{"real", "high", "worst"}
	if v := os.Getenv("D36_PROFILES"); v != "" {
		profiles = strings.Split(v, ",")
	}
	for _, profile := range profiles {
		var base float64
		for _, ns := range []int{0, 1, 4, 16, 32, 40} {
			dir := t.TempDir()
			start := time.Date(2026, 10, 29, 0, 0, 0, 0, time.UTC)
			m := d36Monitor(t, dir, start, ns)
			r := rand.New(rand.NewPCG(36, uint64(ns)))
			z := rand.NewZipf(r, 1.2, 1, 299)
			k := 0
			rate := perSite * max(ns, 1)
			for sec := start.Add(time.Second); !sec.After(start.Add(31 * time.Minute)); sec = sec.Add(time.Second) {
				for i := 0; i < rate; i++ {
					k++
					m.Record(d36Req(r, z, profile, k, ns))
				}
				if sec.Unix()%10 == 5 {
					m.Sample(sec)
				}
				m.Tick(sec)
				m.flushWrites()
			}
			_ = m.Close()
			n, sum, mx := d36Blobs(t, dir)
			avg := float64(sum) / float64(max(n, 1))
			if ns == 0 {
				base = avg
			}
			tracked := min(ns, websites.MaxTracked)
			inc := 0.0
			if tracked > 0 {
				inc = (avg - base) / float64(tracked)
			}
			for _, tbl := range []string{"ring_10s", "ring_1m"} {
				db, err := sql.Open("sqlite", "file:"+filepath.Join(dir, "metrics.db"))
				if err != nil {
					t.Fatal(err)
				}
				var rn, rsum int64
				if err := db.QueryRow("SELECT COUNT(*), COALESCE(SUM(LENGTH(core)+COALESCE(LENGTH(top),0)),0) FROM "+tbl+" WHERE t > (SELECT MIN(t) FROM "+tbl+")").Scan(&rn, &rsum); err != nil {
					t.Fatal(err)
				}
				db.Close()
				fmt.Printf("D36RING profile=%s sites=%d %s rows=%d avg_blob=%.0f B\n", profile, ns, tbl, rn, float64(rsum)/float64(max(rn, 1)))
			}
			fmt.Printf("D36SIZE profile=%s sites=%d tracked=%d req_per_site_per_bucket=%d buckets=%d avg_blob=%.0f B max=%d B per_tracked_site=%.0f B (%.2f KiB) -> 2016 buckets: %.2f MiB per site\n",
				profile, ns, tracked, perSite*600, n, avg, mx, inc, inc/1024, inc*2016/(1<<20))
		}
	}
}

// TestD36FourteenDays: 32 tracked websites, high-cardinality traffic, D36_SIM_DAYS
// (default 15) simulated days; logs the metrics.db size and the 10 min ring
// rows and bytes once per simulated day, so it shows where the file stops
// growing.
func TestD36FourteenDays(t *testing.T) {
	dir := os.Getenv("D36_SIM_DIR")
	if dir == "" {
		dir = t.TempDir()
	}
	days, _ := strconv.Atoi(os.Getenv("D36_SIM_DAYS"))
	if days == 0 {
		days = 15
	}
	perSec, _ := strconv.Atoi(os.Getenv("D36_SIM_PER_SEC"))
	if perSec == 0 {
		perSec = 64
	}
	profile := os.Getenv("D36_SIM_PROFILE")
	if profile == "" {
		profile = "high"
	}
	ns := 32
	end := time.Date(2026, 10, 29, 0, 0, 0, 0, time.UTC)
	start := end.Add(-time.Duration(days) * 24 * time.Hour)
	m := d36Monitor(t, dir, start, ns)
	r := rand.New(rand.NewPCG(36, 14))
	z := rand.NewZipf(r, 1.2, 1, 299)
	k := 0
	t0 := time.Now()
	for sec := start.Add(time.Second); !sec.After(end); sec = sec.Add(time.Second) {
		for i := 0; i < perSec; i++ {
			k++
			m.Record(d36Req(r, z, profile, k, ns))
		}
		if sec.Unix()%10 == 5 {
			m.Sample(sec)
		}
		m.Tick(sec)
		m.flushWrites()
		if sec.Unix()%86400 == 0 {
			n, sum, mx := d36Blobs(t, dir)
			var fsz int64
			if st, err := os.Stat(filepath.Join(dir, "metrics.db")); err == nil {
				fsz = st.Size()
			}
			var wsz int64
			if st, err := os.Stat(filepath.Join(dir, "metrics.db-wal")); err == nil {
				wsz = st.Size()
			}
			fmt.Printf("D36DAY day=%.0f metrics.db=%.2f MiB wal=%.2f MiB ring_10m rows=%d bytes=%.2f MiB avg=%.0f B max=%d B elapsed=%s\n",
				sec.Sub(start).Hours()/24, float64(fsz)/(1<<20), float64(wsz)/(1<<20), n, float64(sum)/(1<<20), float64(sum)/float64(max(n, 1)), mx, time.Since(t0).Round(time.Second))
		}
	}
	_ = m.Close()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(dir, "metrics.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, tbl := range []string{"ring_10s", "ring_1m", "ring_10m"} {
		var n, sum, mx int64
		var topSum int64
		if err := db.QueryRow("SELECT COUNT(*), COALESCE(SUM(LENGTH(core)+COALESCE(LENGTH(top),0)),0), COALESCE(MAX(LENGTH(core)+COALESCE(LENGTH(top),0)),0), COALESCE(SUM(LENGTH(top)),0) FROM "+tbl).Scan(&n, &sum, &mx, &topSum); err != nil {
			t.Fatal(err)
		}
		fmt.Printf("D36END %s rows=%d bytes=%.2f MiB (top column %.2f MiB) avg=%.0f B max=%d B\n", tbl, n, float64(sum)/(1<<20), float64(topSum)/(1<<20), float64(sum)/float64(max(1, n)), mx)
	}
	if st, err := os.Stat(filepath.Join(dir, "metrics.db")); err == nil {
		fmt.Printf("D36END metrics.db=%.2f MiB requests=%d profile=%s per_sec=%d sites=%d\n", float64(st.Size())/(1<<20), k, profile, perSec, ns)
	}
}
