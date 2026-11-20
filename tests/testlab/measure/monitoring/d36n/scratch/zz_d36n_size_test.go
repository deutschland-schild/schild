//go:build d36measure

// D36 re-measurement after fix round 1 (TEST ONLY): worst-case size of
// metrics.db against monitoring.MetricsBoundBytes, the 128-byte cut of top
// list keys, and query latency on the worst-case file. Runs in a scratch
// worktree copy of client/internal/monitoring (never in the product tree):
//
//	cp zz_d36n_size_test.go <worktree>/gateway/internal/monitoring/
//	cd <worktree>/gateway
//	# row sizes per profile (31 simulated minutes, fast):
//	D36N_W=32 D36N_PROFILE=ascii D36N_HOST=plain go test -tags d36measure -run TestD36NRows -v ./internal/monitoring/
//	# full fill (15 simulated days, ends at the real clock), then latency and key checks:
//	D36N_W=0 D36N_DAYS=15 D36N_PROFILE=ascii D36N_HOST=plain D36N_DIR=/tmp/x \
//	  go test -tags d36measure -timeout 4h -run TestD36NFill -v ./internal/monitoring/
//	go test -tags d36measure -run TestD36NCut -v ./internal/monitoring/
//	# latency only, on a filled dir (idle machine), end = the newest 1 min bucket:
//	D36N_W=32 D36N_DIR=/tmp/x go test -tags d36measure -run TestD36NLatencyOnly -v ./internal/monitoring/
//
// Note: the first fills (results D36-nachmessung/b/sizes, "referrer v1") used a
// referrer whose registrable label had 8 letters (16-byte keys); the "v2"
// fills use the 63-char label above.
//
// Profiles (every key longer than 128 bytes and distinct in its first 125):
//
//	ascii  paths of three 64-char segments of [A-Za-z._~-] (the path template
//	       keeps such segments: no digits, so no {slug}/{hex}), referrers
//	       with a random 63-char registrable label, AS names of random
//	       printable ASCII (95 symbols, the least compressible text)
//	utf8   the same, AS names random non-ASCII UTF-8 (2, 3 and 4-byte runes
//	       mixed, so the cut lands inside every rune width)
//
// Every request: random class, status 100-599, method, user agent (known
// browsers, bots, tools, random garbage), country (random two letters), net
// class, ASN, 0-8 random rule ids (up to 8 digits), client (IPv4/IPv6),
// latency log-uniform 50 µs-120 s, bytes up to 2 GiB.
//
// Host: plain = the package test fixture (2 mounts, 1 interface); hostile =
// 17 block-device mounts with 127-char mount points, 17 diskstats devices
// with 127-char names, 16 interfaces with 15-char names, all counters
// changing at every sample.
package monitoring

import (
	"fmt"
	"math"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/deutschland-schild/schild/contract/config"
	cm "github.com/deutschland-schild/schild/contract/monitoring"
	"github.com/deutschland-schild/schild/contract/websites"
	"github.com/deutschland-schild/schild/gateway/internal/sites"
)

const d36nPathAlpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz._~-"
const d36nLDH = "abcdefghijklmnopqrstuvwxyz0123456789"
const d36nObj = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.:@-"

var d36nNetClasses = []string{"residential", "mobile", "cgnat", "hosting", "business", "education", "government", "vpn", "tor", "proxy", "unknown", ""}
var d36nMethods = []string{"GET", "POST", "HEAD", "PUT", "DELETE", "PATCH", "OPTIONS", "CONNECT", "TRACE", "PROPFIND", "MKCOL", "FOO"}
var d36nUAs = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15",
	"Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Mobile Safari/537.36",
	"Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
	"Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
	"Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.2; +https://openai.com/gptbot)",
	"Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; ClaudeBot/1.0; +claudebot@anthropic.com",
	"Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)",
	"Mozilla/5.0 (compatible; SemrushBot/7~bl; +http://www.semrush.com/bot.html)",
	"facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)",
	"curl/8.7.1", "python-requests/2.32.3", "Go-http-client/1.1", "Wget/1.21.4", "sqlmap/1.8#stable (https://sqlmap.org)",
	"Nuclei - Open-source project (github.com/projectdiscovery/nuclei)", "Mozilla/5.0 zgrab/0.x", "UptimeRobot/2.0", "",
}

type d36nGen struct {
	r       *rand.Rand
	profile string
	hosts   []string
}

func (g *d36nGen) str(alpha string, n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = alpha[g.r.IntN(len(alpha))]
	}
	return string(b)
}

func (g *d36nGen) seg() string {
	for {
		s := g.str(d36nPathAlpha, 64)
		if s[0] != '.' && strings.ContainsAny(s, "GHIJKLMNOPQRSTUVWXYZghijklmnopqrstuvwxyz") {
			return s
		}
	}
}

func (g *d36nGen) printable(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(0x20 + g.r.IntN(95))
	}
	return string(b)
}

// utf8Mixed: random runes of 2, 3 and 4 bytes (no surrogates, no
// non-characters), n bytes or a little more.
func (g *d36nGen) utf8Mixed(n int) string {
	var sb strings.Builder
	for sb.Len() < n {
		var r rune
		switch g.r.IntN(4) {
		case 0:
			r = rune(0x00A0 + g.r.IntN(0x07FF-0x00A0))
		case 1, 2:
			r = rune(0x0800 + g.r.IntN(0xD7FF-0x0800))
		default:
			r = rune(0x10000 + g.r.IntN(0x10FFFD-0x10000))
		}
		if !utf8.ValidRune(r) || (r&0xFFFE) == 0xFFFE {
			continue
		}
		sb.WriteRune(r)
	}
	return sb.String()
}

func (g *d36nGen) req(k int) *Req {
	r := g.r
	host := g.hosts[k%len(g.hosts)]
	p := "/" + g.seg() + "/" + g.seg() + "/" + g.seg()
	req := httptest.NewRequest(d36nMethods[r.IntN(len(d36nMethods))], "http://"+host+p, nil)
	req.Host = host
	ua := d36nUAs[r.IntN(len(d36nUAs))]
	if r.IntN(10) < 3 {
		ua = g.printable(40 + r.IntN(400))
	}
	req.Header.Set("User-Agent", ua)
	if r.IntN(20) != 0 {
		// the registrable domain (the stored key) is the random 63-char label + ".example"
		req.Header.Set("Referer", "https://www."+string(rune('a'+r.IntN(26)))+g.str(d36nLDH, 62)+".example/"+g.str(d36nLDH, 20))
	}
	asorg := g.printable(200)
	if g.profile == "utf8" {
		asorg = g.utf8Mixed(200)
	}
	var client netip.Addr
	if r.IntN(10) < 7 {
		client = netip.AddrFrom4([4]byte{byte(1 + r.IntN(223)), byte(r.IntN(256)), byte(r.IntN(256)), byte(r.IntN(256))})
	} else {
		var b [16]byte
		for i := range b {
			b[i] = byte(r.IntN(256))
		}
		b[0] = 0x20
		client = netip.AddrFrom16(b)
	}
	total := time.Duration(50e3 * math.Exp(r.Float64()*math.Log(120e9/50e3)))
	q := &Req{R: req, Class: Class(r.IntN(10)), Status: 100 + r.IntN(500), Upstream: uint8(r.IntN(3)), Timed: r.IntN(50) != 0,
		BytesIn: r.Int64N(1 << 31), BytesOut: r.Int64N(1 << 31), Total: total, UpstreamDur: time.Duration(r.Float64() * float64(total)),
		Client: client, Country: string([]byte{byte('A' + r.IntN(26)), byte('A' + r.IntN(26))}), ASN: 1 + r.Uint32N(math.MaxUint32-1), ASOrg: asorg,
		NetClass: d36nNetClasses[r.IntN(len(d36nNetClasses))]}
	if q.Class == Forwarded {
		q.WouldBlock, q.WouldRL = r.IntN(2) == 0, r.IntN(2) == 0
	}
	if r.IntN(2) == 0 {
		q.Detection = true
		for i := 0; i < 1+r.IntN(8); i++ {
			q.Rules = append(q.Rules, strconv.Itoa(100000+r.IntN(99900000)))
		}
	}
	return q
}

func d36nRegistry(t testing.TB, w int) (*sites.Registry, []string) {
	if w == 0 {
		return nil, []string{"shop.example"}
	}
	var blocks []websites.Block
	var hosts []string
	for i := 0; i < w; i++ {
		h := fmt.Sprintf("app%d.example.org", i)
		hosts = append(hosts, h)
		blocks = append(blocks, websites.Block{Addresses: []string{h}, Schild: true, Proxies: true})
	}
	v := sites.NewView(websites.Input{Mode: websites.ModeIngress, Blocks: blocks})
	if v.Err != nil {
		t.Fatal(v.Err)
	}
	return sites.NewRegistry(v), hosts
}

// d36nHost returns the sampler root and a function that advances its
// counters before each sample.
func d36nHost(t testing.TB, kind string, g *d36nGen) (string, func()) {
	if kind != "hostile" {
		return fixtureRoot(t.(*testing.T)), func() {}
	}
	root := fixtureRoot(t.(*testing.T))
	var mi strings.Builder
	mi.WriteString("24 1 8:1 / / rw,relatime - ext4 /dev/sda1 rw\n25 24 0:22 / /proc rw - proc proc rw\n")
	type dev struct {
		name string
		c    [11]int64
	}
	var devs []*dev
	for i := 0; i < 17; i++ {
		point := "/" + g.str(d36nObj, 126)
		name := g.str(d36nObj, 127)
		if err := os.MkdirAll(filepath.Join(root, point), 0o755); err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(&mi, "%d 24 %d:0 / %s rw,relatime - ext4 /dev/%s rw\n", 40+i, 100+i, point, name)
		devs = append(devs, &dev{name: name})
	}
	var ifs []*dev
	for i := 0; i < 16; i++ {
		ifs = append(ifs, &dev{name: "e" + g.str("abcdefghijklmnopqrstuvwxyz0123456789", 14)})
	}
	if err := os.WriteFile(filepath.Join(root, "proc/self/mountinfo"), []byte(mi.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	advance := func() {
		var ds, nd strings.Builder
		for i, d := range devs {
			for j := range d.c {
				d.c[j] += g.r.Int64N(1 << 24)
			}
			fmt.Fprintf(&ds, "%4d %7d %s %d %d %d %d %d %d %d %d %d %d %d\n", 100+i, 0, d.name, d.c[0], d.c[1], d.c[2], d.c[3], d.c[4], d.c[5], d.c[6], d.c[7], d.c[8], d.c[9], d.c[10])
		}
		nd.WriteString("Inter-|   Receive                                                |  Transmit\n face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n")
		for _, d := range ifs {
			for j := range d.c {
				d.c[j] += g.r.Int64N(1 << 30)
			}
			fmt.Fprintf(&nd, "%s: %d %d %d %d 0 0 0 0 %d %d %d %d 0 0 0 0\n", d.name, d.c[0], d.c[1], d.c[2], d.c[3], d.c[4], d.c[5], d.c[6], d.c[7])
		}
		_ = os.WriteFile(filepath.Join(root, "proc/diskstats"), []byte(ds.String()), 0o644)
		_ = os.WriteFile(filepath.Join(root, "proc/net/dev"), []byte(nd.String()), 0o644)
	}
	advance()
	return root, advance
}

func d36nEnv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

type d36nRun struct {
	m     *Monitor
	dir   string
	hosts []string
	w     int
}

// d36nSimulate records traffic from start to end (one Tick per second,
// one Sample per 10 s) and calls daily once per simulated day.
func d36nSimulate(t *testing.T, dir string, w int, start, end time.Time, daily func(day float64)) *d36nRun {
	g := &d36nGen{r: rand.New(rand.NewPCG(36, uint64(w)+7)), profile: d36nEnv("D36N_PROFILE", "ascii")}
	reg, hosts := d36nRegistry(t, w)
	g.hosts = hosts
	root, advance := d36nHost(t, d36nEnv("D36N_HOST", "plain"), g)
	m, err := New(Config{StoragePath: dir,
		Keep:    config.MonitoringKeep{TenSecondsHours: config.DefaultKeepTenSecondsHours, MinuteHours: config.DefaultKeepMinuteHours, TenMinuteDays: config.DefaultKeepTenMinuteDays},
		Sampler: SamplerConfig{Root: root, Linux: true, Host: true, Started: start, Version: "test"},
		Internals: func(bool) Internals {
			return Internals{EventQueueUsed: 3, EventQueueCapacity: 8192, EvalSlotsUsed: 1, EvalSlotsMax: 16, StoreBytes: 1 << 20, StoreMaxBytes: 500 << 20}
		},
		Sites: reg}, start)
	if err != nil {
		t.Fatal(err)
	}
	perSite, _ := strconv.Atoi(d36nEnv("D36N_PER_SITE", "1"))
	minPerSec, _ := strconv.Atoi(d36nEnv("D36N_MIN_PER_SEC", "4"))
	rate := max(minPerSec, perSite*len(hosts))
	k := 0
	for sec := start.Add(time.Second); !sec.After(end); sec = sec.Add(time.Second) {
		for i := 0; i < rate; i++ {
			k++
			m.Record(g.req(k))
		}
		if sec.Unix()%10 == 5 {
			advance()
			m.Sample(sec)
		}
		m.Tick(sec)
		m.flushWrites()
		if daily != nil && sec.Sub(start)%(24*time.Hour) == 0 {
			daily(sec.Sub(start).Hours() / 24)
		}
	}
	m.flushWrites()
	return &d36nRun{m: m, dir: dir, hosts: hosts, w: w}
}

func (r *d36nRun) rings(t *testing.T) string {
	var sb strings.Builder
	for _, tbl := range []string{"ring_10s", "ring_1m", "ring_10m"} {
		var n, sum, mx, top int64
		if err := r.m.store.db.QueryRow("SELECT COUNT(*), COALESCE(SUM(LENGTH(core)+COALESCE(LENGTH(top),0)),0), COALESCE(MAX(LENGTH(core)+COALESCE(LENGTH(top),0)),0), COALESCE(SUM(LENGTH(top)),0) FROM "+tbl).Scan(&n, &sum, &mx, &top); err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(&sb, " %s rows=%d bytes=%.2fMiB top=%.2fMiB avg=%.0fB max=%dB;", tbl, n, float64(sum)/(1<<20), float64(top)/(1<<20), float64(sum)/float64(max(1, n)), mx)
	}
	return sb.String()
}

func fsize(p string) int64 {
	st, err := os.Stat(p)
	if err != nil {
		return 0
	}
	return st.Size()
}

// TestD36NRows: 31 simulated minutes, largest stored row per ring against
// RowBound10s/1m/10m (the per-row inputs of MetricsBoundBytes).
func TestD36NRows(t *testing.T) {
	w, _ := strconv.Atoi(d36nEnv("D36N_W", "32"))
	end := time.Now().UTC().Truncate(10 * time.Minute)
	r := d36nSimulate(t, t.TempDir(), w, end.Add(-31*time.Minute), end, nil)
	defer r.m.Close()
	q := func(tbl string) (mx int64) {
		_ = r.m.store.db.QueryRow("SELECT MAX(LENGTH(core)+COALESCE(LENGTH(top),0)) FROM " + tbl).Scan(&mx)
		return
	}
	bw := int64(min(w, websites.MaxTracked+1))
	fmt.Printf("D36NROWS profile=%s host=%s W=%d max row 10s=%d (bound %d) 1m=%d (bound %d) 10m=%d (bound %d)\n", d36nEnv("D36N_PROFILE", "ascii"), d36nEnv("D36N_HOST", "plain"), w,
		q("ring_10s"), RowBound10s(bw), q("ring_1m"), RowBound1m(bw), q("ring_10m"), RowBound10m(bw))
}

// TestD36NFill: D36N_DAYS simulated days ending now; daily file sizes; at
// the end the file against MetricsBoundBytes, the key checks and the
// query latency.
func TestD36NFill(t *testing.T) {
	w, _ := strconv.Atoi(d36nEnv("D36N_W", "0"))
	days, _ := strconv.Atoi(d36nEnv("D36N_DAYS", "15"))
	dir := d36nEnv("D36N_DIR", t.TempDir())
	_ = os.MkdirAll(dir, 0o755)
	end := time.Now().UTC().Truncate(10 * time.Second)
	start := end.Add(-time.Duration(days) * 24 * time.Hour)
	t0 := time.Now()
	db := filepath.Join(dir, "metrics.db")
	var r *d36nRun
	r = d36nSimulate(t, dir, w, start, end, func(day float64) {
		fmt.Printf("D36NDAY W=%d day=%.0f metrics.db=%.2fMiB wal=%.2fMiB elapsed=%s\n", w, day, float64(fsize(db))/(1<<20), float64(fsize(db+"-wal"))/(1<<20), time.Since(t0).Round(time.Second))
	})
	m := r.m
	if _, err := m.store.db.Exec("PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
		t.Fatal(err)
	}
	bound := MetricsBoundBytes(m.rings, int64(w))
	fmt.Printf("D36NEND W=%d profile=%s host=%s%s\n", w, d36nEnv("D36N_PROFILE", "ascii"), d36nEnv("D36N_HOST", "plain"), r.rings(t))
	fmt.Printf("D36NEND W=%d metrics.db=%d B (%.2f MiB) wal=%d B bound=%d B (%.2f MiB) ratio=%.3f exceeds=%v elapsed=%s\n", w, fsize(db), float64(fsize(db))/(1<<20), fsize(db+"-wal"),
		bound, float64(bound)/(1<<20), float64(fsize(db))/float64(bound), fsize(db) > bound, time.Since(t0).Round(time.Second))
	d36nKeys(t, m, end, w)
	d36nLatency(t, r, end)
	_ = m.Close()
	fmt.Printf("D36NCLOSED W=%d metrics.db=%d B (%.2f MiB) wal=%d B\n", w, fsize(db), float64(fsize(db))/(1<<20), fsize(db+"-wal"))
}

// d36nKeys walks every top entry of every 1 min and 10 min bucket
// (gateway and per website) and checks the cut keys and labels.
func d36nKeys(t *testing.T, m *Monitor, end time.Time, w int) {
	type stat struct{ n, long, invalid, cut, noMarker, maxLen int }
	st := map[string]*stat{}
	var walk func(v reflect.Value, where string)
	walk = func(v reflect.Value, where string) {
		switch v.Kind() {
		case reflect.Pointer, reflect.Interface:
			if !v.IsNil() {
				walk(v.Elem(), where)
			}
		case reflect.Slice, reflect.Array:
			for i := 0; i < v.Len(); i++ {
				walk(v.Index(i), where)
			}
		case reflect.Map:
			for _, k := range v.MapKeys() {
				walk(v.MapIndex(k), where)
			}
		case reflect.Struct:
			if v.Type() == reflect.TypeOf(cm.TopEntry{}) {
				e := v.Interface().(cm.TopEntry)
				for _, f := range []struct{ name, s string }{{"key", e.Key}, {"label", e.Label}} {
					s := st[where+"."+f.name]
					if s == nil {
						s = &stat{}
						st[where+"."+f.name] = s
					}
					s.n++
					s.maxLen = max(s.maxLen, len(f.s))
					if len(f.s) > MaxTopKeyBytes {
						s.long++
					}
					if !utf8.ValidString(f.s) {
						s.invalid++
					}
					if strings.HasSuffix(f.s, TruncMarker) {
						s.cut++
					} else if len(f.s) >= MaxTopKeyBytes-len(TruncMarker)-3 {
						s.noMarker++
					}
				}
				return
			}
			for i := 0; i < v.NumField(); i++ {
				name := v.Type().Field(i).Name
				nw := where
				if name == "Path" || name == "ASN" || name == "Referrer" || name == "Rule" || name == "Country" {
					nw = where + "/" + name
				}
				if name == "Sites" {
					nw = "site"
				}
				walk(v.Field(i), nw)
			}
		}
	}
	for _, res := range []string{"1m", "10m"} {
		cursor := ""
		pages := 0
		for {
			page, err := m.Buckets(res, end.Add(-15*24*time.Hour), cursor, 0, end)
			if err != nil {
				t.Fatal(err)
			}
			walk(reflect.ValueOf(page.Items), res)
			pages++
			if page.NextCursor == nil || *page.NextCursor == "" || pages > 100000 {
				break
			}
			cursor = *page.NextCursor
		}
	}
	keys := make([]string, 0, len(st))
	for k := range st {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		s := st[k]
		fmt.Printf("D36NKEYS W=%d %s entries=%d max_len=%d over_128=%d invalid_utf8=%d cut_with_marker=%d long_without_marker=%d\n", w, k, s.n, s.maxLen, s.long, s.invalid, s.cut, s.noMarker)
	}
}

func d36nPct(ds []time.Duration) string {
	sort.Slice(ds, func(i, j int) bool { return ds[i] < ds[j] })
	p := func(q float64) time.Duration { return ds[min(len(ds)-1, int(math.Ceil(q*float64(len(ds))))-1)] }
	return fmt.Sprintf("n=%d p50=%.1fms p95=%.1fms max=%.1fms", len(ds), float64(p(0.5))/1e6, float64(p(0.95))/1e6, float64(ds[len(ds)-1])/1e6)
}

var d36nSiteSeries = []string{"traffic.requests:rate", "traffic.forwarded:rate", "traffic.stopped:rate", "traffic.fail_closed:rate", "traffic.would_block:rate",
	"traffic.latency_total:p50", "traffic.latency_total:p95", "traffic.latency_total:p99", "traffic.latency_overhead:p95", "traffic.latency_upstream:p95",
	"traffic.bytes_in:rate", "traffic.bytes_out:rate", "traffic.clients_unique", "traffic.upstream_errors:rate", "traffic.status_5xx:rate", "traffic.detections:rate"}

func d36nLatency(t *testing.T, r *d36nRun, end time.Time) {
	m := r.m
	reps, _ := strconv.Atoi(d36nEnv("D36N_REPS", "20"))
	run := func(name string, f func() error) {
		var ds []time.Duration
		for i := 0; i < reps; i++ {
			t0 := time.Now()
			if err := f(); err != nil {
				fmt.Printf("D36NLAT W=%d %s error: %v\n", r.w, name, err)
				return
			}
			ds = append(ds, time.Since(t0))
		}
		fmt.Printf("D36NLAT W=%d %s %s\n", r.w, name, d36nPct(ds))
	}
	sitesToTry := []string{""}
	if r.w > 0 {
		sitesToTry = append(sitesToTry, r.hosts[0])
	}
	for _, site := range sitesToTry {
		label := "gateway"
		metrics := series16
		if site != "" {
			label = "site=" + site
			metrics = d36nSiteSeries
		}
		run("series 16x1000 1m "+label, func() error {
			res, err := m.Series(SeriesQuery{Metrics: metrics, From: end.Add(-1000 * time.Minute), To: end, Resolution: "1m", Site: site}, end)
			if err == nil && res.Points != 1000 {
				return fmt.Errorf("points %d", res.Points)
			}
			return err
		})
		run("series 16 metrics 14d auto "+label, func() error {
			_, err := m.Series(SeriesQuery{Metrics: metrics, From: end.Add(-14 * 24 * time.Hour), To: end, Resolution: "auto", Site: site}, end)
			return err
		})
		for _, by := range cm.Dimensions {
			run("breakdown 14d by="+by+" "+label, func() error {
				_, err := m.Breakdown(by, end.Add(-14*24*time.Hour), end, site, nil, 20, end)
				return err
			})
		}
		run("kpis 7d "+label, func() error {
			_, err := m.Kpis(site, end.Add(-7*24*time.Hour), end, nil, end)
			return err
		})
	}
}

// TestD36NCut: keys that differ only after the cut count as one; a cut
// AS name of every rune width stays valid UTF-8 and ends with the marker;
// an AS name that is not valid UTF-8 (geo database bytes) is reported.
func TestD36NCut(t *testing.T) {
	end := time.Now().UTC().Truncate(10 * time.Minute)
	g := &d36nGen{r: rand.New(rand.NewPCG(1, 1)), profile: "utf8", hosts: []string{"shop.example"}}
	m, err := New(Config{StoragePath: t.TempDir(), Sampler: SamplerConfig{Root: fixtureRoot(t), Linux: true, Host: true, Started: end.Add(-20 * time.Minute), Version: "test"}}, end.Add(-20*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	prefix := "/" + g.seg() + "/" + g.seg() + "/" + g.seg()[:10]
	invalid := 0
	for s := end.Add(-20 * time.Minute).Add(time.Second); !s.After(end); s = s.Add(time.Second) {
		if s.Equal(end.Add(-15 * time.Minute)) {
			for i := 0; i < 200; i++ {
				req := httptest.NewRequest(http.MethodGet, "http://shop.example"+prefix+"/"+g.seg(), nil)
				org := strings.Repeat("ä", 62) + g.utf8Mixed(80) // the cut lands in different rune widths
				if i%3 == 1 {
					org = strings.Repeat("a", 1+i%4) + g.utf8Mixed(200)
				}
				if i%50 == 0 {
					org = strings.Repeat("x", 124) + "\xff\xfe\xfd" + "tail" // invalid bytes at the cut
					invalid++
				}
				m.Record(&Req{R: req, Class: Forwarded, Status: 200, Timed: true, Total: time.Millisecond, ASN: uint32(1000 + i), ASOrg: org, Country: "DE"})
			}
		}
		m.Tick(s)
		m.flushWrites()
	}
	m.flushWrites()
	bd, err := m.Breakdown("path", end.Add(-20*time.Minute), end, "", nil, 100, end)
	if err != nil {
		t.Fatal(err)
	}
	for _, it := range bd.Items {
		fmt.Printf("D36NCUT path key len=%d requests=%d marker=%v valid=%v\n", len(it.Key), it.Requests, strings.HasSuffix(it.Key, TruncMarker), utf8.ValidString(it.Key))
	}
	bd, err = m.Breakdown("asn", end.Add(-20*time.Minute), end, "", nil, 100, end)
	if err != nil {
		t.Fatal(err)
	}
	bad, cut := 0, 0
	for _, it := range bd.Items {
		if !utf8.ValidString(it.Label) {
			bad++
			fmt.Printf("D36NCUT invalid label len=%d tail=%q\n", len(it.Label), it.Label[max(0, len(it.Label)-8):])
		}
		if strings.HasSuffix(it.Label, TruncMarker) && len(it.Label) <= MaxTopKeyBytes {
			cut++
		}
	}
	fmt.Printf("D36NCUT asn labels=%d cut_with_marker_le_128=%d invalid_utf8=%d (inputs with invalid bytes: %d)\n", len(bd.Items), cut, bad, invalid)
	// direct: the cut of every rune width and of invalid input bytes
	for _, in := range []string{strings.Repeat("a", 124) + "ä" + "tail", strings.Repeat("a", 123) + "€" + "tail", strings.Repeat("a", 122) + "😀" + "tail",
		strings.Repeat("x", 124) + "\xff\xfe\xfd" + "tail", strings.Repeat("ü", 100)} {
		k := truncKey(in)
		fmt.Printf("D36NCUT direct in_len=%d out_len=%d marker=%v valid_in=%v valid_out=%v\n", len(in), len(k), strings.HasSuffix(k, TruncMarker), utf8.ValidString(in), utf8.ValidString(k))
	}
}

// TestD36NLatencyOnly reopens a filled D36N_DIR (same websites) and
// measures the query latency with end = the end of the newest 1 min bucket.
func TestD36NLatencyOnly(t *testing.T) {
	w, _ := strconv.Atoi(d36nEnv("D36N_W", "0"))
	dir := os.Getenv("D36N_DIR")
	reg, hosts := d36nRegistry(t, w)
	now := time.Now().UTC()
	m, err := New(Config{StoragePath: dir, Keep: config.MonitoringKeep{TenSecondsHours: config.DefaultKeepTenSecondsHours, MinuteHours: config.DefaultKeepMinuteHours, TenMinuteDays: config.DefaultKeepTenMinuteDays},
		Sampler: SamplerConfig{Root: fixtureRoot(t), Linux: true, Host: true, Started: now, Version: "test"}, Sites: reg}, now)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	var maxT int64
	if err := m.store.db.QueryRow("SELECT MAX(t) FROM ring_1m").Scan(&maxT); err != nil {
		t.Fatal(err)
	}
	var end time.Time
	switch {
	case maxT > 1e12:
		end = time.UnixMilli(maxT)
	default:
		end = time.Unix(maxT, 0)
	}
	end = end.UTC().Add(time.Minute).Truncate(time.Minute)
	fmt.Printf("D36NLATONLY W=%d end=%s\n", w, end.Format(time.RFC3339))
	d36nLatency(t, &d36nRun{m: m, dir: dir, hosts: hosts, w: w}, end)
}
