// Command measure runs the mechanics measurements of the test lab (MVP-05):
// request-overhead latency (B01/T20, M1), the K3 resilience corpus bypass
// check (M1), and the lab ingest burst (B13, M6). It runs inside the stack on
// the internal networks and only talks to the test lab's own containers.
//
// It is intentionally an independent harness: it does not reuse a component's
// own benchmark. Output is one JSON object on stdout (and -out if given).
//
//	measure latency -target http://schild-api:8080 -rps 500 -duration 20s
//	measure k3      -schild http://schild-api:8080 -origin http://site-api:8080
//	measure burst   -lab https://lab-a:7443 -rate 3000 -duration 15s
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/auth"
	"github.com/deutschland-schild/schild/contract/jsonx"
	"github.com/deutschland-schild/schild/contract/msg"
	"github.com/deutschland-schild/schild/contract/testkeys"
	"github.com/deutschland-schild/schild/testlab/internal/label"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: measure {latency|k3|burst} [flags]")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "latency":
		err = cmdLatency(os.Args[2:])
	case "k3":
		err = cmdK3(os.Args[2:])
	case "burst":
		err = cmdBurst(os.Args[2:])
	case "scrape":
		err = cmdScrape(os.Args[2:])
	case "egress":
		err = cmdEgress(os.Args[2:])
	default:
		err = fmt.Errorf("unknown subcommand %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "measure: %v\n", err)
		os.Exit(1)
	}
}

// ---------- shared helpers ----------

func emit(out string, v any) error {
	b, _ := json.MarshalIndent(v, "", "  ")
	fmt.Println(string(b))
	if out != "" {
		if err := os.WriteFile(out, append(b, '\n'), 0o644); err != nil {
			return err
		}
	}
	return nil
}

func percentile(sorted []float64, q float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	i := int(q * float64(len(sorted)))
	if i >= len(sorted) {
		i = len(sorted) - 1
	}
	return sorted[i]
}

type latStats struct {
	N      int     `json:"n"`
	P50    float64 `json:"p50_ms"`
	P95    float64 `json:"p95_ms"`
	P99    float64 `json:"p99_ms"`
	Max    float64 `json:"max_ms"`
	Mean   float64 `json:"mean_ms"`
	Errors int     `json:"errors"`
}

func stats(lat []float64, errs int) latStats {
	sort.Float64s(lat)
	var sum, max float64
	for _, v := range lat {
		sum += v
		if v > max {
			max = v
		}
	}
	s := latStats{N: len(lat), P50: percentile(lat, 0.50), P95: percentile(lat, 0.95), P99: percentile(lat, 0.99), Max: max, Errors: errs}
	if len(lat) > 0 {
		s.Mean = sum / float64(len(lat))
	}
	return s
}

// openLoop fires one request per tick at rps for duration (rps<=0: closed loop
// with workers). do returns the latency and whether it was an error.
func openLoop(rps float64, workers int, duration time.Duration, do func() (float64, bool)) ([]float64, int) {
	var (
		mu      sync.Mutex
		lat     []float64
		errs    atomic.Int64
		wg      sync.WaitGroup
		deadCtx = make(chan struct{})
	)
	record := func(d float64, bad bool) {
		if bad {
			errs.Add(1)
			return
		}
		mu.Lock()
		lat = append(lat, d)
		mu.Unlock()
	}
	if rps > 0 {
		// Open loop: a producer releases work on an absolute schedule
		// (start + i*interval), so scheduling jitter never lowers the offered
		// rate. A worker pool executes it; if the server saturates, the
		// channel backs up and the measured latency reflects that queueing.
		_ = deadCtx
		work := make(chan struct{}, 1<<22)
		pool := workers
		if pool <= 0 {
			pool = 512
		}
		for w := 0; w < pool; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for range work {
					record(do())
				}
			}()
		}
		interval := float64(time.Second) / rps
		n := int(rps * duration.Seconds())
		start := time.Now()
		for i := 0; i < n; i++ {
			target := start.Add(time.Duration(float64(i) * interval))
			if d := time.Until(target); d > 0 {
				time.Sleep(d)
			}
			work <- struct{}{}
		}
		close(work)
		wg.Wait()
		return lat, int(errs.Load())
	}
	// Closed loop.
	if workers <= 0 {
		workers = 32
	}
	stop := time.After(duration)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					record(do())
				}
			}
		}()
	}
	wg.Wait()
	return lat, int(errs.Load())
}

// ---------- latency (B01/T20, M1) ----------

func cmdLatency(args []string) error {
	fs := flagset(args)
	target := fs.string("target", "http://schild-api:8080", "URL to load")
	label := fs.string("label", "", "label for the result")
	rps := fs.float("rps", 500, "offered requests/s (0 = closed loop)")
	workers := fs.int("workers", 512, "worker pool size")
	dur := fs.duration("duration", 20*time.Second, "run duration")
	warmup := fs.duration("warmup", 3*time.Second, "warmup duration (discarded)")
	attackShare := fs.float("attack-share", 0, "fraction of requests carrying an SQLi query (triggers CRS)")
	out := fs.string("out", "", "write JSON here too")
	if err := fs.parse(); err != nil {
		return err
	}
	hc := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{MaxIdleConns: 4096, MaxIdleConnsPerHost: 4096, MaxConnsPerHost: 4096, IdleConnTimeout: 90 * time.Second}}
	// A representative benign mix: homepage, list, item, create.
	paths := []struct{ method, path, body string }{
		{"GET", "/", ""},
		{"GET", "/api/items?page=1&sort=name", ""},
		{"GET", "/api/items/2", ""},
		{"POST", "/api/items", `{"name":"Lampe","price":12}`},
	}
	ua := "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0 Safari/537.36"
	var seq atomic.Uint64
	statuses := &sync.Map{}
	do := func() (float64, bool) {
		i := int(seq.Add(1))
		p := paths[i%len(paths)]
		var rd io.Reader
		method, path, body := p.method, p.path, p.body
		// Deterministic attack share: a distinct SQLi param so each is a new
		// request signature. Suspicious but, in observe mode, never blocked -
		// so it measures the full inspect path.
		if *attackShare > 0 && float64(i%1000)/1000.0 < *attackShare {
			method, body = "GET", ""
			path = fmt.Sprintf("/api/items?q%d=%s", i%97, "1%27%20OR%20%271%27%3D%271")
		}
		req, _ := http.NewRequest(method, strings.TrimRight(*target, "/")+path, rd)
		if body != "" {
			rd = strings.NewReader(body)
			req, _ = http.NewRequest(method, strings.TrimRight(*target, "/")+path, rd)
		}
		req.Header.Set("User-Agent", ua)
		req.Header.Set("Accept", "application/json")
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		t0 := time.Now()
		resp, err := hc.Do(req)
		if err != nil {
			return 0, true
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		d := float64(time.Since(t0).Microseconds()) / 1000.0
		v, _ := statuses.LoadOrStore(resp.StatusCode, new(atomic.Int64))
		v.(*atomic.Int64).Add(1)
		bad := resp.StatusCode >= 500
		return d, bad
	}
	// Warmup.
	openLoop(*rps, *workers, *warmup, do)
	statuses = &sync.Map{}
	t0 := time.Now()
	lat, errs := openLoop(*rps, *workers, *dur, do)
	elapsed := time.Since(t0).Seconds()
	st := map[string]int64{}
	statuses.Range(func(k, v any) bool { st[fmt.Sprintf("%d", k.(int))] = v.(*atomic.Int64).Load(); return true })
	res := map[string]any{
		"kind": "latency", "label": *label, "target": *target,
		"offered_rps": *rps, "achieved_rps": float64(len(lat)+errs) / elapsed,
		"duration_s": round(elapsed, 2), "stats": stats(lat, errs), "statuses": st,
	}
	return emit(*out, res)
}

// ---------- K3 resilience corpus (M1 bypass) ----------

func cmdK3(args []string) error {
	fs := flagset(args)
	schildURL := fs.string("schild", "http://schild-api:8080", "URL through schild")
	out := fs.string("out", "", "write JSON here too")
	loadRPS := fs.float("load-rps", 300, "concurrent benign load while sending the corpus")
	loadDur := fs.duration("load-duration", 10*time.Second, "how long to keep the corpus/load running")
	if err := fs.parse(); err != nil {
		return err
	}
	hc := &http.Client{Timeout: 40 * time.Second, Transport: &http.Transport{MaxIdleConnsPerHost: 1024}}
	base := strings.TrimRight(*schildURL, "/")

	// Each K3 case names the status schild must answer (never a backend 2xx):
	// oversized body -> 413, nested JSON deeper than 64 -> 400, ReDoS query is
	// bounded by RE2 (linear) and the eval timeout (503 if too slow), a slow
	// body is bounded by the read timeout. "bypass" = a malicious payload that
	// reaches the origin unblocked (a 2xx carrying the site-api JSON body).
	type kase struct {
		name, method, path, ct string
		body                   []byte
		wantBlockStatuses      []int // statuses that count as safely handled
	}
	big := bytes.Repeat([]byte("A"), 20*1024*1024) // 20 MiB > 12.5 MiB hard limit
	nested := []byte(strings.Repeat(`{"a":`, 200) + "1" + strings.Repeat("}", 200))
	redos := "q=" + strings.Repeat("a", 60) + "!"
	hugeField := "x=" + strings.Repeat("A", 2*1024*1024) // 2 MiB single urlencoded value: slow in Coraza -> 503
	cases := []kase{
		{"oversized_body", "POST", "/api/items", "application/json", big, []int{413}},
		{"nested_json", "POST", "/api/items", "application/json", nested, []int{400}},
		{"redos_query", "GET", "/search?" + redos, "", nil, []int{200, 403, 404, 503}},
		{"huge_urlencoded_field", "POST", "/api/items", "application/x-www-form-urlencoded", []byte(hugeField), []int{400, 403, 413, 503}},
		{"too_many_args", "GET", "/api/items?" + manyArgs(1500), "", nil, []int{400, 403}},
	}

	// Backend fingerprint: site-api answers JSON. If a K3 malicious request
	// returns 2xx AND the body looks like the origin app, it reached the
	// origin unblocked.
	type caseResult struct {
		Name          string  `json:"name"`
		Status        int     `json:"status"`
		SafeHandle    bool    `json:"safely_handled"`
		ReachedOrigin bool    `json:"reached_origin"`
		LatencyMS     float64 `json:"latency_ms"`
		Detail        string  `json:"detail"`
	}
	send := func(k kase) caseResult {
		var rd io.Reader
		if k.body != nil {
			rd = bytes.NewReader(k.body)
		}
		req, _ := http.NewRequest(k.method, base+k.path, rd)
		if k.ct != "" {
			req.Header.Set("Content-Type", k.ct)
		}
		req.Header.Set("User-Agent", "python-requests/2.32.3")
		t0 := time.Now()
		resp, err := hc.Do(req)
		cr := caseResult{Name: k.name}
		if err != nil {
			cr.Detail = "error: " + err.Error()
			// A connection error is not a bypass (nothing reached the origin).
			cr.SafeHandle = true
			return cr
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		cr.Status = resp.StatusCode
		cr.LatencyMS = round(float64(time.Since(t0).Microseconds())/1000.0, 1)
		reached := resp.StatusCode < 300 && bytes.Contains(body, []byte(`"service":"site-api"`)) ||
			(resp.StatusCode < 300 && bytes.Contains(body, []byte(`"id":`)) && bytes.Contains(body, []byte(`"name":`)))
		cr.ReachedOrigin = reached
		for _, s := range k.wantBlockStatuses {
			if resp.StatusCode == s {
				cr.SafeHandle = true
			}
		}
		// For redos/too_many_args a 2xx that returns an EMPTY search result is
		// inspected-and-benign, not a bypass; only an origin-app payload for a
		// payload we expect blocked is a bypass.
		if k.name == "oversized_body" || k.name == "nested_json" || k.name == "huge_urlencoded_field" {
			if reached {
				cr.SafeHandle = false
			}
		}
		return cr
	}

	// Start benign background load so the corpus hits a busy proxy.
	stopLoad := make(chan struct{})
	var loadWG sync.WaitGroup
	if *loadRPS > 0 {
		loadWG.Add(1)
		go func() {
			defer loadWG.Done()
			lhc := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{MaxIdleConnsPerHost: 512}}
			interval := time.Duration(float64(time.Second) / *loadRPS)
			t := time.NewTicker(interval)
			defer t.Stop()
			for {
				select {
				case <-stopLoad:
					return
				case <-t.C:
					go func() {
						resp, err := lhc.Get(base + "/api/items?page=1")
						if err == nil {
							io.Copy(io.Discard, resp.Body)
							resp.Body.Close()
						}
					}()
				}
			}
		}()
	}

	// Send each case repeatedly for the duration, interleaved.
	var results []caseResult
	bypass := 0
	deadline := time.Now().Add(*loadDur)
	round := 0
	for time.Now().Before(deadline) {
		for _, k := range cases {
			cr := send(k)
			if !cr.SafeHandle || cr.ReachedOrigin {
				bypass++
			}
			if round == 0 {
				results = append(results, cr)
			}
		}
		round++
	}
	close(stopLoad)
	loadWG.Wait()

	res := map[string]any{
		"kind": "k3", "schild": *schildURL, "rounds": round, "load_rps": *loadRPS,
		"bypass_count": bypass, "first_round": results,
	}
	return emit(*out, res)
}

func manyArgs(n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteByte('&')
		}
		fmt.Fprintf(&b, "p%d=%d", i, i)
	}
	return b.String()
}

// ---------- burst (B13, M6) ----------

func cmdBurst(args []string) error {
	fs := flagset(args)
	labURL := fs.string("lab", "https://lab-a:7443", "lab ingest base URL")
	labName := fs.string("lab-name", "lab-a", "lab test key name (ack verification is not done here)")
	rate := fs.float("rate", 3000, "offered submissions/s (open loop)")
	dur := fs.duration("duration", 15*time.Second, "burst duration")
	workers := fs.int("workers", 512, "worker pool")
	metrics := fs.string("metrics", "", "optional lab metrics URL to scrape ack p99")
	out := fs.string("out", "", "write JSON here too")
	if err := fs.parse(); err != nil {
		return err
	}
	_ = labName
	// Presign one pool of submissions with the three configured test site keys.
	keys := []string{"site-a", "site-b", "site-c"}
	signers := make([]*auth.SiteKeySigner, len(keys))
	for i, k := range keys {
		signers[i] = auth.NewSiteKeySigner(testkeys.Signer(k))
	}
	pool := presignSubmissions(signers, 4096)

	hc := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		TLSClientConfig: testCAConfig(), MaxIdleConnsPerHost: 2048, MaxConnsPerHost: 2048, ForceAttemptHTTP2: true,
	}}
	url := strings.TrimRight(*labURL, "/") + "/v0/submit"
	statuses := &sync.Map{}
	var noAck, timeouts atomic.Int64
	var idx atomic.Uint64
	do := func() (float64, bool) {
		body := pool[int(idx.Add(1))%len(pool)]
		t0 := time.Now()
		resp, err := hc.Post(url, "application/json", bytes.NewReader(body))
		if err != nil {
			timeouts.Add(1)
			return 0, true
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		d := float64(time.Since(t0).Microseconds()) / 1000.0
		v, _ := statuses.LoadOrStore(resp.StatusCode, new(atomic.Int64))
		v.(*atomic.Int64).Add(1)
		// Every answer must carry a signed ack (200/202/429/503).
		if !(len(b) > 0 && b[0] == '{') {
			noAck.Add(1)
		}
		return d, false
	}
	t0 := time.Now()
	lat, errs := openLoop(*rate, *workers, *dur, do)
	elapsed := time.Since(t0).Seconds()
	st := map[string]int64{}
	statuses.Range(func(k, v any) bool { st[fmt.Sprintf("%d", k.(int))] = v.(*atomic.Int64).Load(); return true })

	res := map[string]any{
		"kind": "burst", "lab": *labURL,
		"offered_rate": *rate, "achieved_rate": round(float64(len(lat)+errs)/elapsed, 1), "duration_s": round(elapsed, 2),
		"client_observed": stats(lat, errs), "statuses": st,
		"responses_without_ack": noAck.Load(), "connection_errors_or_timeouts": timeouts.Load(),
	}
	if *metrics != "" {
		if p99, ok := scrapeAckP99(hc, *metrics); ok {
			res["lab_ack_p99_ms_metric"] = round(p99*1000, 3)
		}
	}
	return emit(*out, res)
}

func presignSubmissions(signers []*auth.SiteKeySigner, n int) [][]byte {
	out := make([][]byte, n)
	now := time.Now()
	rng := rand.New(rand.NewSource(1))
	var wg sync.WaitGroup
	chunk := (n + 15) / 16
	for w := 0; w < 16; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := w * chunk; i < n && i < (w+1)*chunk; i++ {
				signer := signers[i%len(signers)]
				var envs []json.RawMessage
				for k := 0; k < 4; k++ {
					s := msg.Signal{
						Schema: msg.SchemaSignal, ID: msg.NewID(), Kind: "tip",
						TimeBucket: msg.TimeBucket(now, 5),
						ActionSig:  "sqli/api",
						RequestSig: msg.RequestSig(msg.RequestShape{Method: "GET", PathTemplate: fmt.Sprintf("/api/items/{n}/%d", rng.Intn(40)), ParamNames: []string{"id"}, ContentType: "application/json", RuleIDs: []int{942100}}),
						WAFRules:   []int{942100}, Score: 80, Category: "sqli",
						Origin: msg.Origin{Country: "NL", ASN: 64500, NetClass: "hosting", Attribution: "tcp_peer"},
						Agent:  msg.Agent{Family: "python-requests", Major: 2},
					}
					payload, _ := jsonx.Marshal(&s)
					sealed, err := signer.Seal(context.Background(), contract.KindSignal, payload)
					if err != nil {
						panic(err)
					}
					raw, _ := sealed.Envelope.Marshal()
					envs = append(envs, raw)
				}
				out[i], _ = json.Marshal(msg.Submission{RequestID: msg.NewID(), Envelopes: envs})
			}
		}(w)
	}
	wg.Wait()
	return out
}

func scrapeAckP99(hc *http.Client, url string) (float64, bool) {
	resp, err := hc.Get(url)
	if err != nil {
		return 0, false
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "schild_lab_ack_p99_seconds") {
			f := strings.Fields(line)
			if len(f) >= 2 {
				var v float64
				fmt.Sscanf(f[len(f)-1], "%g", &v)
				return v, true
			}
		}
	}
	return 0, false
}

func testCAConfig() *tls.Config {
	pool := x509.NewCertPool()
	if p := os.Getenv("SCHILD_TEST_CA"); p != "" {
		if pem, err := os.ReadFile(p); err == nil {
			pool.AppendCertsFromPEM(pem)
		}
	}
	return &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
}

func round(f float64, places int) float64 {
	p := 1.0
	for i := 0; i < places; i++ {
		p *= 10
	}
	return float64(int64(f*p+0.5)) / p
}

// ---------- egress (T19, M2): plant canaries, then the log is checked ----------
//
// D72: the gateway no longer sends signals or writes a transparency log, so
// there is no outgoing log to check after this run. The canary traffic stays
// usable for scans of what the gateway stores (egress-check -scan-dirs).

func cmdEgress(args []string) error {
	fs := flagset(args)
	stripper := fs.string("stripper", "http://stripper-api:8080", "label stripper URL (sets ground truth)")
	n := fs.int("n", 60, "attack requests to send (each a new request signature)")
	out := fs.string("out", "", "write JSON here too")
	if err := fs.parse(); err != nil {
		return err
	}
	secret := os.Getenv("SCHILD_LABEL_SECRET")
	if secret == "" {
		return fmt.Errorf("SCHILD_LABEL_SECRET not set")
	}
	hc := &http.Client{Timeout: 20 * time.Second}
	base := strings.TrimRight(*stripper, "/")
	// Canary markers planted in every spot a value could leak from, and canary
	// source IPs (v4 and v6) set as the visitor address via X-Forwarded-For
	// (the stripper and this generator are trusted proxies of the site).
	canaries := []string{"CANARYqv", "CANARYbody", "CANARYcookie", "CANARYua", "CANARYpath"}
	canaryIPs := []string{"203.0.113.66", "2001:db8:dead:beef::66"}
	sent := 0
	for i := 0; i < *n; i++ {
		// A distinct SQLi parameter per request -> a fresh request signature
		// (before D72 schild offered a signal for each).
		q := fmt.Sprintf("inj%d=%s", i, "1%27%20OR%20%271%27%3D%271")
		path := fmt.Sprintf("/api/items/CANARYpath%d?%s&probe=CANARYqv%d", i, q, i)
		body := fmt.Sprintf(`{"name":"CANARYbody%d","note":"x"}`, i)
		req, _ := http.NewRequest("POST", base+path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", fmt.Sprintf("python-requests/2.32.3 CANARYua%d", i))
		req.Header.Set("Cookie", fmt.Sprintf("sid=CANARYcookie%d", i))
		req.Header.Set("X-Forwarded-For", canaryIPs[i%len(canaryIPs)])
		l := label.Label{Class: label.Malicious, Scenario: "T19", Source: "egress", Technique: "sqli", ExpectBlock: true, Seq: i}
		hdr, err := label.Sign([]byte(secret), l)
		if err != nil {
			return err
		}
		req.Header.Set(label.HeaderName, hdr)
		resp, err := hc.Do(req)
		if err != nil {
			return fmt.Errorf("send %d: %w", i, err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		sent++
		time.Sleep(60 * time.Millisecond)
	}
	return emit(*out, map[string]any{
		"kind": "egress_traffic", "stripper": *stripper, "sent": sent,
		"canaries": canaries, "canary_ips": canaryIPs,
	})
}

// ---------- scrape (read selected Prometheus metric lines) ----------

func cmdScrape(args []string) error {
	fs := flagset(args)
	url := fs.string("url", "", "metrics URL")
	prefix := fs.string("prefix", "schild_", "metric name prefix to keep")
	out := fs.string("out", "", "write JSON here too")
	if err := fs.parse(); err != nil {
		return err
	}
	hc := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: testCAConfig()}}
	resp, err := hc.Get(*url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	lines := map[string]float64{}
	for _, line := range strings.Split(string(b), "\n") {
		if line == "" || line[0] == '#' || !strings.HasPrefix(line, *prefix) {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		var v float64
		fmt.Sscanf(f[len(f)-1], "%g", &v)
		lines[strings.Join(f[:len(f)-1], " ")] = v
	}
	return emit(*out, map[string]any{"kind": "scrape", "url": *url, "metrics": lines})
}

// ---------- flag helper (wraps the standard flag package) ----------

type fsHelper struct {
	fs   *flag.FlagSet
	args []string
}

func flagset(args []string) *fsHelper {
	return &fsHelper{fs: flag.NewFlagSet("measure", flag.ContinueOnError), args: args}
}
func (f *fsHelper) string(name, def, usage string) *string { return f.fs.String(name, def, usage) }
func (f *fsHelper) float(name string, def float64, u string) *float64 {
	return f.fs.Float64(name, def, u)
}
func (f *fsHelper) int(name string, def int, u string) *int { return f.fs.Int(name, def, u) }
func (f *fsHelper) duration(name string, def time.Duration, u string) *time.Duration {
	return f.fs.Duration(name, def, u)
}
func (f *fsHelper) parse() error { return f.fs.Parse(f.args) }
