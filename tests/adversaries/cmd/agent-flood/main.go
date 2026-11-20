// Command agent-flood is the MVP-11 review probe for the kill criterion
// "agent or check failures affect request handling": it floods a gateway's
// agent listener (POST /v0/agent/report, /v0/agent/enrol) while a second
// instance measures request latency on the site the same schild protects.
// TEST LAB ONLY: it signs with the public test key test-agent-a.
//
//	agent-flood latency -url http://schild-api:8080/ -rps 40 -dur 60s -tag baseline
//	agent-flood flood -gw https://schild-api:8790 -mode signed -c 32 -dur 60s -report report.json -gateway site-api
//
// Modes: big (768 KiB valid JSON envelope, bad signature), signed (valid
// test-agent-a reports with ~500 KiB payload, a new nonce and report id
// each), hold (768 KiB bodies sent but the last byte held back ~50 s),
// malformed (random bytes), enrol (enrolment requests with wrong codes).
// Every request comes from this container's address; run several containers
// to get past the per-address limit. Output: one JSON line on stdout.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// test-agent-a of contracts/testkeys/keys.json (public TEST ONLY key).
const (
	agentKeyID = "test-agent-a"
	agentSeed  = "8ee5e06468d6c586bb8da295d260078de0a394770db51f2dad87f8ac1f082da5"
	reportType = "application/vnd.schild.agent-report.v0+json"
	enrolType  = "application/vnd.schild.agent-enrolment.v0+json"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: agent-flood latency|flood [flags]")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "latency":
		latency(os.Args[2:])
	case "flood":
		flood(os.Args[2:])
	case "sink":
		sink(os.Args[2:])
	default:
		fmt.Fprintln(os.Stderr, "unknown command", os.Args[1])
		os.Exit(2)
	}
}

// ---------------------------------------------------------------- latency

func latency(args []string) {
	fs := flag.NewFlagSet("latency", flag.ExitOnError)
	url := fs.String("url", "http://schild-api:8080/", "site URL behind schild")
	rps := fs.Int("rps", 40, "requests per second")
	dur := fs.Duration("dur", 60*time.Second, "duration")
	tag := fs.String("tag", "", "label in the output")
	_ = fs.Parse(args)
	cl := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{MaxIdleConnsPerHost: 64}}
	var mu sync.Mutex
	var lat []float64
	codes := map[string]int{}
	tick := time.NewTicker(time.Second / time.Duration(*rps))
	defer tick.Stop()
	end := time.Now().Add(*dur)
	var wg sync.WaitGroup
	for time.Now().Before(end) {
		<-tick.C
		wg.Add(1)
		go func() {
			defer wg.Done()
			t0 := time.Now()
			resp, err := cl.Get(*url)
			d := time.Since(t0).Seconds() * 1000
			k := "error"
			if err == nil {
				_, _ = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				k = strconv.Itoa(resp.StatusCode)
			}
			mu.Lock()
			lat = append(lat, d)
			codes[k]++
			mu.Unlock()
		}()
	}
	wg.Wait()
	sort.Float64s(lat)
	q := func(p float64) float64 {
		if len(lat) == 0 {
			return 0
		}
		return lat[min(len(lat)-1, int(p*float64(len(lat))))]
	}
	out, _ := json.Marshal(map[string]any{"probe": "latency", "tag": *tag, "n": len(lat), "codes": codes,
		"p50_ms": q(0.50), "p95_ms": q(0.95), "p99_ms": q(0.99), "max_ms": q(1)})
	fmt.Println(string(out))
}

// ---------------------------------------------------------------- sink

// sink is the control: a TLS listener that answers like a rate-limited
// gateway (429 without reading the body), so a flood against it costs the
// generators the same CPU while schild sees nothing.
func sink(args []string) {
	fs := flag.NewFlagSet("sink", flag.ExitOnError)
	addr := fs.String("listen", ":8790", "listen address")
	_ = fs.Parse(args)
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "sink"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, priv.Public(), priv)
	if err != nil {
		fail(err)
	}
	srv := &http.Server{Addr: *addr, TLSConfig: &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: priv}}},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(429)
			_, _ = io.WriteString(w, `{"schema":"schild.agent_ack/0.1","status":"retry","nonce":"00000000000000000000000000000000","received_at":"2026-10-27T00:00:00Z","error":null,"retry_after_s":60}`)
		})}
	fail(srv.ListenAndServeTLS("", ""))
}

// ---------------------------------------------------------------- flood

func flood(args []string) {
	fs := flag.NewFlagSet("flood", flag.ExitOnError)
	gw := fs.String("gw", "https://schild-api:8790", "agent listener")
	mode := fs.String("mode", "big", "big|signed|hold|malformed|enrol")
	conc := fs.Int("c", 16, "concurrent workers")
	dur := fs.Duration("dur", 60*time.Second, "duration")
	reportFile := fs.String("report", "", "host report JSON (from `schild check --json`) for mode signed")
	gateway := fs.String("gateway", "site-api", "gateway node_name")
	padKiB := fs.Int("pad", 360, "payload size target in KiB (mode signed; at most 1990 padding items)")
	_ = fs.Parse(args)

	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, MaxIdleConnsPerHost: *conc, //nolint:gosec // test lab
		DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext}
	cl := &http.Client{Transport: tr, Timeout: 120 * time.Second}
	priv := ed25519.NewKeyFromSeed(mustHex(agentSeed))
	var base map[string]any
	if *mode == "signed" {
		b, err := os.ReadFile(*reportFile)
		if err != nil {
			fail(err)
		}
		if err := json.Unmarshal(b, &base); err != nil {
			fail(err)
		}
		host := base["host"].(map[string]any)
		host["role"], host["agent_key_id"] = "agent", agentKeyID
		// Up to the contract's 2000 inventory items with long names (the
		// schema allows 128 characters): the largest report a valid agent
		// may send, so every delivery takes the full verification path.
		inv, _ := base["inventory"].([]any)
		for i := 0; len(inv) < 1990 && len(inv)*190 < *padKiB<<10; i++ {
			name := fmt.Sprintf("flood-pad-%06d-", i) + strings.Repeat("x", 100)
			inv = append(inv, map[string]any{"kind": "os_package", "name": name, "version": "1.0", "eol": nil, "source": "dpkg"})
		}
		base["inventory"] = inv
	}
	bigBody := func() []byte {
		junk := make([]byte, 570<<10)
		_, _ = rand.Read(junk)
		env := map[string]any{"payloadType": reportType, "payload": base64.StdEncoding.EncodeToString(junk),
			"signatures": []any{map[string]any{"keyid": agentKeyID, "sig": base64.StdEncoding.EncodeToString(make([]byte, 64))}}}
		return mustJSON(env)
	}
	body := func() []byte {
		switch *mode {
		case "big", "hold":
			return bigBody()
		case "malformed":
			b := make([]byte, 64<<10)
			_, _ = rand.Read(b)
			return b
		case "enrol":
			seed := make([]byte, 32)
			_, _ = rand.Read(seed)
			k := ed25519.NewKeyFromSeed(seed)
			kid := "flood-" + hex.EncodeToString(seed[:4]) + "/agent/2026-10"
			p := map[string]any{"schema": "schild.agent_enrolment/0.1", "gateway": *gateway, "code": "ABCD-EFGH-JKLM-NPQR", "keyid": kid,
				"public_key": "ed25519:" + base64.StdEncoding.EncodeToString(k.Public().(ed25519.PublicKey)), "hostname": "flood.example",
				"issued_at": time.Now().UTC().Format("2006-01-02T15:04:05Z"), "nonce": nonce()}
			return sign(enrolType, mustJSON(p), kid, k)
		default: // signed
			r := cloneMap(base)
			r["report_id"] = uuid4()
			p := map[string]any{"schema": "schild.agent_report/0.1", "gateway": *gateway,
				"issued_at": time.Now().UTC().Format("2006-01-02T15:04:05Z"), "nonce": nonce(), "report": r}
			return sign(reportType, mustJSON(p), agentKeyID, priv)
		}
	}
	path := "/v0/agent/report"
	if *mode == "enrol" {
		path = "/v0/agent/enrol"
	}
	var mu sync.Mutex
	statuses := map[string]int{}
	var sent, bytesSent atomic.Int64
	ctx, cancel := context.WithTimeout(context.Background(), *dur)
	defer cancel()
	var wg sync.WaitGroup
	for w := 0; w < *conc; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ctx.Err() == nil {
				b := body()
				var rd io.Reader = bytes.NewReader(b)
				if *mode == "hold" {
					rd = &holdReader{b: b, hold: 50 * time.Second}
				}
				req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, *gw+path, rd)
				req.ContentLength = int64(len(b))
				req.Header.Set("Content-Type", "application/json")
				resp, err := cl.Do(req)
				k := "error"
				if err == nil {
					ab, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
					resp.Body.Close()
					var a struct {
						Status string  `json:"status"`
						Error  *string `json:"error"`
					}
					_ = json.Unmarshal(ab, &a)
					k = strconv.Itoa(resp.StatusCode) + ":" + a.Status
					if a.Error != nil {
						k += ":" + *a.Error
					}
				} else if strings.Contains(err.Error(), "reset") || strings.Contains(err.Error(), "EOF") {
					k = "conn_closed"
				}
				sent.Add(1)
				bytesSent.Add(int64(len(b)))
				mu.Lock()
				statuses[k]++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	out, _ := json.Marshal(map[string]any{"probe": "flood", "mode": *mode, "c": *conc, "sent": sent.Load(), "mib": bytesSent.Load() >> 20, "statuses": statuses})
	fmt.Println(string(out))
}

// holdReader sends everything but the last byte at once and the last byte
// after hold: the server keeps the whole body buffered meanwhile.
type holdReader struct {
	b    []byte
	off  int
	hold time.Duration
}

func (h *holdReader) Read(p []byte) (int, error) {
	if h.off >= len(h.b) {
		return 0, io.EOF
	}
	if h.off == len(h.b)-1 {
		time.Sleep(h.hold)
	}
	end := min(len(h.b)-1, h.off+len(p))
	if h.off == len(h.b)-1 {
		end = len(h.b)
	}
	n := copy(p, h.b[h.off:end])
	h.off += n
	return n, nil
}

func sign(payloadType string, payload []byte, keyid string, k ed25519.PrivateKey) []byte {
	pae := fmt.Sprintf("DSSEv1 %d %s %d ", len(payloadType), payloadType, len(payload))
	sig := ed25519.Sign(k, append([]byte(pae), payload...))
	return mustJSON(map[string]any{"payloadType": payloadType, "payload": base64.StdEncoding.EncodeToString(payload),
		"signatures": []any{map[string]any{"keyid": keyid, "sig": base64.StdEncoding.EncodeToString(sig)}}})
}

func nonce() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func uuid4() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

func cloneMap(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		fail(err)
	}
	return b
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		fail(err)
	}
	return b
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "agent-flood:", err)
	os.Exit(1)
}
