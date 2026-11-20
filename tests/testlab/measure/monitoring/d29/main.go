// Command d29 is the measurement harness for the D29 amendment (block
// duration per net class, 2026-10-29). TEST ONLY: it writes a geo database
// of synthetic 10.0.0.0/8 networks with every net class, triggers the
// path_probing and waf_repeat scenarios through a running gateway with a
// trusted X-Forwarded-For, floods it with distinct addresses and validates
// stored events against the contract.
//
//	d29 geo      -out geo.mmdb -table geo.json
//	d29 probe    -url http://127.0.0.1:19200 -host shop.test IP...
//	d29 status   -url ... IP...            (status of one plain GET per IP)
//	d29 flood    -url ... -n 1000000 -c 64 -base 10.128.0.0 [-waf]
//	d29 validate < events.jsonl            (contract validator, one event per line)
package main

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/deutschland-schild/schild/contract/verify"
	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
)

type geoEntry struct {
	CIDR     string `json:"cidr"`
	Country  string `json:"country"`
	ASN      uint32 `json:"asn"`
	ASOrg    string `json:"as_org"`
	NetClass string `json:"net_class"`
}

// geoTable: one /16 per net class (the AS organisations are neutral so the
// gateway's own Classify heuristic does not override the class), the flood
// range 10.128.0.0/9 as residential and 10.64.0.0/10 as hosting.
// 100.64.0.0/10 and 172.16.0.0/12 are left out: the gateway classifies them
// itself (cgnat by prefix, unknown).
func geoTable() []geoEntry {
	return []geoEntry{
		{"10.0.0.0/16", "DE", 64600, "D29 Net residential", "residential"},
		{"10.1.0.0/16", "NL", 64601, "D29 Net hosting", "hosting"},
		{"10.2.0.0/16", "DE", 64602, "D29 Net business", "business"},
		{"10.3.0.0/16", "DE", 64603, "D29 Net education", "education"},
		{"10.4.0.0/16", "DE", 64604, "D29 Net government", "government"},
		{"10.20.0.0/16", "SE", 64620, "D29 Net v", "vpn"},
		{"10.21.0.0/16", "US", 64621, "D29 Net p", "proxy"},
		{"10.22.0.0/16", "DE", 64622, "D29 Net t", "tor"},
		{"10.23.0.0/16", "DE", 64623, "D29 Net m", "mobile"},
		{"10.24.0.0/16", "DE", 64624, "D29 Net c", "cgnat"},
		{"10.25.0.0/16", "DE", 64625, "D29 Net u", "unknown"},
		{"10.64.0.0/10", "NL", 64664, "D29 Net hosting flood", "hosting"},
		{"10.128.0.0/9", "DE", 64628, "D29 Net residential flood", "residential"},
	}
}

func cmdGeo(args []string) error {
	fs := flag.NewFlagSet("geo", flag.ExitOnError)
	out := fs.String("out", "geo.mmdb", "")
	tbl := fs.String("table", "", "write the table as JSON")
	_ = fs.Parse(args)
	w, err := mmdbwriter.New(mmdbwriter.Options{DatabaseType: "schild-geo-fixture", IncludeReservedNetworks: true, IPVersion: 6, RecordSize: 28,
		Languages: []string{"en"}, Description: map[string]string{"en": "TEST ONLY d29 measurement"}})
	if err != nil {
		return err
	}
	t := geoTable()
	for _, e := range t {
		_, n, err := net.ParseCIDR(e.CIDR)
		if err != nil {
			return err
		}
		rec := mmdbtype.Map{
			"country":                        mmdbtype.Map{"iso_code": mmdbtype.String(e.Country)},
			"city":                           mmdbtype.Map{"names": mmdbtype.Map{"en": mmdbtype.String("Testcity")}},
			"autonomous_system_number":       mmdbtype.Uint32(e.ASN),
			"autonomous_system_organization": mmdbtype.String(e.ASOrg),
			"schild_net_class":               mmdbtype.String(e.NetClass),
		}
		if err := w.Insert(n, rec); err != nil {
			return err
		}
	}
	f, err := os.Create(*out)
	if err != nil {
		return err
	}
	if _, err := w.WriteTo(f); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if *tbl != "" {
		b, _ := json.MarshalIndent(t, "", " ")
		return os.WriteFile(*tbl, b, 0o644)
	}
	return nil
}

var client = &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{MaxIdleConns: 512, MaxIdleConnsPerHost: 512}}

func get(url, host, ip, path string, hdr map[string]string) (int, error) {
	req, _ := http.NewRequest("GET", url+path, nil)
	req.Host = host
	req.Header.Set("X-Forwarded-For", ip)
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0")
	req.Header.Set("Accept", "text/html")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.StatusCode, nil
}

// probe sends 25 distinct paths answered 404 by the backend (X-Status),
// enough for path_probing (20 distinct 404 paths in 60 s).
func cmdProbe(args []string) error {
	fs := flag.NewFlagSet("probe", flag.ExitOnError)
	url := fs.String("url", "http://127.0.0.1:19200", "")
	host := fs.String("host", "shop.test", "")
	n := fs.Int("n", 25, "")
	_ = fs.Parse(args)
	for _, ip := range fs.Args() {
		counts := map[int]int{}
		for i := 0; i < *n; i++ {
			st, err := get(*url, *host, ip, fmt.Sprintf("/d29/missing-%d-%d", time.Now().UnixNano(), i), map[string]string{"X-Status": "404"})
			if err != nil {
				return err
			}
			counts[st]++
		}
		after, _ := get(*url, *host, ip, "/", nil)
		b, _ := json.Marshal(map[string]any{"ip": ip, "probe_statuses": counts, "status_after": after, "t": time.Now().UTC().Format(time.RFC3339)})
		fmt.Println(string(b))
	}
	return nil
}

func cmdStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	url := fs.String("url", "http://127.0.0.1:19200", "")
	host := fs.String("host", "shop.test", "")
	_ = fs.Parse(args)
	for _, ip := range fs.Args() {
		st, err := get(*url, *host, ip, "/", nil)
		b, _ := json.Marshal(map[string]any{"ip": ip, "status": st, "err": fmt.Sprint(err), "t": time.Now().UTC().Format(time.RFC3339)})
		fmt.Println(string(b))
	}
	return nil
}

// flood sends one request per distinct address (n addresses from base) or,
// with -waf, two attack requests per address that match distinct CRS rules
// (waf_repeat: 2 distinct rules over 2 requests), so every address gets a
// behaviour block.
func cmdFlood(args []string) error {
	fs := flag.NewFlagSet("flood", flag.ExitOnError)
	url := fs.String("url", "http://127.0.0.1:19200", "")
	host := fs.String("host", "shop.test", "")
	n := fs.Int("n", 100000, "distinct addresses")
	c := fs.Int("c", 64, "concurrency")
	base := fs.String("base", "10.128.0.0", "")
	waf := fs.Bool("waf", false, "two attack requests per address")
	_ = fs.Parse(args)
	b := netip.MustParseAddr(*base).As4()
	start := binary.BigEndian.Uint32(b[:])
	var next atomic.Int64
	var mu sync.Mutex
	statuses := map[int]int{}
	var errs atomic.Int64
	t0 := time.Now()
	var wg sync.WaitGroup
	for w := 0; w < *c; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			local := map[int]int{}
			for {
				i := next.Add(1) - 1
				if i >= int64(*n) {
					break
				}
				var a [4]byte
				binary.BigEndian.PutUint32(a[:], start+uint32(i))
				ip := netip.AddrFrom4(a).String()
				paths := []string{fmt.Sprintf("/f/%d", i)}
				if *waf {
					paths = []string{"/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E", "/item?id=1%27%20OR%20%271%27%3D%271%27%20--"}
				}
				for _, p := range paths {
					st, err := get(*url, *host, ip, p, nil)
					if err != nil {
						errs.Add(1)
						continue
					}
					local[st]++
				}
			}
			mu.Lock()
			for k, v := range local {
				statuses[k] += v
			}
			mu.Unlock()
		}()
	}
	wg.Wait()
	el := time.Since(t0)
	out, _ := json.Marshal(map[string]any{"addresses": *n, "base": *base, "waf": *waf, "statuses": statuses, "errors": errs.Load(),
		"seconds": el.Seconds(), "rps": float64(*n) * map[bool]float64{true: 2, false: 1}[*waf] / el.Seconds()})
	fmt.Println(string(out))
	return nil
}

// validate checks every event (one JSON per line on stdin) with the
// contract's own validator (events.schema.json via verify.Document).
func cmdValidate(args []string) error {
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 1<<20), 16<<20)
	ok, bad := 0, 0
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		if _, err := verify.Document(verify.DocEvent, append([]byte(nil), line...), &verify.Context{}); err != nil {
			bad++
			fmt.Printf("INVALID %s\n  %s\n", err, line)
			continue
		}
		ok++
	}
	fmt.Printf("valid %d invalid %d\n", ok, bad)
	if bad > 0 {
		os.Exit(1)
	}
	return sc.Err()
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: d29 geo|probe|status|flood|validate ...")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "geo":
		err = cmdGeo(os.Args[2:])
	case "probe":
		err = cmdProbe(os.Args[2:])
	case "status":
		err = cmdStatus(os.Args[2:])
	case "flood":
		err = cmdFlood(os.Args[2:])
	case "validate":
		err = cmdValidate(os.Args[2:])
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
