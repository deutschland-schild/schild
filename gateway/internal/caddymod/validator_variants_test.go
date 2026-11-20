package caddymod

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The Caddyfile variants of the independent MVP-19 measurement: 29 of the
// first measurement (results/MVP-19-messung/validator/variants), 8 of the
// re-measurement (N*, results/MVP-19-messung/nachmessung/variants) and 2 of
// fix round 2, copied to testdata. Each file names its
// ingress.unprotected_sites and the expected verdict. Variants 20-23 were
// accepted before although a request reached the backend without schild
// (finding 2); N01, N02, N03, N06 and N23 were accepted after the first fix
// round (re-measurement finding 1: handle_errors is server-wide).
// Measurement 3 (results/MVP-19-messung/messung-3) adds M01-M26, the
// re-measurement's normal configs O01-O18 (O06, O14, O16, O18 refused since
// fix round 2) and their one-line fixes A-*. The evening measurement of
// 2026-10-29 (testlab/measure/ingress-load/variants) adds P01-P24. Since the D31
// amendment (contracts/ingress-order.md, rule rewrite_before_schild) a
// rewrite, uri or method before schild is refused: M18, M24, M25 and P01-P04,
// P07, P09, P12-P15, P17-P23. P05, P06, P08, P10, P11, P16 and P24 keep the
// validator's earlier verdict (pass); the `# expect:` lines of the P files
// are the gateway validator's verdicts, not the measurement's. The measurement
// before the live step (2026-10-30) adds V00-V14: V01 and V14 hide a header
// from schild and write it back, refused since D40 (header_hidden_from_schild,
// accepted before); the other thirteen keep the verdict of that measurement.
func TestMeasurementVariants(t *testing.T) {
	files, err := filepath.Glob("testdata/variants/*.caddy")
	if err != nil || len(files) != 130 {
		t.Fatalf("variants: %d files, %v", len(files), err)
	}
	for _, f := range files {
		name := strings.TrimSuffix(filepath.Base(f), ".caddy")
		t.Run(name, func(t *testing.T) {
			b, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			var unprotected []string
			expect := ""
			var body strings.Builder
			body.WriteString("{\n\tadmin off\n\tauto_https off\n}\n(schild) {\n\tschild\n}\n")
			for _, l := range strings.Split(string(b), "\n") {
				switch {
				case strings.HasPrefix(l, "# unprotected: "):
					list := strings.Trim(strings.TrimPrefix(l, "# unprotected: "), "[] ")
					for _, e := range strings.Split(list, ",") {
						if e = strings.Trim(strings.TrimSpace(e), `"`); e != "" {
							unprotected = append(unprotected, e)
						}
					}
				case strings.HasPrefix(l, "# expect: "):
					expect = strings.TrimPrefix(l, "# expect: ")
				case strings.HasPrefix(l, "# "):
				default:
					body.WriteString(l + "\n")
				}
			}
			c, err := CheckConfig(adapt(t, body.String()), unprotected)
			if err != nil {
				t.Fatal(err)
			}
			got := "pass"
			if len(c.Errors) > 0 {
				got = "refuse"
			}
			if got != expect {
				t.Fatalf("got %s, want %s: %+v", got, expect, c)
			}
		})
	}
}

func TestCheckConfigConservative(t *testing.T) {
	const snip = "(schild) {\n\tschild\n}\n"
	cases := []struct {
		name, caddyfile string
		refuse          bool
	}{
		// handle_response (intercept, reverse_proxy)
		{"intercept proxy behind schild", snip + "http://a.example.test {\n\timport schild\n\tintercept {\n\t\t@any status 2xx\n\t\thandle_response @any {\n\t\t\treverse_proxy 127.0.0.1:9\n\t\t}\n\t}\n\trespond \"x\" 200\n}\n", false},
		{"intercept proxy, schild only in another site", snip + "http://b.example.test {\n\timport schild\n\treverse_proxy 127.0.0.1:9\n}\nhttp://a.example.test {\n\tintercept {\n\t\thandle_response {\n\t\t\treverse_proxy 127.0.0.1:9\n\t\t}\n\t}\n\trespond 200\n}\n", true},
		{"reverse_proxy handle_response proxy behind schild", snip + "http://a.example.test {\n\timport schild\n\treverse_proxy 127.0.0.1:9 {\n\t\t@e status 404\n\t\thandle_response @e {\n\t\t\treverse_proxy 127.0.0.1:10\n\t\t}\n\t}\n}\n", false},
		// A matcher on a route covers all of its handlers: everything behind
		// a schild in it runs behind that schild (security review 3.3); a
		// later route does not.
		{"route with matcher, schild first in it", snip + "http://a.example.test {\n\troute /api/* {\n\t\timport schild\n\t\treverse_proxy 127.0.0.1:9\n\t}\n\trespond 404\n}\n", false},
		{"schild with matcher, proxy in the next route", snip + "http://a.example.test {\n\troute {\n\t\tschild /api/*\n\t\treverse_proxy 127.0.0.1:9\n\t}\n}\n", true},
		// mutually exclusive handle blocks
		{"every handle branch protected", snip + "http://a.example.test {\n\thandle /api/* {\n\t\timport schild\n\t\treverse_proxy 127.0.0.1:9\n\t}\n\thandle {\n\t\timport schild\n\t\treverse_proxy 127.0.0.1:10\n\t}\n}\n", false},
		{"schild before all handle branches", snip + "http://a.example.test {\n\timport schild\n\thandle /api/* {\n\t\theader X-Api 1\n\t}\n\thandle {\n\t\treverse_proxy 127.0.0.1:10\n\t}\n}\n", false},
		{"schild in the fallback handle, proxy after", snip + "http://a.example.test {\n\thandle /a/* {\n\t\trespond 204\n\t}\n\thandle /b/* {\n\t\timport schild\n\t}\n\treverse_proxy 127.0.0.1:9\n}\n", true},
		{"handle_path branch with schild, proxy after", snip + "http://a.example.test {\n\thandle_path /x/* {\n\t\timport schild\n\t}\n\thandle {\n\t\theader X 1\n\t}\n\treverse_proxy 127.0.0.1:9\n}\n", true},
		// errors before schild reaching handle_errors
		{"basic_auth before schild, handle_errors proxies", snip + "http://a.example.test {\n\troute {\n\t\tbasic_auth {\n\t\t\tu $2a$14$Zkx19XLiW6VYouLHR5NmfOFU0z2GTNmpkT/5qqR7hx4IjWJPDhjvG\n\t\t}\n\t\tschild\n\t\treverse_proxy 127.0.0.1:9\n\t}\n\thandle_errors {\n\t\treverse_proxy 127.0.0.1:9\n\t}\n}\n", true},
		{"file matcher before schild, handle_errors proxies", snip + "http://a.example.test {\n\t@f file\n\theader @f X-F 1\n\timport schild\n\treverse_proxy 127.0.0.1:9\n\thandle_errors {\n\t\treverse_proxy 127.0.0.1:9\n\t}\n}\n", true},
		{"error before schild, schild inside handle_errors", snip + "http://a.example.test {\n\troute {\n\t\terror /x/* 404\n\t\tschild\n\t\treverse_proxy 127.0.0.1:9\n\t}\n\thandle_errors {\n\t\timport schild\n\t\treverse_proxy 127.0.0.1:9\n\t}\n}\n", false},
		{"expression matcher before schild, no handle_errors", snip + "http://a.example.test {\n\t@bad expression `int({http.request.uri.query.n}) > 5`\n\theader @bad X-Bad 1\n\timport schild\n\treverse_proxy 127.0.0.1:9\n}\n", false},
		// handle_errors is server-wide: a proxying handle_errors needs schild
		// inside, even when its own site is fully guarded (fix round 2).
		{"guarded site, handle_errors proxies without schild", snip + "http://a.example.test {\n\t@h header X-A 1\n\theader @h X-B 2\n\tvars v 1\n\trequest_body {\n\t\tmax_size 1MB\n\t}\n\timport schild\n\treverse_proxy 127.0.0.1:9\n\thandle_errors {\n\t\treverse_proxy 127.0.0.1:9\n\t}\n}\n", true},
		{"guarded site, handle_errors proxies with schild", snip + "http://a.example.test {\n\timport schild\n\treverse_proxy 127.0.0.1:9\n\thandle_errors {\n\t\timport schild\n\t\treverse_proxy 127.0.0.1:9\n\t}\n}\n", false},
		{"handle_errors php_fastcgi without schild", snip + "http://a.example.test {\n\timport schild\n\treverse_proxy 127.0.0.1:9\n\thandle_errors {\n\t\tphp_fastcgi 127.0.0.1:9000\n\t}\n}\n", true},
		{"handle_errors invokes a proxy route without schild", snip + "&(app) {\n\treverse_proxy 127.0.0.1:9\n}\nhttp://a.example.test {\n\timport schild\n\treverse_proxy 127.0.0.1:9\n\thandle_errors {\n\t\tinvoke app\n\t}\n}\n", true},
		{"handle_errors static pages only", snip + "http://a.example.test {\n\timport schild\n\treverse_proxy 127.0.0.1:9\n\thandle_errors {\n\t\troot * /srv/errors\n\t\trewrite * /{err.status_code}.html\n\t\tfile_server\n\t}\n}\nhttp://b.example.test {\n\troot * /srv/b\n\tfile_server\n}\n", false},
		{"handle_errors proxy listed as unprotected host only", snip + "http://a.example.test {\n\timport schild\n\treverse_proxy 127.0.0.1:9\n}\nhttp://b.example.test {\n\treverse_proxy 127.0.0.1:9\n\thandle_errors {\n\t\treverse_proxy 127.0.0.1:9\n\t}\n}\n", true},
		// invoke of a named route that starts with schild guards what follows.
		{"invoke named route with schild first", snip + "&(guard) {\n\tschild\n}\nhttp://a.example.test {\n\tinvoke guard\n\treverse_proxy 127.0.0.1:9\n}\n", false},
		{"invoke named route with schild under a path", snip + "&(guard) {\n\tschild /x/*\n}\nhttp://a.example.test {\n\tinvoke guard\n\treverse_proxy 127.0.0.1:9\n}\n", true},
		{"handle_errors proxy for a site guarded only on one path", snip + "http://a.example.test {\n\thandle /app/* {\n\t\timport schild\n\t\treverse_proxy 127.0.0.1:9\n\t}\n\trespond 404\n\thandle_errors {\n\t\treverse_proxy 127.0.0.1:9\n\t}\n}\n", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := CheckConfig(adapt(t, tc.caddyfile), nil)
			if err != nil {
				t.Fatal(err)
			}
			if (len(c.Errors) > 0) != tc.refuse {
				t.Fatalf("refuse=%v, want %v: %+v", len(c.Errors) > 0, tc.refuse, c)
			}
		})
	}
}

// JSON configs the Caddyfile adapter does not produce, but a config can hold.
func TestCheckConfigJSONOnly(t *testing.T) {
	cases := []struct {
		name, json string
		refuse     bool
	}{
		{"subroute errors proxy after schild", `{"apps":{"http":{"servers":{"s":{"routes":[{"match":[{"host":["a.test"]}],"handle":[{"handler":"subroute","routes":[{"handle":[{"handler":"schild"},{"handler":"error","status_code":404}]}],"errors":{"routes":[{"handle":[{"handler":"reverse_proxy","upstreams":[{"dial":"127.0.0.1:9"}]}]}]}}]}]}}}}}`, true},
		{"unknown handler without schild", `{"apps":{"http":{"servers":{"s":{"routes":[{"match":[{"host":["a.test"]}],"handle":[{"handler":"something_new"}]}]}}}}}`, true},
		{"unknown handler behind schild", `{"apps":{"http":{"servers":{"s":{"routes":[{"match":[{"host":["a.test"]}],"handle":[{"handler":"schild"},{"handler":"something_new"}]}]}}}}}`, false},
		{"group: second route without matcher does not guard", `{"apps":{"http":{"servers":{"s":{"routes":[{"match":[{"host":["a.test"]}],"handle":[{"handler":"subroute","routes":[{"group":"g","match":[{"path":["/x"]}],"handle":[{"handler":"static_response"}]},{"group":"g","handle":[{"handler":"schild"}]},{"handle":[{"handler":"reverse_proxy","upstreams":[{"dial":"127.0.0.1:9"}]}]}]}]}]}}}}}`, true},
		{"group: first route without matcher guards", `{"apps":{"http":{"servers":{"s":{"routes":[{"match":[{"host":["a.test"]}],"handle":[{"handler":"subroute","routes":[{"group":"g","handle":[{"handler":"schild"}]},{"group":"g","match":[{"path":["/x"]}],"handle":[{"handler":"static_response"}]},{"handle":[{"handler":"reverse_proxy","upstreams":[{"dial":"127.0.0.1:9"}]}]}]}]}]}}}}}`, false},
		{"invoke of a missing named route", `{"apps":{"http":{"servers":{"s":{"routes":[{"match":[{"host":["a.test"]}],"handle":[{"handler":"invoke","name":"gone"}]}]}}}}}`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := CheckConfig([]byte(tc.json), nil)
			if err != nil {
				t.Fatal(err)
			}
			if (len(c.Errors) > 0) != tc.refuse {
				t.Fatalf("refuse=%v, want %v: %+v", len(c.Errors) > 0, tc.refuse, c)
			}
		})
	}
}
