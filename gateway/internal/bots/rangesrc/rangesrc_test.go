package rangesrc

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestParseRanges(t *testing.T) {
	js := `{"creationTime":"2026-10-29T00:00:00.000000","prefixes":[{"ipv4Prefix":"66.249.66.7/27"},{"ipv6Prefix":"2001:4860:4801:10::/64"},{"ipv4Prefix":"66.249.66.0/27"},{"ipv6Prefix":"::ffff:192.0.2.0/120"}]}`
	ps, err := ParseRanges(FormatJSON, []byte(js))
	if err != nil {
		t.Fatal(err)
	}
	got := CanonicalPrefixes(ps)
	want := []string{"66.249.66.0/27", "192.0.2.0/24", "2001:4860:4801:10::/64"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	ls, err := ParseRanges(FormatLines, []byte("3.12.251.153\n# comment\n\n2001:19f0:200:125d::426\n198.51.100.0/24 \n"))
	if err != nil {
		t.Fatal(err)
	}
	if got := CanonicalPrefixes(ls); !reflect.DeepEqual(got, []string{"3.12.251.153/32", "198.51.100.0/24", "2001:19f0:200:125d::426/128"}) {
		t.Fatalf("lines: %v", got)
	}
	for _, bad := range []string{`{"prefixes":[]}`, `{"prefixes":[{"ipv4Prefix":"300.1.1.1/8"}]}`, `not json`, `{"prefixes":[{"ipv6Prefix":"fe80::1%eth0/64"}]}`} {
		if _, err := ParseRanges(FormatJSON, []byte(bad)); err == nil {
			t.Errorf("%s: accepted", bad)
		}
	}
	if _, err := ParseRanges(FormatLines, []byte("host.example\n")); err == nil {
		t.Error("lines: a host name was accepted")
	}
}

func TestFetchSourceCapsAndMerges(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/a.json":
			w.Write([]byte(`{"prefixes":[{"ipv4Prefix":"192.0.2.0/25"}]}`))
		case "/b.json":
			w.Write([]byte(`{"prefixes":[{"ipv4Prefix":"192.0.2.0/25"},{"ipv4Prefix":"198.51.100.0/24"}]}`))
		case "/big":
			w.Write([]byte(strings.Repeat(" ", MaxRangeBytes+1)))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	c := srv.Client()
	got, err := FetchSource(context.Background(), c, Source{ID: "x", Format: FormatJSON, URLs: []string{srv.URL + "/a.json", srv.URL + "/b.json"}}, "test")
	if err != nil || !reflect.DeepEqual(got, []string{"192.0.2.0/25", "198.51.100.0/24"}) {
		t.Fatalf("merge: %v %v", got, err)
	}
	for _, path := range []string{"/big", "/missing"} {
		if _, err := FetchSource(context.Background(), c, Source{ID: "x", Format: FormatJSON, URLs: []string{srv.URL + path}}, "test"); err == nil {
			t.Errorf("%s: no error", path)
		}
	}
	if _, err := FetchSource(context.Background(), c, Source{ID: "x", Format: FormatJSON, URLs: []string{"http://example.org/x.json"}}, "test"); err == nil {
		t.Error("http URL accepted")
	}
}

func TestParseRangesRejectsBroadAndNonPublic(t *testing.T) {
	rejected := []string{
		"0.0.0.0/0",
		"1.0.0.0/8",
		"198.51.0.0/15",
		"::/0",
		"2001:db8::/16",
		"127.0.0.1/32",
		"10.0.0.0/24",
		"172.16.0.0/24",
		"192.168.1.0/24",
		"169.254.169.254/32",
		"100.64.0.0/24",
		"0.1.0.0/24",
		"224.0.0.0/24",
		"fc00::/48",
		"fe80::/64",
		"::1/128",
	}
	for _, p := range rejected {
		if _, err := ParseRanges(FormatLines, []byte(p+"\n")); err == nil {
			t.Errorf("prefix %s was accepted, want rejection", p)
		}
	}
	accepted := []string{
		"9.129.0.0/16",
		"66.249.64.0/19",
		"2600:1f28::/32",
		"2001:4860:4801:10::/64",
	}
	for _, p := range accepted {
		if _, err := ParseRanges(FormatLines, []byte(p+"\n")); err != nil {
			t.Errorf("valid public prefix %s rejected: %v", p, err)
		}
	}
}

func TestHTTPClientRejectsCrossHostRedirect(t *testing.T) {
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"prefixes":[{"ipv4Prefix":"192.0.2.0/24"}]}`))
	}))
	defer target.Close()

	redirector := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/cross":
			http.Redirect(w, r, target.URL+"/data.json", http.StatusFound)
		case "/same":
			http.Redirect(w, r, "/final.json", http.StatusFound)
		case "/final.json":
			_, _ = w.Write([]byte(`{"prefixes":[{"ipv4Prefix":"192.0.2.0/24"}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer redirector.Close()

	c := HTTPClient(5 * time.Second)
	c.Transport = redirector.Client().Transport

	if _, err := FetchSource(context.Background(), c, Source{ID: "x", Format: FormatJSON, URLs: []string{redirector.URL + "/cross"}}, "test"); err == nil {
		t.Fatal("cross-host redirect was followed")
	}
	got, err := FetchSource(context.Background(), c, Source{ID: "x", Format: FormatJSON, URLs: []string{redirector.URL + "/same"}}, "test")
	if err != nil || !reflect.DeepEqual(got, []string{"192.0.2.0/24"}) {
		t.Fatalf("same-host redirect failed: %v %v", got, err)
	}
}
