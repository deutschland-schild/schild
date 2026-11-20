package bots

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/contract/websites"
)

const robotsSample = "\xef\xbb\xbf# example\r\n" +
	"User-agent: GPTBot\n" +
	"User-agent: CCBot/2.0\n" +
	"Disallow: /\n" +
	"\n" +
	"User-agent: Googlebot\n" +
	"Disallow: /private/\n" +
	"Allow: /private/public*.html$\n" +
	"Disallow: /*.pdf$\n" +
	"Disallow: /search?\n" +
	"Sitemap: https://example.org/sitemap.xml\n" +
	"Disallow: /tmp # comment\n" +
	"\n" +
	"user-agent: *\n" +
	"disallow: /admin\n" +
	"allow: /admin/help\n" +
	"disallow: /p\n" +
	"allow: /p\n" +
	"disallow: /caf%c3%a9\n" +
	"disallow: /ünïcode\n" +
	"Disallow:\n" +
	"\n" +
	"User-agent: googlebot\n" + // merged with the Googlebot group
	"Disallow: /merged\n" +
	"Allow: /merged/ok$\n"

func TestRobotsParseAndMatch(t *testing.T) {
	f := parseRobots([]byte(robotsSample))
	cases := []struct {
		tok, path string
		dis       bool
	}{
		{"GPTBot", "/", true},
		{"gptbot", "/anything", true},
		{"GPTBot", "/robots.txt", false},
		{"CCBot", "/x", true},
		{"Googlebot", "/private/x", true},
		{"Googlebot", "/private/public-1.html", false},
		{"Googlebot", "/private/public-1.html?x", true}, // $ anchors
		{"Googlebot", "/files/a.pdf", true},
		{"Googlebot", "/files/a.pdf.html", false},
		{"Googlebot", "/search?q=1", true},
		{"Googlebot", "/search", false},
		{"Googlebot", "/tmp/x", true},
		{"Googlebot", "/admin", false}, // its own group, not *
		{"Googlebot", "/merged/a", true},
		{"Googlebot", "/merged/ok", false},
		{"Googlebot", "/merged/ok/x", true},
		{"Bingbot", "/admin/x", true},
		{"Bingbot", "/admin/help/1", false}, // longer allow wins
		{"Bingbot", "/p/1", false},          // equal length: allow wins
		{"Bingbot", "/café", true},          // normalized both ways
		{"Bingbot", "/caf%C3%A9", true},
		{"Bingbot", "/caf%c3%a9", true},
		{"Bingbot", "/%C3%BCn%C3%AFcode/x", true},
		{"Bingbot", "/ok", false},
	}
	for _, c := range cases {
		if got := f.disallowed(c.tok, c.path); got != c.dis {
			t.Errorf("%s %s: disallowed %v, want %v", c.tok, c.path, got, c.dis)
		}
	}
	// Rules before any user-agent line and unknown records are ignored; an
	// empty file allows everything.
	g := parseRobots([]byte("Disallow: /\nCrawl-delay: 5\n"))
	if g.disallowed("x", "/a") {
		t.Error("rule without a group applied")
	}
	if parseRobots(nil).disallowed("x", "/") {
		t.Error("empty file disallows")
	}
}

func TestRobotsWildcards(t *testing.T) {
	for _, c := range []struct {
		pat, path string
		want      bool
	}{
		{"/", "/x", true}, {"/fish", "/fish.html", true}, {"/fish", "/Fish", false},
		{"/fish*", "/fishheads", true}, {"/fish/", "/fish", false}, {"/*.php", "/index.php", true},
		{"/*.php", "/folder/x.php?p=1", true}, {"/*.php$", "/x.php?p", false}, {"/*.php$", "/x.php", true},
		{"/fish*.php", "/fish/salmon.php", true}, {"/fish*.php", "/Fish.PHP", false}, {"/a*b*c$", "/axbxc", true},
		{"/a*b*c$", "/axbxcx", false}, {"/a*b*c$", "/abcbc", true}, {"*", "/any", true}, {"/$", "/", true}, {"/$", "/a", false},
		{"/a**b", "/ab", true}, {"/a$b", "/a$b", true},
	} {
		r := newRule(c.pat, false)
		if got := r.match(normalizePath(c.path)); got != c.want {
			t.Errorf("%q vs %q: %v, want %v", c.pat, c.path, got, c.want)
		}
	}
}

// fakeUpstream serves robots.txt per Host header and counts requests.
type fakeUpstream struct {
	srv  *httptest.Server
	hits atomic.Int32
}

func newFakeUpstream(t *testing.T) *fakeUpstream {
	u := &fakeUpstream{}
	u.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.hits.Add(1)
		if r.URL.Path == "/moved.txt" {
			w.Write([]byte("User-agent: *\nDisallow: /moved\n"))
			return
		}
		if r.URL.Path != "/robots.txt" || r.Header.Get("User-Agent") != RobotsUA || r.Header.Get("X-Forwarded-Host") != r.Host {
			http.Error(w, "unexpected request", http.StatusTeapot)
			return
		}
		switch r.Host {
		case "a.example":
			w.Write([]byte("User-agent: GPTBot\nDisallow: /\n"))
		case "b.example":
			http.NotFound(w, r)
		case "c.example":
			http.Error(w, "down", http.StatusInternalServerError)
		case "d.example":
			http.Redirect(w, r, "https://d.example/robots.txt", http.StatusMovedPermanently)
		case "e.example":
			http.Redirect(w, r, "/moved.txt", http.StatusFound)
		case "big.example":
			w.Write([]byte("User-agent: *\nDisallow: /early\n"))
			w.Write([]byte(strings.Repeat("#"+strings.Repeat("x", 1023)+"\n", MaxRobotsBytes/1024+8)))
			w.Write([]byte("Disallow: /late\n"))
		default:
			http.Error(w, "unknown host", http.StatusBadGateway)
		}
	}))
	t.Cleanup(u.srv.Close)
	return u
}

func TestRobotsProxyFetch(t *testing.T) {
	up := newFakeUpstream(t)
	fetch, err := ProxyFetch(up.srv.URL, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	var sites []RobotsSite
	for _, h := range []string{"a", "b", "c", "d", "e", "big"} {
		sites = append(sites, RobotsSite{ID: h, Host: h + ".example"})
	}
	r := NewRobots(sites, fetch)
	if _, known := r.Disallowed("a", "GPTBot", "/"); known {
		t.Fatal("known before any fetch")
	}
	if up.hits.Load() != 0 {
		t.Fatal("NewRobots fetched")
	}
	r.Refresh(context.Background())
	check := func(site, tok, path string, dis, known bool) {
		t.Helper()
		d, k := r.Disallowed(site, tok, path)
		if d != dis || k != known {
			t.Errorf("%s %s %s: disallowed %v known %v, want %v %v", site, tok, path, d, k, dis, known)
		}
	}
	check("a", "GPTBot", "/page", true, true)
	check("a", "Googlebot", "/page", false, true)
	check("b", "GPTBot", "/page", false, true)  // 404: everything allowed
	check("c", "GPTBot", "/page", false, false) // 500: unknown
	check("d", "GPTBot", "/page", false, false) // redirect to another host: not followed
	check("e", "GPTBot", "/moved", true, true)  // redirect on the same upstream, Host kept
	check("big", "GPTBot", "/early", true, true)
	check("big", "GPTBot", "/late", false, true) // beyond MaxRobotsBytes
	check("zzz", "GPTBot", "/", false, false)
	if r.FetchedAt("a").IsZero() || !r.FetchedAt("c").IsZero() {
		t.Error("FetchedAt")
	}
	// A failing fetch keeps the last good copy.
	r.fetch = func(context.Context, string) (*http.Response, error) { return nil, context.DeadlineExceeded }
	r.Refresh(context.Background())
	check("a", "GPTBot", "/page", true, true)
	// SetSites keeps unchanged websites.
	r.SetSites([]RobotsSite{{ID: "a", Host: "a.example"}, {ID: "n", Host: "n.example"}})
	check("a", "GPTBot", "/page", true, true)
	check("b", "GPTBot", "/page", false, false)
}

func TestRobotsStart(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host == "shop.example" && r.URL.Path == "/robots.txt" {
			w.Write([]byte("User-agent: ClaudeBot\nDisallow: /cart\n"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})
	r := NewRobots([]RobotsSite{{ID: "shop", Host: "shop.example"}, {ID: "blog", Host: "blog.example"}}, func(ctx context.Context, host string) (*http.Response, error) {
		req := httptest.NewRequestWithContext(ctx, http.MethodGet, "http://"+host+"/robots.txt", nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w.Result(), nil
	})
	r.delay = 10 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r.Start(ctx)
	deadline := time.Now().Add(5 * time.Second)
	for r.FetchedAt("blog").IsZero() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	r.Close()
	if d, k := r.Disallowed("shop", "ClaudeBot", "/cart/1"); !d || !k {
		t.Errorf("shop: %v %v", d, k)
	}
	if d, k := r.Disallowed("blog", "ClaudeBot", "/cart/1"); d || !k {
		t.Errorf("blog (404): %v %v", d, k)
	}
	if _, err := ProxyFetch("ftp://x", time.Second); err == nil {
		t.Error("ftp upstream accepted")
	}
}

func TestRobotsSitesOf(t *testing.T) {
	got := RobotsSitesOf([]websites.Website{
		{ID: "default", Protection: websites.Protected},
		{ID: "shop", Hosts: []string{"*.shop.example", "shop.example"}, Protection: websites.Protected},
		{ID: "wild", Hosts: []string{"*.wild.example"}, Protection: websites.Partial},
		{ID: "off", Hosts: []string{"off.example"}, Protection: websites.Unprotected},
	})
	want := []RobotsSite{{ID: "default"}, {ID: "shop", Host: "shop.example"}}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("%+v", got)
	}
}

func TestRobotsDisallowedDoesNotAllocate(t *testing.T) {
	r := NewRobots([]RobotsSite{{ID: "a", Host: "a.example"}}, nil)
	(*r.sites.Load())["a"].cur.Store(&robotsState{file: parseRobots([]byte(robotsSample)), fetched: time.Now()})
	paths := []string{"/private/public-1.html", "/files/a.pdf", "/caf%c3%a9/x", "/café", "/admin/help/x", "/" + strings.Repeat("x", 3000)}
	toks := []string{"Googlebot", "GPTBot", "Bingbot", "ClaudeBot"}
	i := 0
	if n := testing.AllocsPerRun(2000, func() {
		r.Disallowed("a", toks[i%len(toks)], paths[i%len(paths)])
		i++
	}); n != 0 {
		t.Errorf("Disallowed allocates %v", n)
	}
}

func BenchmarkRobotsDisallowed(b *testing.B) {
	r := NewRobots([]RobotsSite{{ID: "a", Host: "a.example"}}, nil)
	(*r.sites.Load())["a"].cur.Store(&robotsState{file: parseRobots([]byte(robotsSample)), fetched: time.Now()})
	paths := []string{"/private/public-1.html", "/files/a.pdf", "/blog/2026/10/some-post", "/admin/help/x"}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		r.Disallowed("a", "Googlebot", paths[i%len(paths)])
	}
}
