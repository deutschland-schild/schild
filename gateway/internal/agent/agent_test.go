package agent

import "testing"

func TestParse(t *testing.T) {
	cases := map[string]Info{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36":                         {"chrome", 130, false},
		"Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1": {"safari", 18, false},
		"Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0":                                                                  {"firefox", 131, false},
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.2849.56":       {"edge", 130, false},
		"python-requests/2.32.3":                   {"python-requests", 2, false},
		"sqlmap/1.8.4#stable (https://sqlmap.org)": {"sqlmap", 1, false},
		"curl/8.5.0": {"curl", 8, false},
		"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)": {"googlebot", 2, true},
		"":                       {"none", 0, false},
		"SomethingElse/3":        {"other", 0, false},
		"MyCrawler (contact me)": {"other-bot", 0, true},
		"Go-http-client/1.1":     {"go-http-client", 1, false},
	}
	for ua, want := range cases {
		if got := Parse(ua); got != want {
			t.Errorf("Parse(%q) = %+v, want %+v", ua, got, want)
		}
	}
}
