// Package legit generates realistic, deterministic legitimate traffic:
// browsing sessions (a landing page, then a few follow-up pages), API clients
// (GET/POST JSON), good bots with recognisable user agents, and a small number
// of canary requests that carry a unique marker the egress check watches for.
//
// Everything is a pure function of the seed, so make traffic SEED=42 replays
// the same requests. Nothing here is an attack: every request is labelled
// benign, good_bot or canary and must pass the WAF.
package legit

import (
	"fmt"
	"math/rand"

	"github.com/deutschland-schild/schild/testlab/internal/label"
	"github.com/deutschland-schild/schild/testlab/traffic/internal/req"
)

var browsePaths = []string{"/", "/about", "/blog", "/blog/post-1", "/contact", "/products", "/products/42", "/search"}
var apiPaths = []string{"/api/items", "/api/items/1", "/api/items/2"}

// goodBots are legitimate crawlers with their user agents. In the test lab the
// CoreDNS mock provides matching reverse DNS so the client can verify them.
var goodBots = []struct{ name, ua string }{
	{"googlebot", "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"},
	{"bingbot", "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)"},
}

var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15", // slow mobile
	"curl/8.4.0", // API client
}

// Generate returns n legitimate requests spread over the given sites. About
// one in twenty is a canary (still benign, but carrying a unique marker); the
// returned canary slice lists those markers for the egress check.
func Generate(seed int64, scenario string, sites []string, n int) (reqs []req.Request, canaries []string) {
	if len(sites) == 0 {
		return nil, nil
	}
	rng := rand.New(rand.NewSource(seed))
	seq := 0
	for len(reqs) < n {
		site := sites[rng.Intn(len(sites))]
		switch rng.Intn(10) {
		case 0, 1: // API client session
			p := apiPaths[rng.Intn(len(apiPaths))]
			r := req.Request{
				Method: "GET", Site: site, Path: p,
				Headers: map[string]string{"User-Agent": "curl/8.4.0", "Accept": "application/json"},
				Label:   label.Label{Class: label.Benign, Scenario: scenario, Source: "legit", Technique: "api", Seq: seq},
			}
			reqs = append(reqs, r)
			seq++
		case 2: // good bot
			b := goodBots[rng.Intn(len(goodBots))]
			r := req.Request{
				Method: "GET", Site: site, Path: browsePaths[rng.Intn(len(browsePaths))],
				Headers: map[string]string{"User-Agent": b.ua},
				Label:   label.Label{Class: label.GoodBot, Scenario: scenario, Source: b.name, Technique: "crawl", Seq: seq},
			}
			reqs = append(reqs, r)
			seq++
		case 3: // canary (benign, unique marker)
			canary := fmt.Sprintf("CANARY-%08X", rng.Uint32())
			canaries = append(canaries, canary)
			r := req.Request{
				Method: "GET", Site: site, Path: "/search",
				Query:   "q=" + canary,
				Headers: map[string]string{"User-Agent": ua(rng), "X-Canary": canary},
				Label:   label.Label{Class: label.Canary, Scenario: scenario, Source: "legit", Technique: "canary", Canary: canary, Seq: seq},
			}
			reqs = append(reqs, r)
			seq++
		default: // browsing session: landing + 1-3 follow-ups
			agent := ua(rng)
			steps := 1 + rng.Intn(3)
			for i := 0; i < steps && len(reqs) < n; i++ {
				p := browsePaths[rng.Intn(len(browsePaths))]
				if i == 0 {
					p = "/"
				}
				r := req.Request{
					Method: "GET", Site: site, Path: p,
					Headers: map[string]string{"User-Agent": agent, "Accept": "text/html"},
					Label:   label.Label{Class: label.Benign, Scenario: scenario, Source: "legit", Technique: "browse", Seq: seq},
				}
				reqs = append(reqs, r)
				seq++
			}
		}
	}
	return reqs[:n], canaries
}

func ua(rng *rand.Rand) string { return userAgents[rng.Intn(len(userAgents))] }
