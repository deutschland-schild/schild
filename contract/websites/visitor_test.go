package websites

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/deutschland-schild/schild/contract/monitoring"
	"github.com/deutschland-schild/schild/contract/schema"
)

// TestVisitorSchemaEnums: the website-visitor input schema uses the value
// sets of the monitoring contract (UAClass, BotCategory, RequestOutcome).
func TestVisitorSchemaEnums(t *testing.T) {
	var doc struct {
		Properties map[string]struct {
			Enum []string `json:"enum"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(schema.Files()["website-visitor.schema.json"], &doc); err != nil {
		t.Fatal(err)
	}
	for k, want := range map[string][]string{"ua_class": monitoring.UAClasses, "bot_category": monitoring.BotCategories, "outcome": monitoring.RequestOutcomes} {
		if got := doc.Properties[k].Enum; !reflect.DeepEqual(got, want) {
			t.Errorf("%s: schema %v, go %v", k, got, want)
		}
	}
}

// TestVisitorRule: only a browser request schild forwarded makes a visitor;
// every non-browser request makes a bot client; nothing is both.
func TestVisitorRule(t *testing.T) {
	for _, ua := range monitoring.UAClasses {
		for _, cat := range monitoring.BotCategories {
			for _, out := range monitoring.RequestOutcomes {
				v, b := monitoring.Visitor(ua, cat, out), monitoring.BotClient(ua, cat)
				browser := ua == "browser" && cat == monitoring.CategoryLikelyBrowser
				if v != (browser && (out == "passed" || out == "would_block")) || b == browser || v && b {
					t.Errorf("%s/%s/%s: visitor %v, bot client %v", ua, cat, out, v, b)
				}
			}
		}
	}
}

// TestOwnHost: Set.OwnHost never matches through the catch-all.
func TestOwnHost(t *testing.T) {
	set, err := Derive(Input{Mode: ModeIngress, Blocks: []Block{
		{Addresses: []string{"shop.example.org"}, Schild: true, Proxies: true},
		{Addresses: []string{"*.kunden.example.org"}, Schild: true, Proxies: true},
		{Addresses: []string{":8080"}, Schild: true, Proxies: true},
	}})
	if err != nil {
		t.Fatal(err)
	}
	for h, want := range map[string]bool{"shop.example.org": true, "Shop.Example.org.:443": true, "a.kunden.example.org": true,
		"kunden.example.org": false, "example.org": false, "": false, "bad host": false} {
		if got := set.OwnHost(h); got != want {
			t.Errorf("OwnHost(%q) = %v, want %v", h, got, want)
		}
		if set.Resolve(h) == "" {
			t.Errorf("Resolve(%q): the catch-all should take it", h)
		}
	}
}
