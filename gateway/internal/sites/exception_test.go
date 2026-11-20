package sites

import (
	"regexp"
	"strings"
	"testing"

	"github.com/deutschland-schild/schild/contract/websites"
)

func TestExceptionScopedToWebsite(t *testing.T) {
	v := NewView(websites.Input{Mode: websites.ModeIngress, Blocks: []websites.Block{
		{Addresses: []string{"shop.example.org", "www.shop.example.org"}, Schild: true},
		{Addresses: []string{":8080"}, Schild: true},
	}})
	file := regexp.MustCompile(`^rules\.d/[a-z0-9._-]{1,64}\.conf$`)
	ex, err := v.Exception("shop.example.org", "942100", "/kontakt/{id}", "ARGS:comment", 9100001)
	if err != nil {
		t.Fatal(err)
	}
	if ex.Scope != websites.ScopeWebsite || ex.Language != "seclang" || !file.MatchString(ex.File) ||
		!strings.Contains(ex.Snippet, "REQUEST_HEADERS:Host") || !strings.Contains(ex.Snippet, `www\.shop\.example\.org`) || !strings.Contains(ex.Snippet, "chain") {
		t.Fatalf("website exception: %+v", ex)
	}
	want, _ := websites.ExceptionSnippet(websites.ExceptionInput{SiteID: "shop.example.org", Hosts: []string{"shop.example.org", "www.shop.example.org"},
		RuleID: "942100", Path: "/kontakt/{id}", Target: "ARGS:comment", ID: 9100001})
	if ex.Snippet != want.Snippet {
		t.Fatalf("snippet differs from the contract:\n%s\n%s", ex.Snippet, want.Snippet)
	}
	any, err := v.Exception("_any", "942100", "/", "", 9100002)
	if err != nil || any.Scope != websites.ScopeGateway || strings.Contains(any.Snippet, "Host") || !file.MatchString(any.File) {
		t.Fatalf("gateway exception: %v %+v", err, any)
	}
	if _, err := v.Exception("nope.example", "942100", "/", "", 1); err != ErrUnknownWebsite {
		t.Fatalf("unknown website: %v", err)
	}
}
