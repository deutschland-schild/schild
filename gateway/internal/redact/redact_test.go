package redact

import (
	"strings"
	"testing"
)

func TestQuery(t *testing.T) {
	cases := map[string]string{
		"q=test&page=2":                                   "q=test&page=2",
		"log=admin&pwd=hunter2hunter2":                    "log=admin&pwd=[redacted]",
		"user_password=x&next=/":                          "user_password=[redacted]&next=/",
		"access_token=abc&x=1":                            "access_token=[redacted]&x=1",
		"API-KEY=1234":                                    "API-KEY=[redacted]",
		"email=max%40example.org&name=Max":                "email=" + "%5Bredacted%5D" + "&name=Max",
		"contact=max@example.org":                         "contact=%5Bredacted%5D",
		"t=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig12345": "t=%5Bredacted%5D",
		"ref=Ab3dE5gH7jK9mN1pQ3sT5vX7zB9dF1hJ":            "ref=%5Bredacted%5D",
		"PHPSESSID=deadbeef":                              "PHPSESSID=[redacted]",
		"flag":                                            "flag",
	}
	for in, want := range cases {
		if got := Query(in); got != want {
			t.Errorf("Query(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestTextAndPath(t *testing.T) {
	if got := Path("/users/max@example.org/profile"); strings.Contains(got, "example.org") {
		t.Fatalf("email kept: %s", got)
	}
	if got := Path("/wp-login.php"); got != "/wp-login.php" {
		t.Fatal(got)
	}
	// Segment by segment: a long path of short segments is no token.
	for _, p := range []string{"/build/assets/app-Bx12AbCd.js", "/blog/2024/11/05/some-post", "/.vite/manifest.json"} {
		if got := Path(p); got != p {
			t.Fatalf("%s redacted: %s", p, got)
		}
	}
	if got := Path("/reset/9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c/confirm"); got != "/reset/"+Marker+"/confirm" {
		t.Fatalf("token kept: %s", got)
	}
	if got := UserAgent("Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0"); strings.Contains(got, Marker) {
		t.Fatalf("plain UA redacted: %s", got)
	}
	// Long names made of words and numbers are no tokens (D85).
	for _, p := range []string{
		"/blog/my-very-long-post-title-about-something-2024-edition",
		"/media/IMG_20240101_123456789_HDR_edited_final.jpg",
		"/downloads/Jahresbericht-2025-Kurzfassung-Version-12",
	} {
		if got := Path(p); got != p {
			t.Fatalf("%s redacted: %s", p, got)
		}
	}
	for _, p := range []string{
		"/magic/Zk3-xP9_qL2vR8tY5wB1nM4cH7jD0sF6gA3eU9iO2k",
		"/s/5f2b8c1e9d3a4f7b6c0e1d2a3b4c5d6e7f8091a2",
	} {
		if got := Path(p); !strings.Contains(got, Marker) {
			t.Fatalf("token kept: %s", got)
		}
	}
}

// The User-Agent is stored as sent (D85): an app name with a build number is
// no token, the contact address of a crawler is public.
func TestUserAgent(t *testing.T) {
	for _, ua := range []string{
		"Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0",
		"SomeLongSchoolAppName-iOS/20261.1.29.10.33 CFNetwork/6681.2.2 Darwin/27.0.1",
		"crawler (contact: bot@example.org)",
	} {
		if got := UserAgent(ua); got != ua {
			t.Fatalf("UserAgent(%q) = %q", ua, got)
		}
	}
	if got := UserAgent(strings.Repeat("a", 2000)); len(got) != 1024 {
		t.Fatal(len(got))
	}
}

func TestSecretNames(t *testing.T) {
	for _, n := range []string{
		"password", "Passwort_password", "csrf_token", "Authorization", "session_id", "api_key", "jwt", "apiKey", "API-KEY",
		"csrfmiddlewaretoken", "PHPSESSID", "pwd", "code", "reset_code", "user[pass]", "sig", "X-Auth", "client_secret",
	} {
		if !IsSecretName(n) {
			t.Errorf("%s should be secret", n)
		}
	}
	for _, n := range []string{
		"q", "page", "s", "id", "lang", "category", "monkey", "zipcode", "zip_code", "country_code", "promo_code", "bypass",
		"shipping", "author", "inside", "account", "keyword", "hashtag", "pinned", "passenger",
	} {
		if IsSecretName(n) {
			t.Errorf("%s should not be secret", n)
		}
	}
}
