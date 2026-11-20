package pathtpl

import "testing"

func TestTemplate(t *testing.T) {
	cases := map[string]string{
		"":                        "/",
		"/":                       "/",
		"/wp-login.php":           "/wp-login.php",
		"/wp-json/wp/v2/users/12": "/wp-json/wp/v2/users/{n}",
		"/api/orders/6f1c2b7e-1d4a-4c8e-9b2f-6a5d4e3c2b1a/items": "/api/orders/{uuid}/items",
		"/download/deadbeefcafe1234":                             "/download/{hex}",
		"/blog/mein-erster-beitrag/":                             "/blog/{slug}/",
		"/produkte/":                                             "/produkte/",
		"/users/max@example.org":                                 "/users/{slug}",
		"/x/AbCdEf0123456789xyz":                                 "/x/{slug}",
		"/search?q=1":                                            "/search",
		"/a/../../etc/passwd":                                    "/a/../../etc/passwd",
	}
	for in, want := range cases {
		if got := Template(in); got != want {
			t.Errorf("Template(%q) = %q, want %q", in, got, want)
		}
	}
}
