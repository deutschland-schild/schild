package agentapi

import "testing"

func TestSuggestTarget(t *testing.T) {
	for _, c := range []struct{ v, k, want string }{
		{"ARGS_POST", "json.components.0.updates.text", "ARGS:json.components.*.updates.text"},
		{"ARGS", "q", "ARGS:q"},
		{"REQUEST_COOKIES", "session", "REQUEST_COOKIES:session"},
		{"REQUEST_HEADERS", "Referer", "REQUEST_HEADERS:Referer"},
		{"ARGS", "", ""},             // a whole collection
		{"ARGS", "0", ""},            // nothing but a wildcard
		{"ARGS", "a b", ""},          // not a name an exception takes
		{"REQUEST_FILENAME", "", ""}, // no field
		{"ARGS_NAMES", "q", ""},
	} {
		if got := SuggestTarget(c.v, c.k); got != c.want {
			t.Errorf("%s:%s = %q, want %q", c.v, c.k, got, c.want)
		}
	}
	if SuggestPath("/livewire/update?x=1") != "/livewire/update" || SuggestPath("/a b") != "" || SuggestPath("/{id}") != "" {
		t.Error("SuggestPath")
	}
}

func TestValidTestRequest(t *testing.T) {
	ok := TestRequest{Website: "w", Method: "POST", Path: "/a?b=c", Headers: map[string]string{"Cookie": "a=b"}}
	if !ValidTestRequest(ok) {
		t.Fatal("valid refused")
	}
	for _, bad := range []TestRequest{
		{Website: "", Method: "GET", Path: "/"},
		{Website: "w", Method: "get", Path: "/"},
		{Website: "w", Method: "GET", Path: "/ä"},
		{Website: "w", Method: "GET", Path: "/", Headers: map[string]string{"Transfer-Encoding": "chunked"}},
		{Website: "w", Method: "GET", Path: "/", Headers: map[string]string{"X": "a\nb"}},
		{Website: "w", Method: "GET", Path: "/", ContentType: "a\nb"},
	} {
		if ValidTestRequest(bad) {
			t.Errorf("accepted %+v", bad)
		}
	}
}
