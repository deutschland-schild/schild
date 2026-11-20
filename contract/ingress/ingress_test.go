package ingress

import (
	"strings"
	"testing"
)

func TestMessage(t *testing.T) {
	f := Finding{Code: CodeRewriteBeforeSchild, MsgKey: MsgKeyRewriteBeforeSchild, Server: "srv0", Route: "/routes/0",
		Hosts: []string{"a.example.test"}, Directive: DirectiveRewrite, Rewrite: "/routes/0/handle/0", Schild: "/routes/0/handle/1"}
	m := Message(f)
	if !strings.HasPrefix(m, "rewrite_before_schild: site a.example.test runs `rewrite` before schild") {
		t.Fatal(m)
	}
	f.Route, f.Hosts = "/errors/routes/0", nil
	if m := Message(f); !strings.Contains(m, "handle_errors of every host on server srv0") {
		t.Fatal(m)
	}
}

// P20 of the measurement, reduced to the adapted shape.
func TestP20(t *testing.T) {
	raw := `{"servers":{"srv0":{"routes":[{"match":[{"host":["a.example.test"]}],"handle":[{"handler":"subroute","routes":[
	{"handle":[{"handler":"vars","saved":"{http.request.uri.query}"}]},
	{"group":"group0","handle":[{"handler":"rewrite","uri":"/hidden?"}]},
	{"handle":[{"handler":"schild"},{"handler":"rewrite","uri_substring":[{"find":"/hidden","replace":"/hidden?{http.vars.saved}"}]},{"handler":"reverse_proxy"}]}]}]}]}}}`
	res, err := RunVector([]byte(raw))
	if err != nil || len(res.Findings) != 1 || res.Findings[0].Rewrite != "/routes/0/handle/0/routes/1/handle/0" || res.Findings[0].Schild != "/routes/0/handle/0/routes/2/handle/0" {
		t.Fatalf("%+v %v", res, err)
	}
	// schild first: no finding.
	raw = strings.Replace(raw, `{"group":"group0","handle":[{"handler":"rewrite","uri":"/hidden?"}]},`, "", 1)
	raw = strings.Replace(raw, `{"handle":[{"handler":"vars"`, `{"handle":[{"handler":"schild"},{"handler":"rewrite","uri":"/hidden?"},{"handler":"vars"`, 1)
	if res, err := RunVector([]byte(raw)); err != nil || len(res.Findings) != 0 {
		t.Fatalf("%+v %v", res, err)
	}
}
