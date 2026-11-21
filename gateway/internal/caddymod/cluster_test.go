package caddymod

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestClusterRefusesAnOpenProxyProtocol(t *testing.T) {
	site := "\nhttp://app.example.test:8080 {\n\tschild\n\treverse_proxy 127.0.0.1:9000\n}\n"
	global := func(pp string) string {
		return "{\n\tservers {\n\t\tlistener_wrappers {\n" + pp + "\t\t}\n\t}\n\tauto_https off\n}\n" + site
	}
	cases := []struct {
		name, caddyfile, want string
	}{
		{"no proxy protocol", "{\n\tauto_https off\n}\n" + site, ""},
		{"allow list", global("\t\t\tproxy_protocol {\n\t\t\t\tallow 10.0.0.0/24\n\t\t\t}\n"), ""},
		{"allow list, others rejected", global("\t\t\tproxy_protocol {\n\t\t\t\tallow 10.0.0.0/24\n\t\t\t\tfallback_policy reject\n\t\t\t}\n"), ""},
		{"no allow list", global("\t\t\tproxy_protocol\n"), "no allow list"},
		{"header of anyone is used", global("\t\t\tproxy_protocol {\n\t\t\t\tallow 10.0.0.0/24\n\t\t\t\tfallback_policy use\n\t\t\t}\n"), "fallback_policy use"},
		{"header of anyone is required", global("\t\t\tproxy_protocol {\n\t\t\t\tallow 10.0.0.0/24\n\t\t\t\tfallback_policy require\n\t\t\t}\n"), "fallback_policy require"},
	}
	for _, c := range cases {
		path := filepath.Join(t.TempDir(), "Caddyfile")
		if err := os.WriteFile(path, []byte(c.caddyfile), 0o600); err != nil {
			t.Fatal(err)
		}
		o := IngressOptions{Caddyfile: path, DefaultStorage: t.TempDir()}
		// A single gateway takes every one of them, as before.
		if _, err := PrepareIngress(o); err != nil {
			t.Errorf("%s, single gateway: %v", c.name, err)
		}
		o.Cluster = true
		_, err := PrepareIngress(o)
		switch {
		case c.want == "" && err != nil:
			t.Errorf("%s, in a group: %v", c.name, err)
		case c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)):
			t.Errorf("%s, in a group: got %v, want an error with %q", c.name, err, c.want)
		}
	}
}
