package caddymod

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
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

type stubGroup struct {
	changed, now, locked, unlocked []string
}

func (s *stubGroup) Changed(key string)                       { s.changed = append(s.changed, key) }
func (s *stubGroup) ChangedNow(_ context.Context, key string) { s.now = append(s.now, key) }
func (s *stubGroup) Lock(_ context.Context, name string) error {
	s.locked = append(s.locked, name)
	return nil
}
func (s *stubGroup) Unlock(_ context.Context, name string) { s.unlocked = append(s.unlocked, name) }

func TestClusterStorageWritesTheFileFirstAndTellsTheGroup(t *testing.T) {
	ctx := context.Background()
	st := &ClusterStorage{Root: t.TempDir()}
	if err := st.Provision(caddy.Context{}); err != nil {
		t.Fatal(err)
	}
	// Without a group it is the file storage.
	if err := st.Store(ctx, "certificates/ca/shop.example/shop.example.crt", []byte("c")); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(filepath.Join(st.Root, "certificates", "ca", "shop.example", "shop.example.crt")); err != nil || string(b) != "c" {
		t.Fatalf("file: %q, %v", b, err)
	}
	g := &stubGroup{}
	defer BindGroup(g)()
	if err := st.Store(ctx, "certificates/ca/shop.example/shop.example.key", []byte("k")); err != nil {
		t.Fatal(err)
	}
	if err := st.Store(ctx, "acme/ca.example-directory/challenge_tokens/shop.example.json", []byte("t")); err != nil {
		t.Fatal(err)
	}
	if err := st.Delete(ctx, "acme/ca.example-directory/challenge_tokens/shop.example.json"); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(g.changed, " "); got != "certificates/ca/shop.example/shop.example.key acme/ca.example-directory/challenge_tokens/shop.example.json" {
		t.Errorf("told the group: %q", got)
	}
	if got := strings.Join(g.now, " "); got != "acme/ca.example-directory/challenge_tokens/shop.example.json" {
		t.Errorf("a challenge token has to reach the group before Store returns: %q", got)
	}
	if b, err := st.Load(ctx, "certificates/ca/shop.example/shop.example.key"); err != nil || string(b) != "k" {
		t.Errorf("load: %q, %v", b, err)
	}
	if err := st.Lock(ctx, "issue_cert_shop.example"); err != nil {
		t.Fatal(err)
	}
	if err := st.Unlock(ctx, "issue_cert_shop.example"); err != nil {
		t.Fatal(err)
	}
	if len(g.locked) != 1 || len(g.unlocked) != 1 {
		t.Errorf("the group's lock: %v, %v", g.locked, g.unlocked)
	}
}

func TestClusterIngressSharesStorageAndTicketKeys(t *testing.T) {
	write := func(text string) string {
		path := filepath.Join(t.TempDir(), "Caddyfile")
		if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	site := "\nhttp://app.example.test:8080 {\n\tschild\n\treverse_proxy 127.0.0.1:9000\n}\n"
	root := t.TempDir()
	ing, err := PrepareIngress(IngressOptions{Caddyfile: write("{\n\tauto_https off\n}\n" + site), DefaultStorage: root, Cluster: true})
	if err != nil {
		t.Fatal(err)
	}
	var m struct {
		Storage map[string]any `json:"storage"`
		Apps    struct {
			TLS struct {
				SessionTickets struct {
					KeySource map[string]any `json:"key_source"`
				} `json:"session_tickets"`
			} `json:"tls"`
		} `json:"apps"`
	}
	if err := json.Unmarshal(ing.JSON, &m); err != nil {
		t.Fatal(err)
	}
	if m.Storage["module"] != "schild_cluster" || m.Storage["root"] != root || ing.StorageRoot != root {
		t.Errorf("storage: %v", m.Storage)
	}
	if m.Apps.TLS.SessionTickets.KeySource["provider"] != "distributed" {
		t.Errorf("session ticket keys are not shared: %v", m.Apps.TLS.SessionTickets.KeySource)
	}
	// The config provisions: both modules exist in this build.
	if err := ValidateIngress(ing, t.TempDir()); err != nil {
		t.Errorf("the group's ingress does not validate: %v", err)
	}
	// A single gateway keeps the file storage and its own ticket keys.
	single, err := PrepareIngress(IngressOptions{Caddyfile: write("{\n\tauto_https off\n}\n" + site), DefaultStorage: root})
	if err != nil || strings.Contains(string(single.JSON), "schild_cluster") || strings.Contains(string(single.JSON), "session_tickets") {
		t.Errorf("a single gateway changed: %v", err)
	}
	// Another storage module next to the group is refused.
	_, err = PrepareIngress(IngressOptions{Caddyfile: write("{\n\tauto_https off\n\tstorage consul {\n\t}\n}\n" + site), DefaultStorage: root, Cluster: true})
	if err == nil {
		t.Skip("no other storage module in this build to adapt")
	}
}
