package caddymod

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"unicode"

	"github.com/caddyserver/caddy/v2"

	// The DNS challenge needs a module for the DNS service of the domain,
	// and stock Caddy has none. The list of modules compiled into schild is
	// short and checked (MVP-37): each one is third-party code in the gateway.
	_ "github.com/caddy-dns/hetzner/v2"
)

// hetznerTokenEnv is where the Hetzner module looks when the token of the
// config is empty.
const hetznerTokenEnv = "LIBDNS_HETZNER_TOKEN"

// DNSTokenProblems returns one line for each Hetzner DNS provider of an
// adapted Caddy config whose API token is empty or unusable in this process:
// a missing file, an environment variable that is not set, a token with a
// space or a line break. Caddy accepts such a config, and the module panics
// when the first order needs the token. No line holds a token.
func DNSTokenProblems(cfgJSON []byte) []string {
	var root any
	if json.Unmarshal(cfgJSON, &root) != nil {
		return nil
	}
	repl := caddy.NewReplacer()
	found := map[string]bool{}
	var visit func(key string, v any)
	visit = func(key string, v any) {
		switch t := v.(type) {
		case map[string]any:
			// challenges.dns.provider of an issuer, apps.tls.dns
			if (key == "provider" || key == "dns") && t["name"] == "hetzner" {
				if p := hetznerTokenProblem(repl, t); p != "" {
					found[p] = true
				}
			}
			for k, c := range t {
				visit(k, c)
			}
		case []any:
			for _, c := range t {
				visit(key, c)
			}
		}
	}
	visit("", root)
	out := make([]string, 0, len(found))
	for p := range found {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

func hetznerTokenProblem(repl *caddy.Replacer, provider map[string]any) string {
	raw, _ := provider["api_token"].(string)
	token := repl.ReplaceAll(raw, "")
	if token == "" {
		token = os.Getenv(hetznerTokenEnv)
	}
	// Only a placeholder is named, never a token written into the Caddyfile.
	from := ""
	if strings.HasPrefix(raw, "{") && strings.HasSuffix(raw, "}") {
		from = " from " + raw
	}
	switch {
	case token == "":
		return fmt.Sprintf("dns hetzner: the API token%s is empty (file missing or not readable for this user, or the variable is not set)", from)
	case strings.ContainsFunc(token, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }):
		return fmt.Sprintf("dns hetzner: the API token%s holds a space or a line break", from)
	}
	return ""
}
