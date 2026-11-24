package caddymod

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/caddyserver/caddy/v2"
)

// ListenAddresses returns what the servers of a config listen on, one entry
// per address and protocol (tcp or udp), sorted.
//
// A reload compares them (ReloadIngress): a config that fails to open a port
// half way leaves its servers running inside Caddy, on the addresses it
// shares with the config before it, so a reload never opens one.
func ListenAddresses(cfgJSON []byte) ([]string, error) {
	var c struct {
		Apps struct {
			HTTP struct {
				Servers map[string]struct {
					Listen          []string   `json:"listen"`
					Protocols       []string   `json:"protocols"`
					ListenProtocols [][]string `json:"listen_protocols"`
				} `json:"servers"`
			} `json:"http"`
		} `json:"apps"`
	}
	if err := json.Unmarshal(cfgJSON, &c); err != nil {
		return nil, fmt.Errorf("caddyfile: adapted config: %w", err)
	}
	seen := map[string]bool{}
	for _, s := range c.Apps.HTTP.Servers {
		for i, l := range s.Listen {
			a, err := caddy.ParseNetworkAddress(l)
			if err != nil {
				return nil, fmt.Errorf("caddyfile: listen address %q: %w", l, err)
			}
			protocols := s.Protocols
			if i < len(s.ListenProtocols) && s.ListenProtocols[i] != nil {
				protocols = s.ListenProtocols[i]
			}
			if len(protocols) == 0 {
				protocols = []string{"h1", "h2", "h3"} // Caddy's default
			}
			for _, p := range protocols {
				if p == "h3" {
					seen[strings.Replace(a.String(), "tcp/", "", 1)+" (HTTP/3)"] = true
				} else {
					seen[a.String()] = true
				}
			}
		}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out, nil
}
