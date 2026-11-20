package caddymod

import (
	"encoding/json"
	"sort"
	"strings"
)

// Helpers for taking over an existing Caddy (`schild init -caddyfile`, D79).
// They read the adapted JSON, as the directive check does.

// FileStorageRoot is the root of a `storage file_system` option of the
// Caddyfile ("" without one, or with another storage module).
func FileStorageRoot(cfgJSON []byte) string {
	var c struct {
		Storage struct {
			Module string `json:"module"`
			Root   string `json:"root"`
		} `json:"storage"`
	}
	if json.Unmarshal(cfgJSON, &c) != nil || c.Storage.Module != "file_system" {
		return ""
	}
	return c.Storage.Root
}

// LogFiles are the files the Caddyfile writes logs to (`output file`),
// sorted. The user schild runs as needs write access to them.
func LogFiles(cfgJSON []byte) []string {
	var c struct {
		Logging struct {
			Logs map[string]struct {
				Writer struct {
					Output   string `json:"output"`
					Filename string `json:"filename"`
				} `json:"writer"`
			} `json:"logs"`
		} `json:"logging"`
	}
	if json.Unmarshal(cfgJSON, &c) != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, l := range c.Logging.Logs {
		if l.Writer.Output == "file" && l.Writer.Filename != "" && !seen[l.Writer.Filename] {
			seen[l.Writer.Filename] = true
			out = append(out, l.Writer.Filename)
		}
	}
	sort.Strings(out)
	return out
}

// HTTP3Open reports whether a server on port 443 leaves HTTP/3 on: Caddy
// serves it unless `servers { protocols h1 h2 }` says otherwise. HTTP/3
// ignores the read_body timeout (D41), so the docs keep it off.
func HTTP3Open(cfgJSON []byte) bool {
	var c struct {
		Apps struct {
			HTTP struct {
				Servers map[string]struct {
					Listen    []string `json:"listen"`
					Protocols []string `json:"protocols"`
				} `json:"servers"`
			} `json:"http"`
		} `json:"apps"`
	}
	if json.Unmarshal(cfgJSON, &c) != nil {
		return false
	}
	for _, s := range c.Apps.HTTP.Servers {
		tls := false
		for _, l := range s.Listen {
			if strings.HasSuffix(l, ":443") {
				tls = true
			}
		}
		if !tls {
			continue
		}
		if len(s.Protocols) == 0 {
			return true
		}
		for _, p := range s.Protocols {
			if p == "h3" {
				return true
			}
		}
	}
	return false
}

// UnixSockets are the unix sockets the Caddyfile dials (reverse_proxy and
// php_fastcgi upstreams written as unix//path), sorted.
func UnixSockets(cfgJSON []byte) []string {
	var v any
	if json.Unmarshal(cfgJSON, &v) != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	var visit func(any)
	visit = func(v any) {
		switch t := v.(type) {
		case map[string]any:
			if ups, ok := t["upstreams"].([]any); ok {
				for _, u := range ups {
					m, _ := u.(map[string]any)
					dial, _ := m["dial"].(string)
					if p, ok := strings.CutPrefix(dial, "unix/"); ok && p != "" && !seen[p] {
						seen[p] = true
						out = append(out, p)
					}
				}
			}
			for _, c := range t {
				visit(c)
			}
		case []any:
			for _, c := range t {
				visit(c)
			}
		}
	}
	visit(v)
	sort.Strings(out)
	return out
}
