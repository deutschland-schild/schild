// Package req holds the request type shared by every traffic generator. It is
// a leaf package so generators (legit, corpus, ...) and the plan assembler can
// all depend on it without an import cycle.
package req

import "github.com/deutschland-schild/schild/testlab/internal/label"

// Request is one planned HTTP request with its ground-truth label. A plan is a
// deterministic, ordered slice of these; sending is a separate step so the
// plan can be counted and compared without touching the network.
type Request struct {
	Method  string            `json:"method"`
	Site    string            `json:"site"` // logical target name, e.g. "wp"
	Path    string            `json:"path"`
	Query   string            `json:"query,omitempty"`
	Body    []byte            `json:"body,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
	SrcIP   string            `json:"src_ip,omitempty"`
	Label   label.Label       `json:"label"`
}

// Target maps a logical site name to where to send and how it runs.
type Target struct {
	Name    string `json:"name"`
	BaseURL string `json:"base_url"` // e.g. http://edge-wp:8080
	Host    string `json:"host"`     // Host header, e.g. wp.example
	Mode    string `json:"mode"`     // observe|review|autoblock
}
