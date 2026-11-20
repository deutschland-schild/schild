// Package webui serves the embedded client dashboard (dashboard/apps/client-dashboard
// built by `make ui` and copied into dist/). When dist/index.html is missing
// it serves a placeholder page. Unknown non-API paths fall back to
// index.html (SPA routing).
package webui

import (
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"io/fs"
	"net/http"
	"path"
	"regexp"
	"strings"
)

//go:embed all:dist
var dist embed.FS

//go:embed placeholder.html placeholder.css
var placeholder embed.FS

// Built reports whether a built dashboard is embedded.
func Built() bool {
	_, err := fs.Stat(dist, "dist/index.html")
	return err == nil
}

// Handler serves the dashboard files.
func Handler() http.Handler {
	sub, _ := fs.Sub(dist, "dist")
	files := http.FileServer(http.FS(sub))
	assets := &gzipAssets{fsys: sub, next: files}
	built := Built()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !built {
			servePlaceholder(w, r)
			return
		}
		p := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
		if p == "" || p == "index.html" {
			serveIndex(w, r, sub)
			return
		}
		if st, err := fs.Stat(sub, p); err == nil && !st.IsDir() {
			if strings.HasPrefix(p, "assets/") {
				w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
			}
			assets.serve(w, r, p)
			return
		}
		serveIndex(w, r, sub) // SPA fallback
	})
}

func serveIndex(w http.ResponseWriter, r *http.Request, sub fs.FS) {
	b, err := fs.ReadFile(sub, "index.html")
	if err != nil {
		servePlaceholder(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write(b)
}

func servePlaceholder(w http.ResponseWriter, r *http.Request) {
	name := "placeholder.html"
	ct := "text/html; charset=utf-8"
	if r.URL.Path == "/__schild_placeholder.css" {
		name, ct = "placeholder.css", "text/css; charset=utf-8"
	}
	b, _ := placeholder.ReadFile(name)
	w.Header().Set("Content-Type", ct)
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write(b)
}

var inlineScript = regexp.MustCompile(`(?s)<script>(.*?)</script>`)

// InlineScriptHashes returns CSP source expressions ('sha256-...') for the
// inline scripts of index.html, so the CSP can stay strict without
// 'unsafe-inline'.
func InlineScriptHashes() []string {
	b, err := fs.ReadFile(dist, "dist/index.html")
	if err != nil {
		return nil
	}
	var out []string
	for _, m := range inlineScript.FindAllSubmatch(b, -1) {
		sum := sha256.Sum256(m[1])
		out = append(out, "'sha256-"+base64.StdEncoding.EncodeToString(sum[:])+"'")
	}
	return out
}
