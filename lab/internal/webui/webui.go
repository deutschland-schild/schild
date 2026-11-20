// Package webui embeds the lab dashboard (ui/apps/lab-dashboard, copied
// to dist/ by `make ui`). Without a build it serves a placeholder page.
// Unknown non-API paths fall back to index.html (SPA routing).
package webui

import (
	"embed"
	"io/fs"
	"net/http"
	"path"
	"strings"
)

//go:embed all:dist
var dist embed.FS

//go:embed placeholder.html
var placeholder []byte

// Built reports whether a dashboard build is embedded.
func Built() bool {
	_, err := fs.Stat(dist, "dist/index.html")
	return err == nil
}

// Handler serves the embedded dashboard.
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
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Cache-Control", "no-store")
			w.Write(placeholder)
			return
		}
		p := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
		if p == "" || p == "index.html" {
			serveIndex(w, sub)
			return
		}
		if st, err := fs.Stat(sub, p); err != nil || st.IsDir() || strings.HasPrefix(path.Base(p), ".") {
			serveIndex(w, sub) // SPA fallback
			return
		}
		if strings.HasPrefix(p, "assets/") {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		}
		assets.serve(w, r, p)
	})
}

func serveIndex(w http.ResponseWriter, sub fs.FS) {
	b, err := fs.ReadFile(sub, "index.html")
	if err != nil {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(placeholder)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Write(b)
}
