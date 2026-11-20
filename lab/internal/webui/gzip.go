package webui

import (
	"bytes"
	"compress/gzip"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strconv"
	"strings"
	"sync"
)

// gzipAssets serves compressible embedded files gzip-compressed to clients
// that accept it. The embedded files never change, so each one is compressed
// once and kept in memory (the dashboards' text assets are about 1 MB raw,
// about 0.3 MB compressed). Everything else goes to next.
type gzipAssets struct {
	fsys  fs.FS
	next  http.Handler
	cache sync.Map // path -> []byte (nil: not worth compressing)
}

var compressibleExt = map[string]bool{".js": true, ".mjs": true, ".css": true, ".svg": true, ".json": true, ".html": true, ".txt": true}

func (g *gzipAssets) serve(w http.ResponseWriter, r *http.Request, p string) {
	ext := path.Ext(p)
	if !compressibleExt[ext] {
		g.next.ServeHTTP(w, r)
		return
	}
	w.Header().Add("Vary", "Accept-Encoding")
	if !acceptsGzip(r) {
		g.next.ServeHTTP(w, r)
		return
	}
	gz := g.compressed(p)
	if gz == nil {
		g.next.ServeHTTP(w, r)
		return
	}
	ct := mime.TypeByExtension(ext)
	if ct == "" {
		ct = "application/octet-stream"
	}
	w.Header().Set("Content-Type", ct)
	w.Header().Set("Content-Encoding", "gzip")
	w.Header().Set("Content-Length", strconv.Itoa(len(gz)))
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write(gz)
}

func (g *gzipAssets) compressed(p string) []byte {
	if v, ok := g.cache.Load(p); ok {
		return v.([]byte)
	}
	var out []byte
	if raw, err := fs.ReadFile(g.fsys, p); err == nil && len(raw) >= 1024 {
		var buf bytes.Buffer
		zw, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
		if _, err := zw.Write(raw); err == nil && zw.Close() == nil && buf.Len() < len(raw)*9/10 {
			out = buf.Bytes()
		}
	}
	g.cache.Store(p, out)
	return out
}

// acceptsGzip reports whether the request accepts gzip (q=0 refuses it).
func acceptsGzip(r *http.Request) bool {
	for _, part := range strings.Split(r.Header.Get("Accept-Encoding"), ",") {
		name, params, _ := strings.Cut(strings.TrimSpace(part), ";")
		if !strings.EqualFold(strings.TrimSpace(name), "gzip") {
			continue
		}
		q := strings.ReplaceAll(strings.TrimSpace(params), " ", "")
		return q != "q=0" && q != "q=0.0" && q != "q=0.00" && q != "q=0.000"
	}
	return false
}
