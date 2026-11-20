package webui

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

func TestGzipAssets(t *testing.T) {
	js := []byte(strings.Repeat("export const schild = 'Grundschutz aktiv';\n", 200))
	fsys := fstest.MapFS{
		"assets/app.js":     {Data: js},
		"assets/tiny.css":   {Data: []byte("a{}")},
		"assets/font.woff2": {Data: bytes.Repeat([]byte{1, 2, 3}, 1000)},
	}
	g := &gzipAssets{fsys: fsys, next: http.FileServer(http.FS(fsys))}
	get := func(p, ae string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "/"+p, nil)
		if ae != "" {
			r.Header.Set("Accept-Encoding", ae)
		}
		w := httptest.NewRecorder()
		g.serve(w, r, p)
		return w
	}

	w := get("assets/app.js", "br, gzip;q=0.8")
	if w.Code != 200 || w.Header().Get("Content-Encoding") != "gzip" || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/javascript") {
		t.Fatalf("js: %d %v", w.Code, w.Header())
	}
	if !strings.Contains(w.Header().Get("Vary"), "Accept-Encoding") || w.Body.Len() >= len(js)/2 {
		t.Fatalf("js: vary %q, %d of %d bytes", w.Header().Get("Vary"), w.Body.Len(), len(js))
	}
	zr, err := gzip.NewReader(w.Body)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := io.ReadAll(zr); !bytes.Equal(got, js) {
		t.Fatal("gzip body differs from the file")
	}
	// Second request: from the cache, same bytes.
	if w2 := get("assets/app.js", "gzip"); w2.Header().Get("Content-Encoding") != "gzip" {
		t.Fatal("cached gzip missing")
	}
	for _, c := range []struct{ p, ae string }{
		{"assets/app.js", ""},             // no Accept-Encoding
		{"assets/app.js", "gzip;q=0, br"}, // gzip refused
		{"assets/tiny.css", "gzip"},       // too small
		{"assets/font.woff2", "gzip"},     // already compressed type
	} {
		w := get(c.p, c.ae)
		if w.Code != 200 || w.Header().Get("Content-Encoding") != "" {
			t.Fatalf("%s %q: %d %q", c.p, c.ae, w.Code, w.Header().Get("Content-Encoding"))
		}
	}
	r := httptest.NewRequest("HEAD", "/assets/app.js", nil)
	r.Header.Set("Accept-Encoding", "gzip")
	hw := httptest.NewRecorder()
	g.serve(hw, r, "assets/app.js")
	if hw.Body.Len() != 0 || hw.Header().Get("Content-Length") == "" {
		t.Fatal("HEAD: body or length wrong")
	}
}
