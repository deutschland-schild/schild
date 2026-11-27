package caddymod

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestReloadWaitsForSlowServerGoroutine: net/http drops a request it has
// read when its server stops before the goroutine of the connection looks
// (server.go, "if c.server.shuttingDown() { return }"). On a busy machine
// that goroutine can wait long between the two. The reload has to outlast
// such a pause: here every connection pauses there for 150 ms.
func TestReloadWaitsForSlowServerGoroutine(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the socket of an address is kept on Linux only (socket.go)")
	}
	afterActive = func() { time.Sleep(150 * time.Millisecond) }
	t.Cleanup(func() { afterActive = nil })
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("app ok")) }))
	defer backend.Close()
	bind(t, testGate(t))
	dir := caddyDir(t)
	addr := freePort(t)
	config := func(extra int) []byte {
		text := "{\n\tauto_https off\n}\n"
		for i := 0; i <= extra; i++ {
			text += fmt.Sprintf("http://site%d.example:%s {\n\tschild\n\treverse_proxy %s\n}\n", i, port(addr), strings.TrimPrefix(backend.URL, "http://"))
		}
		ing, err := PrepareIngress(IngressOptions{Caddyfile: writeFile(t, dir, "Caddyfile", text), DefaultStorage: filepath.Join(dir, "caddy-data")})
		if err != nil {
			t.Fatal(err)
		}
		return ing.JSON
	}
	if err := Load(config(0)); err != nil {
		t.Fatal(err)
	}
	defer Stop()
	var sent, failed atomic.Int64
	var first atomic.Value
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			// A new connection per request: the case a reload can lose.
			c := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}, Timeout: 10 * time.Second}
			for {
				select {
				case <-stop:
					return
				default:
				}
				req, _ := http.NewRequest("GET", "http://"+addr+"/", nil)
				req.Host = "site0.example"
				resp, err := c.Do(req)
				sent.Add(1)
				if err == nil {
					if body := drain(resp.Body); resp.StatusCode == 200 && body == "app ok" {
						continue
					}
					err = fmt.Errorf("status %d", resp.StatusCode)
				}
				failed.Add(1)
				first.CompareAndSwap(nil, err.Error())
			}
		})
	}
	for i := 1; i <= 10; i++ {
		if err := Load(config(i)); err != nil {
			t.Fatal(err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	close(stop)
	wg.Wait()
	t.Logf("%d of %d requests failed over 10 reloads", failed.Load(), sent.Load())
	if failed.Load() > 0 {
		t.Fatalf("the first: %v", first.Load())
	}
}
