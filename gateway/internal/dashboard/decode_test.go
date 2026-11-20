package dashboard

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestDecodeBodyDeadline: a body that stalls is cut off after
// bodyReadTimeout, and the deadline ends with the body, so a handler that
// works on after decode keeps its request context.
func TestDecodeBodyDeadline(t *testing.T) {
	old := bodyReadTimeout
	bodyReadTimeout = 200 * time.Millisecond
	defer func() { bodyReadTimeout = old }()
	ctxErr := make(chan error, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var v map[string]any
		if !decode(w, r, &v) {
			return
		}
		time.Sleep(3 * bodyReadTimeout)
		ctxErr <- r.Context().Err()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	resp, err := http.Post(srv.URL, "application/json", strings.NewReader(`{"a":1}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("complete body: %d", resp.StatusCode)
	}
	if err := <-ctxErr; err != nil {
		t.Fatalf("context ended after the body was read: %v", err)
	}

	c, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	fmt.Fprint(c, "POST / HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{\"a\":")
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	start := time.Now()
	b, _ := io.ReadAll(c)
	if !bytes.HasPrefix(b, []byte("HTTP/1.1 400")) || time.Since(start) > 3*time.Second {
		t.Fatalf("stalled body after %v: %.80q", time.Since(start), b)
	}
}
