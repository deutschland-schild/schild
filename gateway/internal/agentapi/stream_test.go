//go:build !release

package agentapi_test

import (
	"bufio"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	contractapi "github.com/deutschland-schild/schild/contract/agentapi"
	"github.com/deutschland-schild/schild/gateway/internal/agentapi"
)

// openStream opens the monitoring stream with tok and returns a channel that
// closes when the gateway ends it.
func openStream(t *testing.T, ctx context.Context, srv *httptest.Server, tok string) <-chan struct{} {
	t.Helper()
	req, _ := http.NewRequestWithContext(ctx, "GET", srv.URL+"/agent/v0/monitoring/stream", nil)
	req.Host = listen
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	if resp.StatusCode != 200 {
		t.Fatalf("stream: %d", resp.StatusCode)
	}
	ended := make(chan struct{})
	go func() {
		sc := bufio.NewScanner(resp.Body)
		for sc.Scan() {
		}
		close(ended)
	}()
	return ended
}

// TestStreamEndsWithToken: revoking a token, or its expiry, also ends a
// stream that the token opened before.
func TestStreamEndsWithToken(t *testing.T) {
	a := newAgent(t, "")
	agentapi.SetStreamCheck(a.h.App.AgentAPI, 50*time.Millisecond)
	srv := httptest.NewServer(a.srv)
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ended := openStream(t, ctx, srv, a.token)
	select {
	case <-ended:
		t.Fatal("stream ended before the revocation")
	case <-time.After(300 * time.Millisecond):
	}
	if err := a.h.App.Store.RevokeAgentToken(context.Background(), contractapi.TokenID(a.token), time.Now()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ended:
	case <-ctx.Done():
		t.Fatal("stream still open after the revocation")
	}

	short := a.addToken(contractapi.ScopeAgentRead, time.Second)
	start := time.Now()
	ended = openStream(t, ctx, srv, short)
	select {
	case <-ended:
		if time.Since(start) < 500*time.Millisecond {
			t.Fatalf("stream ended after %v, before the token expired", time.Since(start))
		}
	case <-ctx.Done():
		t.Fatal("stream still open after the token expired")
	}
}
