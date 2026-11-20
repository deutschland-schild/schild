package feed

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/msg"
	"github.com/deutschland-schild/schild/contract/peerauth"
	"github.com/deutschland-schild/schild/contract/testkeys"
	"github.com/deutschland-schild/schild/contract/verify"
	"github.com/deutschland-schild/schild/lab/internal/rules"
	"github.com/deutschland-schild/schild/lab/internal/store"
	"github.com/deutschland-schild/schild/relay/upstream"
)

func newFeed(t *testing.T) *Feed {
	db, err := store.Open(filepath.Join(t.TempDir(), "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	eng, err := rules.New(db, rules.Config{Lab: "lab-a", Operator: "op-test-a", Channel: "schild-main", RulesSigner: testkeys.Signer("lab-a"),
		Trust: testkeys.TrustStore("lab-a", "lab-b", "lab-c")}, quiet)
	if err != nil {
		t.Fatal(err)
	}
	f := New(Config{Lab: "lab-a", Channel: "schild-main", CheckpointSigner: testkeys.Signer("lab-a"), TTL: 3 * time.Minute, Heartbeat: -1,
		PeerTrust: testkeys.TrustStore("lab-b", "lab-c")}, db, eng, quiet, nil)
	eng.Publisher = f
	return f
}

func TestCheckpointSignedAndLogged(t *testing.T) {
	f := newFeed(t)
	for i := 0; i < 3; i++ {
		if err := f.Sign(); err != nil {
			t.Fatal(err)
		}
	}
	env, seq, _ := f.Checkpoint()
	res, err := verify.Signed(contract.KindCheckpoint, env, &verify.Context{Now: time.Now(), Trust: testkeys.TrustStore("lab-a")})
	if err != nil {
		t.Fatalf("checkpoint does not verify for clients: %v", err)
	}
	cp := res.Value.(*msg.Checkpoint)
	at, _ := msg.ParseTime(cp.IssuedAt)
	exp, _ := msg.ParseTime(cp.Expires)
	if cp.Seq != seq || seq != 3 || exp.Sub(at) != 3*time.Minute || cp.Bundle.Version != 0 || cp.Bundle.Digest != msg.Digest(nil) || cp.Log == nil {
		t.Fatalf("checkpoint %+v", cp)
	}
	// Unchanged state is logged once (then hourly), not every minute.
	if cp.Log.Size != 1 {
		t.Fatalf("log size %d, want 1 checkpoint entry", cp.Log.Size)
	}
	srv := httptest.NewServer(f.Handler())
	defer srv.Close()
	resp, _ := http.Get(srv.URL + "/v0/checkpoint")
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !bytes.Equal(b, env) {
		t.Fatal("served checkpoint differs")
	}
	if resp, _ := http.Get(srv.URL + "/readyz"); resp.StatusCode != 200 {
		t.Fatal("feed not ready with a checkpoint")
	}
}

func TestSignaturePostsAreRateLimited(t *testing.T) {
	f := newFeed(t)
	srv := httptest.NewServer(f.Handler())
	defer srv.Close()
	limited := false
	for i := 0; i < 40; i++ {
		resp, err := http.Post(srv.URL+"/v0/signatures", "application/json", bytes.NewReader([]byte(`{"kind":"rule-bundle","digest":"sha256:00","signature":{"keyid":"test-evil","sig":"AA=="}}`)))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusTooManyRequests {
			limited = true
			break
		}
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("unknown key: %d", resp.StatusCode)
		}
	}
	if !limited {
		t.Fatal("signature posts are not rate limited")
	}
}

// D40: a forged post naming a peer's key costs that key nothing: the budget
// per key counts after the signature was checked.
func TestForgedSignatureSpendsNoKeyBudget(t *testing.T) {
	f := newFeed(t)
	srv := httptest.NewServer(f.Handler())
	defer srv.Close()
	for i := 0; i < 5; i++ {
		resp, err := http.Post(srv.URL+"/v0/signatures", "application/json", bytes.NewReader([]byte(`{"kind":"rule-bundle","digest":"sha256:00","signature":{"keyid":"test-lab-b","sig":"AA=="}}`)))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusTooManyRequests {
			t.Fatalf("forged post: %d", resp.StatusCode)
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.sigKeys) != 0 {
		t.Fatalf("a forged post touched a key budget: %v", f.sigKeys)
	}
}

// v0.1: GET /v0/collecting holds rule texts that are not published yet; only
// configured peers with a valid request signature get them.
// Self-reported relay names cannot grow the list without limit (security
// review P4): disconnected entries go first, then newcomers share one entry.
func TestRelayEntriesBounded(t *testing.T) {
	f := &Feed{relays: map[string]*Relay{}, conns: map[*http.Request]string{}, Now: time.Now}
	stream := func(name string) *http.Request {
		r := httptest.NewRequest("GET", "/v0/stream", nil)
		r.Header.Set(upstream.HeaderName, name)
		return r
	}
	var open []*http.Request
	for i := range maxRelayEntries {
		r := stream(fmt.Sprintf("relay-%d", i))
		f.track(r, true)
		open = append(open, r)
	}
	f.track(open[0], false)
	f.track(stream("new-one"), true)
	if len(f.relays) != maxRelayEntries || f.relays["relay/new-one"] == nil || f.relays["relay/relay-0"] != nil {
		t.Fatalf("after a free entry: %d", len(f.relays))
	}
	f.track(stream("new-two"), true)
	if len(f.relays) != maxRelayEntries+1 || f.relays["relay/unnamed"] == nil {
		t.Fatalf("all connected: %d", len(f.relays))
	}
	f.track(stream("new-three"), true)
	if len(f.relays) != maxRelayEntries+1 || f.relays["relay/unnamed"].connections != 2 {
		t.Fatalf("second newcomer: %d", len(f.relays))
	}
}

func TestCollectingNeedsPeerSignature(t *testing.T) {
	f := newFeed(t)
	srv := httptest.NewServer(f.Handler())
	defer srv.Close()
	get := func(sign func(*http.Request)) int {
		req, _ := http.NewRequest("GET", srv.URL+"/v0/collecting", nil)
		if sign != nil {
			sign(req)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	signAs := func(key, lab, target string, at time.Time) func(*http.Request) {
		return func(r *http.Request) {
			if err := peerauth.SetHeader(r, testkeys.Signer(key), lab, target, nil, at); err != nil {
				t.Fatal(err)
			}
		}
	}
	now := time.Now()
	for name, c := range map[string]struct {
		sign func(*http.Request)
		want int
	}{
		"anonymous":        {nil, 401},
		"peer lab-b":       {signAs("lab-b", "lab-b", "lab-a", now), 200},
		"peer lab-c":       {signAs("lab-c", "lab-c", "lab-a", now), 200},
		"not a peer":       {signAs("lab-d", "lab-d", "lab-a", now), 401},
		"own key":          {signAs("lab-a", "lab-a", "lab-a", now), 401},
		"for another lab":  {signAs("lab-b", "lab-b", "lab-c", now), 401},
		"old signature":    {signAs("lab-b", "lab-b", "lab-a", now.Add(-10*time.Minute)), 401},
		"claims other lab": {signAs("lab-b", "lab-c", "lab-a", now), 401},
	} {
		if got := get(c.sign); got != c.want {
			t.Errorf("%s: status %d, want %d", name, got, c.want)
		}
	}
}
