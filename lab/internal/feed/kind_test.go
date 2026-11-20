package feed

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/contract/peerauth"
	"github.com/deutschland-schild/schild/contract/testkeys"
	"github.com/deutschland-schild/schild/relay/upstream"
)

// Contracts v0.2: Relay.kind comes from the peer signature on the stream
// request, never from the self-reported X-Schild-Relay name.
func TestSubscriberKind(t *testing.T) {
	f := newFeed(t)
	now := time.Now()
	req := func(name, key, from string, at time.Time) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/v0/stream", nil)
		if name != "" {
			r.Header.Set(upstream.HeaderName, name)
		}
		if key != "" {
			if err := peerauth.SetHeader(r, testkeys.Signer(key), from, "lab-a", nil, at); err != nil {
				t.Fatal(err)
			}
		}
		return r
	}
	cases := []struct {
		name     string
		r        *http.Request
		kind, id string
	}{
		{"relay", req("relay-1", "", "", now), KindRelay, "relay-1"},
		{"signed peer", req("lab-b", "lab-b", "lab-b", now), KindPeerLab, "lab-b"},
		// The verified lab id wins over the self-reported name.
		{"signed peer, other name", req("whatever", "lab-c", "lab-c", now), KindPeerLab, "lab-c"},
		{"relay named like a peer", req("lab-b", "", "", now), KindRelay, "lab-b"},
		{"not a configured peer", req("lab-d", "lab-d", "lab-d", now), KindRelay, "lab-d"},
		{"stale signature", req("lab-b", "lab-b", "lab-b", now.Add(-10*time.Minute)), KindRelay, "lab-b"},
		{"own key", req("lab-a", "lab-a", "lab-a", now), KindRelay, "lab-a"},
		{"unnamed", req("", "", "", now), KindRelay, "unnamed"},
	}
	for _, c := range cases {
		if kind, id := f.subscriber(c.r); kind != c.kind || id != c.id {
			t.Errorf("%s: got %s/%s, want %s/%s", c.name, kind, id, c.kind, c.id)
		}
	}

	// A relay calling itself lab-b and the signed peer lab-b are two entries.
	peer, fake := req("lab-b", "lab-b", "lab-b", now), req("lab-b", "", "", now)
	f.track(peer, true)
	f.track(fake, true)
	f.delivered(peer, "heartbeat", "e-1", []byte(`{}`))
	got := f.Relays()
	sort.Slice(got, func(i, j int) bool { return got[i].Kind < got[j].Kind })
	if len(got) != 2 || got[0].Kind != KindPeerLab || got[0].ID != "lab-b" || got[1].Kind != KindRelay || got[1].ID != "lab-b" {
		t.Fatalf("relays %+v", got)
	}
	if got[0].LastEventID != "e-1" || got[1].LastEventID != "" {
		t.Fatalf("delivery recorded on the wrong entry: %+v", got)
	}
	f.track(peer, false)
	f.track(fake, false)
	for _, rl := range f.Relays() {
		if rl.Status != "disconnected" {
			t.Fatalf("still connected: %+v", rl)
		}
	}
	if len(f.conns) != 0 {
		t.Fatalf("connections leak: %d", len(f.conns))
	}
}

// End to end through the hub: a peer manager style subscriber that signs its
// subscription shows up as peer_lab, an unsigned one with the same name as relay.
func TestSignedSubscriptionThroughHub(t *testing.T) {
	f := newFeed(t)
	srv := httptest.NewServer(f.Handler())
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	signed := &upstream.Subscriber{Base: srv.URL, Client: srv.Client(), Name: "lab-b",
		Authorize: func(r *http.Request) error {
			return peerauth.SetHeader(r, testkeys.Signer("lab-b"), "lab-b", "lab-a", nil, time.Now())
		}}
	unsigned := &upstream.Subscriber{Base: srv.URL, Client: srv.Client(), Name: "lab-b"}
	go signed.Run(ctx)
	go unsigned.Run(ctx)
	deadline := time.Now().Add(5 * time.Second)
	for {
		kinds := map[string]string{}
		for _, r := range f.Relays() {
			if r.Status == "connected" {
				kinds[r.Kind] = r.ID
			}
		}
		if kinds[KindPeerLab] == "lab-b" && kinds[KindRelay] == "lab-b" {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("subscribers %+v", f.Relays())
		}
		time.Sleep(20 * time.Millisecond)
	}
}
