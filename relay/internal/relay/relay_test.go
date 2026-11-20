package relay

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/jsonx"
	"github.com/deutschland-schild/schild/contract/msg"
	"github.com/deutschland-schild/schild/contract/stream"
	"github.com/deutschland-schild/schild/contract/testkeys"
	"github.com/deutschland-schild/schild/contract/verify"
	"github.com/deutschland-schild/schild/relay/hub"
	"github.com/deutschland-schild/schild/relay/internal/testfeed"
	"github.com/deutschland-schild/schild/relay/upstream"
)

// fakeLab is a lab feed: a hub plus the files of /v0/bundles.
type fakeLab struct {
	mu     sync.Mutex
	state  []stream.Event
	files  map[string][]byte
	hub    *hub.Hub
	server *httptest.Server
}

func newFakeLab(t *testing.T) *fakeLab {
	l := &fakeLab{files: map[string][]byte{}}
	l.hub = hub.New(hub.Options{ID: "lab-a", Heartbeat: -1, Snapshot: func() []stream.Event {
		l.mu.Lock()
		defer l.mu.Unlock()
		return append([]stream.Event(nil), l.state...)
	}})
	mux := http.NewServeMux()
	mux.Handle("GET /v0/stream", l.hub)
	mux.HandleFunc("GET /v0/bundles/{id}/{file}", func(w http.ResponseWriter, r *http.Request) {
		l.mu.Lock()
		b, ok := l.files[r.URL.Path]
		l.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Write(b)
	})
	l.server = httptest.NewServer(mux)
	t.Cleanup(func() { l.hub.Close(); l.server.Close() })
	return l
}

func (l *fakeLab) publish(ev stream.Event, coalesce string) {
	l.mu.Lock()
	l.state = append(l.state, ev)
	l.mu.Unlock()
	if _, err := l.hub.Publish(ev, coalesce); err != nil {
		panic(err)
	}
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) Add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func startRelay(t *testing.T, ups []string, now func() time.Time, epoch string) (*Relay, *httptest.Server, context.CancelFunc) {
	r := New(Config{ID: "relay-1", Upstreams: ups, Client: http.DefaultClient, Heartbeat: -1, Now: now, Epoch: epoch, MaxPerIP: 1000})
	ctx, cancel := context.WithCancel(context.Background())
	go r.Run(ctx)
	srv := httptest.NewServer(r.Handler())
	t.Cleanup(func() { cancel(); srv.Close() })
	return r, srv, cancel
}

// verifier is the client side: it verifies every event like schild does.
type verifier struct {
	now   func() time.Time
	ctx   *verify.Context
	fresh *stream.Freshness
}

func newVerifier(now func() time.Time) *verifier {
	return &verifier{now: now, fresh: stream.NewFreshness(0), ctx: &verify.Context{
		Trust: testkeys.TrustStore("lab-a", "lab-b", "lab-c"), Threshold: 2, Channel: testfeed.Channel,
		State: verify.State{CheckpointSeq: map[string]uint64{}, CheckpointDigest: map[string]string{}},
	}}
}

// check verifies one event; fetch resolves refs.
func (v *verifier) check(ev *stream.Event, fetch func(*stream.Ref) []byte) error {
	v.ctx.Now = v.now()
	env := ev.Envelope
	switch {
	case ev.Type == stream.TypeHeartbeat:
		env = ev.Checkpoint
	case ev.Ref != nil:
		env = fetch(ev.Ref)
		if upstream.SHA256(env) != ev.Ref.SHA256 {
			return contract.Errf(contract.CodeEnvelope, "ref sha256 mismatch")
		}
	}
	res, err := verify.Signed(verify.StreamKind(ev.Type), env, v.ctx)
	if err != nil {
		return err
	}
	switch x := res.Value.(type) {
	case *msg.Checkpoint:
		v.ctx.State.CheckpointSeq[x.Lab], v.ctx.State.CheckpointDigest[x.Lab] = x.Seq, res.Digest
		at, _ := msg.ParseTime(x.IssuedAt)
		v.fresh.Observe(at)
	case *msg.Bundle:
		v.ctx.State.BundleVersion, v.ctx.State.BundleDigest = x.Version, res.Digest
	case *msg.Withdrawal:
		v.ctx.State.WithdrawalSeq, v.ctx.State.WithdrawalDigest = x.Seq, res.Digest
	}
	return nil
}

type sse struct {
	rd     *stream.Reader
	cancel context.CancelFunc
}

func connect(t *testing.T, url, lastID string) *sse {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url+stream.Path, nil)
	if lastID != "" {
		req.Header.Set("Last-Event-ID", lastID)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != 200 {
		cancel()
		t.Fatalf("connect: %v %v", err, resp)
	}
	t.Cleanup(cancel)
	return &sse{rd: stream.NewReader(resp.Body), cancel: cancel}
}

func (s *sse) next(t *testing.T) *stream.Event {
	t.Helper()
	type res struct {
		f   *stream.Frame
		err error
	}
	ch := make(chan res, 1)
	go func() { f, err := s.rd.Next(); ch <- res{f, err} }()
	select {
	case r := <-ch:
		if r.err != nil {
			t.Fatal(r.err)
		}
		ev, _, err := upstream.Parse(r.f.Data)
		if err != nil {
			t.Fatal(err)
		}
		return ev
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for relay event")
	}
	return nil
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not reached")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func fetcher(t *testing.T, base string) func(*stream.Ref) []byte {
	return func(ref *stream.Ref) []byte {
		resp, err := http.Get(base + ref.URLPath)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return b
	}
}

func TestRelayForwardsVerifiableEvents(t *testing.T) {
	clk := &clock{t: time.Now().UTC().Truncate(time.Second)}
	lab := newFakeLab(t)
	bundle := testfeed.Bundle(1, clk.Now(), []msg.Rule{testfeed.ObserveRule(1)}, "lab-a", "lab-b")
	lab.publish(stream.Event{Type: stream.TypeBundle, Envelope: bundle}, "")
	lab.publish(stream.Event{Type: stream.TypeCheckpoint, Envelope: testfeed.Checkpoint("lab-a", 1, clk.Now(), 1, "", 0)}, "checkpoint:lab-a")

	r, srv, _ := startRelay(t, []string{lab.server.URL}, clk.Now, "")
	waitFor(t, func() bool { l, b, _ := r.State.Counts(); return l == 1 && b == 1 })

	v := newVerifier(clk.Now)
	c := connect(t, srv.URL, "")
	for i := 0; i < 2; i++ { // full sync: bundle, checkpoint
		ev := c.next(t)
		if err := v.check(ev, fetcher(t, srv.URL)); err != nil {
			t.Fatalf("client rejects relayed %s: %v", ev.Type, err)
		}
	}
	// Emergency stop arrives live and verifies.
	lab.publish(stream.Event{Type: stream.TypeWithdrawal, Envelope: testfeed.Withdrawal(1, 1, clk.Now(), "lab-a", "lab-c")}, "")
	ev := c.next(t)
	if ev.Type != stream.TypeWithdrawal {
		t.Fatalf("got %s", ev.Type)
	}
	if err := v.check(ev, nil); err != nil {
		t.Fatal(err)
	}
	if v.ctx.State.WithdrawalSeq != 1 || v.ctx.State.BundleVersion != 1 {
		t.Fatalf("client state %+v", v.ctx.State)
	}
	// Static files: checkpoint and bundle bytes are served unchanged.
	resp, _ := http.Get(srv.URL + "/v0/bundles/schild-main/1.json")
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(b) != string(bundle) {
		t.Fatalf("relay changed the bundle bytes")
	}
	resp, _ = http.Get(srv.URL + "/v0/state.json")
	var st pollResponse
	json.NewDecoder(resp.Body).Decode(&st)
	resp.Body.Close()
	if !st.FullSync || len(st.Events) != 3 {
		t.Fatalf("state.json: %+v", st)
	}
	var first stream.Event
	json.Unmarshal(st.Events[0], &first)
	if first.Type != stream.TypeWithdrawal {
		t.Fatalf("state.json must start with withdrawals, got %s", first.Type)
	}
}

func TestRelayRestartTriggersFullSyncWithoutGaps(t *testing.T) {
	clk := &clock{t: time.Now().UTC().Truncate(time.Second)}
	lab := newFakeLab(t)
	lab.publish(stream.Event{Type: stream.TypeBundle, Envelope: testfeed.Bundle(1, clk.Now(), nil, "lab-a", "lab-b")}, "")
	lab.publish(stream.Event{Type: stream.TypeCheckpoint, Envelope: testfeed.Checkpoint("lab-a", 1, clk.Now(), 1, "", 0)}, "checkpoint:lab-a")
	r1, srv1, stop1 := startRelay(t, []string{lab.server.URL}, clk.Now, "epocha")
	waitFor(t, func() bool { l, _, _ := r1.State.Counts(); return l == 1 })
	c := connect(t, srv1.URL, "")
	c.next(t)
	c.next(t)
	last := c.rd.LastEventID()
	c.cancel()
	stop1()
	srv1.Close()

	// While the relay is down the lab publishes bundle 2 and a withdrawal.
	lab.publish(stream.Event{Type: stream.TypeBundle, Envelope: testfeed.Bundle(2, clk.Now(), nil, "lab-a", "lab-b")}, "")
	lab.publish(stream.Event{Type: stream.TypeWithdrawal, Envelope: testfeed.Withdrawal(1, 2, clk.Now(), "lab-a", "lab-b")}, "")

	r2, srv2, _ := startRelay(t, []string{lab.server.URL}, clk.Now, "epochb")
	waitFor(t, func() bool { _, _, w := r2.State.Counts(); return w == 1 })
	v := newVerifier(clk.Now)
	c2 := connect(t, srv2.URL, last) // id of the old epoch: unknown -> full sync
	got := map[string]bool{}
	for i := 0; i < 3; i++ {
		ev := c2.next(t)
		if err := v.check(ev, nil); err != nil {
			t.Fatalf("%s: %v", ev.Type, err)
		}
		got[ev.Type] = true
		if i == 0 && ev.Type != stream.TypeWithdrawal {
			t.Fatalf("full sync must send withdrawals first, got %s", ev.Type)
		}
	}
	if v.ctx.State.BundleVersion != 2 || v.ctx.State.WithdrawalSeq != 1 {
		t.Fatalf("client missed state after restart: %+v", v.ctx.State)
	}
}

func TestRelayCannotForge(t *testing.T) {
	clk := &clock{t: time.Now().UTC().Truncate(time.Second)}
	lab := newFakeLab(t)
	lab.publish(stream.Event{Type: stream.TypeCheckpoint, Envelope: testfeed.Checkpoint("lab-a", 1, clk.Now(), 0, "", 0)}, "checkpoint:lab-a")
	r, srv, _ := startRelay(t, []string{lab.server.URL}, clk.Now, "")
	waitFor(t, func() bool { l, _, _ := r.State.Counts(); return l == 1 })
	v := newVerifier(clk.Now)
	v.ctx.Trust = testkeys.TrustStore("lab-a", "lab-a2", "lab-b", "lab-c")
	c := connect(t, srv.URL, "")
	if err := v.check(c.next(t), nil); err != nil {
		t.Fatal(err)
	}
	// The relay forwards whatever an upstream sends (it cannot judge):
	// a valid bundle, then under-signed, single-operator, untrusted,
	// expired and rolled-back ones. Clients accept only the valid one.
	good := testfeed.Bundle(5, clk.Now(), nil, "lab-a", "lab-b")
	bad := []json.RawMessage{
		testfeed.Bundle(6, clk.Now(), nil, "lab-a"),
		testfeed.Bundle(7, clk.Now(), nil, "lab-a", "lab-a2"), // one operator twice
		testfeed.Bundle(8, clk.Now(), nil, "evil", "lab-a"),
		testfeed.Bundle(9, clk.Now().Add(-8*24*time.Hour), nil, "lab-a", "lab-b"), // expired
		testfeed.Bundle(4, clk.Now(), nil, "lab-a", "lab-b"),                      // rollback after 5
		testfeed.Withdrawal(1, 5, clk.Now(), "lab-b"),                             // under-signed stop
	}
	lab.publish(stream.Event{Type: stream.TypeBundle, Envelope: good}, "")
	for _, b := range bad {
		typ := stream.TypeBundle
		if json.Valid(b) && contains(string(b), "withdrawal.v0") {
			typ = stream.TypeWithdrawal
		}
		lab.publish(stream.Event{Type: typ, Envelope: b}, "")
	}
	accepted, rejected := 0, 0
	for i := 0; i < 1+len(bad); i++ {
		ev := c.next(t)
		if err := v.check(ev, fetcher(t, srv.URL)); err != nil {
			rejected++
			continue
		}
		accepted++
		if string(ev.Envelope) != string(good) {
			t.Fatalf("client accepted an invalid %s", ev.Type)
		}
	}
	if accepted != 1 || rejected != len(bad) || v.ctx.State.BundleVersion != 5 {
		t.Fatalf("accepted=%d rejected=%d state=%+v", accepted, rejected, v.ctx.State)
	}
}

func contains(s, sub string) bool { return strings.Contains(s, sub) }

func TestFrozenRelayDetectedByClients(t *testing.T) {
	clk := &clock{t: time.Now().UTC().Truncate(time.Second)}
	lab := newFakeLab(t)
	lab.publish(stream.Event{Type: stream.TypeCheckpoint, Envelope: testfeed.Checkpoint("lab-a", 1, clk.Now(), 0, "", 0)}, "checkpoint:lab-a")
	r, srv, _ := startRelay(t, []string{lab.server.URL}, clk.Now, "")
	waitFor(t, func() bool { l, _, _ := r.State.Counts(); return l == 1 })
	v := newVerifier(clk.Now)
	c := connect(t, srv.URL, "")
	if err := v.check(c.next(t), nil); err != nil {
		t.Fatal(err)
	}
	if v.fresh.Frozen(clk.Now()) {
		t.Fatal("fresh checkpoint reported as frozen")
	}
	// The lab keeps signing (seq 2 at +60 s) and the relay forwards.
	clk.Add(60 * time.Second)
	lab.publish(stream.Event{Type: stream.TypeCheckpoint, Envelope: testfeed.Checkpoint("lab-a", 2, clk.Now(), 0, "", 0)}, "checkpoint:lab-a")
	if err := v.check(c.next(t), nil); err != nil {
		t.Fatal(err)
	}
	// Now the relay freezes: it keeps sending heartbeats, but only with the
	// old checkpoint (it withholds everything new).
	lab.hub.Close()
	frozenAt := time.Duration(0)
	for step := 0; step < 20; step++ {
		clk.Add(15 * time.Second)
		r.Hub.Heartbeat()
		ev := c.next(t)
		if ev.Type != stream.TypeHeartbeat {
			t.Fatalf("got %s", ev.Type)
		}
		_ = v.check(ev, nil) // the old checkpoint verifies until it expires
		if v.fresh.Frozen(clk.Now()) {
			frozenAt = time.Duration(step+1) * 15 * time.Second
			break
		}
	}
	if frozenAt == 0 || frozenAt > stream.FreezeAfter+15*time.Second {
		t.Fatalf("frozen relay detected after %s, want <= %s", frozenAt, stream.FreezeAfter+15*time.Second)
	}
}

func TestRefBundleIsFetchedCheckedAndServed(t *testing.T) {
	clk := &clock{t: time.Now().UTC().Truncate(time.Second)}
	lab := newFakeLab(t)
	var rules []msg.Rule
	for i := 1; i <= 120; i++ { // > 32 KiB envelope
		rules = append(rules, testfeed.ObserveRule(i))
	}
	env := testfeed.Bundle(3, clk.Now(), rules, "lab-a", "lab-b")
	if len(env) <= contract.MaxInlineEnvelope {
		t.Fatalf("fixture too small: %d", len(env))
	}
	path := stream.BundleURLPath(testfeed.Channel, 3)
	lab.mu.Lock()
	lab.files[path] = env
	lab.mu.Unlock()
	ref := &stream.Ref{BundleID: testfeed.Channel, Version: 3, URLPath: path, SHA256: upstream.SHA256(env), Size: len(env)}
	lab.publish(stream.Event{Type: stream.TypeBundle, Ref: ref}, "")
	// A ref with a wrong hash is dropped by the relay.
	lab.mu.Lock()
	lab.files["/v0/bundles/schild-main/9.json"] = env
	lab.mu.Unlock()
	lab.publish(stream.Event{Type: stream.TypeBundle, Ref: &stream.Ref{BundleID: testfeed.Channel, Version: 9, URLPath: "/v0/bundles/schild-main/9.json", SHA256: "sha256:" + "00" + upstream.SHA256(env)[9:], Size: len(env)}}, "")

	r, srv, _ := startRelay(t, []string{lab.server.URL}, clk.Now, "")
	waitFor(t, func() bool { _, b, _ := r.State.Counts(); return b == 1 })
	v := newVerifier(clk.Now)
	c := connect(t, srv.URL, "")
	ev := c.next(t)
	if ev.Ref == nil {
		t.Fatal("large bundle must travel by reference")
	}
	if err := v.check(ev, fetcher(t, srv.URL)); err != nil {
		t.Fatalf("client rejects ref bundle served by the relay: %v", err)
	}
	if resp, _ := http.Get(srv.URL + "/v0/bundles/schild-main/9.json"); resp.StatusCode == 200 {
		// on-demand fetch is allowed (bytes are self-verifying), but the
		// relay never announced it
		resp.Body.Close()
	}
}

// On-demand bytes without a reference are passed on but never cached as
// immutable; wrong bytes are not served at all; with a reference the size and
// hash of the subscribe path apply (security review 2.5).
func TestFetchOnDemandChecksBytes(t *testing.T) {
	lab := newFakeLab(t)
	const path = "/v0/bundles/schild-main/3.json"
	env := testfeed.Bundle(3, time.Now(), []msg.Rule{testfeed.ObserveRule(1)}, "lab-a", "lab-b")
	lab.mu.Lock()
	lab.files[path] = env
	lab.files["/v0/bundles/schild-main/4.json"] = env // right envelope, wrong path
	lab.files["/v0/bundles/schild-main/5.json"] = []byte("not an envelope")
	lab.mu.Unlock()
	r, srv, _ := startRelay(t, []string{lab.server.URL}, time.Now, "")
	get := func(p string) *http.Response {
		t.Helper()
		resp, err := http.Get(srv.URL + p)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp
	}
	if resp := get(path); resp.StatusCode != 200 || resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("no ref: %d %q", resp.StatusCode, resp.Header.Get("Cache-Control"))
	}
	if _, ok := r.State.Cached(path); ok {
		t.Fatal("unverified bytes in the cache")
	}
	for _, p := range []string{"/v0/bundles/schild-main/4.json", "/v0/bundles/schild-main/5.json"} {
		if resp := get(p); resp.StatusCode != 404 {
			t.Fatalf("%s: %d", p, resp.StatusCode)
		}
	}
	// A reference with another hash refuses what the upstream serves.
	bad := &stream.Ref{BundleID: testfeed.Channel, Version: 3, URLPath: path, SHA256: "sha256:" + strings.Repeat("0", 64), Size: len(env)}
	r.State.mu.Lock()
	r.State.up("x").bundles[testfeed.Channel] = &bundleEntry{bundleID: testfeed.Channel, version: 3, ref: bad}
	r.State.mu.Unlock()
	if resp := get(path); resp.StatusCode != 404 {
		t.Fatalf("hash mismatch served: %d", resp.StatusCode)
	}
	good := &stream.Ref{BundleID: testfeed.Channel, Version: 3, URLPath: path, SHA256: upstream.SHA256(env), Size: len(env)}
	r.State.mu.Lock()
	r.State.up("x").bundles[testfeed.Channel].ref = good
	r.State.mu.Unlock()
	if resp := get(path); resp.StatusCode != 200 || !strings.Contains(resp.Header.Get("Cache-Control"), "immutable") {
		t.Fatalf("with ref: %d %q", resp.StatusCode, resp.Header.Get("Cache-Control"))
	}
	if _, ok := r.State.Cached(path); !ok {
		t.Fatal("verified bytes not cached")
	}
}

func TestClientAddr(t *testing.T) {
	proxies, err := ParseTrustedProxies("10.0.0.0/8, 2001:db8::/32")
	if err != nil {
		t.Fatal(err)
	}
	r := New(Config{ID: "relay-1", Client: http.DefaultClient, Heartbeat: -1, TrustedProxies: proxies})
	defer r.Hub.Close()
	cases := []struct{ name, remote, xff, want string }{
		{"direct client, header ignored", "203.0.113.7:1", "198.51.100.1", "203.0.113.7"},
		{"trusted proxy", "10.0.0.5:1", "198.51.100.1", "198.51.100.1"},
		{"spoofed left part stays out", "10.0.0.5:1", "192.0.2.1, 198.51.100.1, 10.0.0.9", "198.51.100.1"},
		{"no header", "10.0.0.5:1", "", "10.0.0.5"},
		{"junk stays with the proxy", "10.0.0.5:1", "198.51.100.1, junk", "10.0.0.5"},
		{"all trusted", "10.0.0.5:1", "10.0.0.8, 10.0.0.9", "10.0.0.8"},
	}
	for _, c := range cases {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = c.remote
		if c.xff != "" {
			req.Header.Set("X-Forwarded-For", c.xff)
		}
		if got := r.clientAddr(req); got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}
	for _, bad := range []string{"0.0.0.0/0", "::/0", "1.2.3.0/7", "nonsense"} {
		if _, err := ParseTrustedProxies(bad); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}

func TestPerIPConnectionLimit(t *testing.T) {
	r := New(Config{ID: "relay-1", Client: http.DefaultClient, Heartbeat: -1, MaxPerIP: 2})
	srv := httptest.NewServer(r.Handler())
	defer srv.Close()
	defer r.Hub.Close()
	connect(t, srv.URL, "")
	connect(t, srv.URL, "")
	waitFor(t, func() bool { return r.Hub.Clients() == 2 })
	resp, err := http.Get(srv.URL + stream.Path)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests || resp.Header.Get("Retry-After") == "" {
		t.Fatalf("third stream from one IP: status %d", resp.StatusCode)
	}
}

func TestReadyAndCheckpointEndpoints(t *testing.T) {
	clk := &clock{t: time.Now().UTC().Truncate(time.Second)}
	lab := newFakeLab(t)
	r, srv, _ := startRelay(t, []string{lab.server.URL}, clk.Now, "")
	if resp, _ := http.Get(srv.URL + "/readyz"); resp.StatusCode != 503 {
		t.Fatalf("ready without checkpoint")
	}
	cp := testfeed.Checkpoint("lab-a", 1, clk.Now(), 0, "", 0)
	lab.publish(stream.Event{Type: stream.TypeCheckpoint, Envelope: cp}, "checkpoint:lab-a")
	waitFor(t, func() bool { l, _, _ := r.State.Counts(); return l == 1 })
	if resp, _ := http.Get(srv.URL + "/readyz"); resp.StatusCode != 200 {
		t.Fatalf("not ready with checkpoint")
	}
	resp, _ := http.Get(srv.URL + "/v0/checkpoint")
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(b) != string(cp) {
		t.Fatal("checkpoint endpoint changed bytes")
	}
	v, _ := jsonx.ParseObject(b)
	if v["payloadType"] != contract.KindCheckpoint.PayloadType() {
		t.Fatal("not a checkpoint")
	}
}
