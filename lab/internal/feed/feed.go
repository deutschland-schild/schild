// Package feed is the lab feed for relays and peers (port 7444):
//
//	GET  /v0/stream                       SSE (contracts/stream.md)
//	GET  /v0/bundles/<id>/<version>.json  published bundle envelopes
//	GET  /v0/checkpoint                   newest checkpoint envelope
//	GET  /v0/collecting                   own bundles/withdrawals waiting for co-signatures
//	                                      (v0.1: only for configured peers, signed request, cosign.md)
//	POST /v0/signatures                   a co-signature from another lab
//	GET  /v0/log?from=&limit=             the public append-only log
//	GET  /healthz, /readyz
//
// The checkpoint is re-signed every checkpoint_interval_s (default 60 s)
// with a validity of checkpoint_ttl_s (<= 10 min) and announces the newest
// bundle, the newest withdrawal seq and the public log head.
package feed

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/dsse"
	"github.com/deutschland-schild/schild/contract/jsonx"
	"github.com/deutschland-schild/schild/contract/keys"
	"github.com/deutschland-schild/schild/contract/msg"
	"github.com/deutschland-schild/schild/contract/peerauth"
	"github.com/deutschland-schild/schild/contract/stream"
	"github.com/deutschland-schild/schild/lab/internal/publog"
	"github.com/deutschland-schild/schild/lab/internal/rules"
	"github.com/deutschland-schild/schild/lab/internal/store"
	"github.com/deutschland-schild/schild/relay/hub"
	"github.com/deutschland-schild/schild/relay/metrics"
	"github.com/deutschland-schild/schild/relay/upstream"
)

// Config of the feed.
type Config struct {
	Lab, Channel     string
	CheckpointSigner *keys.Signer
	Interval         time.Duration // re-sign interval (default 60 s)
	TTL              time.Duration // checkpoint validity (<= 10 min)
	Heartbeat        time.Duration // hub heartbeat (default 15 s)
	// PeerTrust holds the rules keys of the configured peers. GET
	// /v0/collecting answers only requests signed with one of them
	// (peerauth, contracts v0.1): unpublished rule texts are not public.
	PeerTrust *keys.TrustStore
}

// Subscriber kinds (dashboard Relay.kind, contracts v0.2).
const (
	KindRelay   = "relay"
	KindPeerLab = "peer_lab"
)

// Relay is a subscriber of this feed (dashboard RelayList).
//
// Kind is derived from authenticated configuration, never from the
// self-reported X-Schild-Relay name: a subscriber is a peer lab only when
// its stream request carries a valid Schild-Peer-Auth signature by a rules
// key of a configured peer (PeerTrust); its ID is then the verified peer lab
// id. Everyone else is a relay under its self-reported name, so a relay that
// calls itself like a peer lab shows up as a separate relay entry.
type Relay struct {
	ID             string     `json:"id"`
	Kind           string     `json:"kind"`
	Status         string     `json:"status"`
	ConnectedSince *time.Time `json:"connected_since"`
	LastEventID    string     `json:"last_event_id,omitempty"`
	BundleVersion  uint64     `json:"bundle_version"` // newest bundle delivered (v0.1)
	WithdrawalSeq  uint64     `json:"withdrawal_seq"` // newest withdrawal delivered (v0.1)
	connections    int
}

// maxRelayEntries bounds Feed.relays.
const maxRelayEntries = 1024

// Feed publishes the lab's signed state.
type Feed struct {
	cfg    Config
	DB     *store.DB
	Engine *rules.Engine
	Hub    *hub.Hub
	Log    *slog.Logger
	Now    func() time.Time

	mu        sync.Mutex
	cpEnv     []byte
	cpSeq     uint64
	cpAt      time.Time
	logged    string // state of the last logged checkpoint
	loggedAt  time.Time
	changed   chan struct{}
	relays    map[string]*Relay        // key: kind + "/" + id
	conns     map[*http.Request]string // open stream request -> relays key
	cpCounter *metrics.Counter
	// POST /v0/signatures budgets (token buckets, 5/s, burst 20): per address
	// before anything is read, per key after the signature was checked.
	sigAddrs map[string]*tokenBucket
	sigKeys  map[string]*tokenBucket
}

// tokenBucket is one budget of POST /v0/signatures.
type tokenBucket struct {
	tokens float64
	last   time.Time
}

// maxSigAddrs bounds the buckets per address: a full map starts over, which
// only ever gives a sender more room for a moment.
const maxSigAddrs = 4096

// takeToken spends one token of the bucket under key.
func (f *Feed) takeToken(buckets map[string]*tokenBucket, key string) bool {
	now := f.Now()
	b := buckets[key]
	if b == nil {
		b = &tokenBucket{tokens: 20, last: now}
		buckets[key] = b
	}
	b.tokens = min(20, b.tokens+now.Sub(b.last).Seconds()*5)
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// allowAddress limits co-signature posts per sender address: the endpoint is
// public (signatures are the only authentication).
func (f *Feed) allowAddress(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.sigAddrs == nil || len(f.sigAddrs) >= maxSigAddrs {
		f.sigAddrs = map[string]*tokenBucket{}
	}
	return f.takeToken(f.sigAddrs, host)
}

// allowKey limits co-signature posts per signing key, each of which takes the
// store's write lock. It runs after the signature was checked: before that the
// key in the body is only a claim, and a forger could spend a peer's budget.
func (f *Feed) allowKey(keyID string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.sigKeys == nil {
		f.sigKeys = map[string]*tokenBucket{}
	}
	return f.takeToken(f.sigKeys, keyID)
}

// New builds the feed and its hub.
func New(cfg Config, db *store.DB, eng *rules.Engine, log *slog.Logger, reg *metrics.Registry) *Feed {
	if cfg.Interval <= 0 {
		cfg.Interval = stream.CheckpointInterval
	}
	if cfg.TTL <= 0 || cfg.TTL > contract.MaxCheckpointValidity {
		cfg.TTL = 3 * time.Minute
	}
	f := &Feed{cfg: cfg, DB: db, Engine: eng, Log: log, Now: time.Now, changed: make(chan struct{}, 1), relays: map[string]*Relay{}, conns: map[*http.Request]string{}}
	var hm *hub.Metrics
	if reg != nil {
		hm = hub.NewMetrics(reg, "schild_lab_feed")
		f.cpCounter = reg.Counter("schild_lab_checkpoints_total", "Checkpoints signed by this lab.").With()
	}
	f.Hub = hub.New(hub.Options{
		ID:                  cfg.Lab,
		Heartbeat:           cfg.Heartbeat,
		Snapshot:            f.snapshot,
		HeartbeatCheckpoint: f.checkpoint,
		Metrics:             hm,
		Now:                 func() time.Time { return f.Now() },
		Track:               f.track,
		Delivered:           f.delivered,
	})
	return f
}

// subscriber identifies a stream request: a configured peer lab when the
// request is signed by one of its rules keys (peerauth over GET /v0/stream),
// otherwise a relay under its self-reported name.
func (f *Feed) subscriber(r *http.Request) (kind, id string) {
	if r.Header.Get(peerauth.Header) != "" && f.cfg.PeerTrust != nil {
		peer, err := peerauth.VerifyHTTP(r, nil, f.cfg.Lab, f.cfg.PeerTrust, f.Now())
		if err == nil && peer != f.cfg.Lab {
			return KindPeerLab, peer
		}
		if f.Log != nil {
			f.Log.Warn("stream subscriber with invalid peer signature, listed as relay", "err", err)
		}
	}
	id = r.Header.Get(upstream.HeaderName)
	if !validID(id) {
		id = "unnamed" // subscribers without a relay id share one entry
	}
	return KindRelay, id
}

func (f *Feed) track(r *http.Request, connected bool) {
	var kind, id string
	if connected {
		kind, id = f.subscriber(r) // before the lock: verifies a signature
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	key, known := f.conns[r]
	if connected {
		key = kind + "/" + id
		// The relay name is self-reported, so an anonymous stream request can
		// add an entry. Past the bound: forget disconnected relays, and while
		// that frees nothing, newcomers share the unnamed entry.
		if _, ok := f.relays[key]; !ok && len(f.relays) >= maxRelayEntries {
			for k, rl := range f.relays {
				if rl.connections == 0 && rl.Kind == KindRelay {
					delete(f.relays, k)
				}
			}
			if len(f.relays) >= maxRelayEntries && kind == KindRelay {
				id, key = "unnamed", KindRelay+"/unnamed"
			}
		}
		f.conns[r] = key
	} else {
		delete(f.conns, r)
		if !known {
			return
		}
	}
	rl := f.relays[key]
	if rl == nil {
		if !connected {
			return
		}
		rl = &Relay{ID: id, Kind: kind}
		f.relays[key] = rl
	}
	if connected {
		rl.connections++
		if rl.ConnectedSince == nil {
			t := f.Now().UTC()
			rl.ConnectedSince = &t
		}
	} else if rl.connections > 0 {
		rl.connections--
		if rl.connections == 0 {
			rl.ConnectedSince = nil
		}
	}
}

// delivered records what a relay received (dashboard relay coverage).
func (f *Feed) delivered(r *http.Request, typ, id string, data []byte) {
	var version, seq uint64
	switch typ {
	case stream.TypeBundle, stream.TypeWithdrawal:
		var ev struct {
			Envelope *dsse.Envelope `json:"envelope"`
			Ref      *stream.Ref    `json:"ref"`
		}
		if json.Unmarshal(data, &ev) != nil {
			break
		}
		if ev.Ref != nil {
			version = ev.Ref.Version
			break
		}
		if ev.Envelope == nil {
			break
		}
		payload, err := ev.Envelope.DecodePayload()
		if err != nil {
			break
		}
		var p struct {
			Version uint64 `json:"version"`
			Seq     uint64 `json:"seq"`
		}
		if json.Unmarshal(payload, &p) == nil {
			version, seq = p.Version, p.Seq
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	rl := f.relays[f.conns[r]]
	if rl == nil {
		return
	}
	rl.LastEventID = id
	if typ == stream.TypeBundle && version > rl.BundleVersion {
		rl.BundleVersion = version
	}
	if typ == stream.TypeWithdrawal && seq > rl.WithdrawalSeq {
		rl.WithdrawalSeq = seq
	}
}

func validID(s string) bool {
	if s == "" || len(s) > 63 {
		return false
	}
	for i, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' && i > 0) {
			return false
		}
	}
	return true
}

// Relays lists known subscribers.
func (f *Feed) Relays() []Relay {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]Relay, 0, len(f.relays))
	for _, r := range f.relays {
		c := *r
		c.Status = "disconnected"
		if r.connections > 0 {
			c.Status = "connected"
		}
		out = append(out, c)
	}
	return out
}

// Checkpoint returns the newest checkpoint envelope, its seq and time.
func (f *Feed) Checkpoint() ([]byte, uint64, time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.cpEnv, f.cpSeq, f.cpAt
}

func (f *Feed) checkpoint() json.RawMessage {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.cpEnv
}

// bundleEvent renders a published bundle inline or by reference.
func (f *Feed) bundleEvent(version uint64, env []byte) stream.Event {
	if len(env) <= contract.MaxInlineEnvelope {
		return stream.Event{Type: stream.TypeBundle, Envelope: env}
	}
	return stream.Event{Type: stream.TypeBundle, Ref: &stream.Ref{BundleID: f.cfg.Channel, Version: version,
		URLPath: stream.BundleURLPath(f.cfg.Channel, version), SHA256: upstream.SHA256(env), Size: len(env)}}
}

func (f *Feed) snapshot() []stream.Event {
	st := f.Engine.CurrentState()
	var out []stream.Event
	for _, w := range st.Withdrawals {
		out = append(out, stream.Event{Type: stream.TypeWithdrawal, Envelope: w})
	}
	if st.BundleEnv != nil {
		out = append(out, f.bundleEvent(st.BundleVersion, st.BundleEnv))
	}
	f.mu.Lock()
	cp := f.cpEnv
	f.mu.Unlock()
	if cp != nil {
		out = append(out, stream.Event{Type: stream.TypeCheckpoint, Envelope: cp})
	}
	return out
}

// PublishBundle implements rules.Publisher.
func (f *Feed) PublishBundle(version uint64, env []byte) {
	if _, err := f.Hub.Publish(f.bundleEvent(version, env), ""); err != nil {
		f.Log.Error("feed: publish bundle", "version", version, "err", err)
	}
}

// PublishWithdrawal implements rules.Publisher.
func (f *Feed) PublishWithdrawal(seq uint64, env []byte) {
	if _, err := f.Hub.Publish(stream.Event{Type: stream.TypeWithdrawal, Envelope: env}, ""); err != nil {
		f.Log.Error("feed: publish withdrawal", "seq", seq, "err", err)
	}
}

// Changed implements rules.Publisher: re-sign the checkpoint soon.
func (f *Feed) Changed() {
	select {
	case f.changed <- struct{}{}:
	default:
	}
}

// Sign signs and publishes a new checkpoint now.
func (f *Feed) Sign() error {
	now := f.Now().UTC().Truncate(time.Second)
	st := f.Engine.CurrentState()
	var env []byte
	var seq uint64
	err := f.DB.Update(func(tx *bolt.Tx) error {
		var err error
		seq, err = store.NextCounter(tx, "checkpoint_seq")
		if err != nil {
			return err
		}
		head := publog.HeadTx(tx)
		cp := msg.Checkpoint{Schema: msg.SchemaCheckpoint, Lab: f.cfg.Lab, Seq: seq, IssuedAt: msg.FormatTime(now), Expires: msg.FormatTime(now.Add(f.cfg.TTL)),
			Bundle: msg.BundleRef{BundleID: f.cfg.Channel, Version: st.BundleVersion, Digest: st.BundleDigest}, WithdrawalSeq: st.WithdrawalSeq,
			Log: &msg.LogState{Size: head.Size, Root: head.Root}}
		payload, err := jsonx.Marshal(&cp)
		if err != nil {
			return err
		}
		e, err := dsse.Sign(contract.KindCheckpoint.PayloadType(), payload, f.cfg.CheckpointSigner)
		if err != nil {
			return err
		}
		if env, err = e.Marshal(); err != nil {
			return err
		}
		// Log checkpoints when the announced state changes, and hourly.
		state := fmt.Sprintf("%d/%d", st.BundleVersion, st.WithdrawalSeq)
		f.mu.Lock()
		logIt := state != f.logged || now.Sub(f.loggedAt) >= time.Hour
		f.mu.Unlock()
		if logIt {
			if _, err := publog.Append(tx, now, publog.KindCheckpoint, strconv.FormatUint(seq, 10), msg.Digest(payload),
				fmt.Sprintf("checkpoint %d: bundle %d, withdrawal %d", seq, st.BundleVersion, st.WithdrawalSeq), env); err != nil {
				return err
			}
			f.mu.Lock()
			f.logged, f.loggedAt = state, now
			f.mu.Unlock()
		}
		return nil
	})
	if err != nil {
		return err
	}
	f.mu.Lock()
	f.cpEnv, f.cpSeq, f.cpAt = env, seq, now
	f.mu.Unlock()
	if f.cpCounter != nil {
		f.cpCounter.Inc()
	}
	_, err = f.Hub.Publish(stream.Event{Type: stream.TypeCheckpoint, Envelope: env}, "checkpoint:"+f.cfg.Lab)
	return err
}

// Run signs checkpoints and sends heartbeats until ctx ends.
func (f *Feed) Run(ctx context.Context) {
	if err := f.Sign(); err != nil {
		f.Log.Error("feed: first checkpoint", "err", err)
	}
	go f.Hub.Run(ctx)
	t := time.NewTicker(f.cfg.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-f.changed:
		}
		if err := f.Sign(); err != nil {
			f.Log.Error("feed: checkpoint", "err", err)
		}
	}
}

// Handler serves the feed endpoints.
func (f *Feed) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET "+stream.Path, f.Hub)
	mux.HandleFunc("GET /v0/bundles/{id}/{file}", f.bundle)
	mux.HandleFunc("GET "+stream.CheckpointPath, func(w http.ResponseWriter, r *http.Request) {
		env, _, _ := f.Checkpoint()
		if env == nil {
			http.Error(w, "no checkpoint yet", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-cache, max-age=5")
		w.Write(env)
	})
	mux.HandleFunc("GET /v0/collecting", f.collecting)
	mux.HandleFunc("POST /v0/signatures", f.signature)
	mux.HandleFunc("GET /v0/log", f.log)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok\n")) })
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		if env, _, _ := f.Checkpoint(); env == nil {
			http.Error(w, "no checkpoint yet", http.StatusServiceUnavailable)
			return
		}
		w.Write([]byte("ready\n"))
	})
	return mux
}

func (f *Feed) bundle(w http.ResponseWriter, r *http.Request) {
	ver, ok := strings.CutSuffix(r.PathValue("file"), ".json")
	v, err := strconv.ParseUint(ver, 10, 64)
	if !ok || err != nil || r.PathValue("id") != f.cfg.Channel {
		http.NotFound(w, r)
		return
	}
	b, err := f.Engine.GetBundle(v)
	if err != nil || b.Envelope == nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	w.Write(b.Envelope)
}

// collecting lists this lab's items waiting for co-signatures. They hold
// rule texts that are not published yet, so only configured peers get them:
// the request must carry a valid Schild-Peer-Auth signature by a rules key
// of a peer (contracts v0.1, cosign.md). Everyone else gets 401.
func (f *Feed) collecting(w http.ResponseWriter, r *http.Request) {
	if f.cfg.PeerTrust == nil {
		problem(w, http.StatusUnauthorized, "unauthenticated", "no peers configured")
		return
	}
	peer, err := peerauth.VerifyHTTP(r, nil, f.cfg.Lab, f.cfg.PeerTrust, f.Now())
	if err != nil || peer == f.cfg.Lab {
		w.Header().Set("WWW-Authenticate", peerauth.Header)
		code := string(contract.CodeOf(err))
		if code == "" {
			code = "signature"
		}
		problem(w, http.StatusUnauthorized, "unauthenticated", "peer signature required ("+code+")")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"lab": f.cfg.Lab, "items": f.Engine.Collecting()})
}

// SignatureRequest is the body of POST /v0/signatures.
type SignatureRequest struct {
	Kind      string         `json:"kind"`
	Digest    string         `json:"digest"`
	Signature dsse.Signature `json:"signature"`
}

func (f *Feed) signature(w http.ResponseWriter, r *http.Request) {
	if !f.allowAddress(r) {
		w.Header().Set("Retry-After", "2")
		problem(w, http.StatusTooManyRequests, "rate_limited", "too many signature posts")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 8<<10))
	if err != nil {
		problem(w, http.StatusBadRequest, "malformed", "unreadable body")
		return
	}
	var req SignatureRequest
	v, err := jsonx.ParseObject(body)
	if err == nil {
		err = jsonx.Decode(v, &req)
	}
	if err != nil {
		problem(w, http.StatusBadRequest, "malformed", "body must be {kind, digest, signature{keyid, sig}}")
		return
	}
	fail := func(err error) {
		var re *rules.Error
		if errors.As(err, &re) {
			problem(w, re.Status, re.Code, re.Detail)
			return
		}
		problem(w, http.StatusInternalServerError, "internal", "could not store the signature")
	}
	if err := f.Engine.CheckSignature(contract.Kind(req.Kind), req.Digest, req.Signature); err != nil {
		fail(err)
		return
	}
	if !f.allowKey(req.Signature.KeyID) {
		w.Header().Set("Retry-After", "2")
		problem(w, http.StatusTooManyRequests, "rate_limited", "too many signature posts")
		return
	}
	ops, published, err := f.Engine.AddSignature(contract.Kind(req.Kind), req.Digest, req.Signature)
	if err != nil {
		fail(err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"operators": ops, "published": published})
}

// LogPage is the public log response.
type LogPage struct {
	Head    publog.Head     `json:"head"`
	Entries []*publog.Entry `json:"entries"`
}

func (f *Feed) log(w http.ResponseWriter, r *http.Request) {
	from, _ := strconv.ParseUint(r.URL.Query().Get("from"), 10, 64)
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	var page LogPage
	_ = f.DB.View(func(tx *bolt.Tx) error {
		page.Head = publog.HeadTx(tx)
		page.Entries = publog.Range(tx, from, limit)
		return nil
	})
	if page.Entries == nil {
		page.Entries = []*publog.Entry{}
	}
	writeJSON(w, http.StatusOK, page)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	w.Write(b)
}

func problem(w http.ResponseWriter, status int, code, detail string) {
	b, _ := json.Marshal(map[string]any{"type": "about:blank", "title": http.StatusText(status), "status": status, "code": code, "detail": detail})
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	w.Write(b)
}
