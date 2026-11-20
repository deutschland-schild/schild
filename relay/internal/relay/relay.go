// Package relay implements schild-relay (MVP-04): an untrusted public SSE
// fan-out of lab-signed checkpoints, rule bundles and withdrawals.
//
// The relay subscribes to one or more upstream lab feeds (or other relays),
// numbers every event with its own ids, keeps the current state for full
// syncs and serves:
//
//	GET /v0/stream                       SSE (contracts/stream.md), Last-Event-ID resume
//	GET /v0/bundles/<id>/<version>.json  bundle envelope bytes (immutable)
//	GET /v0/checkpoint[?lab=<id>]        newest checkpoint envelope
//	GET /v0/state.json                   static fallback: full sync as JSON
//	GET /v0/poll?last_event_id=&wait=    long-poll fallback (JSON)
//	GET /healthz, /readyz
//
// Clients verify everything; the relay can only delay or withhold, which
// clients detect through the signed checkpoints (heartbeat every 15 s).
package relay

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/msg"
	"github.com/deutschland-schild/schild/contract/stream"
	"github.com/deutschland-schild/schild/relay/hub"
	"github.com/deutschland-schild/schild/relay/metrics"
	"github.com/deutschland-schild/schild/relay/upstream"
)

// Config of a relay.
type Config struct {
	ID         string
	Upstreams  []string
	Buffer     int
	MaxPerIP   int
	MaxClients int
	Heartbeat  time.Duration // default 15 s
	Ring       int
	Client     *http.Client // upstream client
	Log        *slog.Logger
	Registry   *metrics.Registry
	Now        func() time.Time
	Epoch      string // tests
	// TrustedProxies are the peers whose ClientIPHeader names the client
	// (SCHILD_RELAY_TRUSTED_PROXIES); empty: the TCP peer always.
	TrustedProxies []netip.Prefix
	// ClientIPHeader is read from trusted peers (default X-Forwarded-For).
	ClientIPHeader string
}

// Relay is one relay process.
type Relay struct {
	cfg   Config
	State *State
	Hub   *hub.Hub
	subs  []*upstream.Subscriber
	log   *slog.Logger
	now   func() time.Time

	connMu  sync.Mutex
	perIP   map[string]int
	total   int
	rejects *metrics.CounterVec
	upEvts  *metrics.CounterVec
	upConn  *metrics.GaugeVec
	fetchMu sync.Mutex
}

// New builds a relay.
func New(cfg Config) *Relay {
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	if cfg.Registry == nil {
		cfg.Registry = metrics.NewRegistry()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.MaxPerIP <= 0 {
		cfg.MaxPerIP = 32
	}
	if cfg.MaxClients <= 0 {
		cfg.MaxClients = 50000
	}
	if cfg.ClientIPHeader == "" {
		cfg.ClientIPHeader = "X-Forwarded-For"
	}
	r := &Relay{cfg: cfg, State: NewState(), log: cfg.Log, now: cfg.Now, perIP: map[string]int{}}
	reg := cfg.Registry
	r.Hub = hub.New(hub.Options{
		ID:                  cfg.ID,
		Epoch:               cfg.Epoch,
		Buffer:              cfg.Buffer,
		Ring:                cfg.Ring,
		Heartbeat:           cfg.Heartbeat,
		Snapshot:            r.State.Snapshot,
		HeartbeatCheckpoint: func() json.RawMessage { return r.State.NewestCheckpoint("") },
		Now:                 cfg.Now,
		Metrics:             hub.NewMetrics(reg, "schild_relay"),
	})
	r.rejects = reg.Counter("schild_relay_rejected_connections_total", "Stream or poll requests refused by connection limits.", "reason")
	r.upEvts = reg.Counter("schild_relay_upstream_events_total", "Events received from upstreams, by type and result.", "type", "result")
	r.upConn = reg.Gauge("schild_relay_upstream_connected", "1 when the upstream stream is connected.", "upstream")
	reg.GaugeFunc("schild_relay_checkpoint_age_seconds", "Age of the newest checkpoint known to the relay (-1 if none).", func() float64 {
		if d, ok := r.State.CheckpointAge(r.now()); ok {
			return d.Seconds()
		}
		return -1
	})
	reg.GaugeFunc("schild_relay_labs", "Labs with a known checkpoint.", func() float64 { l, _, _ := r.State.Counts(); return float64(l) })
	for _, u := range cfg.Upstreams {
		base := strings.TrimRight(u, "/")
		g := r.upConn.With(base)
		r.subs = append(r.subs, &upstream.Subscriber{
			Base:    base,
			Client:  cfg.Client,
			Name:    cfg.ID,
			OnEvent: r.Handle,
			OnState: func(c bool) {
				if c {
					g.Set(1)
				} else {
					g.Set(0)
				}
			},
			Log: cfg.Log,
		})
	}
	return r
}

// Run follows the upstreams and sends heartbeats until ctx ends.
func (r *Relay) Run(ctx context.Context) {
	var wg sync.WaitGroup
	for _, s := range r.subs {
		wg.Add(1)
		go func(s *upstream.Subscriber) { defer wg.Done(); s.Run(ctx) }(s)
	}
	r.Hub.Run(ctx)
	wg.Wait()
}

// Handle processes one upstream event: update the state first, then publish.
func (r *Relay) Handle(ev upstream.Event) {
	e := ev.Event
	switch e.Type {
	case stream.TypeCheckpoint, stream.TypeHeartbeat:
		env := e.Envelope
		if e.Type == stream.TypeHeartbeat {
			env = e.Checkpoint
		}
		c, fresh := r.State.Checkpoint(env)
		if !fresh {
			r.upEvts.With(e.Type, "known").Inc()
			return
		}
		r.publish(stream.Event{Type: stream.TypeCheckpoint, Envelope: c.env}, "checkpoint:"+c.lab)
		r.upEvts.With(e.Type, "published").Inc()
	case stream.TypeBundle:
		env, inline := []byte(e.Envelope), true
		if e.Ref != nil {
			inline = false
			if b, ok := r.State.Cached(e.Ref.URLPath); ok && upstream.SHA256(b) == e.Ref.SHA256 {
				env = b
			} else {
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				b, err := upstream.Fetch(ctx, r.cfg.Client, ev.Upstream, e.Ref)
				cancel()
				if err != nil {
					r.log.Warn("bundle fetch failed", "upstream", ev.Upstream, "path", e.Ref.URLPath, "err", err)
					r.upEvts.With(e.Type, "fetch_failed").Inc()
					return
				}
				env = b
			}
		}
		b, fresh := r.State.Bundle(ev.Upstream, env, inline, e.Ref)
		if b == nil || !fresh {
			r.upEvts.With(e.Type, "known").Inc()
			return
		}
		r.publish(bundleEvent(b), "")
		r.upEvts.With(e.Type, "published").Inc()
	case stream.TypeWithdrawal:
		w, fresh := r.State.Withdrawal(ev.Upstream, e.Envelope)
		if w == nil || !fresh {
			r.upEvts.With(e.Type, "known").Inc()
			return
		}
		r.publish(stream.Event{Type: stream.TypeWithdrawal, Envelope: w.env}, "")
		r.upEvts.With(e.Type, "published").Inc()
	}
}

func (r *Relay) publish(ev stream.Event, coalesce string) {
	if _, err := r.Hub.Publish(ev, coalesce); err != nil {
		r.log.Warn("publish failed", "type", ev.Type, "err", err)
	}
}

// Handler returns the public HTTP handler.
func (r *Relay) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET "+stream.Path, r.limit(r.Hub))
	mux.Handle("GET /v0/poll", r.limit(http.HandlerFunc(r.poll)))
	mux.HandleFunc("GET /v0/state.json", r.stateJSON)
	mux.HandleFunc("GET "+stream.CheckpointPath, r.checkpoint)
	mux.HandleFunc("GET /v0/bundles/{id}/{file}", r.bundle)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok\n")) })
	mux.HandleFunc("GET /readyz", r.ready)
	return mux
}

// limit enforces the per-IP and total connection limits on long-lived requests.
func (r *Relay) limit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		ip := r.clientAddr(req)
		r.connMu.Lock()
		switch {
		case r.total >= r.cfg.MaxClients:
			r.connMu.Unlock()
			r.rejects.With("max_clients").Inc()
			retryLater(w, http.StatusServiceUnavailable)
			return
		case r.perIP[ip] >= r.cfg.MaxPerIP:
			r.connMu.Unlock()
			r.rejects.With("per_ip").Inc()
			retryLater(w, http.StatusTooManyRequests)
			return
		}
		r.perIP[ip]++
		r.total++
		r.connMu.Unlock()
		defer func() {
			r.connMu.Lock()
			if r.perIP[ip]--; r.perIP[ip] <= 0 {
				delete(r.perIP, ip)
			}
			r.total--
			r.connMu.Unlock()
		}()
		next.ServeHTTP(w, req)
	})
}

// clientAddr is the address the per-IP limit counts: the TCP peer, or behind
// a trusted proxy the rightmost address of ClientIPHeader that is not a
// trusted proxy (all trusted: the leftmost). A malformed header counts as the
// peer, so a client cannot leave its proxy's bucket by sending junk.
func (r *Relay) clientAddr(req *http.Request) string {
	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		host = req.RemoteAddr
	}
	peer, err := netip.ParseAddr(host)
	if err != nil || !r.trusted(peer) {
		return host
	}
	var chain []netip.Addr
	for _, v := range req.Header.Values(r.cfg.ClientIPHeader) {
		for _, part := range strings.Split(v, ",") {
			a, err := netip.ParseAddr(strings.TrimSpace(part))
			if err != nil {
				return host
			}
			chain = append(chain, a.Unmap())
		}
	}
	if len(chain) == 0 {
		return host
	}
	for i := len(chain) - 1; i >= 0; i-- {
		if !r.trusted(chain[i]) {
			return chain[i].String()
		}
	}
	return chain[0].String()
}

func (r *Relay) trusted(a netip.Addr) bool {
	a = a.Unmap()
	for _, p := range r.cfg.TrustedProxies {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// ParseTrustedProxies reads SCHILD_RELAY_TRUSTED_PROXIES, comma-separated
// CIDRs. Ranges wider than /8 (IPv4) or /32 (IPv6) are refused: anyone inside
// could pick an address and step around the per-IP limit (as G5 in schild).
func ParseTrustedProxies(v string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, c := range strings.Split(v, ",") {
		if c = strings.TrimSpace(c); c == "" {
			continue
		}
		p, err := netip.ParsePrefix(c)
		if err != nil {
			return nil, fmt.Errorf("SCHILD_RELAY_TRUSTED_PROXIES: %q: %w", c, err)
		}
		if (p.Addr().Is4() && p.Bits() < 8) || (!p.Addr().Is4() && p.Bits() < 32) {
			return nil, fmt.Errorf("SCHILD_RELAY_TRUSTED_PROXIES: %q is too broad (at least /8 for IPv4, /32 for IPv6)", c)
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

// retryLater answers with a randomised Retry-After (spreads reconnect storms).
func retryLater(w http.ResponseWriter, status int) {
	w.Header().Set("Retry-After", strconv.Itoa(5+rand.IntN(26)))
	http.Error(w, http.StatusText(status), status)
}

type pollResponse struct {
	LastEventID string            `json:"last_event_id"`
	FullSync    bool              `json:"full_sync"`
	Events      []json.RawMessage `json:"events"`
}

func (r *Relay) poll(w http.ResponseWriter, req *http.Request) {
	wait := 25 * time.Second
	if v := req.URL.Query().Get("wait"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 && n <= 60 {
			wait = time.Duration(n) * time.Second
		}
	}
	evs, next, full := r.Hub.Poll(req.Context(), hub.LastEventID(req), wait)
	if evs == nil {
		evs = []json.RawMessage{}
	}
	writeJSON(w, pollResponse{LastEventID: next, FullSync: full, Events: evs}, "no-store")
}

func (r *Relay) stateJSON(w http.ResponseWriter, req *http.Request) {
	evs, next, _ := r.Hub.Poll(req.Context(), "", 0)
	if evs == nil {
		evs = []json.RawMessage{}
	}
	writeJSON(w, pollResponse{LastEventID: next, FullSync: true, Events: evs}, "no-cache, max-age=5")
}

func (r *Relay) checkpoint(w http.ResponseWriter, req *http.Request) {
	env := r.State.NewestCheckpoint(req.URL.Query().Get("lab"))
	if env == nil {
		http.Error(w, "no checkpoint yet", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-cache, max-age=5")
	w.Write(env)
}

func (r *Relay) bundle(w http.ResponseWriter, req *http.Request) {
	id, file := req.PathValue("id"), req.PathValue("file")
	ver, ok := strings.CutSuffix(file, ".json")
	v, err := strconv.ParseUint(ver, 10, 64)
	if !ok || err != nil || v == 0 {
		http.NotFound(w, req)
		return
	}
	path := stream.BundleURLPath(id, v)
	b, found := r.State.Cached(path)
	immutable := found
	if !found {
		b, immutable, found = r.fetchOnDemand(req.Context(), path)
	}
	if !found {
		http.NotFound(w, req)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if immutable {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	} else {
		w.Header().Set("Cache-Control", "no-store")
	}
	w.Header().Set("ETag", `"`+strings.TrimPrefix(upstream.SHA256(b), "sha256:")+`"`)
	w.Write(b)
}

// fetchOnDemand asks the upstreams for a bundle the relay does not hold.
// With a reference from a stream event the bytes are checked as on the
// subscribe path (size and SHA-256) and cached. Without one nothing can vouch
// for them: an envelope that really is this bundle is passed on for the
// client to verify (signatures), never cached, and immutable is false. One
// lying upstream therefore cannot pin wrong bytes for a year.
func (r *Relay) fetchOnDemand(ctx context.Context, path string) (b []byte, immutable, ok bool) {
	r.fetchMu.Lock()
	defer r.fetchMu.Unlock()
	if b, ok := r.State.Cached(path); ok {
		return b, true, true
	}
	ref := r.State.RefFor(path)
	for _, s := range r.subs {
		cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		if ref != nil {
			b, err := upstream.Fetch(cctx, r.cfg.Client, s.Base, ref)
			cancel()
			if err == nil {
				r.State.PutCached(path, b)
				return b, true, true
			}
			r.log.Warn("bundle fetch failed", "upstream", s.Base, "path", path, "err", err)
			continue
		}
		b, err := fetchRaw(cctx, r.cfg.Client, s.Base+path)
		cancel()
		if err != nil {
			continue
		}
		var m msg.Bundle
		if payloadOf(b, &m) == nil && stream.BundleURLPath(m.BundleID, m.Version) == path {
			return b, false, true
		}
		r.log.Warn("upstream bundle does not match its path", "upstream", s.Base, "path", path)
	}
	return nil, false, false
}

func (r *Relay) ready(w http.ResponseWriter, _ *http.Request) {
	connected := len(r.subs) == 0
	for _, s := range r.subs {
		if s.Status().Connected {
			connected = true
		}
	}
	labs, _, _ := r.State.Counts()
	if !connected || labs == 0 {
		http.Error(w, "not ready: waiting for an upstream checkpoint", http.StatusServiceUnavailable)
		return
	}
	w.Write([]byte("ready\n"))
}

// Status lists the upstream subscriptions.
func (r *Relay) Status() []upstream.Status {
	out := make([]upstream.Status, len(r.subs))
	for i, s := range r.subs {
		out[i] = s.Status()
	}
	return out
}

func writeJSON(w http.ResponseWriter, v any, cache string) {
	b, err := json.Marshal(v)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", cache)
	w.Write(b)
}

var errNotFound = errors.New("not found")

func fetchRaw(ctx context.Context, c *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, errNotFound
	}
	return readLimited(resp)
}

func readLimited(resp *http.Response) ([]byte, error) {
	max := int64(contract.LimitsFor(contract.KindBundle).MaxEnvelopeBytes)
	b, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, errors.New("bundle too large")
	}
	return b, nil
}
