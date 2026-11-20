// Package app wires schild-lab together: config and keys, the durable
// queue, ingest, scoring, the rules engine, the feed, peers, the dashboard
// and metrics - each on its own listener (conventions §4):
//
//	ingest     0.0.0.0:7443  POST /v0/submit (TLS when tls is configured)
//	feed       0.0.0.0:7444  /v0/stream, /v0/bundles, /v0/checkpoint, ... (TLS)
//	dashboard  127.0.0.1:8789 UI + /api/v0
//	metrics    127.0.0.1:9102 /metrics
//
// Ingest and scoring share nothing but the queue: separate goroutines,
// separate files, bounded in-flight work (concept 21 §5.0).
package app

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/config"
	"github.com/deutschland-schild/schild/contract/keys"
	"github.com/deutschland-schild/schild/lab/internal/d2export"
	"github.com/deutschland-schild/schild/lab/internal/dashboard"
	"github.com/deutschland-schild/schild/lab/internal/feed"
	"github.com/deutschland-schild/schild/lab/internal/ingest"
	"github.com/deutschland-schild/schild/lab/internal/peers"
	"github.com/deutschland-schild/schild/lab/internal/queue"
	"github.com/deutschland-schild/schild/lab/internal/rules"
	"github.com/deutschland-schild/schild/lab/internal/scoring"
	"github.com/deutschland-schild/schild/lab/internal/settings"
	"github.com/deutschland-schild/schild/lab/internal/store"
	"github.com/deutschland-schild/schild/relay/metrics"
	"github.com/deutschland-schild/schild/relay/upstream"
)

// Options beyond lab.yaml.
type Options struct {
	DataDir    string            // overrides storage.path (SCHILD_LAB_DATA_DIR)
	Threshold  int               // k for publishing (SCHILD_LAB_THRESHOLD), floor 2, default 3
	Simulated  map[string]string // lab -> simulated operator (test profile only)
	QueueSync  queue.SyncMode    // SCHILD_LAB_QUEUE_SYNC (os | full)
	HTTPClient *http.Client      // peers (default: upstream.HTTPClient)
	Log        *slog.Logger
	Now        func() time.Time
	// Test hooks.
	CheckpointInterval time.Duration
	Heartbeat          time.Duration
	PeerPoll           time.Duration
}

// App is one running lab.
type App struct {
	Cfg      *config.LabConfig
	Settings *settings.Manager
	DB       *store.DB
	Q        *queue.Queue
	Engine   *rules.Engine
	Scorer   *scoring.Scorer
	Ingest   *ingest.Ingest
	Feed     *feed.Feed
	Peers    *peers.Manager
	Dash     *dashboard.Server
	Reg      *metrics.Registry
	Trust    *keys.TrustStore
	Log      *slog.Logger
	now      func() time.Time
	depthG   *metrics.GaugeVec
}

type signers struct{ ack, rules, checkpoint *keys.Signer }

func loadSigners(cfg *config.LabConfig) (*signers, []keys.TrustedKey, error) {
	var s signers
	var own []keys.TrustedKey
	for _, k := range cfg.Keys {
		sg, err := keys.LoadSigner(k.KeyID, k.PrivateKeyFile)
		if err != nil {
			return nil, nil, fmt.Errorf("key %s: %w", k.KeyID, err)
		}
		own = append(own, keys.TrustedKey{KeyID: k.KeyID, Public: sg.Public(), Purposes: k.Purposes, Operator: cfg.Identity.Operator, Lab: cfg.Identity.Lab})
		for _, p := range k.Purposes {
			switch p {
			case contract.PurposeAck:
				if s.ack == nil {
					s.ack = sg
				}
			case contract.PurposeRules:
				if s.rules == nil {
					s.rules = sg
				}
			case contract.PurposeCheckpoint:
				if s.checkpoint == nil {
					s.checkpoint = sg
				}
			}
		}
	}
	if s.ack == nil || s.rules == nil || s.checkpoint == nil {
		return nil, nil, errors.New("lab.yaml keys need the purposes ack, rules and checkpoint")
	}
	return &s, own, nil
}

// PeerTrust builds the store of the configured peers' keys only (never this
// lab's own): who may read GET /v0/collecting (contracts v0.1).
func PeerTrust(cfg *config.LabConfig) (*keys.TrustStore, error) {
	ts := keys.NewTrustStore()
	for _, p := range cfg.Peers {
		for _, k := range p.Keys {
			pub, err := keys.ParsePublicKey(k.PublicKey)
			if err != nil {
				return nil, fmt.Errorf("peer %s key %s: %w", p.Lab, k.KeyID, err)
			}
			if err := ts.Add(keys.TrustedKey{KeyID: k.KeyID, Public: pub, Purposes: k.Purposes, Operator: p.Operator, Lab: p.Lab}); err != nil {
				return nil, err
			}
		}
	}
	return ts, nil
}

// LabTrust builds the store of all lab keys this lab knows (own and peers).
func LabTrust(cfg *config.LabConfig, own []keys.TrustedKey) (*keys.TrustStore, error) {
	ts := keys.NewTrustStore()
	for _, k := range own {
		if err := ts.Add(k); err != nil {
			return nil, err
		}
	}
	for _, p := range cfg.Peers {
		for _, k := range p.Keys {
			pub, err := keys.ParsePublicKey(k.PublicKey)
			if err != nil {
				return nil, fmt.Errorf("peer %s key %s: %w", p.Lab, k.KeyID, err)
			}
			if err := ts.Add(keys.TrustedKey{KeyID: k.KeyID, Public: pub, Purposes: k.Purposes, Operator: p.Operator, Lab: p.Lab}); err != nil {
				return nil, fmt.Errorf("peer %s: %w", p.Lab, err)
			}
		}
	}
	return ts, nil
}

// New builds a lab from its configuration.
func New(cfg *config.LabConfig, o Options) (*App, error) {
	if o.Log == nil {
		o.Log = slog.Default()
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if len(o.Simulated) > 0 && (cfg.Profile != "test" || keys.Release) {
		return nil, errors.New("simulated operators need profile test and a non-release build")
	}
	if o.Threshold != 0 && o.Threshold < contract.MinIndependentOperatorsFloor {
		return nil, fmt.Errorf("threshold %d below the floor of %d operators", o.Threshold, contract.MinIndependentOperatorsFloor)
	}
	dir := o.DataDir
	if dir == "" {
		dir = cfg.Storage.Path
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	sg, own, err := loadSigners(cfg)
	if err != nil {
		return nil, err
	}
	trust, err := LabTrust(cfg, own)
	if err != nil {
		return nil, err
	}
	a := &App{Cfg: cfg, Reg: metrics.NewRegistry(), Trust: trust, Log: o.Log, now: o.Now}
	ok := false
	defer func() {
		if !ok {
			a.Close()
		}
	}()
	if a.DB, err = store.Open(filepath.Join(dir, "store.db")); err != nil {
		return nil, err
	}
	if a.Settings, err = settings.Load(cfg, a.DB); err != nil {
		return nil, err
	}
	eff := a.Settings.Config()
	if a.Q, err = queue.Open(queue.Options{Path: filepath.Join(dir, "queue"), MaxDepth: int64(eff.Ingest.QueueMaxDepth), Sync: o.QueueSync}); err != nil {
		return nil, err
	}
	// Rebuild the replay set before ingest opens.
	window := int64(eff.Ingest.ReplayWindowS) + 2*int64(contract.MaxClockSkew.Seconds())
	if err := scoring.KnownIDs(a.DB, func(id string, ms int64) { a.Q.Remember(id, ms/1000+window) }); err != nil {
		return nil, err
	}

	a.Scorer = scoring.New(a.Q, a.DB, scoringConfig(eff), o.Log.With("part", "scoring"), scoring.NewMetrics(a.Reg))
	a.Scorer.Now = o.Now
	a.Engine, err = rules.New(a.DB, rules.Config{Lab: cfg.Identity.Lab, Operator: cfg.Identity.Operator, Channel: cfg.Channel,
		Threshold: o.Threshold, RulesSigner: sg.rules, Trust: trust, Simulated: o.Simulated}, o.Log.With("part", "rules"))
	if err != nil {
		return nil, err
	}
	a.Engine.Now = o.Now
	a.Engine.Scoring = a.Scorer.Config
	a.Engine.ValidityHours = func() int { return a.Settings.Config().Publish.BundleValidityHours }

	a.Ingest = ingest.New(cfg.Identity.Lab, sg.ack, a.Q, ingestSettings(eff), 0, o.Log.With("part", "ingest"), ingest.NewMetrics(a.Reg))
	a.Ingest.Now = o.Now
	a.Ingest.OnEnqueued = a.Scorer.Wake
	if err := a.Ingest.SetClients(eff.Clients, eff.Issuers); err != nil {
		return nil, err
	}

	peerTrust, err := PeerTrust(cfg)
	if err != nil {
		return nil, err
	}
	a.Feed = feed.New(feed.Config{Lab: cfg.Identity.Lab, Channel: cfg.Channel, CheckpointSigner: sg.checkpoint, PeerTrust: peerTrust,
		Interval: or(o.CheckpointInterval, time.Duration(eff.Publish.CheckpointIntervalS)*time.Second),
		TTL:      time.Duration(eff.Publish.CheckpointTTLS) * time.Second, Heartbeat: o.Heartbeat}, a.DB, a.Engine, o.Log.With("part", "feed"), a.Reg)
	a.Feed.Now = o.Now
	a.Engine.Publisher = a.Feed

	client := o.HTTPClient
	if client == nil {
		if client, err = upstream.HTTPClient(); err != nil {
			return nil, err
		}
	}
	a.Peers = peers.New(cfg.Identity.Lab, cfg.Identity.Operator, cfg.Peers, a.Engine, trust, client, o.Log.With("part", "peers"))
	a.Peers.Now = o.Now
	a.Peers.Signer = sg.rules
	if o.PeerPoll > 0 {
		a.Peers.PollEvery = o.PeerPoll
	}
	a.Engine.Courier = a.Peers

	a.Dash = dashboard.New(dashboard.Deps{DB: a.DB, Engine: a.Engine, Scorer: a.Scorer, Ingest: a.Ingest, Queue: a.Q, Feed: a.Feed,
		Peers: a.Peers, Settings: a.Settings, Log: o.Log.With("part", "dashboard"), Now: o.Now}, time.Duration(eff.Dashboard.SessionTTLMinutes)*time.Minute)
	a.Scorer.OnSignal = a.Dash.PublishSignal

	a.Settings.OnChange = func(c *config.LabConfig) {
		a.Scorer.SetConfig(scoringConfig(c))
		a.Ingest.SetSettings(ingestSettings(c))
		if err := a.Ingest.SetClients(c.Clients, c.Issuers); err != nil {
			a.Log.Error("applying clients failed", "err", err)
		}
	}
	a.depthG = a.Reg.Gauge("schild_lab_queue_depth", "Queued items by priority.", "priority")
	a.Reg.GaugeFunc("schild_lab_queue_max_depth", "Configured queue bound.", func() float64 { return float64(a.Q.MaxDepth()) })
	a.Reg.GaugeFunc("schild_lab_queue_oldest_seconds", "Age of the oldest unread queue item.", func() float64 { return a.Q.Oldest(a.now()).Seconds() })
	a.Reg.GaugeFunc("schild_lab_ack_p99_seconds", "Ack latency p99 over the last 300 s.", func() float64 { return a.Ingest.Window.Summary().P99 / 1000 })
	a.Reg.GaugeFunc("schild_lab_replay_ids", "Message ids remembered for dedupe and replay.", func() float64 { return float64(a.Q.SeenSize()) })
	ok = true
	return a, nil
}

func or(d, def time.Duration) time.Duration {
	if d > 0 {
		return d
	}
	return def
}

func scoringConfig(c *config.LabConfig) scoring.Config {
	return scoring.Config{MinIssuers: c.Scoring.MinIssuers, MaxIssuerShare: c.Scoring.MaxIssuerShare, WindowMinutes: c.Scoring.WindowMinutes, MinScore: *c.Scoring.MinScore}
}

func ingestSettings(c *config.LabConfig) ingest.Settings {
	return ingest.Settings{MaxBodyBytes: c.Ingest.MaxBodyBytes, MaxEnvelopes: c.Ingest.MaxEnvelopes, RatePerClientPerMin: c.Ingest.RatePerClientPerMin,
		RetryAfterMS: c.Ingest.RetryAfterMS, ReplayWindowS: c.Ingest.ReplayWindowS, MinScore: *c.Scoring.MinScore}
}

func health(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok\n")) }

// IngestHandler serves the ingest port.
func (a *App) IngestHandler() http.Handler {
	m := http.NewServeMux()
	m.Handle("POST /v0/submit", a.Ingest)
	m.HandleFunc("GET /healthz", health)
	m.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		if a.Q.Full() {
			http.Error(w, "queue full", http.StatusServiceUnavailable)
			return
		}
		w.Write([]byte("ready\n"))
	})
	return m
}

// FeedHandler serves the feed port.
func (a *App) FeedHandler() http.Handler { return a.Feed.Handler() }

// DashboardHandler serves the dashboard port.
func (a *App) DashboardHandler() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("GET /healthz", health)
	m.HandleFunc("GET /readyz", health)
	m.Handle("/", a.Dash)
	return m
}

// MetricsHandler serves the metrics port.
func (a *App) MetricsHandler() http.Handler {
	m := http.NewServeMux()
	m.Handle("GET /metrics", a.Reg.Handler())
	m.HandleFunc("GET /healthz", health)
	// D2 export (runbook 13.2): patterns and site key ids only, no IPs.
	m.Handle("GET /export/d2", d2export.Handler(a.DB, a.Cfg.Identity.Lab, func() int { return a.Scorer.Config().MinScore }))
	return m
}

// Background runs scoring, feed, peers, live views and maintenance.
func (a *App) Background(ctx context.Context) {
	var wg sync.WaitGroup
	for _, f := range []func(context.Context){a.Scorer.Run, a.Feed.Run, a.Peers.Run, a.Dash.Run, a.maintain} {
		wg.Add(1)
		go func(f func(context.Context)) { defer wg.Done(); f(ctx) }(f)
	}
	wg.Wait()
}

func (a *App) maintain(ctx context.Context) {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	var n int
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		n++
		d := a.Q.Depth()
		for p := queue.Priority(0); p < 3; p++ {
			a.depthG.With(p.String()).Set(float64(d[p]))
		}
		if n%30 == 0 {
			a.Q.GC(a.now())
		}
		if n%300 == 0 {
			if err := scoring.RefreshAll(a.DB, a.now().UTC(), a.Scorer.Config()); err != nil {
				a.Log.Error("refresh patterns", "err", err)
			}
		}
		if n%3600 == 0 {
			c := a.Settings.Config()
			for {
				k, err := scoring.Prune(a.DB, a.now().UTC(), c.Retention.SignalsDays, c.Retention.AggregatesDays, 5000)
				if err != nil {
					a.Log.Error("retention", "err", err)
				}
				if err != nil || k < 5000 || ctx.Err() != nil {
					break
				}
			}
		}
	}
}

// Close releases files.
func (a *App) Close() {
	if a.Q != nil {
		a.Q.Close()
	}
	if a.DB != nil {
		a.DB.Close()
	}
}

// Serve listens on the configured addresses until ctx ends.
func (a *App) Serve(ctx context.Context) error {
	cfg := a.Cfg
	var tlsCfg *tls.Config
	if cfg.TLS != nil {
		cert, err := tls.LoadX509KeyPair(cfg.TLS.CertFile, cfg.TLS.KeyFile)
		if err != nil {
			return fmt.Errorf("tls: %w", err)
		}
		tlsCfg = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}}
	} else {
		a.Log.Warn("no tls configured: ingest and feed are served over plain HTTP (test lab only)")
	}
	type srv struct {
		name, addr string
		h          http.Handler
		tls        bool
	}
	srvs := []srv{
		{"ingest", cfg.Listen.Ingest, a.IngestHandler(), true},
		{"feed", cfg.Listen.Feed, a.FeedHandler(), true},
		{"metrics", cfg.Listen.Metrics, a.MetricsHandler(), false},
	}
	if cfg.Dashboard.Enabled == nil || *cfg.Dashboard.Enabled {
		srvs = append(srvs, srv{"dashboard", cfg.Listen.Dashboard, a.DashboardHandler(), false})
		if !a.Dash.Auth.HasUsers() {
			a.Log.Info("dashboard first run: set the admin password with this one-time code", "setup_code", a.Dash.Auth.SetupCode)
		}
	}
	errc := make(chan error, len(srvs))
	var servers []*http.Server
	for _, s := range srvs {
		hs := &http.Server{Addr: s.addr, Handler: s.h, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 120 * time.Second, MaxHeaderBytes: 32 << 10}
		if s.name == "ingest" {
			hs.ReadTimeout, hs.WriteTimeout = 10*time.Second, 10*time.Second
		}
		ln, err := net.Listen("tcp", s.addr)
		if err != nil {
			return fmt.Errorf("%s listen %s: %w", s.name, s.addr, err)
		}
		if s.tls && tlsCfg != nil {
			hs.TLSConfig = tlsCfg
			ln = tls.NewListener(ln, tlsCfg)
		}
		servers = append(servers, hs)
		a.Log.Info("listening", "server", s.name, "addr", s.addr, "tls", s.tls && tlsCfg != nil)
		go func(hs *http.Server, ln net.Listener) {
			if err := hs.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
				errc <- err
			}
		}(hs, ln)
	}
	bg, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { a.Background(bg); close(done) }()
	var err error
	select {
	case <-ctx.Done():
	case err = <-errc:
	}
	a.Feed.Hub.Close()
	sctx, scancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer scancel()
	for _, hs := range servers {
		_ = hs.Shutdown(sctx)
	}
	cancel()
	<-done
	return err
}
