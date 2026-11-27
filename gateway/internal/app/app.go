// Package app wires `schild run`: configuration, the local store, the WAF
// engine, the gate inside the embedded Caddy, the rule repositories, the
// dashboard and the metrics endpoint, plus the background loops (event
// writer, retention, crowdsec updates, allowlist reloads).
//
// The dashboard runs in-process on its own listener (default
// 127.0.0.1:8788). This is the documented prototype fallback for "dashboard as a
// separate least-privilege process": both share the same binary and user;
// the dashboard listener is bound to localhost by default and every API
// call needs a login.
package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	contractapi "github.com/deutschland-schild/schild/contract/agentapi"
	"github.com/deutschland-schild/schild/contract/bodylimit"
	"github.com/deutschland-schild/schild/contract/config"
	"github.com/deutschland-schild/schild/contract/events"
	"github.com/deutschland-schild/schild/contract/keys"
	"github.com/deutschland-schild/schild/contract/rules"
	"github.com/deutschland-schild/schild/gateway/internal/accesslock"
	"github.com/deutschland-schild/schild/gateway/internal/agentapi"
	"github.com/deutschland-schild/schild/gateway/internal/allowlist"
	"github.com/deutschland-schild/schild/gateway/internal/behaviour"
	"github.com/deutschland-schild/schild/gateway/internal/bots"
	"github.com/deutschland-schild/schild/gateway/internal/buildinfo"
	"github.com/deutschland-schild/schild/gateway/internal/caddymod"
	"github.com/deutschland-schild/schild/gateway/internal/clientip"
	"github.com/deutschland-schild/schild/gateway/internal/cluster"
	"github.com/deutschland-schild/schild/gateway/internal/connlimit"
	"github.com/deutschland-schild/schild/gateway/internal/crawlers"
	"github.com/deutschland-schild/schild/gateway/internal/dashboard"
	"github.com/deutschland-schild/schild/gateway/internal/diskbudget"
	"github.com/deutschland-schild/schild/gateway/internal/eventlog"
	"github.com/deutschland-schild/schild/gateway/internal/gate"
	"github.com/deutschland-schild/schild/gateway/internal/geo"
	"github.com/deutschland-schild/schild/gateway/internal/hosts"
	"github.com/deutschland-schild/schild/gateway/internal/humancheck"
	"github.com/deutschland-schild/schild/gateway/internal/memlimit"
	"github.com/deutschland-schild/schild/gateway/internal/metrics"
	"github.com/deutschland-schild/schild/gateway/internal/monitoring"
	"github.com/deutschland-schild/schild/gateway/internal/ratelog"
	"github.com/deutschland-schild/schild/gateway/internal/reqring"
	"github.com/deutschland-schild/schild/gateway/internal/ruleset"
	"github.com/deutschland-schild/schild/gateway/internal/sites"
	"github.com/deutschland-schild/schild/gateway/internal/stats"
	"github.com/deutschland-schild/schild/gateway/internal/store"
	"github.com/deutschland-schild/schild/gateway/internal/waf"
	"github.com/deutschland-schild/schild/gateway/internal/webui"
)

// Options of a run.
type Options struct {
	ConfigPath string
	DataDir    string // overrides storage.path (SCHILD_DATA_DIR)
	Log        *slog.Logger
	// Test hooks.
	NoListeners bool // do not start Caddy, dashboard and metrics listeners
	// BodyTemp is set by `schild run`, which owns the data directory: it
	// empties the temp space of bodies and points this process at it. Tests
	// leave it off, TMPDIR belongs to the whole test binary.
	BodyTemp bool
	Now      func() time.Time // clock of the rule repositories (tests)
	// BotsNow is the clock of the bot engine: the age of the range
	// snapshots (tests; nil: time.Now).
	BotsNow func() time.Time
}

// App is one running schild.
type App struct {
	mem     memlimit.Result
	opts    Options
	log     *slog.Logger
	mu      sync.Mutex
	cfg     atomic.Pointer[config.Site]
	base    map[string]any
	overlay map[string]any
	dataDir string

	Store *store.Store
	// Rule exceptions of agents (D54), exceptionsMu around changes.
	exceptionsMu sync.Mutex
	exceptions   []contractapi.RuleException
	Engine       *waf.Engine
	// Composer builds and swaps the WAF, Repos are the rule repositories
	// crs, crowdsec and local (D73).
	Composer  *ruleset.Composer
	Repos     *ruleset.Registry
	Gate      *gate.Gate
	Allow     *allowlist.List
	Geo       *geo.DB
	Events    *eventlog.Log
	Metrics   *metrics.Metrics
	Dashboard *dashboard.Server
	// Hosts is the server check and agents (MVP-11); nil without host_check.
	Hosts *hosts.Gateway

	// GeoUpdater downloads the geo database with the operator's own key
	// (geo.provider ipinfo or maxmind, MVP-22); nil with dbip.
	GeoUpdater *geo.Updater

	setupCode    string
	resetPending bool
	// droppedOverlay and droppedLimits: what the dashboard stored did not fit
	// schild.yaml at start and is not applied (stored.go).
	droppedOverlay atomic.Bool
	droppedLimits  atomic.Bool
	mirror         *eventlog.NDJSONMirror
	sumMu          sync.Mutex
	summaries      map[store.SummaryKey]int
	allowVersion   atomic.Int64
	started        time.Time
	// dashLimits are the rate limits created in the dashboard (MVP-17); they
	// are appended to behaviour.rate_limits and validated with the file.
	dashLimits []config.RateLimit
	// Behaviour is MVP-17 (shared with the gate).
	Behaviour *behaviour.Engine
	// Monitor is MVP-21 traffic and server monitoring; nil when off.
	Monitor *monitoring.Monitor
	// Requests is the MVP-22 request ring; nil when off.
	Requests *reqring.Ring
	// botEngine, robots and botDir: MVP-22 bot catalogue, verification and
	// robots.txt observation (nil with monitoring off).
	botEngine *bots.Engine
	robots    *bots.Robots
	botDir    botDir
	// AgentAPI is the agent API (MVP-21). It is always built; whether its
	// listener is open is the switch (D103, agentSwitch).
	AgentAPI *agentapi.Server
	agent    agentSwitch
	// blockOps feeds the writer of kept behaviour blocks (D29 amendment).
	blockOps chan blockOp
	// Sites are the websites of this gateway (v0.5, D36).
	Sites *sites.Registry
	// budget is the last disk budget check (D38).
	budget atomic.Pointer[diskbudget.Figures]
	// capUnreachable: the last size-cap pass could not reach the cap
	// (hint store_cap_unreachable, D38); capWarnedAt rate-limits its log
	// line to one per hour.
	capUnreachable atomic.Bool
	capWarnedAt    time.Time
	// proxiesTooBroad: forwarding headers are ignored (G5, D40).
	proxiesTooBroad bool
	// Conns bounds the open connections of the ingress (D46).
	Conns *connlimit.Limiter
	// configHash is the config version of the agent API (D46).
	configHash atomic.Pointer[string]
	// loops are the background loops of goLoop; Run waits for them before it
	// closes the stores.
	loops sync.WaitGroup
	// Access is the access lock (D56, MVP-14 step 1); accessMu around changes.
	Access   *accesslock.Lock
	accessMu sync.Mutex
	// HumanCheck is browser verification and Under Attack (MVP-12 v1_cut).
	HumanCheck   *humancheck.Gate
	humanCheckMu sync.Mutex
	// Crawlers is crawler control (D57, MVP-29); crawlersMu around changes.
	Crawlers   *crawlers.Control
	crawlersMu sync.Mutex
	// Cluster is this gateway as a node of its group (MVP-27, D105); nil
	// without cluster.enabled or before the node joined a group.
	Cluster     *cluster.Node
	groupBlocks groupBlocks
	// readyNoted is the readiness the log last named (noteReadiness).
	readyNoted, readyNotedOnce atomic.Bool
	// groupData shares events, incidents and requests (cluster_data.go);
	// erased: when each address was erased in the group.
	groupData *groupData
	// groupMetrics: the metric buckets of the other gateways (cluster_metrics.go).
	groupMetrics *groupMetrics
	erased       erasedSet
	// groupVersions: the config and build versions the other gateways of
	// the group told; groupConfig is this node's (cluster_status.go).
	groupVersions groupVersions
	// firstKeysSince, firstKeysLead: since when this node keeps back a thing
	// made once for the group, and since when it keeps the group's tasks
	// (holdFirstKeys; under sharedMu).
	firstKeysSince, firstKeysLead time.Time
	firstKeysDone                 bool
	// sharedApplied: what the node took of its group was applied once since
	// it came in step; inStepNoted: the mark for it is written (inService).
	sharedApplied, inStepNoted atomic.Bool
	// The loop of the shared things works only when there is something to
	// do (cluster_state.go syncShared). storeWatch: whether schild.db
	// changed; sharedDue: a round is asked for; sharedRan, sharedWasSynced:
	// the last round (under sharedMu); sharedRounds counts the rounds that
	// worked (tests). stateGen moves with everything that may change the
	// state this node hashes (cluster_fingerprint.go).
	storeWatch      *store.Watcher
	sharedDue       atomic.Bool
	sharedRan       time.Time
	sharedWasSynced bool
	sharedRounds    atomic.Int64
	stateGen        atomic.Uint64
	// Keys of the store shared without registration (cluster_generic.go);
	// guarded by sharedMu, the hooks by their own lock.
	// sharedRepair: classes whose things are compared with the group's
	// records in the next round (cluster_fingerprint.go).
	sharedRepair map[string]bool
	stateWatch   stateWatch
	// groupHashKey keys the hashes of the state the nodes compare.
	groupHashKey               [16]byte
	sharedNamed, sharedGeneric map[string]bool
	sharedGenericCaught        bool
	sharedHooksMu              sync.Mutex
	sharedHooks                map[string]func(context.Context, []byte)
	// warmDone: the running counts of the group were taken at the start, or
	// there was nobody to take them from; warmFailed: a member was in reach
	// and they were not taken (cluster_warm.go). clockOut: the node left
	// traffic because its clock is off the group's (cluster_clock.go).
	warmDone, warmFailed, clockOut atomic.Bool
	// testClocks stands in for the clocks of the members in reach (tests).
	testClocks  atomic.Pointer[func() []time.Duration]
	groupConfig atomic.Pointer[string]
	// shared are the whole values the group shares (cluster_state.go);
	// sharedMu around taking and publishing them.
	shared   []sharedThing
	sharedMu sync.Mutex
	// sharedPending: entries other nodes changed, per thing, waiting for
	// the loop; sharedMarks: what this node last brought in step, per thing
	// and entry; sharedCaught: things whose group entries were taken once.
	sharedPending map[string]map[string]pendingEntry
	sharedMarks   map[string]map[string]string
	sharedCaught  map[string]bool
	// hubShare is the hub source as the group shares its index
	// (cluster_hub.go); tests put another one in.
	hubShare atomic.Pointer[hubIndex]
	// clusterNode: the node New opened, which startCluster runs;
	// groupHash: the engine hashes under the key of the group.
	clusterNode *cluster.Node
	groupHash   bool
	// groupNodeID is the node id of this gateway in its group; "": none.
	groupNodeID string
	// draining: the node left traffic (readiness 503) and stops; drainCh
	// is closed by Drain. started is when Run began to serve.
	draining  atomic.Bool
	drainCh   chan struct{}
	drainOnce sync.Once
	// GroupFiles shares the certificate storage with the group
	// (cluster_files.go); nil without a group or without a Caddyfile.
	GroupFiles *groupFiles
}

const (
	overlayKey     = "settings_overlay_v1"
	dashLimitsKey  = "behaviour_rate_limits_v1"
	installedAtKey = "installed_at_v1"
)

// Config returns the effective configuration.
func (a *App) Config() *config.Site { return a.cfg.Load() }

// SetupCode returns the first-run code ("" when a password exists).
func (a *App) SetupCode() string { return a.setupCode }

// DataDir resolves the data directory.
func DataDir(cfg *config.Site, override string) string {
	if override != "" {
		return override
	}
	if v := os.Getenv("SCHILD_DATA_DIR"); v != "" {
		return v
	}
	return cfg.Storage.Path
}

// LoadConfig loads schild.yaml and returns the parsed config and its JSON map.
func LoadConfig(path string) (*config.Site, map[string]any, error) {
	if path == "" {
		path = os.Getenv(config.SitePathEnv)
	}
	if path == "" {
		path = config.SitePathDefault
	}
	cfg, err := config.LoadSite(path)
	if err != nil {
		return nil, nil, err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	j, err := config.YAMLToJSON(b)
	if err != nil {
		return nil, nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(j, &m); err != nil {
		return nil, nil, err
	}
	return cfg, m, nil
}

// New builds the app without starting listeners or loops.
func New(ctx context.Context, opts Options) (*App, error) {
	log := opts.Log
	if log == nil {
		log = slog.Default()
	}
	cfg, base, err := LoadConfig(opts.ConfigPath)
	if err != nil {
		return nil, err
	}
	if err := CheckHostAgents(cfg, os.Getenv); err != nil {
		return nil, err
	}
	a := &App{opts: opts, log: log, base: base, overlay: map[string]any{}, summaries: map[store.SummaryKey]int{}, started: time.Now().UTC(), drainCh: make(chan struct{})}
	a.dataDir = DataDir(cfg, opts.DataDir)
	if opts.BodyTemp {
		n, err := PrepareBodyTemp(a.dataDir)
		if err != nil {
			return nil, err
		}
		if n > 0 {
			log.Info("removed temp files of request bodies from an earlier process", "files", n)
		}
	}
	a.Store, err = store.OpenMigrate(filepath.Join(a.dataDir, "schild.db"), log)
	if err != nil {
		return nil, fmt.Errorf("open store in %s: %w", a.dataDir, err)
	}
	// Rate limits created in the dashboard (MVP-17).
	if raw, err := a.Store.Get(ctx, dashLimitsKey); err == nil {
		var ls []config.RateLimit
		if json.Unmarshal(raw, &ls) == nil {
			a.dashLimits = ls
		}
	}
	if len(a.dashLimits) > 0 {
		if merged, err := a.merged(map[string]any{}); err == nil {
			cfg = merged
		} else {
			log.Warn(droppedLimitsMsg, "err", err)
			a.dashLimits = nil
			a.droppedLimits.Store(true)
		}
	}
	if _, err := a.Store.Get(ctx, installedAtKey); err != nil {
		_ = a.Store.Put(ctx, installedAtKey, []byte(time.Now().UTC().Format(time.RFC3339)))
	}
	// Settings changed in the dashboard are kept in an overlay in the data
	// directory (schild.yaml is often mounted read-only) and validated with
	// the same contract validator as the file.
	if raw, err := a.Store.Get(ctx, overlayKey); err == nil {
		var ov map[string]any
		if json.Unmarshal(raw, &ov) == nil {
			if merged, err := a.merged(ov); err == nil {
				cfg, a.overlay = merged, ov
			} else {
				log.Warn(droppedOverlayMsg, "err", err)
				a.droppedOverlay.Store(true)
			}
		}
	}
	a.cfg.Store(cfg)
	if cfg.Profile == "test" {
		log.Warn("TEST PROFILE: nothing is blocked, every source only records what it would block. Never use this outside the test lab or the live test on own projects.")
	}
	for _, w := range cfg.Warnings() {
		log.Warn(w)
	}
	a.Metrics = metrics.New()
	// Before the event log and the engine: both take from the group.
	if err := a.prepareCluster(cfg); err != nil {
		return nil, err
	}
	a.Events = eventlog.New(a.Store, a.eventNode(cfg), a.Metrics, log)
	a.Sites = sites.NewRegistry(a.websitesView(cfg))
	a.Events.Sites = a.Sites
	// Test lab evaluation: mirror local events as an NDJSON file for the
	// evaluator. Never in release builds (the file is outside retention).
	if dir := os.Getenv("SCHILD_EVENTS_NDJSON_DIR"); dir != "" {
		if keys.Release {
			log.Warn("SCHILD_EVENTS_NDJSON_DIR is ignored in release builds")
		} else if m, err := eventlog.OpenNDJSONMirror(dir, 256<<20, log); err != nil {
			log.Error("event NDJSON mirror not opened", "dir", dir, "err", err)
		} else {
			a.Events.Mirror = m
			a.mirror = m
			log.Warn("TEST LAB: local events are mirrored as NDJSON (full IPs, outside retention)", "dir", dir)
		}
	}
	a.Engine = &waf.Engine{}
	resolver, err := clientip.New(cfg.Ingress.TrustedProxies, cfg.Ingress.ClientIPHeaders)
	if err != nil {
		return nil, err
	}
	if broad := resolver.TooBroad(); len(broad) > 0 {
		// G5, D40: a too broad trusted proxy list would let anybody pick the
		// client address, so forwarding headers are ignored and every client
		// counts as its TCP peer until it is fixed.
		a.proxiesTooBroad = true
		log.Error("ingress.trusted_proxies is too broad: forwarding headers are ignored, every client counts as its TCP peer", "ranges", strings.Join(broad, ","))
	}
	a.Geo, a.GeoUpdater, err = geo.FromConfig(cfg.Geo, log)
	if err != nil {
		if _, ok := geo.Found(cfg.Geo.DBPath); !ok {
			// No file at all is the normal state of an installation from the
			// tarball: a note, in the words of `schild preflight`.
			log.Info(geo.MissingNote(cfg.Geo))
		} else {
			log.Warn("geo database not loaded: country and network of an address stay unknown, everything else works", "err", err)
		}
	}
	baseWAF := waf.Config{BodyLimit: int64(cfg.WAF.RequestBodyLimitBytes), ArgsLimit: waf.DefaultLimits.Args}
	if baseWAF.Exceptions, err = a.loadRuleExceptions(context.Background()); err != nil {
		return nil, err
	}
	mem := memlimit.Apply()
	a.mem = mem
	log.Info("go memory limit", "limit_mib", mem.Limit>>20, "source", mem.Source, "total_mib", mem.Total>>20,
		"rule", mem.Rule, "headroom_mib", max(mem.Total-mem.Limit, 0)>>20)
	bodyLimits := bodylimit.Limits{MaxPerClient: cfg.WAF.Body.MaxPerClient, MaxPerNetwork: cfg.WAF.Body.MaxPerNetwork,
		MaxInFlight: bodylimit.InFlightLimit(cfg.WAF.Body.MaxInFlight, bodyMemory(mem)), MaxInFlightBytes: cfg.WAF.Body.MaxInFlightBytes,
		MaxWaitingBytesPerClient: cfg.WAF.Body.MaxWaitingBytesPerClient, MaxWaitingBytesPerNetwork: cfg.WAF.Body.MaxWaitingBytesPerNetwork,
		MaxWaitingBytes:  bodylimit.WaitingLimit(cfg.WAF.Body.MaxWaitingBytes, bodyMemory(mem)),
		MaxLargeInFlight: bodylimit.LargeInFlightLimit(cfg.WAF.Body.MaxLargeInFlight, bodyMemory(mem))}
	log.Info("request body limits", "per_client", bodyLimits.MaxPerClient, "per_network", bodyLimits.MaxPerNetwork, "in_flight", bodyLimits.MaxInFlight, "large_in_flight", bodyLimits.MaxLargeInFlight,
		"in_flight_mib", bodyLimits.MaxInFlightBytes>>20, "waiting_mib", bodyLimits.MaxWaitingBytes>>20, "raw_kib", cfg.WAF.RawBodyLimitBytes>>10)
	requestLimits := bodylimit.RequestLimits{MaxPerClient: cfg.WAF.Requests.MaxWaitingPerClient, MaxPerNetwork: cfg.WAF.Requests.MaxWaitingPerNetwork,
		Max: bodylimit.RequestLimit(cfg.WAF.Requests.MaxWaiting, bodyMemory(mem))}
	log.Info("waiting request limits", "per_client", requestLimits.MaxPerClient, "per_network", requestLimits.MaxPerNetwork, "gateway", requestLimits.Max)
	a.Conns = a.newConnLimiter(cfg, resolver, requestLimits)
	a.Gate = gate.New(gate.Settings{Mode: cfg.Mode, Limits: waf.Limits{Body: int64(cfg.WAF.RequestBodyLimitBytes), Raw: cfg.WAF.RawBodyLimitBytes, Args: waf.DefaultLimits.Args, JSONDepth: waf.DefaultLimits.JSONDepth},
		Body: bodyLimits, Requests: requestLimits, EvalTimeout: time.Duration(cfg.WAF.EvalTimeoutMS) * time.Millisecond, Resolver: resolver})
	evalLimits, err := evalLimits(cfg, os.Getenv, keys.Release)
	if err != nil {
		return nil, err
	}
	if keys.Release && (os.Getenv("SCHILD_WAF_MAX_EVALS") != "" || os.Getenv("SCHILD_WAF_QUEUE_WAIT_MS") != "") {
		log.Warn("SCHILD_WAF_MAX_EVALS and SCHILD_WAF_QUEUE_WAIT_MS are test lab switches and are ignored in release builds; set waf.max_concurrent_evals and waf.queue_wait_ms in schild.yaml")
	}
	evalLimits.MemBudget = memlimit.EvalBudget(mem, gate.DefaultMemBudget)
	a.Gate.SetEvalLimits(evalLimits)
	lim := a.Gate.EvalLimits()
	log.Info("waf evaluation slots", "max_concurrent", lim.MaxConcurrent, "max_heavy", lim.MaxHeavy, "per_client", lim.PerClient, "net_share", config.NetEvalShare(lim.MaxHeavy),
		"queue_wait", lim.QueueWait, "mem_budget_mib", lim.MemBudget>>20)
	a.Gate.Engine = a.Engine
	a.Gate.Geo = a.Geo
	a.Gate.Events = a.Events
	a.Gate.Metrics = a.Metrics
	a.Gate.Log = log
	a.Gate.Counters = gate.NewCounters()
	a.Gate.Summary = a.addSummary
	a.Gate.Sites = a.Sites
	if err := a.newAccess(ctx); err != nil {
		return nil, err
	}
	if err := a.newHumanCheck(ctx); err != nil {
		return nil, err
	}
	a.Gate.SetWaitingPage(cfg.WaitingPage.On()) // D37
	// MVP-17: behaviour across requests and rate limits, local only.
	a.Behaviour = behaviour.New(a.behaviourConfig(cfg))
	a.Behaviour.KnownHost = a.knownSiteHost
	a.Behaviour.Sink = behaviour.Sink{
		Emit: func(id, typ string, t time.Time, data any, idx eventlog.Index) {
			a.Events.EmitWithID(id, typ, t, data, idx)
		},
		Incident: a.Gate.QueueIncident,
	}
	a.Gate.Behaviour = a.Behaviour
	a.startBlockWriter()
	a.Allow = allowlist.New()
	a.Gate.Allow = a.Allow
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	a.Composer = ruleset.NewComposer(a.Engine, baseWAF, log, a.Metrics)
	start := time.Now()
	a.Repos, err = ruleset.New(ctx, ruleset.Options{Store: a.Store, Composer: a.Composer, Settings: a, Events: a.Events, Log: log, Metrics: a.Metrics,
		Now: now, Mode: func() string { return a.Gate.Settings().Mode }, Hits: a.ruleHits, CRSVersion: buildinfo.CRSVersion, OnLocal: a.setConfigHash})
	if err != nil {
		return nil, err
	}
	a.Repos.Prepare(ctx)
	a.Gate.Rules = a.Repos
	if err := a.Repos.Start(); err != nil {
		return nil, fmt.Errorf("build WAF: %w", err)
	}
	log.Info("WAF ready", "crs", cfg.Rules.CRS.State, "crs_version", buildinfo.CRSVersion, "crowdsec", cfg.Rules.Crowdsec.State,
		"local", cfg.Rules.Local.State, "local_rules", a.Repos.LocalRules(), "build", time.Since(start).Round(time.Millisecond))
	a.Metrics.BaselineProtection.Set(boolf(cfg.Rules.CRS.State != rules.StateOff))
	if err := a.ReloadAllow(ctx); err != nil {
		return nil, err
	}
	a.restoreBlocks(ctx)
	if xs, err := a.Store.ActiveExceptions(ctx, time.Now()); err == nil {
		a.Gate.Exceptions.Load(xs)
	}
	if !a.Store.HasUsers(ctx) {
		if a.Store.PendingSetupHash(ctx) != nil {
			a.resetPending = true // code shown once by schild dashboard reset-password
		} else {
			a.setupCode = dashboard.NewSetupCode()
		}
	}
	a.Dashboard = &dashboard.Server{St: a.Store, Gate: a.Gate, Allow: a.Allow,
		Geo: a.Geo, Events: a.Events, Config: a.Config, Apply: a.Apply, ReloadAllow: a.ReloadAllow, SetupCode: a.setupCode,
		Version: buildinfo.String(), CRSVersion: buildinfo.CRSVersion, Started: a.started, Log: log, UI: webui.Handler(),
		ScriptHashes: webui.InlineScriptHashes(), ProxiesTooBroad: a.proxiesTooBroad, ProxyMissing: a.Gate.Proxies.Missing,
		Listen: cfg.Listen.Dashboard, SettingsDropped: a.SettingsDropped}
	if cfg.Cluster.Enabled {
		// Without cluster.enabled the dashboard answers "single" by itself.
		a.Dashboard.Group = a.GroupStatus
		a.Dashboard.MemberName = func() string {
			if node := a.Cluster; node != nil {
				return node.Name()
			}
			return ""
		}
		a.Dashboard.ClusterReasons = a.clusterReasons
		a.Dashboard.BlockNode = a.blockNode
	}
	if a.resetPending {
		a.Dashboard.LoadPendingSetup(ctx)
	}
	a.Hosts = a.newHosts(ctx, cfg)
	a.Dashboard.Hosts = a.Hosts
	a.Dashboard.Repos = a.Repos
	a.Dashboard.Access = a.dashboardAccess()
	a.Dashboard.HumanCheck = a.dashboardHumanCheck()
	a.Dashboard.Behaviour = a.Behaviour
	a.Dashboard.OwnAddress = a.ownAddress
	a.Dashboard.GeoOf = func(ip netip.Addr) events.Geo {
		if a.Geo == nil {
			return events.Geo{Country: "ZZ", NetClass: "unknown"}
		}
		g := a.Geo.Lookup(ip)
		return events.Geo{Country: g.Country, ASN: g.ASN, ASOrg: g.ASOrg, NetClass: g.NetClass}
	}
	a.Dashboard.ApplyBehaviour = a.ApplyBehaviour
	a.Dashboard.SetDashboardLimits = a.SetDashboardLimits
	a.Dashboard.DashboardLimits = a.DashboardLimits
	a.Dashboard.InstalledAt = a.InstalledAt
	a.Dashboard.ApplyDistributed = a.ApplyDistributed
	a.Monitor = a.newMonitor(cfg)
	a.Gate.Monitor = a.Monitor
	a.Dashboard.Monitor = a.Monitor
	// D57: after the monitor, so the policies use its bot engine.
	if err := a.newCrawlers(ctx); err != nil {
		return nil, err
	}
	a.Dashboard.Crawlers = a.dashboardCrawlers()
	a.Dashboard.Exceptions = a.listRuleExceptions
	a.Dashboard.CreateException = func(ctx context.Context, req contractapi.ExceptionRequest) (contractapi.RuleException, error) {
		x, err := a.createRuleException(ctx, req, "", "")
		return x, dashboardRefusal(err)
	}
	a.Dashboard.RemoveException = func(ctx context.Context, id int, rules []string) (bool, error) {
		ok, err := a.removeRuleException(ctx, id, rules, "", "", "")
		return ok, dashboardRefusal(err)
	}
	a.Dashboard.Requests = a.Requests
	if a.botEngine != nil {
		a.Dashboard.Bots = a.botDir
	}
	a.Dashboard.Sites = a.Sites
	a.logConfigChange(ctx, a.started, "", cfg)
	a.setConfigHash(a.Repos.LocalText())
	a.AgentAPI = a.newAgentAPI()
	// D87: what `schild firewall run` said in its last call.
	a.Dashboard.FirewallState = a.AgentAPI.Firewall.State
	a.loadAgentSwitch(ctx)
	a.OnSharedKey(agentAPIStoreKey, a.followAgentSwitch)
	a.Dashboard.AgentAPI = a.agentAPIState
	a.Dashboard.SetAgentAPI = a.setAgentAPI
	// Last: the mesh listener is bound and held from here on.
	if err := a.openCluster(cfg); err != nil {
		return nil, err
	}
	a.Gate.SetReady(true)
	return a, nil
}

func boolf(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

// ruleHits are the rule hits of the last 24 h and the requests of that
// window, for the rule lists.
func (a *App) ruleHits(now time.Time) (map[string]int64, int64) {
	if a.Gate == nil || a.Gate.Counters == nil {
		return map[string]int64{}, 0
	}
	return a.Gate.Counters.Hits.Rules(now), a.Gate.Counters.Rolling.Sum(stats.Requests, 24*time.Hour, now)
}

// ReloadAllow loads config and stored allowlist entries into the matcher.
func (a *App) ReloadAllow(ctx context.Context) error {
	var entries []store.AllowEntry
	for i, e := range a.Config().Allowlist {
		entries = append(entries, store.AllowEntry{ID: fmt.Sprintf("cfg-%d", i+1), IP: e.IP, CIDR: e.CIDR, Host: e.Host, Label: e.Label,
			Level: e.Level, Expires: e.Expires, CreatedAt: a.started, Source: "config"})
	}
	stored, err := a.Store.ListAllow(ctx)
	if err != nil {
		return err
	}
	entries = append(entries, stored...)
	for _, e := range a.Allow.Set(entries) {
		a.log.Warn("allowlist entry skipped", "err", e)
	}
	a.allowVersion.Store(a.Store.AllowVersion(ctx))
	a.dropAllowlistedBlocks()
	return nil
}

func (a *App) addSummary(outcome, country string, t time.Time) {
	k := store.SummaryKey{Hour: t.Unix() / 3600, Outcome: outcome, Country: country}
	a.sumMu.Lock()
	a.summaries[k]++
	a.sumMu.Unlock()
}

func (a *App) flushSummaries(ctx context.Context) {
	a.sumMu.Lock()
	s := a.summaries
	a.summaries = map[store.SummaryKey]int{}
	a.sumMu.Unlock()
	if err := a.Store.AddSummaries(ctx, s); err != nil {
		a.log.Error("write summaries", "err", err)
	}
}

// Retention applies the retention settings once: age retention, the
// bounded tables and one size-cap pass (D38).
func (a *App) Retention(ctx context.Context) {
	c := a.Config().Retention
	res, err := a.Store.ApplyRetention(ctx, time.Now().UTC(), store.Retention{RawIPDays: c.RawIPDays, EventsDays: c.EventsDays, MaxSizeMB: c.MaxSizeMB, SummariesDays: c.SummariesDays}, dashboard.TruncateBody)
	if err != nil {
		a.log.Error("retention", "err", err)
		return
	}
	calls := 0
	if res.Cap != nil {
		calls = res.Cap.Calls
		a.noteCap(res.Cap, time.Now())
	}
	if res.Truncated+res.Deleted+res.DeletedSize+calls+res.KeptBlocks+res.Allow > 0 {
		a.log.Info("retention applied", "ip_truncated", res.Truncated, "deleted_age", res.Deleted, "deleted_size", res.DeletedSize, "agent_calls_trimmed", calls,
			"kept_blocks_ended", res.KeptBlocks, "allowlist_expired", res.Allow)
	}
}

// noteCap keeps the outcome of a size-cap pass for the hint
// store_cap_unreachable and logs at most one warning per hour while the cap
// cannot be reached.
func (a *App) noteCap(r *store.CapResult, now time.Time) {
	a.capUnreachable.Store(r.Unreachable)
	if r.Unreachable && now.Sub(a.capWarnedAt) >= time.Hour {
		a.capWarnedAt = now
		a.log.Warn("schild.db stays above retention.max_size_mb: every value class is at its floor of newest rows (store_cap_unreachable)",
			"used_bytes", r.UsedAfter, "cap_bytes", r.CapBytes)
	}
}

// retentionLoop runs Retention (age retention, bounded tables, size cap)
// at start and every 10 minutes, and a size-cap pass alone as soon as the
// writers wrote a tenth of the cap (storage.CheckDue, D38).
func (a *App) retentionLoop(ctx context.Context) {
	sched := store.NewCapScheduler(a.Store)
	check := func() {
		now := time.Now()
		maxMB := a.Config().Retention.MaxSizeMB
		if !sched.Due(now, maxMB) {
			return
		}
		full := sched.Full(now)
		sched.Ran(now)
		if full {
			a.Retention(ctx)
			return
		}
		res, err := a.Store.SizeCap(ctx, maxMB)
		if err != nil {
			a.log.Error("size cap", "err", err)
			return
		}
		a.noteCap(res, time.Now())
		if n := res.Total(); n > 0 {
			a.log.Info("size cap applied", "deleted_size", n-res.Calls, "agent_calls_trimmed", res.Calls, "used_bytes", res.UsedAfter, "cap_bytes", res.CapBytes)
		}
	}
	check()
	every(ctx, time.Second, check)
}

// Loops starts the background goroutines (no listeners).
func (a *App) Loops(ctx context.Context) {
	a.goLoop(ctx, "events", a.Events.Run)
	a.goLoop(ctx, "incidents", func(ctx context.Context) { a.Gate.RunIncidents(ctx, a.Store) })
	a.goLoop(ctx, "body-spool", a.spoolLoop)
	a.goLoop(ctx, "memory", a.watchMemory)
	// Reports the suppressed tail of rate-limited warnings (D38 section 5).
	a.goLoop(ctx, "ratelog", ratelog.Default.Run)
	// The crowdsec rules update in the background and never block request
	// handling (D39).
	a.goLoop(ctx, "crowdsec", a.Repos.Run)
	a.goLoop(ctx, "allowlist-reload", tick(2*time.Second, func() {
		if v := a.Store.AllowVersion(ctx); v != a.allowVersion.Load() {
			_ = a.ReloadAllow(ctx)
		}
	}))
	a.goLoop(ctx, "allowlist-dns", tick(5*time.Minute, func() { a.Allow.RefreshDNS(ctx) }))
	a.goLoop(ctx, "behaviour-sweep", tick(time.Minute, a.Behaviour.Sweep))
	a.startCluster(ctx)
	a.startJobs(ctx)
	a.goLoop(ctx, "summaries", tick(time.Minute, func() {
		a.flushSummaries(ctx)
		if xs, err := a.Store.ActiveExceptions(ctx, time.Now()); err == nil {
			a.Gate.Exceptions.Load(xs)
		}
	}))
	a.goLoop(ctx, "retention", a.retentionLoop)
	if a.Hosts != nil {
		a.goLoop(ctx, "hosts", a.Hosts.Loop)
	}
	if a.Monitor != nil {
		a.Monitor.Start(ctx)
	}
	if a.Requests != nil {
		a.Requests.Start(ctx)
	}
	if a.botEngine != nil {
		a.botEngine.Start(ctx)
	}
	if a.robots != nil {
		a.robots.Start(ctx)
		a.goLoop(ctx, "robots", a.robotsLoop)
	}
	a.goLoop(ctx, "storage-budget", a.storageBudgetLoop)
	// The geo download is the only outbound connection of geo; it never
	// blocks request handling.
	if a.GeoUpdater != nil {
		a.goLoop(ctx, "geo-download", a.GeoUpdater.Run)
	}
	a.goLoop(ctx, "geo-reload", tick(time.Hour, func() {
		if a.Geo != nil {
			if err := a.Geo.Reload(); err != nil {
				// No database at all was said once at start.
				if _, ok := geo.Found(a.Config().Geo.DBPath); ok {
					a.log.Warn("geo reload", "err", err)
				}
			}
		}
	}))
	a.Allow.RefreshDNS(ctx)
}

func every(ctx context.Context, d time.Duration, f func()) {
	t := time.NewTicker(d)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			f()
		}
	}
}

// Run starts everything and blocks until ctx ends, then shuts down.
func (a *App) Run(ctx context.Context) error {
	cfg := a.Config()
	inner, cancel := context.WithCancel(context.Background())
	defer cancel()
	a.Loops(inner)
	if a.setupCode != "" && *cfg.Dashboard.Enabled {
		// One line, so `grep setup_code` on the log finds everything needed.
		a.log.Warn("FIRST START: the dashboard has no password yet. Open dashboard_url (from your own machine through ssh -L, see docs) and set one with setup_code. Show the code again: schild dashboard setup-code",
			"setup_code", a.setupCode, "dashboard_url", DashboardURL(cfg.Listen.Dashboard), "dashboard", cfg.Listen.Dashboard)
	}
	if a.resetPending {
		a.log.Warn("dashboard: access was reset on the host. Set a new password with the one-time setup code shown by schild dashboard reset-password",
			"dashboard", cfg.Listen.Dashboard)
	}
	WarnDashboardExposed(a.log, cfg)
	var servers []*http.Server
	var startErr error
	errc := make(chan error, 3)
	if !a.opts.NoListeners {
		metricsMux := http.NewServeMux()
		metricsMux.Handle("GET /metrics", a.Metrics.Handler())
		metricsMux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok\n")) })
		metricsMux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
			if !a.Gate.Ready() {
				w.WriteHeader(503)
			}
			_, _ = w.Write([]byte("ok\n"))
		})
		ms := &http.Server{Addr: cfg.Listen.Metrics, Handler: metricsMux, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 2 * time.Minute}
		servers = append(servers, ms)
		go func() { errc <- listen(ms, "metrics") }()
		if *cfg.Dashboard.Enabled {
			ds := &http.Server{Addr: cfg.Listen.Dashboard, Handler: a.Dashboard.Handler(), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 2 * time.Minute}
			servers = append(servers, ds)
			go func() { errc <- listen(ds, "dashboard") }()
		}
		a.startAgentListener(&servers)
		a.startAgentAPI(inner)
		// A start that is refused here (another gate bound, a Caddyfile
		// schild does not accept, a port in use) ends like a run: loops
		// stopped, events flushed, stores closed. Returning at once left
		// the loops writing into the data directory behind Run's back.
		release, err := caddymod.Bind(a.Gate)
		if err != nil {
			startErr = err
		} else {
			defer release()
			defer caddymod.BindConns(a.Conns)()
			if a.GroupFiles != nil {
				// The storage module of the Caddyfile hands certificates
				// to the group through it (MVP-27).
				defer caddymod.BindGroup(a.GroupFiles)()
			}
			startErr = a.startCaddy(cfg)
		}
	}
	runErr := startErr
	if startErr == nil {
		select {
		case <-ctx.Done():
		case <-a.drainCh:
		case runErr = <-errc:
		}
		if runErr == nil {
			a.leaveTraffic()
		}
		a.log.Info("schild stopping")
	}
	if !a.opts.NoListeners {
		_ = caddymod.Stop()
	}
	sctx, scancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer scancel()
	for _, s := range servers {
		_ = s.Shutdown(sctx)
	}
	a.stopAgentAPI()
	a.Events.Flush(sctx)
	a.flushSummaries(sctx)
	cancel()
	if !a.waitLoops(5 * time.Second) {
		a.log.Warn("background loops still running at shutdown; closing the stores anyway")
	}
	if a.mirror != nil {
		a.mirror.Close()
	}
	if a.Cluster != nil {
		a.Cluster.Close()
	}
	if a.Monitor != nil {
		_ = a.Monitor.Close()
	}
	if a.Requests != nil {
		_ = a.Requests.Close()
	}
	if a.robots != nil {
		a.robots.Close()
	}
	if a.botEngine != nil {
		a.botEngine.Close()
	}
	_ = a.Store.Close()
	return runErr
}

// startCaddy loads the embedded Caddy: the operator's Caddyfile in ingress
// mode (MVP-19), else the single proxy route listen.proxy -> upstream.
func (a *App) startCaddy(cfg *config.Site) error {
	if cfg.CaddyIngress() {
		ing, err := a.PrepareIngress()
		if ing != nil {
			for _, w := range ing.Check.Warnings {
				a.log.Warn("ingress: "+w, "caddyfile", cfg.Ingress.Caddyfile)
			}
		}
		if err != nil {
			return fmt.Errorf("ingress: %w", err)
		}
		// A lost token must not take down sites whose certificates are
		// valid, so this is an error in the log and not a refusal.
		for _, p := range caddymod.DNSTokenProblems(ing.JSON) {
			a.log.Error("ingress: "+p+"; schild serves the certificates it holds and obtains or renews none that needs this token. Fix it and restart schild", "caddyfile", cfg.Ingress.Caddyfile)
		}
		// The gate decides each request by the website of the site block
		// Caddy routed it to (D69).
		if ing.JSON, err = caddymod.BindWebsites(ing.JSON, a.Sites.View().Set.RouteWebsite); err != nil {
			return fmt.Errorf("ingress: %w", err)
		}
		if err := caddymod.Load(ing.JSON); err != nil {
			return fmt.Errorf("ingress: load Caddyfile %s: %w", cfg.Ingress.Caddyfile, err)
		}
		var sites []string
		for _, s := range ing.Check.Sites {
			sites = append(sites, s.Name())
		}
		a.log.Info("schild running as ingress", "profile", cfg.Profile, "caddyfile", cfg.Ingress.Caddyfile,
			"storage", ing.StorageRoot, "sites", strings.Join(sites, "; "), "dashboard", cfg.Listen.Dashboard, "metrics", cfg.Listen.Metrics,
			"version", buildinfo.String(), "caddy", caddymod.CaddyVersion())
		return nil
	}
	trusted := cfg.Ingress.TrustedProxies
	if a.proxiesTooBroad {
		trusted = nil // Caddy believes no forwarding header either (D40)
	}
	var grace time.Duration
	if cfg.Cluster.Enabled {
		grace = cfg.Cluster.Drain.Grace()
	}
	if err := caddymod.Start(caddymod.Options{Listen: cfg.Listen.Proxy, Upstream: cfg.Upstream.URL, UpstreamTimeout: time.Duration(cfg.Upstream.TimeoutMS) * time.Millisecond,
		TrustedProxies: trusted, DataDir: a.dataDir, LogLevel: os.Getenv("SCHILD_CADDY_LOG_LEVEL"), Grace: grace}); err != nil {
		return fmt.Errorf("start proxy: %w", err)
	}
	a.log.Info("schild running", "profile", cfg.Profile, "proxy", cfg.Listen.Proxy, "upstream", cfg.Upstream.URL,
		"dashboard", cfg.Listen.Dashboard, "metrics", cfg.Listen.Metrics, "version", buildinfo.String())
	return nil
}

// PrepareIngress adapts and checks the Caddyfile of schild.yaml (MVP-19).
func (a *App) PrepareIngress() (*caddymod.Ingress, error) {
	return IngressFor(a.Config(), a.dataDir)
}

// IngressFor adapts and checks the Caddyfile of cfg; the default storage
// root is <dataDir>/caddy.
func IngressFor(cfg *config.Site, dataDir string) (*caddymod.Ingress, error) {
	return caddymod.PrepareIngress(caddymod.IngressOptions{Caddyfile: cfg.Ingress.Caddyfile, Storage: cfg.Ingress.CaddyStorage, ExposeServerHeaders: cfg.Ingress.ExposeServerHeaders,
		DefaultStorage: caddymod.DefaultStorage(dataDir), Unprotected: cfg.Ingress.UnprotectedSites, TrustedProxies: cfg.Ingress.TrustedProxies,
		Cluster: cfg.Cluster.Enabled, Grace: cfg.Cluster.Drain.Grace()})
}

func listen(s *http.Server, name string) error {
	if err := s.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("%s listener %s: %w", name, s.Addr, err)
	}
	return nil
}

// ---------------------------------------------------------------- settings

func deepMerge(dst, src map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range dst {
		out[k] = v
	}
	for k, v := range src {
		if sm, ok := v.(map[string]any); ok {
			if dm, ok := out[k].(map[string]any); ok {
				out[k] = deepMerge(dm, sm)
				continue
			}
		}
		out[k] = v
	}
	return out
}

func (a *App) merged(ov map[string]any) (*config.Site, error) {
	return a.mergedWith(ov, a.dashLimits)
}

// mergedWith merges the overlay and appends the dashboard rate limits to
// behaviour.rate_limits, then validates everything like schild.yaml.
func (a *App) mergedWith(ov map[string]any, dash []config.RateLimit) (*config.Site, error) {
	return mergeConfig(a.base, ov, dash)
}

func cloneMap(m map[string]any) map[string]any {
	b, _ := json.Marshal(m)
	var out map[string]any
	_ = json.Unmarshal(b, &out)
	if out == nil {
		out = map[string]any{}
	}
	return out
}

func sub(m map[string]any, k string) map[string]any {
	if v, ok := m[k].(map[string]any); ok {
		return v
	}
	v := map[string]any{}
	m[k] = v
	return v
}

// Apply validates and applies a settings patch from the dashboard.
func (a *App) Apply(ctx context.Context, p dashboard.SettingsPatch) (*config.Site, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	ov := cloneMap(a.overlay)
	if r := p.Retention; r != nil {
		m := sub(ov, "retention")
		if r.RawIPDays != nil {
			m["raw_ip_days"] = *r.RawIPDays
		}
		if r.EventsDays != nil {
			m["events_days"] = *r.EventsDays
		}
		if r.SummariesDays != nil {
			m["summaries_days"] = *r.SummariesDays
		}
	}
	next, err := a.merged(ov)
	if err != nil {
		return nil, err
	}
	b, _ := json.Marshal(ov)
	if err := a.Store.Put(ctx, overlayKey, b); err != nil {
		return nil, err
	}
	prev := a.Config()
	a.overlay = ov
	a.droppedOverlay.Store(false)
	a.cfg.Store(next)
	a.applyRuntime(ctx, prev, next)
	a.log.Info("settings changed in the dashboard")
	return next, nil
}

func (a *App) applyRuntime(ctx context.Context, prev, next *config.Site) {
	s := a.Gate.Settings()
	s.Mode = next.Mode
	a.Gate.SetSettings(s)
	a.Gate.SetWaitingPage(next.WaitingPage.On())
	a.Behaviour.SetConfig(a.behaviourConfig(next))
	a.logConfigChange(ctx, time.Now().UTC(), prev.Mode, next)
}

// evalLimits reads the WAF evaluation slots (MVP-19 measurement, finding 1):
// waf.max_concurrent_evals and waf.queue_wait_ms of schild.yaml (v0.4
// addendum, D33), overridden by the test lab's environment variables
// SCHILD_WAF_MAX_EVALS and SCHILD_WAF_QUEUE_WAIT_MS, which win. Release
// builds never read them (D77). Neither sets the expensive slots: the gate
// derives them (config.ExpensiveEvalSlots).
func evalLimits(cfg *config.Site, getenv func(string) string, release bool) (gate.EvalLimits, error) {
	var l gate.EvalLimits
	if cfg != nil {
		l.MaxConcurrent = cfg.WAF.MaxConcurrentEvals
		l.QueueWait = time.Duration(cfg.WAF.QueueWaitMS) * time.Millisecond
	}
	if release {
		return l, nil
	}
	env, err := evalLimitsFromEnv(getenv)
	if err != nil {
		return l, err
	}
	if env.MaxConcurrent > 0 {
		// At least MinEvalSlots like the key; the gate caps the expensive
		// slots at config.ExpensiveEvalSlots of this count, so the override
		// cannot take the reserved slots (D31 amendment 2026-10-29).
		l.MaxConcurrent = max(env.MaxConcurrent, config.MinEvalSlots)
	}
	if env.QueueWait > 0 {
		l.QueueWait = env.QueueWait
	}
	return l, nil
}

// evalLimitsFromEnv reads the test lab overrides SCHILD_WAF_MAX_EVALS
// (evaluations at once) and SCHILD_WAF_QUEUE_WAIT_MS (longest wait for a
// free slot before 503).
func evalLimitsFromEnv(getenv func(string) string) (gate.EvalLimits, error) {
	var l gate.EvalLimits
	if v := getenv("SCHILD_WAF_MAX_EVALS"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 1024 {
			return l, fmt.Errorf("SCHILD_WAF_MAX_EVALS: want 1..1024, got %q", v)
		}
		l.MaxConcurrent = n
	}
	if v := getenv("SCHILD_WAF_QUEUE_WAIT_MS"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 10000 {
			return l, fmt.Errorf("SCHILD_WAF_QUEUE_WAIT_MS: want 1..10000, got %q", v)
		}
		l.QueueWait = time.Duration(n) * time.Millisecond
	}
	return l, nil
}
