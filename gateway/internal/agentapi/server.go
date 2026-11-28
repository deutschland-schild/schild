// Package agentapi is the agent API of `schild run` (MVP-21,
// contracts/api/gateway-agent.openapi.yaml, DECISIONS D33): a dedicated
// loopback listener with bearer tokens only, /agent/v0, described by its own
// OpenAPI document at /agent/v0/openapi.json (D61). It reads; the only
// writes are those of contractapi.WriteOperations, each for tokens with its
// write scope: rule repositories and rules (D73), single blocks (D42), rule
// exceptions (D54) and the crawler policy (D57). Session cookies are never
// accepted here and tokens never on the dashboard listener.
package agentapi

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"github.com/deutschland-schild/schild/gateway/internal/auditlog"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	contractapi "github.com/deutschland-schild/schild/contract/agentapi"
	"github.com/deutschland-schild/schild/contract/config"
	"github.com/deutschland-schild/schild/contract/websites"
	"github.com/deutschland-schild/schild/gateway/internal/monitoring"
	"github.com/deutschland-schild/schild/gateway/internal/ratelog"
	"github.com/deutschland-schild/schild/gateway/internal/reqring"
	"github.com/deutschland-schild/schild/gateway/internal/ruleset"
	"github.com/deutschland-schild/schild/gateway/internal/sites"
	"github.com/deutschland-schild/schild/gateway/internal/store"
)

const prefix = "/agent/v0"

// Server serves the agent API.
type Server struct {
	St      *store.Store
	Monitor *monitoring.Monitor
	// Requests is the MVP-22 request ring (nil: off, 409 requests_off).
	Requests *reqring.Ring
	// Bots is the MVP-22 bot catalogue for getBotOverview (nil: none).
	Bots reqring.BotDirectory
	// Overview returns the dashboard Overview (getAgentStatus).
	Overview func(ctx context.Context) any
	Config   func() *config.Site
	// Settings returns the read-only AgentSettings.
	Settings func(ctx context.Context) Settings
	Log      *slog.Logger
	Now      func() time.Time
	// v0.5 (D36): the websites (same handlers as the client dashboard).
	Sites         *sites.Registry
	Websites      func(now time.Time) websites.List
	Website       func(ctx context.Context, id string, now time.Time) (websites.Detail, bool)
	SitesAffected func(ctx context.Context, ip, site string, t time.Time) *websites.SitesAffected
	// Repos are the rule repositories (D73), the same service as the
	// dashboard's; nil: their operations answer 404.
	Repos *ruleset.Registry
	// Blocks: the block writes (D42); nil: they answer 404.
	Blocks *BlockDeps
	// Exceptions: rule exceptions (D54); nil: they answer 404.
	Exceptions *ExceptionDeps
	// Firewall: the handoff of the blocks to the host's firewall (D87).
	Firewall *FirewallDeps
	// Hints returns the possible false positives (D54).
	Hints func(ctx context.Context, site string, from, to time.Time) (any, error)
	// Rules: the rule list and the request test (D55); nil: they answer 404.
	Rules *RuleDeps
	// Crawlers: crawler control (D57); nil: it answers 404.
	Crawlers *CrawlerDeps
	// Audit is the audit log (MVP-36); nil in tests of a part: a change
	// happens without an entry.
	Audit *auditlog.Log
	// IncidentBlock is the timed block behind an incident (nil: none).
	IncidentBlock func(ctx context.Context, in *store.Incident) *contractapi.IncidentBlock

	once   sync.Once
	mux    *http.ServeMux
	key    []byte
	limits sync.Map // token id -> *tokenLimit
	calls  chan store.AgentCall
	// refused counts 429s per token and minute; written as one row each.
	refusedMu sync.Mutex
	refused   map[refusedKey]int
	// streamCheck overrides streamRecheck (tests).
	streamCheck time.Duration
}

type refusedKey struct {
	token  string
	minute int64
}

type ctxKey struct{}

type callInfo struct {
	token *store.AgentToken
	op    string
	rows  int
}

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

func (s *Server) cfg() *config.Site { return s.Config() }

// Problem writes a problem with a stable code.
func Problem(w http.ResponseWriter, status int, code, detail string) {
	monitoring.Problem(w, status, code, detail)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

func (s *Server) init() {
	s.once.Do(func() {
		s.calls = make(chan store.AgentCall, 1024)
		k, err := s.St.PseudonymKey(context.Background())
		if err != nil {
			// Without the stored key pseudonyms still work, only not across restarts.
			k = make([]byte, 32)
			_, _ = rand.Read(k)
		}
		s.key = k
		mux := http.NewServeMux()
		h := func(pattern, op string, f http.HandlerFunc) {
			if _, write := contractapi.WriteOperations[op]; write {
				registerWrite(pattern, op)
			}
			mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
				if c, ok := r.Context().Value(ctxKey{}).(*callInfo); ok {
					c.op = op
					// A write carries the origin of its change: the code
					// that stores it notes the audit entry there.
					if _, write := contractapi.WriteOperations[op]; write && auditedWrite(op) {
						r = r.WithContext(auditlog.WithOrigin(r.Context(), origin(r, c.token, op)))
					}
				}
				f(w, r)
			})
		}
		h("GET "+prefix+"/status", "getAgentStatus", s.getStatus)
		h("GET "+prefix+"/openapi.json", contractapi.OpOpenAPI, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(contractapi.OpenAPI)
		})
		ops := map[string]string{"/monitoring/now": "getMonitoringNow", "/monitoring/stream": "streamMonitoring", "/monitoring/series": "queryMetricSeries",
			"/monitoring/traffic/breakdown": "getTrafficBreakdown", "/monitoring/server": "getServerSnapshot", "/monitoring/catalogue": "getMetricCatalogue",
			"/monitoring/buckets": "listMetricBuckets"}
		s.Monitor.Routes(func(pattern string, f http.HandlerFunc) {
			path := strings.TrimPrefix(strings.TrimPrefix(pattern, "GET "), prefix)
			h(pattern, ops[path], f)
		}, prefix)
		h("GET "+prefix+"/events", "listAgentEvents", s.listEvents)
		h("GET "+prefix+"/events/{id}", "getAgentEvent", s.getEvent)
		h("GET "+prefix+"/incidents", "listAgentIncidents", s.listIncidents)
		h("GET "+prefix+"/incidents/{incident}", "getAgentIncident", s.getIncident)
		h("GET "+prefix+"/websites", "listWebsites", s.listWebsites)
		h("GET "+prefix+"/websites/{website}", "getWebsite", s.getWebsite)
		// v0.5 (MVP-22): the request ring (409 requests_off without it).
		h("GET "+prefix+"/requests", "queryRequests", s.queryRequests)
		h("GET "+prefix+"/requests/context/{event_id}", "getRequestContext", s.getRequestContext)
		h("GET "+prefix+"/requests/bots", "getBotOverview", s.getBotOverview)
		h("GET "+prefix+"/rule-repositories", "listAgentRuleRepositories", s.listRepositories)
		h("GET "+prefix+"/rule-repositories/{repository}", "getAgentRuleRepository", s.getRepository)
		h("PATCH "+prefix+"/rule-repositories/{repository}", contractapi.OpUpdateRuleRepository, s.updateRepository)
		h("POST "+prefix+"/rule-repositories/{repository}/sync", contractapi.OpSyncRuleRepository, s.syncRepository)
		h("POST "+prefix+"/rule-repositories/{repository}/reset", contractapi.OpResetRuleRepository, s.resetRepository)
		h("GET "+prefix+"/rules/{repository}/{rule}", "getAgentRule", s.getRule)
		h("PATCH "+prefix+"/rules/{repository}/{rule}", contractapi.OpUpdateRule, s.updateRule)
		h("POST "+prefix+"/blocks", contractapi.OpCreateBlock, s.createBlock)
		h("POST "+prefix+"/incidents/{incident}/lift", contractapi.OpLiftBlock, s.liftBlock)
		h("GET "+prefix+"/exceptions", "listAgentExceptions", s.listExceptions)
		h("POST "+prefix+"/exceptions", contractapi.OpCreateException, s.createException)
		h("POST "+prefix+"/exceptions/{id}/remove", contractapi.OpRemoveException, s.removeException)
		h("GET "+prefix+"/requests/false-positives", "listAgentFalsePositiveHints", s.listHints)
		h("GET "+prefix+"/rules", "listAgentRules", s.listRules)
		h("POST "+prefix+"/rules/test", contractapi.OpTestRequest, s.testRequest)
		h("GET "+prefix+"/crawlers", "getAgentCrawlers", s.getCrawlers)
		h("POST "+prefix+"/crawlers", contractapi.OpSetCrawlers, s.setCrawlers)
		h("POST "+prefix+"/firewall/sync", contractapi.OpSyncFirewall, s.syncFirewall)
		h("GET "+prefix+"/audit", OpListAudit, s.listAudit)
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			Problem(w, http.StatusForbidden, "forbidden", "Not part of the agent API.")
		})
		s.mux = mux
	})
}

// maxWriteBody bounds the body of a rule write.
const maxWriteBody = 1 << 10

func requestsOff(w http.ResponseWriter, _ *http.Request) {
	Problem(w, http.StatusConflict, "requests_off", "The request ring (monitoring.requests) is not running on this gateway.")
}

// Handler returns the agent API handler for a listener on addr.
func (s *Server) Handler(addr string) http.Handler {
	s.init()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { s.serve(w, r, addr) })
}

// hostOK: the Host header names this listener (DNS rebinding guard).
func hostOK(host, addr string) bool {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	h, p, err := net.SplitHostPort(host)
	if err != nil || p != port {
		return false
	}
	h = strings.ToLower(strings.Trim(h, "[]"))
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request, addr string) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.Header.Get("Origin") != "" || !hostOK(r.Host, addr) {
		Problem(w, http.StatusForbidden, "forbidden", "Requests from browsers or for another host are refused.")
		return
	}
	if r.URL.Path != prefix && !strings.HasPrefix(r.URL.Path, prefix+"/") {
		Problem(w, http.StatusForbidden, "forbidden", "Not part of the agent API.")
		return
	}
	isWrite := isWriteCall(r)
	// The request test posts a sample and changes nothing (D55): it is a read.
	isTest := r.Method == http.MethodPost && r.URL.Path == prefix+"/rules/test"
	if !isWrite && !isTest && r.Method != http.MethodGet {
		Problem(w, http.StatusForbidden, "forbidden", "The agent API only reads, except the writes of rule repositories and rules, single blocks, rule exceptions and the crawler policy.")
		return
	}
	tok, ok := s.authenticate(r)
	if !ok {
		s.refusedCall(r, nil, "")
		w.Header().Set("WWW-Authenticate", `Bearer realm="schild-agent"`)
		Problem(w, http.StatusUnauthorized, "unauthenticated", "Missing, unknown, expired or revoked token.")
		return
	}
	// A write answers scope_required itself, so a refusal is in the call log.
	if !isWrite && !contractapi.CanRead(tok.Scope) && !(tok.Scope == contractapi.ScopeExportRead && r.URL.Path == prefix+"/monitoring/buckets") {
		s.refusedCall(r, tok, "")
		Problem(w, http.StatusForbidden, "forbidden", "This token's scope does not allow this operation.")
		return
	}
	writeOp := ""
	if isWrite {
		writeOp = opOfWrite(r)
	}
	release, retry := s.admit(tok)
	if release == nil {
		s.refusedCall(r, tok, writeOp)
		w.Header().Set("Retry-After", strconv.Itoa(retry))
		Problem(w, http.StatusTooManyRequests, "rate_limited", "Too many requests for this token.")
		s.countRefused(tok.ID)
		return
	}
	defer release()
	// What one token may write into the audit log in an hour
	// (audit.TokenEntriesPerHour; blocks have their own bound).
	if isWrite && auditedWrite(writeOp) {
		if ok, retry := s.Audit.BudgetLeft(tok.ID); !ok {
			s.refusedCall(r, tok, writeOp)
			w.Header().Set("Retry-After", strconv.Itoa(retry))
			Problem(w, http.StatusTooManyRequests, "change_budget", "This token wrote as many changes into the audit log as one token may in an hour.")
			s.logCall(store.AgentCall{TokenID: tok.ID, Time: s.now(), Op: writeOp, Status: http.StatusTooManyRequests})
			return
		}
	}
	ci := &callInfo{token: tok}
	r = r.WithContext(context.WithValue(r.Context(), ctxKey{}, ci))
	if strings.HasSuffix(r.URL.Path, "/monitoring/stream") {
		// The token's expiry ends the stream (s.now may be a test clock).
		ctx, cancel := context.WithTimeout(r.Context(), tok.Expires.Sub(s.now()))
		defer cancel()
		r = r.WithContext(ctx)
		go s.endWhenRevoked(ctx, cancel, r)
		cw := &countWriter{ResponseWriter: w, status: 200}
		s.mux.ServeHTTP(cw, r)
		s.logCall(store.AgentCall{TokenID: tok.ID, Time: s.now(), Op: ci.op, Status: cw.status, Bytes: cw.n})
		return
	}
	// Everything else is buffered so the 1 MiB cap holds.
	bw := &bufWriter{h: http.Header{}, status: 200}
	s.mux.ServeHTTP(bw, r)
	// A write the handler refused for the scope of its token.
	if isWrite && bw.status == http.StatusForbidden {
		s.refusedCall(r, tok, ci.op)
	}
	if bw.buf.Len() > contractapi.MaxBytes {
		bw = &bufWriter{h: http.Header{}}
		Problem(bw, http.StatusInternalServerError, "internal", "The answer would exceed 1 MiB; narrow the request.")
	}
	for k, v := range bw.h {
		w.Header()[k] = v
	}
	w.WriteHeader(bw.status)
	_, _ = w.Write(bw.buf.Bytes())
	s.logCall(store.AgentCall{TokenID: tok.ID, Time: s.now(), Op: ci.op, Status: bw.status, Rows: ci.rows, Bytes: int64(bw.buf.Len())})
}

// streamRecheck is how often an open stream checks its token again.
const streamRecheck = 15 * time.Second

// endWhenRevoked cancels an open stream once its token no longer
// authenticates. The token was checked when the stream began; revocation
// with `schild token revoke` only writes the store, so the stream reads it
// again every streamRecheck (the expiry ends it through its deadline).
func (s *Server) endWhenRevoked(ctx context.Context, cancel context.CancelFunc, r *http.Request) {
	every := s.streamCheck
	if every <= 0 {
		every = streamRecheck
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if _, ok := s.authenticate(r); !ok {
				cancel()
				return
			}
		}
	}
}

// isWriteCall reports whether r is one of the writes of this API.
func isWriteCall(r *http.Request) bool {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, prefix+"/"), "/")
	for _, p := range parts {
		if p == "" {
			return false
		}
	}
	switch r.Method {
	case http.MethodPatch:
		// /rule-repositories/{repository}, /rules/{repository}/{rule}
		return len(parts) == 2 && parts[0] == "rule-repositories" || len(parts) == 3 && parts[0] == "rules"
	case http.MethodPost:
		switch {
		case len(parts) == 1:
			return parts[0] == "blocks" || parts[0] == "exceptions" || parts[0] == "crawlers"
		case len(parts) == 2 && parts[0] == "firewall":
			return parts[1] == "sync"
		case len(parts) == 3 && parts[0] == "exceptions":
			return parts[2] == "remove"
		case len(parts) == 3 && parts[0] == "incidents":
			return parts[2] == "lift"
		case len(parts) == 3 && parts[0] == "rule-repositories":
			return parts[2] == "sync" || parts[2] == "reset"
		}
	}
	return false
}

func (s *Server) authenticate(r *http.Request) (*store.AgentToken, bool) {
	a := r.Header.Get("Authorization")
	tok, ok := strings.CutPrefix(a, "Bearer ")
	if !ok || !contractapi.ValidToken(tok) {
		return nil, false
	}
	h := contractapi.HashToken(tok)
	t, err := s.St.AgentTokenByHash(r.Context(), h)
	if err != nil || subtle.ConstantTimeCompare([]byte(t.Hash), []byte(h)) != 1 || !t.Active(s.now()) {
		return nil, false
	}
	return t, true
}

// ---------------------------------------------------------------- limits

type tokenLimit struct {
	mu       sync.Mutex
	window   []time.Time
	inFlight int
}

// admit applies requests_per_minute and max_concurrent of the token; nil
// release means refused (retry after seconds).
func (s *Server) admit(t *store.AgentToken) (release func(), retry int) {
	c := s.cfg().AgentAPI
	v, _ := s.limits.LoadOrStore(t.ID, &tokenLimit{})
	l := v.(*tokenLimit)
	now := s.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	cut := 0
	for cut < len(l.window) && now.Sub(l.window[cut]) >= time.Minute {
		cut++
	}
	l.window = l.window[cut:]
	if len(l.window) >= c.RequestsPerMinute {
		wait := time.Minute - now.Sub(l.window[0])
		return nil, max(1, int(wait.Seconds()+0.999))
	}
	if l.inFlight >= c.MaxConcurrent {
		return nil, 1
	}
	l.window = append(l.window, now)
	l.inFlight++
	return func() {
		l.mu.Lock()
		l.inFlight--
		l.mu.Unlock()
	}, 0
}

// ---------------------------------------------------------------- call log

// countRefused aggregates a refused call (429) of a token: at most one
// call log row per token and minute, however many calls were refused.
func (s *Server) countRefused(tokenID string) {
	m := s.now().Unix() / 60
	s.refusedMu.Lock()
	if s.refused == nil {
		s.refused = map[refusedKey]int{}
	}
	s.refused[refusedKey{tokenID, m}]++
	s.refusedMu.Unlock()
}

// takeRefused returns the aggregated refusals of finished minutes (all with
// all set) as call log rows.
func (s *Server) takeRefused(all bool) []store.AgentCall {
	cur := s.now().Unix() / 60
	s.refusedMu.Lock()
	defer s.refusedMu.Unlock()
	var out []store.AgentCall
	for k, n := range s.refused {
		if !all && k.minute >= cur {
			continue
		}
		out = append(out, store.AgentCall{TokenID: k.token, Time: time.Unix(k.minute*60, 0).UTC(), Op: "rate_limited", Status: http.StatusTooManyRequests, Count: n})
		delete(s.refused, k)
	}
	return out
}

func (s *Server) logCall(c store.AgentCall) {
	if c.Op == "" {
		c.Op = "unknown"
	}
	select {
	case s.calls <- c:
	default: // the log never blocks a call
	}
}

// Run writes the call log and prunes it (agent_api.log_days).
func (s *Server) Run(ctx context.Context) {
	s.init()
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	prune := time.NewTicker(time.Hour)
	defer prune.Stop()
	var batch []store.AgentCall
	flush := func() {
		batch = append(batch, s.takeRefused(ctx.Err() != nil)...)
		if len(batch) == 0 {
			return
		}
		if err := s.St.LogAgentCalls(context.Background(), batch); err != nil && s.Log != nil {
			ratelog.Warn(s.Log, "agent API call log", "err", err)
		}
		batch = batch[:0]
	}
	_ = s.St.PruneAgentCalls(ctx, s.now().Add(-time.Duration(s.cfg().AgentAPI.LogDays)*24*time.Hour))
	for {
		select {
		case <-ctx.Done():
			for {
				select {
				case c := <-s.calls:
					batch = append(batch, c)
				default:
					flush()
					return
				}
			}
		case c := <-s.calls:
			batch = append(batch, c)
			if len(batch) >= 100 {
				flush()
			}
		case <-t.C:
			flush()
		case <-prune.C:
			_ = s.St.PruneAgentCalls(ctx, s.now().Add(-time.Duration(s.cfg().AgentAPI.LogDays)*24*time.Hour))
		}
	}
}

// Flush writes queued call log entries (tests).
func (s *Server) Flush(ctx context.Context) {
	s.init()
	var batch []store.AgentCall
	for {
		select {
		case c := <-s.calls:
			batch = append(batch, c)
		default:
			batch = append(batch, s.takeRefused(true)...)
			if len(batch) > 0 {
				_ = s.St.LogAgentCalls(ctx, batch)
			}
			return
		}
	}
}

// ---------------------------------------------------------------- writers

type bufWriter struct {
	h      http.Header
	status int
	wrote  bool
	buf    bytes.Buffer
}

func (b *bufWriter) Header() http.Header { return b.h }
func (b *bufWriter) WriteHeader(code int) {
	if !b.wrote {
		b.status, b.wrote = code, true
	}
}
func (b *bufWriter) Write(p []byte) (int, error) {
	if !b.wrote {
		b.WriteHeader(200)
	}
	if b.buf.Len() > contractapi.MaxBytes+1 {
		return 0, errors.New("response too large")
	}
	return b.buf.Write(p)
}

type countWriter struct {
	http.ResponseWriter
	status int
	n      int64
}

func (c *countWriter) WriteHeader(code int) { c.status = code; c.ResponseWriter.WriteHeader(code) }
func (c *countWriter) Write(p []byte) (int, error) {
	n, err := c.ResponseWriter.Write(p)
	c.n += int64(n)
	return n, err
}
func (c *countWriter) Unwrap() http.ResponseWriter { return c.ResponseWriter }

// ---------------------------------------------------------------- status

// Settings are the read-only AgentSettings.
type Settings struct {
	Profile          string            `json:"profile"`
	ConfigSHA256     string            `json:"config_sha256"`
	Retention        RetentionSettings `json:"retention"`
	WAF              WAFSettings       `json:"waf"`
	Behaviour        BehaviourSettings `json:"behaviour"`
	Monitoring       MonitorSettings   `json:"monitoring"`
	AllowlistEntries int               `json:"allowlist_entries"`
}

// RetentionSettings of AgentSettings.
type RetentionSettings struct {
	RawIPDays     int `json:"raw_ip_days"`
	EventsDays    int `json:"events_days"`
	MaxSizeMB     int `json:"max_size_mb"`
	SummariesDays int `json:"summaries_days"`
}

// WAFSettings of AgentSettings (effective evaluation limits).
type WAFSettings struct {
	CRSEnabled              bool `json:"crs_enabled"`
	ParanoiaLevel           int  `json:"paranoia_level"`
	InboundAnomalyThreshold int  `json:"inbound_anomaly_threshold"`
	EvalTimeoutMS           int  `json:"eval_timeout_ms"`
	MaxConcurrentEvals      int  `json:"max_concurrent_evals"`
	QueueWaitMS             int  `json:"queue_wait_ms"`
}

// BehaviourSettings of AgentSettings.
type BehaviourSettings struct {
	Scenarios            map[string]string `json:"scenarios"`
	ScenariosRecommended map[string]string `json:"scenarios_recommended"`
	RateLimits           int               `json:"rate_limits"`
	LearningUntil        *string           `json:"learning_until,omitempty"`
}

// MonitorSettings of AgentSettings.
type MonitorSettings struct {
	Enabled bool                  `json:"enabled"`
	Host    bool                  `json:"host"`
	Keep    config.MonitoringKeep `json:"keep"`
}

type status struct {
	NodeName string                `json:"node_name"`
	Overview any                   `json:"overview"`
	Settings Settings              `json:"settings"`
	Token    contractapi.TokenInfo `json:"token"`
}

func (s *Server) getStatus(w http.ResponseWriter, r *http.Request) {
	ci := r.Context().Value(ctxKey{}).(*callInfo)
	t := ci.token
	writeJSON(w, status{NodeName: s.cfg().NodeName, Overview: s.Overview(r.Context()), Settings: s.Settings(r.Context()),
		Token: contractapi.TokenInfo{ID: t.ID, Scope: t.Scope, Label: t.Label, ExpiresAt: ts(t.Expires)}})
}

func ts(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05Z") }

// siteParam reads the site filter (v0.5, D36): a website id of this
// gateway; anything else is 400 invalid.
func (s *Server) siteParam(w http.ResponseWriter, r *http.Request) (string, bool) {
	v := r.URL.Query().Get("site")
	if v == "" {
		return "", true
	}
	if s.Sites == nil || len(v) > 253 {
		invalid(w, "site", "unknown site")
		return "", false
	}
	if _, ok := s.Sites.View().Website(v); !ok {
		invalid(w, "site", "unknown site")
		return "", false
	}
	return v, true
}

func (s *Server) listWebsites(w http.ResponseWriter, r *http.Request) {
	if s.Websites == nil {
		Problem(w, http.StatusNotFound, "not_found", "No websites.")
		return
	}
	l := s.Websites(s.now())
	if c, ok := r.Context().Value(ctxKey{}).(*callInfo); ok {
		c.rows = len(l.Websites)
	}
	writeJSON(w, l)
}

func (s *Server) getWebsite(w http.ResponseWriter, r *http.Request) {
	if s.Website == nil {
		Problem(w, http.StatusNotFound, "not_found", "No such website.")
		return
	}
	d, ok := s.Website(r.Context(), r.PathValue("website"), s.now())
	if !ok {
		Problem(w, http.StatusNotFound, "not_found", "No such website.")
		return
	}
	writeJSON(w, d)
}
