package dashboard

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/deutschland-schild/schild/contract/keys"
	"github.com/deutschland-schild/schild/contract/msg"
	"github.com/deutschland-schild/schild/lab/internal/latency"
	"github.com/deutschland-schild/schild/lab/internal/publog"
	"github.com/deutschland-schild/schild/lab/internal/queue"
	"github.com/deutschland-schild/schild/lab/internal/rules"
	"github.com/deutschland-schild/schild/lab/internal/scoring"
	"github.com/deutschland-schild/schild/lab/internal/settings"
)

func withSession(r *http.Request, s *session) context.Context {
	return context.WithValue(r.Context(), ctxKey{}, s)
}

func sessionOf(r *http.Request) *session {
	s, _ := r.Context().Value(ctxKey{}).(*session)
	return s
}

func userOf(r *http.Request) string {
	if s := sessionOf(r); s != nil {
		return s.user
	}
	return ""
}

// --- auth -------------------------------------------------------------------------

func (s *Server) getSession(w http.ResponseWriter, r *http.Request) {
	sess := sessionOf(r)
	if sess == nil && isLocal(r) {
		// Localhost may read and draft without a password; decisions still
		// need a named login (guard: named()).
		sess = s.Auth.create(localhostUser, "localhost")
		s.Auth.setCookie(w, r, sess)
	}
	writeJSON(w, http.StatusOK, s.Auth.view(sess))
}

func (s *Server) setup(w http.ResponseWriter, r *http.Request) {
	var in struct {
		SetupCode string `json:"setup_code"`
		Password  string `json:"password"`
	}
	if !decode(w, r, &in) {
		return
	}
	if s.Auth.HasUsers() {
		problem(w, http.StatusConflict, "conflict", "the admin password is already set", nil)
		return
	}
	// Required from everywhere (D40): on a host with local services or a
	// local proxy, loopback proves nothing about who is asking.
	if in.SetupCode == "" || subtle.ConstantTimeCompare([]byte(in.SetupCode), []byte(s.Auth.SetupCode)) != 1 {
		problem(w, http.StatusForbidden, "forbidden", "setup needs the one-time code from the lab log", []fieldError{{Pointer: "/setup_code", Detail: "wrong or missing code"}})
		return
	}
	if err := s.Auth.SetPassword("admin", in.Password); err != nil {
		problem(w, http.StatusBadRequest, "invalid", err.Error(), []fieldError{{Pointer: "/password", Detail: err.Error()}})
		return
	}
	sess := s.Auth.create("admin", "password")
	s.Auth.setCookie(w, r, sess)
	s.d.Log.Info("audit: dashboard admin password set")
	writeJSON(w, http.StatusOK, s.Auth.view(sess))
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var in struct {
		User     string `json:"user"`
		Password string `json:"password"`
	}
	if !decode(w, r, &in) {
		return
	}
	if in.User == "" {
		in.User = "admin"
	}
	ok, limited := s.Auth.Check(in.User, in.Password)
	if limited {
		w.Header().Set("Retry-After", "900")
		problem(w, http.StatusTooManyRequests, "rate_limited", "too many failed logins; try again in 15 minutes", nil)
		return
	}
	if !ok {
		problem(w, http.StatusUnauthorized, "unauthenticated", "user name or password wrong", []fieldError{{Pointer: "/password", Detail: "wrong"}})
		return
	}
	if old := sessionOf(r); old != nil {
		s.Auth.drop(old)
	}
	sess := s.Auth.create(in.User, "password")
	s.Auth.setCookie(w, r, sess)
	s.d.Log.Info("audit: dashboard login", "user", in.User)
	writeJSON(w, http.StatusOK, s.Auth.view(sess))
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if sess := sessionOf(r); sess != nil {
		s.Auth.drop(sess)
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	w.WriteHeader(http.StatusNoContent)
}

// confirm checks the session user's password for a decision.
func (s *Server) confirm(w http.ResponseWriter, r *http.Request, pw, pointer string) bool {
	ok, limited := s.Auth.Check(userOf(r), pw)
	if limited {
		problem(w, http.StatusTooManyRequests, "rate_limited", "too many wrong passwords; try again in 15 minutes", nil)
		return false
	}
	if !ok {
		problem(w, http.StatusForbidden, "forbidden", "password wrong", []fieldError{{Pointer: pointer, Detail: "wrong password"}})
		return false
	}
	return true
}

type confirmInput struct {
	Password string `json:"password"`
	Note     string `json:"note"`
}

// --- health -------------------------------------------------------------------------

type worker struct {
	Name          string  `json:"name"`
	Status        string  `json:"status"`
	ProcessedPerS float64 `json:"processed_per_s"`
	LagS          float64 `json:"lag_s"`
	LastError     *string `json:"last_error"`
}

func (s *Server) healthView() map[string]any {
	d := s.d
	now := d.Now().UTC()
	cfg := d.Settings.Config()
	ack := d.Ingest.Window.Summary()
	depth := d.Queue.Depth()
	st := d.Scorer.Status()
	sw := worker{Name: "scoring", Status: "idle", ProcessedPerS: round2(st.ProcessedPerS), LagS: round2(st.LagS)}
	switch {
	case st.LastError != "":
		sw.Status, sw.LastError = "failed", &st.LastError
	case depth[0]+depth[1]+depth[2] > 0 && st.LagS > 60:
		sw.Status = "lagging"
	case st.Busy || depth[0]+depth[1]+depth[2] > 0:
		sw.Status = "running"
	}
	cpEnv, cpSeq, cpAt := d.Feed.Checkpoint()
	pub := worker{Name: "publisher", Status: "running"}
	if cpEnv == nil || now.Sub(cpAt) > 3*time.Duration(cfg.Publish.CheckpointIntervalS)*time.Second {
		pub.Status = "lagging"
	}
	cs := d.Engine.CurrentState()
	var lastCP *string
	if !cpAt.IsZero() {
		lastCP = fmtTimePtr(&cpAt)
	}
	return map[string]any{
		"lab": cfg.Identity.Lab, "operator": cfg.Identity.Operator, "profile": cfg.Profile, "generated_at": msg.FormatTime(now),
		"ingest": map[string]any{
			"rate_per_s":           round2(d.Ingest.Rate.PerSecond()),
			"accepted_24h":         d.Ingest.Stats24h("accepted"),
			"duplicate_24h":        d.Ingest.Stats24h("duplicate"),
			"rejected_24h":         d.Ingest.Stats24h("rejected"),
			"rejected_by_reason":   d.Ingest.RejectedByReason(),
			"retry_after_sent_24h": d.Ingest.Stats24h("retry_after"),
		},
		"ack_ms": map[string]any{"p50": round2(ack.P50), "p99": round2(ack.P99), "max": round2(ack.Max), "window_s": latency.WindowSeconds()},
		"queue": map[string]any{
			"depth":        map[string]any{queue.NewPattern.String(): depth[0], queue.Repeat.String(): depth[1], queue.Baseline.String(): depth[2]},
			"max_depth":    d.Queue.MaxDepth(),
			"full":         d.Queue.Full(),
			"oldest_age_s": round2(d.Queue.Oldest(now).Seconds()),
		},
		"workers": []worker{sw, pub},
		"feed": map[string]any{
			"subscribers": d.Feed.Hub.Clients(), "checkpoint_seq": cpSeq, "last_checkpoint_at": lastCP,
			"bundle_version": cs.BundleVersion, "withdrawal_seq": cs.WithdrawalSeq,
		},
	}
}

func round2(f float64) float64 {
	v, _ := strconv.ParseFloat(strconv.FormatFloat(f, 'f', 2, 64), 64)
	return v
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.healthView())
}

// --- patterns and signals ---------------------------------------------------------

func (s *Server) listPatterns(w http.ResponseWriter, r *http.Request) {
	off, lim, ok := page(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	from, ok1 := queryTime(w, r, "from")
	if !ok1 {
		return
	}
	to, ok2 := queryTime(w, r, "to")
	if !ok2 {
		return
	}
	f := scoring.PatternFilter{From: from, To: to, Q: q.Get("q"), Category: q.Get("category"), Country: q.Get("country"), Status: q.Get("status"), Sort: q.Get("sort")}
	if f.Sort != "" && !slices.Contains([]string{"last_seen", "signals", "issuers", "first_seen"}, f.Sort) {
		problem(w, http.StatusBadRequest, "invalid", "unknown sort", []fieldError{{Pointer: "#/query/sort", Detail: "last_seen, signals, issuers or first_seen"}})
		return
	}
	if v := q.Get("asn"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			problem(w, http.StatusBadRequest, "invalid", "asn must be a number", []fieldError{{Pointer: "#/query/asn", Detail: "integer"}})
			return
		}
		f.ASN = &n
	}
	if v := q.Get("min_issuers"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			problem(w, http.StatusBadRequest, "invalid", "min_issuers must be >= 0", []fieldError{{Pointer: "#/query/min_issuers", Detail: "integer >= 0"}})
			return
		}
		f.MinIssuers = n
	}
	var items []scoring.PatternSummary
	next := -1
	_ = s.d.DB.View(func(tx *bolt.Tx) error {
		items, next = scoring.ListPatterns(tx, f, s.d.Now().UTC(), s.d.Scorer.Config(), off, lim)
		return nil
	})
	if items == nil {
		items = []scoring.PatternSummary{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": nextCursor(next)})
}

func (s *Server) getPattern(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("pattern_id")
	var d *scoring.PatternDetail
	found := false
	_ = s.d.DB.View(func(tx *bolt.Tx) error {
		d, found = scoring.Detail(tx, id, s.d.Now().UTC(), s.d.Scorer.Config(), time.Time{}, time.Time{})
		return nil
	})
	if !found {
		problem(w, http.StatusNotFound, "not_found", "pattern not found", nil)
		return
	}
	writeJSON(w, http.StatusOK, d)
}

func (s *Server) listSignals(w http.ResponseWriter, r *http.Request) {
	lim := 50
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 500 {
			problem(w, http.StatusBadRequest, "invalid", "limit must be 1..500", []fieldError{{Pointer: "#/query/limit", Detail: "1..500"}})
			return
		}
		lim = n
	}
	from, ok1 := queryTime(w, r, "from")
	if !ok1 {
		return
	}
	to, ok2 := queryTime(w, r, "to")
	if !ok2 {
		return
	}
	f := scoring.SignalFilter{From: from, To: to, PatternID: r.URL.Query().Get("pattern_id"), Issuer: r.URL.Query().Get("issuer")}
	var items []scoring.ReceivedSignal
	var next string
	_ = s.d.DB.View(func(tx *bolt.Tx) error {
		items, next = scoring.ListSignals(tx, f, r.URL.Query().Get("cursor"), lim)
		return nil
	})
	var nc *string
	if next != "" {
		nc = &next
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": nc})
}

// --- proposals --------------------------------------------------------------------

func (s *Server) listProposals(w http.ResponseWriter, r *http.Request) {
	off, lim, ok := page(w, r)
	if !ok {
		return
	}
	items, next, err := s.d.Engine.ListProposals(r.URL.Query().Get("status"), off, lim)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": nextCursor(next)})
}

func (s *Server) createProposal(w http.ResponseWriter, r *http.Request) {
	var in rules.ProposalInput
	if !decode(w, r, &in) {
		return
	}
	v, err := s.d.Engine.CreateProposal(in, userOf(r))
	if err != nil {
		s.fail(w, err)
		return
	}
	s.d.Log.Info("audit: proposal created", "by", userOf(r), "proposal", v.ID)
	writeJSON(w, http.StatusCreated, v)
}

func (s *Server) getProposal(w http.ResponseWriter, r *http.Request) {
	v, err := s.d.Engine.GetProposal(r.PathValue("id"))
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) updateProposal(w http.ResponseWriter, r *http.Request) {
	var in rules.ProposalInput
	if !decode(w, r, &in) {
		return
	}
	v, err := s.d.Engine.UpdateProposal(r.PathValue("id"), in)
	if err != nil {
		s.fail(w, err)
		return
	}
	s.d.Log.Info("audit: proposal edited", "by", userOf(r), "proposal", v.ID)
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) addEvidence(w http.ResponseWriter, r *http.Request) {
	var in rules.EvidenceInput
	if !decode(w, r, &in) {
		return
	}
	v, err := s.d.Engine.AddEvidence(r.PathValue("id"), in)
	if err != nil {
		s.fail(w, err)
		return
	}
	s.d.Log.Info("audit: evidence added", "by", userOf(r), "proposal", v.ID, "kind", in.Kind)
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) approve(w http.ResponseWriter, r *http.Request) {
	var in rules.ApproveInput
	if !decode(w, r, &in) {
		return
	}
	v, err := s.d.Engine.Approve(r.PathValue("id"), in, userOf(r))
	if err != nil {
		s.fail(w, err)
		return
	}
	s.d.Log.Info("audit: proposal approved", "by", userOf(r), "org", in.Org, "proposal", v.ID, "max_action", in.MaxAction)
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) reject(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Reason string `json:"reason"`
	}
	if !decode(w, r, &in) {
		return
	}
	v, err := s.d.Engine.Reject(r.PathValue("id"), in.Reason, userOf(r))
	if err != nil {
		s.fail(w, err)
		return
	}
	s.d.Log.Info("audit: proposal rejected", "by", userOf(r), "proposal", v.ID)
	writeJSON(w, http.StatusOK, v)
}

// --- bundles and withdrawals --------------------------------------------------------

func (s *Server) listBundles(w http.ResponseWriter, r *http.Request) {
	off, lim, ok := page(w, r)
	if !ok {
		return
	}
	items, next, err := s.d.Engine.ListBundles(off, lim)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": nextCursor(next)})
}

func (s *Server) assembleBundle(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Add           []string `json:"add"`
		Remove        []string `json:"remove"`
		ValidityHours int      `json:"validity_hours"`
	}
	if !decode(w, r, &in) {
		return
	}
	if in.Add == nil || in.Remove == nil {
		problem(w, http.StatusBadRequest, "invalid", "add and remove are required (may be empty)", nil)
		return
	}
	if in.ValidityHours != 0 && (in.ValidityHours < 1 || in.ValidityHours > 744) {
		problem(w, http.StatusBadRequest, "invalid", "validity_hours must be 1..744", []fieldError{{Pointer: "/validity_hours", Detail: "1..744"}})
		return
	}
	v, err := s.d.Engine.Assemble(in.Add, in.Remove, in.ValidityHours, userOf(r))
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, v)
}

func pathUint(w http.ResponseWriter, r *http.Request, name string) (uint64, bool) {
	v, err := strconv.ParseUint(r.PathValue(name), 10, 64)
	if err != nil || v == 0 {
		problem(w, http.StatusNotFound, "not_found", name+" not found", nil)
		return 0, false
	}
	return v, true
}

func (s *Server) getBundle(w http.ResponseWriter, r *http.Request) {
	v, ok := pathUint(w, r, "version")
	if !ok {
		return
	}
	b, err := s.d.Engine.GetBundle(v)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, b)
}

// cosignBundle is an extension of the API (POST /bundles/{version}/cosign,
// body Confirm): co-sign a bundle another lab offered.
func (s *Server) cosignBundle(w http.ResponseWriter, r *http.Request) {
	v, ok := pathUint(w, r, "version")
	if !ok {
		return
	}
	var in confirmInput
	if !decode(w, r, &in) || !s.confirm(w, r, in.Password, "/password") {
		return
	}
	b, err := s.d.Engine.CosignBundle(v, userOf(r))
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, b)
}

func (s *Server) listWithdrawals(w http.ResponseWriter, r *http.Request) {
	off, lim, ok := page(w, r)
	if !ok {
		return
	}
	items, next, err := s.d.Engine.ListWithdrawals(off, lim)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": nextCursor(next)})
}

func (s *Server) createWithdrawal(w http.ResponseWriter, r *http.Request) {
	var in struct {
		RuleIDs []string     `json:"rule_ids"`
		Reason  string       `json:"reason"`
		Note    string       `json:"note"`
		Confirm confirmInput `json:"confirm"`
	}
	if !decode(w, r, &in) {
		return
	}
	if len(in.RuleIDs) == 0 {
		problem(w, http.StatusBadRequest, "invalid", "name at least one rule", []fieldError{{Pointer: "/rule_ids", Detail: "at least one rule id"}})
		return
	}
	if !slices.Contains([]string{"false_positives", "superseded", "compromised_key", "other"}, in.Reason) {
		problem(w, http.StatusBadRequest, "invalid", "unknown reason", []fieldError{{Pointer: "/reason", Detail: "false_positives, superseded, compromised_key or other"}})
		return
	}
	if !s.confirm(w, r, in.Confirm.Password, "/confirm/password") {
		return
	}
	v, err := s.d.Engine.CreateWithdrawal("rules", in.RuleIDs, in.Reason, in.Note, userOf(r))
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, v)
}

func (s *Server) emergencyStop(w http.ResponseWriter, r *http.Request) {
	var in struct {
		ConfirmText string `json:"confirm_text"`
		Password    string `json:"password"`
		Reason      string `json:"reason"`
		Note        string `json:"note"`
	}
	if !decode(w, r, &in) {
		return
	}
	if in.ConfirmText != "NOT-AUS" {
		problem(w, http.StatusBadRequest, "invalid", "type NOT-AUS to confirm", []fieldError{{Pointer: "/confirm_text", Detail: "must be NOT-AUS"}})
		return
	}
	if in.Reason != "emergency_stop" && in.Reason != "compromised_key" {
		problem(w, http.StatusBadRequest, "invalid", "unknown reason", []fieldError{{Pointer: "/reason", Detail: "emergency_stop or compromised_key"}})
		return
	}
	if !s.confirm(w, r, in.Password, "/password") {
		return
	}
	v, err := s.d.Engine.CreateWithdrawal("all", nil, in.Reason, in.Note, userOf(r))
	if err != nil {
		s.fail(w, err)
		return
	}
	s.d.Log.Warn("audit: emergency stop signed", "by", userOf(r), "seq", v.Seq, "signatures", len(v.Signatures), "threshold", v.Threshold)
	writeJSON(w, http.StatusCreated, v)
}

func (s *Server) cosignWithdrawal(w http.ResponseWriter, r *http.Request) {
	seq, ok := pathUint(w, r, "seq")
	if !ok {
		return
	}
	var in confirmInput
	if !decode(w, r, &in) || !s.confirm(w, r, in.Password, "/password") {
		return
	}
	v, err := s.d.Engine.CosignWithdrawal(seq, userOf(r))
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

// --- network ----------------------------------------------------------------------

func (s *Server) listRelays(w http.ResponseWriter, r *http.Request) {
	var items []map[string]any
	for _, rl := range s.d.Feed.Relays() {
		item := map[string]any{"id": rl.ID, "kind": rl.Kind, "status": rl.Status, "connected_since": fmtTimePtr(rl.ConnectedSince),
			"bundle_version": rl.BundleVersion, "withdrawal_seq": rl.WithdrawalSeq}
		if rl.LastEventID != "" {
			item["last_event_id"] = rl.LastEventID
		}
		items = append(items, item)
	}
	if items == nil {
		items = []map[string]any{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) listPeers(w http.ResponseWriter, r *http.Request) {
	var items []map[string]any
	for _, p := range s.d.Peers.List() {
		items = append(items, map[string]any{"lab": p.Lab, "operator": p.Operator, "endpoint": p.Endpoint, "accept_from": p.AcceptFrom,
			"share_with": p.ShareWith, "trust_weight": p.TrustWeight, "observe_only": p.ObserveOnly, "status": p.Status,
			"last_seen": fmtTimePtr(p.LastSeen), "independent": p.Independent})
	}
	if items == nil {
		items = []map[string]any{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

// --- public log -------------------------------------------------------------------

func logView(e *publog.Entry) map[string]any {
	var env any
	if len(e.Envelope) > 0 {
		env = json.RawMessage(e.Envelope)
	}
	return map[string]any{"index": e.Index, "time": e.Time, "kind": e.Kind, "ref": e.Ref, "digest": e.Digest, "summary": e.Summary,
		"envelope_sha256": e.EnvelopeSHA256, "envelope": env}
}

func (s *Server) listLog(w http.ResponseWriter, r *http.Request) {
	before, lim, ok := page(w, r)
	if !ok {
		return
	}
	kind := r.URL.Query().Get("kind")
	if kind != "" && !slices.Contains([]string{"proposal", "bundle", "withdrawal", "checkpoint"}, kind) {
		problem(w, http.StatusBadRequest, "invalid", "unknown kind", []fieldError{{Pointer: "#/query/kind", Detail: "proposal, bundle, withdrawal or checkpoint"}})
		return
	}
	var head publog.Head
	var entries []*publog.Entry
	_ = s.d.DB.View(func(tx *bolt.Tx) error {
		head = publog.HeadTx(tx)
		entries = publog.List(tx, kind, uint64(before), lim+1)
		return nil
	})
	next := -1
	if len(entries) > lim {
		entries = entries[:lim]
		next = int(entries[lim-1].Index)
	}
	items := make([]map[string]any, 0, len(entries))
	for _, e := range entries {
		items = append(items, logView(e))
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": nextCursor(next), "head": head})
}

func (s *Server) getLogEntry(w http.ResponseWriter, r *http.Request) {
	i, err := strconv.ParseUint(r.PathValue("index"), 10, 64)
	if err != nil {
		problem(w, http.StatusNotFound, "not_found", "log entry not found", nil)
		return
	}
	var e *publog.Entry
	found := false
	_ = s.d.DB.View(func(tx *bolt.Tx) error {
		e, found, _ = publog.Get(tx, i)
		return nil
	})
	if !found {
		problem(w, http.StatusNotFound, "not_found", "log entry not found", nil)
		return
	}
	writeJSON(w, http.StatusOK, logView(e))
}

// --- issuers and clients ------------------------------------------------------------

func (s *Server) issuerView(id string) (map[string]any, bool) {
	cfg := s.d.Settings.Config()
	is, _ := s.d.Settings.Access()
	for _, i := range cfg.Issuers {
		if i.ID != id {
			continue
		}
		n := 0
		for _, c := range cfg.Clients {
			if c.Issuer == id {
				n++
			}
		}
		used, rejected := s.d.Ingest.IssuerUsage(id)
		var revokedAt *string
		if ch, ok := is[id]; ok && ch.RevokedAt != "" {
			revokedAt = &ch.RevokedAt
		}
		q := 100000
		if i.QuotaPerDay != nil {
			q = *i.QuotaPerDay
		}
		return map[string]any{"id": i.ID, "quota_per_day": q, "used_24h": used, "clients": n, "signals_24h": used,
			"rejected_24h": rejected, "revoked": i.Revoked, "revoked_at": revokedAt}, true
	}
	return nil, false
}

func (s *Server) listIssuers(w http.ResponseWriter, r *http.Request) {
	var items []map[string]any
	for _, i := range s.d.Settings.Config().Issuers {
		v, _ := s.issuerView(i.ID)
		items = append(items, v)
	}
	if items == nil {
		items = []map[string]any{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) updateIssuer(w http.ResponseWriter, r *http.Request) {
	var in struct {
		QuotaPerDay *int `json:"quota_per_day"`
	}
	if !decode(w, r, &in) {
		return
	}
	if in.QuotaPerDay == nil || *in.QuotaPerDay < 0 || *in.QuotaPerDay > 100000000 {
		problem(w, http.StatusBadRequest, "invalid", "quota_per_day 0..100000000", []fieldError{{Pointer: "/quota_per_day", Detail: "0..100000000"}})
		return
	}
	id := r.PathValue("id")
	if err := s.d.Settings.SetIssuerQuota(id, *in.QuotaPerDay); err != nil {
		s.settingsFail(w, err)
		return
	}
	s.d.Log.Info("audit: issuer quota changed", "by", userOf(r), "issuer", id, "quota", *in.QuotaPerDay)
	v, _ := s.issuerView(id)
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) revokeIssuer(w http.ResponseWriter, r *http.Request) {
	var in confirmInput
	if !decode(w, r, &in) || !s.confirm(w, r, in.Password, "/password") {
		return
	}
	id := r.PathValue("id")
	if err := s.d.Settings.RevokeIssuer(id, userOf(r), s.d.Now()); err != nil {
		s.settingsFail(w, err)
		return
	}
	s.d.Log.Warn("audit: issuer revoked", "by", userOf(r), "issuer", id)
	v, _ := s.issuerView(id)
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) clientView(c clientCfg) map[string]any {
	used, tb := s.d.Ingest.KeyUsage(c.KeyID)
	var last *string
	if tb != "" {
		last = &tb
	}
	pub, _ := keys.ParsePublicKey(c.PublicKey)
	return map[string]any{"keyid": c.KeyID, "issuer": c.Issuer, "public_key": c.PublicKey, "quota_per_day": c.Quota, "used_24h": used,
		"last_seen_bucket": last, "revoked": c.Revoked, "test_key": keys.IsTestKey(c.KeyID, pub)}
}

type clientCfg struct {
	KeyID, Issuer, PublicKey string
	Quota                    int
	Revoked                  bool
}

func (s *Server) clients() []clientCfg {
	cfg := s.d.Settings.Config()
	revokedIssuer := map[string]bool{}
	for _, i := range cfg.Issuers {
		revokedIssuer[i.ID] = i.Revoked
	}
	out := make([]clientCfg, 0, len(cfg.Clients))
	for _, c := range cfg.Clients {
		q := 500
		if c.QuotaPerDay != nil {
			q = *c.QuotaPerDay
		}
		out = append(out, clientCfg{KeyID: c.KeyID, Issuer: c.Issuer, PublicKey: c.PublicKey, Quota: q, Revoked: c.Revoked || revokedIssuer[c.Issuer]})
	}
	return out
}

func (s *Server) listClients(w http.ResponseWriter, r *http.Request) {
	off, lim, ok := page(w, r)
	if !ok {
		return
	}
	issuer := r.URL.Query().Get("issuer")
	var all []clientCfg
	for _, c := range s.clients() {
		if issuer == "" || c.Issuer == issuer {
			all = append(all, c)
		}
	}
	off = min(off, len(all))
	end := min(off+lim, len(all))
	items := make([]map[string]any, 0, end-off)
	for _, c := range all[off:end] {
		items = append(items, s.clientView(c))
	}
	next := -1
	if end < len(all) {
		next = end
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": nextCursor(next)})
}

func (s *Server) clientByID(keyid string) (map[string]any, bool) {
	for _, c := range s.clients() {
		if c.KeyID == keyid {
			return s.clientView(c), true
		}
	}
	return nil, false
}

func (s *Server) updateClient(w http.ResponseWriter, r *http.Request) {
	var in struct {
		QuotaPerDay *int `json:"quota_per_day"`
	}
	if !decode(w, r, &in) {
		return
	}
	if in.QuotaPerDay == nil || *in.QuotaPerDay < 0 || *in.QuotaPerDay > 1000000 {
		problem(w, http.StatusBadRequest, "invalid", "quota_per_day 0..1000000", []fieldError{{Pointer: "/quota_per_day", Detail: "0..1000000"}})
		return
	}
	k := r.PathValue("keyid")
	if err := s.d.Settings.SetClientQuota(k, *in.QuotaPerDay); err != nil {
		s.settingsFail(w, err)
		return
	}
	s.d.Log.Info("audit: client quota changed", "by", userOf(r), "keyid", k, "quota", *in.QuotaPerDay)
	v, _ := s.clientByID(k)
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) revokeClient(w http.ResponseWriter, r *http.Request) {
	var in confirmInput
	if !decode(w, r, &in) || !s.confirm(w, r, in.Password, "/password") {
		return
	}
	k := r.PathValue("keyid")
	if err := s.d.Settings.RevokeClient(k, userOf(r), s.d.Now()); err != nil {
		s.settingsFail(w, err)
		return
	}
	s.d.Log.Warn("audit: client revoked", "by", userOf(r), "keyid", k)
	v, _ := s.clientByID(k)
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) settingsFail(w http.ResponseWriter, err error) {
	if _, ok := err.(settings.ErrNotFound); ok {
		problem(w, http.StatusNotFound, "not_found", err.Error(), nil)
		return
	}
	problem(w, http.StatusBadRequest, "invalid", err.Error(), nil)
}

// --- settings ---------------------------------------------------------------------

func (s *Server) settingsView() map[string]any {
	c := s.d.Settings.Config()
	return map[string]any{
		"identity": map[string]any{"operator": c.Identity.Operator, "lab": c.Identity.Lab},
		"profile":  c.Profile,
		"channel":  c.Channel,
		"scoring": map[string]any{"min_issuers": c.Scoring.MinIssuers, "max_issuer_share": c.Scoring.MaxIssuerShare,
			"window_minutes": c.Scoring.WindowMinutes, "min_score": *c.Scoring.MinScore},
		"publish": map[string]any{"bundle_validity_hours": c.Publish.BundleValidityHours, "checkpoint_interval_s": c.Publish.CheckpointIntervalS,
			"checkpoint_ttl_s": c.Publish.CheckpointTTLS, "require_human_approval": true},
		"ingest": map[string]any{"rate_per_client_per_min": c.Ingest.RatePerClientPerMin, "queue_max_depth": c.Ingest.QueueMaxDepth,
			"retry_after_ms": c.Ingest.RetryAfterMS},
		"retention": map[string]any{"signals_days": c.Retention.SignalsDays, "aggregates_days": c.Retention.AggregatesDays},
	}
}

func (s *Server) getSettings(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.settingsView())
}

func (s *Server) updateSettings(w http.ResponseWriter, r *http.Request) {
	var in struct {
		settings.Patch
		Confirm *confirmInput `json:"confirm"`
	}
	if !decode(w, r, &in) {
		return
	}
	if in.Confirm != nil && !s.confirm(w, r, in.Confirm.Password, "/confirm/password") {
		return
	}
	if _, err := s.d.Settings.Apply(in.Patch); err != nil {
		msgText := err.Error()
		ptr := "/"
		for _, sec := range []string{"scoring", "ingest", "retention"} {
			if strings.Contains(msgText, sec) {
				ptr = "/" + sec
			}
		}
		problem(w, http.StatusBadRequest, "invalid", msgText, []fieldError{{Pointer: ptr, Detail: msgText}})
		return
	}
	s.d.Log.Info("audit: settings changed", "by", userOf(r))
	writeJSON(w, http.StatusOK, s.settingsView())
}
