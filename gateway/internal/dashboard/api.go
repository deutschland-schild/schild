package dashboard

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/deutschland-schild/schild/contract/agentapi"
	"github.com/deutschland-schild/schild/contract/events"
	cm "github.com/deutschland-schild/schild/contract/monitoring"
	"github.com/deutschland-schild/schild/contract/rules"
	"github.com/deutschland-schild/schild/gateway/internal/allowlist"
	"github.com/deutschland-schild/schild/gateway/internal/behaviour"
	"github.com/deutschland-schild/schild/gateway/internal/clientip"
	"github.com/deutschland-schild/schild/gateway/internal/decide"
	"github.com/deutschland-schild/schild/gateway/internal/eventlog"
	"github.com/deutschland-schild/schild/gateway/internal/hub"
	"github.com/deutschland-schild/schild/gateway/internal/monitoring"
	"github.com/deutschland-schild/schild/gateway/internal/ratelog"
	"github.com/deutschland-schild/schild/gateway/internal/ruleset"
	"github.com/deutschland-schild/schild/gateway/internal/store"
)

// ---------------------------------------------------------------- query helpers

type query struct {
	r    *http.Request
	errs []FieldError
}

func (q *query) str(name string, max int, re *regexp.Regexp) string {
	v := q.r.URL.Query().Get(name)
	if v == "" {
		return ""
	}
	if len(v) > max || (re != nil && !re.MatchString(v)) {
		q.errs = append(q.errs, FieldError{Pointer: "#/query/" + name, Detail: "ungültiger Wert"})
		return ""
	}
	return v
}

func (q *query) enum(name string, allowed ...string) string {
	v := q.r.URL.Query().Get(name)
	if v == "" {
		return ""
	}
	for _, a := range allowed {
		if v == a {
			return v
		}
	}
	q.errs = append(q.errs, FieldError{Pointer: "#/query/" + name, Detail: "erlaubt: " + strings.Join(allowed, ", ")})
	return ""
}

var tsRe = regexp.MustCompile(`^20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?Z$`)

func (q *query) time(name string) time.Time {
	v := q.r.URL.Query().Get(name)
	if v == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339Nano, v)
	if err != nil || !tsRe.MatchString(v) {
		q.errs = append(q.errs, FieldError{Pointer: "#/query/" + name, Detail: "Zeit im Format 2026-10-26T12:00:00Z"})
	}
	return t
}

func (q *query) limit() int {
	v := q.r.URL.Query().Get("limit")
	if v == "" {
		return 50
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 || n > 500 {
		q.errs = append(q.errs, FieldError{Pointer: "#/query/limit", Detail: "1 bis 500"})
		return 50
	}
	return n
}

func (q *query) cursor() int64 {
	v := q.r.URL.Query().Get("cursor")
	if len(v) > 256 {
		q.errs = append(q.errs, FieldError{Pointer: "#/query/cursor", Detail: "ungültig"})
		return 0
	}
	n, err := store.ParseCursor(v)
	if err != nil {
		q.errs = append(q.errs, FieldError{Pointer: "#/query/cursor", Detail: "ungültig"})
	}
	return n
}

func (q *query) failed(w http.ResponseWriter) bool {
	if len(q.errs) == 0 {
		return false
	}
	invalid(w, "Einige Filter sind ungültig.", q.errs...)
	return true
}

func nextCursor(n int64) *string {
	if n == 0 {
		return nil
	}
	c := store.FormatCursor(n)
	return &c
}

var (
	typeRe    = regexp.MustCompile(`^schild\.[a-z]+\.[a-z_]+\.v1$`)
	countryRe = regexp.MustCompile(`^[A-Z]{2}$`)
	uuidRe    = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	incRe     = regexp.MustCompile(`^[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}$`)
)

var outcomes = []string{decide.Passed, decide.Logged, decide.Blocked, decide.WouldBlock}

func (q *query) eventFilter() store.EventFilter {
	f := store.EventFilter{
		Type: q.str("type", 64, typeRe), IP: q.str("ip", 64, nil), Country: q.str("country", 2, countryRe),
		Path: q.str("path", 512, nil), Rule: q.str("rule", 32, nil), Outcome: q.enum("outcome", outcomes...),
		Session: q.str("session", 40, nil), Q: q.str("q", 200, nil),
	}
	if v := q.r.URL.Query().Get("asn"); v != "" {
		n, err := strconv.ParseUint(v, 10, 32)
		if err != nil {
			q.errs = append(q.errs, FieldError{Pointer: "#/query/asn", Detail: "Zahl ab 0"})
		} else {
			a := uint32(n)
			f.ASN = &a
		}
	}
	if f.IP != "" {
		if strings.Contains(f.IP, "/") {
			if _, err := netip.ParsePrefix(f.IP); err != nil {
				q.errs = append(q.errs, FieldError{Pointer: "#/query/ip", Detail: "IP-Adresse oder Bereich"})
			}
		} else if _, err := netip.ParseAddr(f.IP); err != nil {
			q.errs = append(q.errs, FieldError{Pointer: "#/query/ip", Detail: "IP-Adresse oder Bereich"})
		}
	}
	return f
}

var methodRe = regexp.MustCompile(`^[A-Z]{1,16}$`)

// breakdownFilters reads the listEvents filters a breakdown row links to
// (D36 amendment 2026-10-29): net_class, method (OTHER = every method
// outside the method breakdown) and ua_class (the monitoring
// classification of the stored user agent, request events only).
func (q *query) breakdownFilters(f *store.EventFilter) {
	f.NetClass = q.enum("net_class", monitoring.NetClasses()...)
	if m := q.str("method", 16, methodRe); m == "OTHER" {
		f.OtherMethods = monitoring.Methods()
	} else {
		f.Method = m
	}
	if c := q.enum("ua_class", cm.UAClasses...); c != "" {
		f.Match = func(e *store.EventRow) bool { return e.Method != "" && monitoring.UAClass(e.UA) == c }
	}
}

// ---------------------------------------------------------------- events

type eventBody struct {
	Data struct {
		Client struct {
			Geo events.Geo `json:"geo"`
		} `json:"client"`
		WouldBlockReason string `json:"would_block_reason"`
	} `json:"data"`
}

func summarize(e *store.EventRow) EventSummary {
	s := EventSummary{ID: e.ID, Time: e.Time.UTC().Format("2006-01-02T15:04:05.000Z"), Type: e.Type, Summary: e.Summary, Site: e.Site}
	if e.Type == events.RequestEvaluated || e.Type == events.RequestBlocked {
		s.Outcome, s.IP, s.Method, s.Host, s.Path, s.Incident, s.SessionID = e.Outcome, e.IP, e.Method, e.Host, e.Path, e.Incident, e.Session
		st, sc := e.Status, e.Score
		s.Status, s.Score = &st, &sc
		s.Rules = append([]string{}, e.Rules...)
		var b eventBody
		if json.Unmarshal(e.Body, &b) == nil {
			if g := b.Data.Client.Geo; g.Country != "" {
				s.Geo = &Geo{Country: g.Country, City: g.City, ASN: g.ASN, ASOrg: g.ASOrg, NetClass: g.NetClass}
			}
			if e.Outcome == decide.WouldBlock {
				s.WouldBlockReason = validReason(b.Data.WouldBlockReason)
			}
		}
	} else if e.Type == events.BlockSet || e.Type == events.BehaviourTriggered || e.Type == events.RateLimitExceeded {
		// Events about one address (a block set by hand or by an agent, a
		// scenario hit, a limit exceeded): the row names the address, where it
		// comes from and the incident, like a request row. Before, such a row
		// read "Hinweis, Ereignis" with every other column empty.
		s.IP, s.Incident, s.Host, s.Path = e.IP, e.Incident, e.Host, e.Path
		switch e.Outcome {
		case decide.Blocked, decide.WouldBlock:
			s.Outcome = e.Outcome
		case "block": // the action of a scenario or limit that blocked
			s.Outcome = decide.Blocked
		}
		var b eventBody
		if json.Unmarshal(e.Body, &b) == nil {
			if g := b.Data.Client.Geo; g.Country != "" {
				s.Geo = &Geo{Country: g.Country, City: g.City, ASN: g.ASN, ASOrg: g.ASOrg, NetClass: g.NetClass}
			}
		}
	} else if len(e.Rules) > 0 {
		s.Rules = append([]string{}, e.Rules...)
	}
	return s
}

func (s *Server) listEvents(w http.ResponseWriter, r *http.Request) {
	q := &query{r: r}
	f := q.eventFilter()
	f.Site = s.siteParam(q)
	f.From, f.To = q.time("from"), q.time("to")
	q.breakdownFilters(&f)
	limit, cursor := q.limit(), q.cursor()
	if q.failed(w) {
		return
	}
	rows, next, err := s.St.ListEvents(r.Context(), f, cursor, limit)
	if err != nil {
		s.internal(w, err)
		return
	}
	page := EventPage{Items: []EventSummary{}, NextCursor: nextCursor(next)}
	for _, e := range rows {
		page.Items = append(page.Items, summarize(e))
	}
	writeJSON(w, 200, page)
}

func (s *Server) getEvent(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !uuidRe.MatchString(id) {
		problem(w, 404, "not_found", "Dieses Ereignis gibt es nicht (mehr).", nil)
		return
	}
	e, err := s.St.GetEvent(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		problem(w, 404, "not_found", "Dieses Ereignis gibt es nicht (mehr). Ereignisse werden nach der eingestellten Frist gelöscht.", nil)
		return
	}
	if err != nil {
		s.internal(w, err)
		return
	}
	d := EventDetail{Event: json.RawMessage(e.Body)}
	if rel, err := s.St.Related(r.Context(), e, 10*time.Minute, 20); err == nil {
		for _, x := range rel {
			d.Related = append(d.Related, summarize(x))
		}
	}
	writeJSON(w, 200, d)
}

// ---------------------------------------------------------------- incidents

func (s *Server) incidentView(ctx context.Context, in *store.Incident) Incident {
	v := Incident{Incident: in.Incident, Status: in.Status, Time: ts(in.Time), Reason: in.Reason,
		UnblockedAt: tsp(in.UnblockedAt), AllowlistEntry: strp(in.AllowlistEntry), Site: in.Site}
	v.SitesAffected = s.SitesAffected(ctx, in.IP, in.Site, in.Time)
	v.Count, v.FirstSeen, v.LastSeen = incidentAggregate(in)
	if e, err := s.St.GetEvent(ctx, in.EventID); err == nil {
		v.Request = summarize(e)
		v.Block = incidentBlock(e, in.Incident)
		if v.Block != nil {
			behaviourRequest(&v.Request, e, in.IP)
			s.blockEnd(v.Block, in)
		}
	} else {
		v.Request = EventSummary{ID: in.EventID, Time: ts(in.Time), Type: events.RequestBlocked, Outcome: decide.Blocked, IP: in.IP, Incident: in.Incident}
	}
	return v
}

// incidentAggregate is count, first_seen and last_seen of an incident
// (D38); a row without them is one request at its time.
func incidentAggregate(in *store.Incident) (int64, string, string) {
	n, first, last := in.Count, in.FirstSeen, in.LastSeen
	if n < 1 {
		n = 1
	}
	if first.IsZero() {
		first = in.Time
	}
	if last.IsZero() {
		last = in.Time
	}
	return n, ts(first), ts(last)
}

// behaviourRequest fills the request of a behaviour incident from the
// event (D36 measurement D.4: the incident page had no address, host or
// origin for a behaviour block): the client address of the incident, the
// host and route the scenario counted, the client's origin.
func behaviourRequest(r *EventSummary, e *store.EventRow, ip string) {
	var body struct {
		Data events.BehaviourTriggeredData `json:"data"`
	}
	if json.Unmarshal(e.Body, &body) != nil {
		return
	}
	d := body.Data
	r.IP, r.Incident, r.Host, r.Path = ip, e.Incident, d.Host, d.Route
	if r.IP == "" && d.Client != nil {
		r.IP = d.Client.IP
	}
	if d.Client != nil && d.Client.Geo.Country != "" {
		g := d.Client.Geo
		r.Geo = &Geo{Country: g.Country, City: g.City, ASN: g.ASN, ASOrg: g.ASOrg, NetClass: g.NetClass}
	}
}

// blockEnd sets the real end of a block that ended before its planned end
// (D36 fix round 2, re-measurement C): unblocked by the operator, it ended
// at unblocked_at; a block that does not run any more (a 15 min block is
// not kept over a restart) ended at the start of this process at the
// latest. A block that still runs keeps its end. The earliest of these
// wins: unblocking a block that already ended with a restart does not move
// its end to the click (evening measurement 2026-10-29 4.4, D29 rest).
func (s *Server) blockEnd(b *BehaviourBlock, in *store.Incident) {
	until, err := time.Parse(time.RFC3339, b.Until)
	if err != nil {
		return
	}
	now := s.now()
	running, known := false, s.Behaviour != nil
	if known && until.After(now) {
		if ip, err := netip.ParseAddr(in.IP); err == nil {
			if bi, ok := s.Behaviour.ActiveBlock(ip); ok && bi.Incident == in.Incident {
				running = true
			}
		}
	}
	var unblocked time.Time
	if in.Status == "unblocked" {
		unblocked = in.UnblockedAt
	}
	end := blockEndAt(until, now, s.Started, in.Time, known, running, unblocked)
	if end.Before(until) {
		b.Until = ts(end)
	}
	if blockEnded(end, now) {
		b.EndedAt = ts(end)
	}
}

// blockEnded reports whether a block whose real end is end (blockEndAt)
// is no longer in force at now (BehaviourBlock.ended_at, contracts v0.5).
func blockEnded(end, now time.Time) bool { return !end.After(now) }

// blockEndAt is the real end of a timed block planned to end at until,
// started at incident: unblocked (non-zero) ends it then; a block the
// engine does not run any more (known: the engine was asked) ended at the
// start of this process when it began before it, else now; the earliest
// end wins.
func blockEndAt(until, now, started, incident time.Time, known, running bool, unblocked time.Time) time.Time {
	end := until
	if until.After(now) && known && !running {
		end = now
		if !started.IsZero() && incident.Before(started) {
			end = started
		}
	}
	if !unblocked.IsZero() && unblocked.Before(end) {
		end = unblocked
	}
	return end
}

// incidentBlock returns the timed block a behaviour event started (the
// event keeps scenario, ladder step, net class, duration and end, so the
// block is known after it ended or after a restart too). nil for every
// other event.
func incidentBlock(e *store.EventRow, incident string) *BehaviourBlock {
	if e.Type == events.BlockSet {
		return agentBlock(e, incident)
	}
	if e.Type != events.BehaviourTriggered {
		return nil
	}
	var body struct {
		Data events.BehaviourTriggeredData `json:"data"`
	}
	if json.Unmarshal(e.Body, &body) != nil {
		return nil
	}
	d := body.Data
	if d.Action != "block" || d.Level < 1 || d.Until == "" || d.Scenario == "" {
		return nil
	}
	b := &BehaviourBlock{Source: "behaviour:" + d.Scenario, Until: d.Until, Level: d.Level, Incident: incident,
		Persisted: d.DurationS > events.PersistOverS}
	if d.Client != nil {
		b.NetClass = d.Client.Geo.NetClass
	}
	if d.DurationS >= 1 {
		b.DurationS = min(d.DurationS, events.MaxBlockHostingS)
	}
	return b
}

// agentBlock returns the block an agent set (D42), or the operator by hand
// (D88, source dashboard, no token), from its event.
func agentBlock(e *store.EventRow, incident string) *BehaviourBlock {
	var body struct {
		Data events.AgentBlockSet `json:"data"`
	}
	if json.Unmarshal(e.Body, &body) != nil {
		return nil
	}
	d := body.Data
	if d.Effect != agentapi.EffectBlock || d.Until == "" {
		return nil
	}
	if d.Actor == "dashboard" {
		return &BehaviourBlock{Source: behaviour.DashboardSource, Until: d.Until, Level: 1, Incident: incident, NetClass: d.Client.Geo.NetClass, DurationS: d.DurationS,
			Persisted: d.Persisted}
	}
	return &BehaviourBlock{Source: behaviour.AgentSource + d.TokenID, Until: d.Until, Level: 1, Incident: incident, NetClass: d.Client.Geo.NetClass, DurationS: d.DurationS,
		Persisted: d.Persisted, SetBy: &BlockSetBy{TokenID: d.TokenID, TokenLabel: d.TokenLabel}, AgentReason: d.Reason}
}

// IncidentBlock is the timed block behind an incident with its end (nil:
// none), for the agent API.
func (s *Server) IncidentBlock(ctx context.Context, in *store.Incident) *BehaviourBlock {
	e, err := s.St.GetEvent(ctx, in.EventID)
	if err != nil {
		return nil
	}
	b := incidentBlock(e, in.Incident)
	if b != nil {
		s.blockEnd(b, in)
	}
	return b
}

func (s *Server) loadIncident(w http.ResponseWriter, r *http.Request) *store.Incident {
	id := strings.ToUpper(strings.TrimSpace(r.PathValue("incident")))
	if !incRe.MatchString(id) {
		problem(w, 404, "not_found", "Diese Vorfallnummer gibt es nicht. Sie hat die Form K7QM-4XWD.", nil)
		return nil
	}
	in, err := s.St.GetIncident(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		problem(w, 404, "not_found", "Zu dieser Vorfallnummer ist nichts gespeichert. Prüf die Schreibweise; alte Vorfälle werden nach der eingestellten Frist gelöscht.", nil)
		return nil
	}
	if err != nil {
		s.internal(w, err)
		return nil
	}
	return in
}

func (s *Server) getIncident(w http.ResponseWriter, r *http.Request) {
	if in := s.loadIncident(w, r); in != nil {
		writeJSON(w, 200, s.incidentView(r.Context(), in))
	}
}

// incidentExportEvents bounds the events in a download (D51).
const incidentExportEvents = 1000

// exportIncident answers the download of one incident (D51). The file leaves
// retention and privacy/delete, so every download is recorded.
func (s *Server) exportIncident(w http.ResponseWriter, r *http.Request) {
	in := s.loadIncident(w, r)
	if in == nil {
		return
	}
	ctx := r.Context()
	rows, err := s.St.EventsByIncident(ctx, in.Incident, incidentExportEvents+1)
	if err != nil {
		s.internal(w, err)
		return
	}
	out := IncidentExport{Incident: s.incidentView(ctx, in), ExportedAt: ts(s.now()), Events: []json.RawMessage{}}
	if len(rows) > incidentExportEvents {
		rows, out.Truncated = rows[:incidentExportEvents], true
	}
	for _, e := range rows {
		out.Events = append(out.Events, json.RawMessage(e.Body))
	}
	if s.Requests != nil {
		c, _, err := s.RequestContext(ctx, in.EventID)
		switch {
		case err == nil:
			out.Context = &c
		case s.Log != nil: // a busy ring or a lost event: the file still helps
			ratelog.Warn(s.Log, "incident export without context", "err", err)
		}
	}
	if s.Events != nil {
		data := events.IncidentExportedData{Incident: in.Incident, By: sessionOf(r).User, Events: len(out.Events)}
		s.Events.Emit(events.IncidentExported, s.now(), data, eventlog.Index{Incident: in.Incident, Summary: "incident exported " + in.Incident})
	}
	w.Header().Set("Content-Disposition", `attachment; filename="schild-incident-`+in.Incident+`.json"`)
	writeJSON(w, 200, out)
}

func (s *Server) unblock(w http.ResponseWriter, r *http.Request) {
	var req UnblockRequest
	if !decode(w, r, &req) {
		return
	}
	if req.AllowTTL == "" {
		req.AllowTTL = "7d"
	}
	if len(req.Note) > 500 {
		invalid(w, "Die Notiz ist zu lang.", FieldError{Pointer: "/note", Detail: "höchstens 500 Zeichen"})
		return
	}
	if _, err := allowlist.Expiry(req.AllowTTL, s.now()); err != nil {
		invalid(w, "Ungültige Dauer.", FieldError{Pointer: "/allow_ttl", Detail: "24h, 7d, 30d oder never"})
		return
	}
	in := s.loadIncident(w, r)
	if in == nil {
		return
	}
	if in.Status != "blocked" {
		problem(w, 409, "conflict", "Dieser Vorfall ist schon freigeschaltet.", nil)
		return
	}
	ctx := r.Context()
	now := s.now()
	ip, ipErr := netip.ParseAddr(in.IP)
	// Exception: this client passes the sources that blocked it, for 24 h.
	var srcs []string
	for _, src := range in.Sources {
		if !strings.HasPrefix(src, "limit") {
			srcs = append(srcs, src)
		}
	}
	if ipErr == nil && len(srcs) > 0 {
		until := now.Add(24 * time.Hour)
		if err := s.St.AddException(ctx, store.Exception{IP: ip.String(), Sources: srcs, Expires: until, Incident: in.Incident}); err != nil {
			s.internal(w, err)
			return
		}
		if s.Gate != nil {
			s.Gate.Exceptions.Add(ip, srcs, until)
		}
	}
	allowID := ""
	if req.AllowIP && ipErr == nil {
		e, errs := allowlist.Validate(allowlist.Input{IP: ip.String(), Label: "Vorfall " + in.Incident, Level: allowlist.NoBlock, TTL: req.AllowTTL}, now)
		if len(errs) == 0 {
			e.Source = "dashboard"
			if err := s.St.AddAllow(ctx, e); err != nil {
				s.internal(w, err)
				return
			}
			allowID = e.ID
			s.reloadAllow(ctx)
		}
	}
	// On a node of a group the lift for the group is noted with the
	// decision, in one transaction (store/outbox.go); a single gateway
	// notes none. When the allowlist entry of this request ended the
	// behaviour block first, which marked the incident unblocked
	// (Sink.Ended), the incident takes the reference to the entry.
	err := s.St.MarkUnblockedLift(ctx, in.Incident, now, allowID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			problem(w, 409, "conflict", "Dieser Vorfall ist schon freigeschaltet.", nil)
			return
		}
		s.internal(w, err)
		return
	}
	// D87: the timed block of this incident ends now, not only for the
	// requests of this client (the exception above): it leaves the list of
	// blocks and, within a second, the host's firewall.
	switch {
	case s.LiftIncident != nil:
		s.LiftIncident(in.Incident)
	case s.Behaviour != nil:
		s.Behaviour.LiftIncident(in.Incident)
	}
	reqID := in.EventID
	data := events.Unblocked{Incident: in.Incident, RequestID: reqID, By: "operator", FalsePositive: req.FalsePositive, AllowlistEntry: allowID}
	if s.Events != nil {
		s.Events.Emit(events.RequestUnblocked, now, data, eventlog.Index{IP: in.IP, Incident: in.Incident, Summary: "incident unblocked " + in.Incident})
	}
	in, _ = s.St.GetIncident(ctx, in.Incident)
	writeJSON(w, 200, s.incidentView(ctx, in))
}

// ---------------------------------------------------------------- rules

// The rule repositories and their rules (D73): the same service as the agent
// API, with session and CSRF token, no password on any change.

func (s *Server) reposOff(w http.ResponseWriter) bool {
	if s.Repos == nil {
		problem(w, http.StatusNotFound, "not_found", "Die Regelquellen gibt es hier nicht.", nil)
		return true
	}
	return false
}

func (s *Server) actor() ruleset.Actor { return ruleset.Actor{Kind: rules.ByDashboard} }

// ruleProblem answers an error of the rule service.
func ruleProblem(w http.ResponseWriter, err error) {
	var se *ruleset.SyncError
	switch {
	case errors.Is(err, ruleset.ErrNotFound):
		problem(w, http.StatusNotFound, "not_found", "Diese Regelquelle oder Regel ist hier nicht bekannt.", nil)
	case errors.Is(err, ruleset.ErrNotSupported):
		problem(w, http.StatusConflict, "not_supported", "Das geht bei dieser Regelquelle nicht.", nil)
	case errors.Is(err, ruleset.ErrConfigLimit):
		problem(w, http.StatusConflict, "config_limit", "Diese Regel ist in schild.yaml ausgeschaltet und lässt sich nur dort wieder einschalten.", nil)
	case errors.Is(err, hub.ErrNoSnapshot):
		problem(w, http.StatusConflict, "no_snapshot", "Dieses Image bringt keine Regeln mit, zu denen du zurück kannst.", nil)
	case errors.As(err, &se):
		problem(w, http.StatusConflict, "sync_refused", "Die Regeln wurden nicht geladen, die laufenden bleiben: "+se.Err.Error(), nil)
	case errors.Is(err, ruleset.ErrInvalid):
		invalid(w, "Gib entweder einen Zustand an oder setz ihn zurück.", FieldError{Pointer: "/state", Detail: "off, detect oder block"})
	case errors.Is(err, ruleset.ErrBusy):
		problem(w, http.StatusServiceUnavailable, "busy", "Gerade laufen andere Regeländerungen. Versuch es gleich noch einmal.", nil)
	default:
		problem(w, http.StatusInternalServerError, "internal", "Das hat nicht geklappt. Die laufenden Regeln bleiben.", nil)
	}
}

func (s *Server) listRuleRepositories(w http.ResponseWriter, _ *http.Request) {
	if s.reposOff(w) {
		return
	}
	writeJSON(w, 200, s.Repos.Repositories())
}

func (s *Server) getRuleRepository(w http.ResponseWriter, r *http.Request) {
	if s.reposOff(w) {
		return
	}
	v, err := s.Repos.Repository(r.PathValue("repository"))
	if err != nil {
		ruleProblem(w, err)
		return
	}
	writeJSON(w, 200, v)
}

func (s *Server) updateRuleRepository(w http.ResponseWriter, r *http.Request) {
	var p ruleset.RepositoryPatch
	if !decode(w, r, &p) || s.reposOff(w) {
		return
	}
	state, reset, ok := p.Check()
	if !ok {
		invalid(w, "Gib entweder einen Zustand an oder setz ihn zurück.", FieldError{Pointer: "/state", Detail: "off, detect oder block"})
		return
	}
	v, err := s.Repos.SetState(r.Context(), r.PathValue("repository"), state, reset, s.actor())
	if err != nil {
		ruleProblem(w, err)
		return
	}
	writeJSON(w, 200, v)
}

// updateRuleRepositorySettings sets the paranoia level and the blocking
// threshold of the CRS (D101).
func (s *Server) updateRuleRepositorySettings(w http.ResponseWriter, r *http.Request) {
	var p ruleset.SettingsPatch
	if !decode(w, r, &p) || s.reposOff(w) {
		return
	}
	set, field := p.Check()
	if field != "" {
		detail := "eine ganze Zahl von 1 bis 4"
		if field == "inbound_anomaly_threshold" {
			detail = "eine ganze Zahl von 1 bis 100"
		}
		invalid(w, "Dieser Wert liegt außerhalb dessen, was Schild annimmt.", FieldError{Pointer: "/" + field, Detail: detail})
		return
	}
	v, err := s.Repos.SetCRSSettings(r.Context(), r.PathValue("repository"), set)
	if err != nil {
		ruleProblem(w, err)
		return
	}
	writeJSON(w, 200, v)
}

func (s *Server) syncRuleRepository(w http.ResponseWriter, r *http.Request) {
	if s.reposOff(w) {
		return
	}
	if _, err := s.Repos.Sync(r.Context(), r.PathValue("repository")); err != nil {
		ruleProblem(w, err)
		return
	}
	s.getRuleRepository(w, r)
}

func (s *Server) resetRuleRepository(w http.ResponseWriter, r *http.Request) {
	if s.reposOff(w) {
		return
	}
	if err := s.Repos.Reset(r.Context(), r.PathValue("repository")); err != nil {
		ruleProblem(w, err)
		return
	}
	s.getRuleRepository(w, r)
}

func (s *Server) listRules(w http.ResponseWriter, r *http.Request) {
	q := &query{r: r}
	repo := q.enum("repository", rules.Repositories...)
	status := q.enum("status", rules.Statuses...)
	limit := q.limit()
	if q.failed(w) || s.reposOff(w) {
		return
	}
	page, err := ruleset.Page(s.Repos.Rules(ruleset.Filter{Repository: repo, Status: status}), r.URL.Query().Get("cursor"), limit)
	if err != nil {
		invalid(w, "Ungültige Anfrage.", FieldError{Pointer: "#/query/cursor", Detail: "ungültig"})
		return
	}
	writeJSON(w, 200, page)
}

func (s *Server) getRule(w http.ResponseWriter, r *http.Request) {
	if s.reposOff(w) {
		return
	}
	d, err := s.Repos.Rule(r.PathValue("repository"), r.PathValue("rule"))
	if err != nil {
		ruleProblem(w, err)
		return
	}
	writeJSON(w, 200, d)
}

func (s *Server) updateRule(w http.ResponseWriter, r *http.Request) {
	var p ruleset.RulePatch
	if !decode(w, r, &p) || s.reposOff(w) {
		return
	}
	if p.Disabled == nil {
		invalid(w, "Sag, ob die Regel aus oder an sein soll.", FieldError{Pointer: "/disabled", Detail: "fehlt"})
		return
	}
	if len(p.Note) > ruleset.MaxNote {
		invalid(w, "Die Notiz ist zu lang.", FieldError{Pointer: "/note", Detail: "höchstens 500 Zeichen"})
		return
	}
	d, err := s.Repos.SetDisabled(r.Context(), r.PathValue("repository"), r.PathValue("rule"), *p.Disabled, p.Note, s.actor())
	if err != nil {
		ruleProblem(w, err)
		return
	}
	writeJSON(w, 200, d)
}

// ---------------------------------------------------------------- allowlist

func (s *Server) reloadAllow(ctx context.Context) {
	if s.ReloadAllow != nil {
		if err := s.ReloadAllow(ctx); err != nil && s.Log != nil {
			s.Log.Error("reload allowlist", "err", err)
		}
	}
}

func (s *Server) allowView(e *allowlist.Entry, now time.Time) AllowlistEntry {
	v := AllowlistEntry{ID: e.ID, IP: e.IP, CIDR: e.CIDR, Host: e.Host, Label: e.Label, Level: e.Level, Expires: e.Expires,
		Expired: e.Expired(now), CreatedAt: ts(e.CreatedAt), Source: e.Source}
	if v.Expires == "" {
		v.Expires = "never"
	}
	for _, a := range e.Resolved {
		v.Resolved = append(v.Resolved, a.String())
	}
	return v
}

func (s *Server) listAllow(w http.ResponseWriter, r *http.Request) {
	q := &query{r: r}
	limit := q.limit()
	off := 0
	if c := r.URL.Query().Get("cursor"); c != "" {
		n, err := strconv.Atoi(strings.TrimPrefix(c, "o"))
		if err != nil || n < 0 || !strings.HasPrefix(c, "o") {
			q.errs = append(q.errs, FieldError{Pointer: "#/query/cursor", Detail: "ungültig"})
		}
		off = n
	}
	if q.failed(w) {
		return
	}
	now := s.now()
	all := s.Allow.Entries()
	page := AllowlistPage{Items: []AllowlistEntry{}}
	if off < len(all) {
		end := min(off+limit, len(all))
		for _, e := range all[off:end] {
			page.Items = append(page.Items, s.allowView(e, now))
		}
		if end < len(all) {
			c := "o" + strconv.Itoa(end)
			page.NextCursor = &c
		}
	}
	writeJSON(w, 200, page)
}

func fieldErrors(m map[string]string) []FieldError {
	var out []FieldError
	for k, v := range m {
		out = append(out, FieldError{Pointer: "/" + k, Detail: v})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Pointer < out[j].Pointer })
	return out
}

func (s *Server) addAllow(w http.ResponseWriter, r *http.Request) {
	var in AllowlistInput
	if !decode(w, r, &in) {
		return
	}
	e, errs := allowlist.Validate(allowlist.Input{IP: in.IP, CIDR: in.CIDR, Host: in.Host, Label: in.Label, Level: in.Level, TTL: in.TTL}, s.now())
	if in.Level == allowlist.BypassWAF && !in.ConfirmBypass {
		if errs == nil {
			errs = map[string]string{}
		}
		errs["confirm_bypass"] = "Bestätige, dass die Prüfung für diesen Absender ganz entfällt."
	}
	if len(errs) > 0 {
		invalid(w, "Bitte prüf die markierten Felder.", fieldErrors(errs)...)
		return
	}
	e.Source = "dashboard"
	if err := s.St.AddAllow(r.Context(), e); err != nil {
		s.internal(w, err)
		return
	}
	s.reloadAllow(r.Context())
	writeJSON(w, http.StatusCreated, s.allowView(&allowlist.Entry{AllowEntry: *e}, s.now()))
}

func (s *Server) caller(r *http.Request) (netip.Addr, string) {
	var res clientip.Result
	if s.Gate != nil {
		res = s.Gate.Settings().Resolver.Resolve(r)
	} else {
		res.IP, _ = clientip.Peer(r.RemoteAddr)
		res.Attribution = clientip.TCPPeer
	}
	attr := res.Attribution
	if res.IP.IsLoopback() {
		attr = "localhost"
	}
	return res.IP, attr
}

func (s *Server) getMine(w http.ResponseWriter, r *http.Request) {
	ip, attr := s.caller(r)
	lvl, _ := s.Allow.Match(ip, s.now())
	writeJSON(w, 200, MyIP{IP: ip.String(), Attribution: attr, Allowlisted: lvl != ""})
}

func (s *Server) allowMine(w http.ResponseWriter, r *http.Request) {
	var in AllowMineRequest
	if !decode(w, r, &in) {
		return
	}
	if in.TTL == "" {
		in.TTL = "7d"
	}
	ip, _ := s.caller(r)
	e, errs := allowlist.Validate(allowlist.Input{IP: ip.String(), Label: in.Label, Level: allowlist.NoBlock, TTL: in.TTL}, s.now())
	if len(errs) > 0 {
		delete(errs, "ip")
		invalid(w, "Bitte prüf die markierten Felder.", fieldErrors(errs)...)
		return
	}
	e.Source = "dashboard"
	if err := s.St.AddAllow(r.Context(), e); err != nil {
		s.internal(w, err)
		return
	}
	s.reloadAllow(r.Context())
	writeJSON(w, http.StatusCreated, s.allowView(&allowlist.Entry{AllowEntry: *e}, s.now()))
}

func (s *Server) deleteAllow(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if strings.HasPrefix(id, "cfg-") {
		problem(w, 409, "conflict", "Dieser Eintrag steht in schild.yaml. Ändere ihn dort.", nil)
		return
	}
	if err := s.St.DeleteAllow(r.Context(), id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			problem(w, 404, "not_found", "Diesen Eintrag gibt es nicht.", nil)
			return
		}
		s.internal(w, err)
		return
	}
	s.reloadAllow(r.Context())
	w.WriteHeader(http.StatusNoContent)
}

// ---------------------------------------------------------------- settings

func (s *Server) settingsView() Settings {
	c := s.Config()
	return Settings{Profile: c.Profile,
		Retention: SettingsRetention{RawIPDays: c.Retention.RawIPDays, EventsDays: c.Retention.EventsDays, MaxSizeMB: c.Retention.MaxSizeMB, SummariesDays: c.Retention.SummariesDays}}
}

func (s *Server) getSettings(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, s.settingsView())
}

func (s *Server) patchSettings(w http.ResponseWriter, r *http.Request) {
	var p SettingsPatch
	if !decode(w, r, &p) {
		return
	}
	if _, err := s.Apply(r.Context(), p); err != nil {
		invalid(w, "Diese Einstellung ist nicht möglich: "+err.Error())
		return
	}
	writeJSON(w, 200, s.settingsView())
}

// ---------------------------------------------------------------- privacy

func parseIP(w http.ResponseWriter, v, pointer string) (netip.Addr, bool) {
	a, err := netip.ParseAddr(strings.TrimSpace(v))
	if err != nil || len(v) > 64 {
		invalid(w, "Das ist keine gültige IP-Adresse.", FieldError{Pointer: pointer, Detail: "IPv4- oder IPv6-Adresse"})
		return netip.Addr{}, false
	}
	return a.Unmap().WithZone(""), true
}

func (s *Server) privacySearch(w http.ResponseWriter, r *http.Request) {
	ip, ok := parseIP(w, r.URL.Query().Get("ip"), "#/query/ip")
	if !ok {
		return
	}
	sum, err := s.St.SummarizeIP(r.Context(), ip.String())
	if err != nil {
		s.internal(w, err)
		return
	}
	lvl, _ := s.Allow.Match(ip, s.now())
	out := PrivacySummary{IP: ip.String(), Events: sum.Events, Sessions: sum.Sessions, Incidents: sum.Incidents,
		FirstSeen: tsp(sum.FirstSeen), LastSeen: tsp(sum.LastSeen), Allowlisted: lvl != ""}
	if !sum.Untruncated.IsZero() {
		days := s.Config().Retention.RawIPDays
		out.IPTruncatedAfter = tsp(sum.Untruncated.Add(time.Duration(days) * 24 * time.Hour))
	}
	writeJSON(w, 200, out)
}

func (s *Server) privacyExport(w http.ResponseWriter, r *http.Request) {
	var req PrivacyRequest
	if !decode(w, r, &req) {
		return
	}
	ip, ok := parseIP(w, req.IP, "/ip")
	if !ok {
		return
	}
	rows, err := s.St.EventsByIP(r.Context(), ip.String(), 100000)
	if err != nil {
		s.internal(w, err)
		return
	}
	out := PrivacyExport{IP: ip.String(), ExportedAt: ts(s.now()), Events: []json.RawMessage{}}
	for _, e := range rows {
		out.Events = append(out.Events, json.RawMessage(e.Body))
	}
	if s.Requests != nil {
		if out.Requests, err = s.Requests.ByIP(r.Context(), ip, 10000, s.now()); err != nil {
			s.internal(w, err)
			return
		}
	}
	w.Header().Set("Content-Disposition", `attachment; filename="schild-export-`+strings.NewReplacer(":", "-", ".", "-").Replace(ip.String())+`.json"`)
	writeJSON(w, 200, out)
}

// TruncateBody replaces the client address in a stored CloudEvent.
func TruncateBody(body []byte, short string) []byte {
	var ev map[string]any
	if json.Unmarshal(body, &ev) != nil {
		return body
	}
	data, _ := ev["data"].(map[string]any)
	if data == nil {
		return body
	}
	if c, ok := data["client"].(map[string]any); ok {
		c["ip"] = short
		delete(c, "port")
	}
	delete(data, "session_id")
	b, err := json.Marshal(ev)
	if err != nil {
		return body
	}
	return b
}

func (s *Server) privacyDelete(w http.ResponseWriter, r *http.Request) {
	var req PrivacyDeleteRequest
	if !decode(w, r, &req) {
		return
	}
	if !req.Confirm {
		invalid(w, "Bestätige das Löschen.", FieldError{Pointer: "/confirm", Detail: "muss true sein"})
		return
	}
	ip, ok := parseIP(w, req.IP, "/ip")
	if !ok {
		return
	}
	// Art. 17 also lifts a running block, kept ones included (D29
	// amendment). The blocks a group holds of this client end with the
	// erasure: their lifts are noted in the transaction that erases, and no
	// block of the group starts between that and the end of the block here.
	var res *store.DeleteResult
	erase := func(lifts []string) (err error) {
		if res, err = s.St.DeleteIP(r.Context(), ip.String(), req.KeepIncidents, TruncateBody, lifts...); err == nil && s.Behaviour != nil {
			s.Behaviour.Forget(ip)
		}
		return err
	}
	var err error
	if s.ClientBlocks != nil {
		err = s.ClientBlocks(ip, erase)
	} else {
		err = erase(nil)
	}
	if err != nil {
		s.internal(w, err)
		return
	}
	if xs, err := s.St.ActiveExceptions(r.Context(), s.now()); err == nil && s.Gate != nil {
		s.Gate.Exceptions.Load(xs)
	}
	s.reloadAllow(r.Context())
	erased := 0
	if s.Requests != nil {
		if erased, err = s.Requests.ForgetIP(r.Context(), ip); err != nil {
			s.internal(w, err)
			return
		}
	}
	out := PrivacyDeleteResult{IP: ip.String(), DeletedEvents: res.Events, DeletedSessions: res.Sessions, DeletedAllowlistEntries: res.Allowlist, ErasedRequests: erased}
	if s.Erased != nil {
		out.Nodes = s.Erased(r.Context(), ip, req.KeepIncidents).bounded()
	}
	writeJSON(w, 200, out)
}
