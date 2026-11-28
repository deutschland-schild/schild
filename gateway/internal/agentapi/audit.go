package agentapi

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"time"

	contractapi "github.com/deutschland-schild/schild/contract/agentapi"
	"github.com/deutschland-schild/schild/contract/audit"
	"github.com/deutschland-schild/schild/gateway/internal/auditlog"
	"github.com/deutschland-schild/schild/gateway/internal/clientip"
	"github.com/deutschland-schild/schild/gateway/internal/ruleset"
	"github.com/deutschland-schild/schild/gateway/internal/store"
)

// The audit log in the agent API (MVP-36, contracts/audit.md). A write
// carries the origin of its change in its context (the token, the address,
// the operation); the code that stores the change notes the entry there. A
// call that was refused is counted (contracts/audit.md section 5). A token
// writes at most audit.TokenEntriesPerHour entries an hour.

// OpListAudit is listAgentAudit.
const OpListAudit = "listAgentAudit"

// auditedWrite reports whether a write operation writes audit entries:
// every write but the ones the catalogue lists as not audited.
func auditedWrite(op string) bool {
	return op != contractapi.OpSyncFirewall && op != contractapi.OpTestRequest
}

// actionOf is the action an operation of the agent API writes, for a call
// that was refused: "" when it writes none.
var actionOf = func() map[string]string {
	m := map[string]string{}
	for _, a := range audit.Actions.Actions {
		for _, o := range a.Operations {
			if _, ok := m[o]; !ok {
				m[o] = a.Action
			}
		}
	}
	return m
}()

// peer is the address a call came from.
func peer(r *http.Request) string {
	p, _ := clientip.Peer(r.RemoteAddr)
	if !p.IsValid() {
		return ""
	}
	return p.String()
}

// origin is the origin of a change a token asks for.
func origin(r *http.Request, tok *store.AgentToken, op string) auditlog.Origin {
	return auditlog.Origin{Operation: auditlog.WayAgent + ":" + op, Actor: auditlog.Agent(tok.ID, tok.Label), Address: peer(r)}
}

// refusedCall counts a call that was refused: with the action it tried when
// it is a write, as a call of the API otherwise. tok is nil for a token
// that is unknown.
func (s *Server) refusedCall(r *http.Request, tok *store.AgentToken, op string) {
	c := auditlog.RefusedCall{Action: "agent_api.call", Operation: auditlog.WayAgent + ":any", Actor: auditlog.Actor{Kind: auditlog.WayAgent}, Address: peer(r)}
	if tok != nil {
		c.Actor = auditlog.Agent(tok.ID, tok.Label)
	}
	if a := actionOf[auditlog.WayAgent+":"+op]; a != "" && op != "" {
		c.Action, c.Operation = a, auditlog.WayAgent+":"+op
	}
	s.Audit.Refused(c)
}

// opOfWrite names the operation of a write call by its path, before the
// handler ran (a call refused for its rate has no handler).
func opOfWrite(r *http.Request) string {
	_, pattern := writeMux.Handler(r)
	return writeOps[pattern]
}

var (
	writeMux = http.NewServeMux()
	writeOps = map[string]string{}
)

// registerWrite notes the pattern of a write operation for opOfWrite.
func registerWrite(pattern, op string) {
	if _, ok := writeOps[pattern]; ok {
		return
	}
	writeOps[pattern] = op
	writeMux.HandleFunc(pattern, func(http.ResponseWriter, *http.Request) {})
}

// written answers an error of an entry that is written after its change (a
// change that is not in schild.db): the change stands, and the answer says
// so.
func (s *Server) written(w http.ResponseWriter, err error) bool {
	if err == nil {
		return true
	}
	if s.Log != nil {
		s.Log.Error("audit log: the entry of a change could not be written; the change stands", "err", err)
	}
	Problem(w, http.StatusInternalServerError, "audit_not_written", "The change is made, but its entry in the audit log could not be written. Details are in the server log.")
	return false
}

// entryOf starts the entry of the call of r from its origin.
func entryOf(r *http.Request, action string) auditlog.Entry {
	o, _ := auditlog.OriginOf(r.Context())
	return o.Entry(action)
}

// ruleFiles runs a change of the rules a repository loads (sync, reset).
// The rules are files, not rows of schild.db: the entry is written after
// the change and before the answer.
func (s *Server) ruleFiles(w http.ResponseWriter, r *http.Request, action string, change func(ctx context.Context, id string) (changed bool, err error)) {
	id := r.PathValue("repository")
	before, _ := s.Repos.Repository(id)
	changed, err := change(r.Context(), id)
	if err != nil {
		RuleProblem(w, err)
		return
	}
	if changed {
		after, _ := s.Repos.Repository(id)
		e := entryOf(r, action)
		e.Subject, e.Before, e.After = id, ruleSetState(before), ruleSetState(after)
		if !s.written(w, s.Audit.Write(r.Context(), e)) {
			return
		}
	}
	s.getRepository(w, r)
}

func ruleSetState(v ruleset.RepositoryView) map[string]any {
	m := map[string]any{"rules_loaded": v.Counts.Rules}
	if v.Crowdsec != nil {
		m["set"] = v.Crowdsec.SetSource
	}
	return m
}

var (
	auditActionRE   = regexp.MustCompile(`^[a-z][a-z_]*\.[a-z][a-z_]*$`)
	auditActorRE    = regexp.MustCompile(`^(tok|pk)_[0-9a-f]{12}$`)
	auditSubjectRE  = regexp.MustCompile(`^[a-z][a-z_]{0,31}$`)
	auditWebsiteRE  = regexp.MustCompile(`^[a-z0-9_][a-z0-9_.-]{0,252}$`)
	auditUUIDRE     = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	auditIncidentRE = regexp.MustCompile(`^[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}$`)
	auditTimeRE     = regexp.MustCompile(`^20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$`)
)

// AuditPage is the answer of listAgentAudit.
type AuditPage struct {
	Items      []map[string]any `json:"items"`
	NextCursor *string          `json:"next_cursor"`
}

// listAudit answers listAgentAudit: what was changed and by which token,
// newest first. An agent sees changes and credentials, without sign-ins,
// refused calls and privacy entries, and without names of people, sessions
// and the address of a call (audit.View): what an agent reads may leave the
// server.
func (s *Server) listAudit(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	bad := false
	str := func(name string, re *regexp.Regexp) string {
		v := q.Get(name)
		if v != "" && (len(v) > 253 || re != nil && !re.MatchString(v)) {
			bad = true
		}
		return v
	}
	at := func(name string) time.Time {
		v := q.Get(name)
		if v == "" {
			return time.Time{}
		}
		t, err := time.Parse("2006-01-02T15:04:05Z", v)
		if err != nil || !auditTimeRE.MatchString(v) {
			bad = true
		}
		return t
	}
	f := auditlog.Filter{From: at("from"), To: at("to"), Website: str("website", auditWebsiteRE), Action: str("action", auditActionRE),
		Actor: str("actor", auditActorRE), Subject: str("subject", auditSubjectRE), SubjectID: str("subject_id", nil),
		Event: str("event", auditUUIDRE), Incident: str("incident", auditIncidentRE)}
	switch c := q.Get("class"); c {
	case "":
	case audit.ClassChange, audit.ClassCredential:
		f.Class = c
	default:
		bad = true
	}
	switch way := q.Get("way"); way {
	case "", auditlog.WayDashboard, auditlog.WayAgent, auditlog.WayIntegration, auditlog.WayCLI, auditlog.WayConfig, auditlog.WaySystem:
		f.Way = way
	default:
		bad = true
	}
	limit := 50
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > contractapi.MaxRows {
			bad = true
		}
		limit = n
	}
	cursor := q.Get("cursor")
	if bad || len(cursor) > 64 {
		Problem(w, http.StatusBadRequest, "invalid", "A filter is not valid. Times are 2026-10-26T12:00:00Z, class is change or credential, limit is 1 to 200.")
		return
	}
	items, next, err := s.Audit.View(r.Context(), f, audit.ViewAgent, "", cursor, limit)
	if errors.Is(err, auditlog.ErrCursor) {
		Problem(w, http.StatusBadRequest, "invalid", "The cursor is not one of this list.")
		return
	}
	if err != nil {
		Problem(w, http.StatusInternalServerError, "internal", "The audit log could not be read.")
		return
	}
	page := AuditPage{Items: items}
	if page.Items == nil {
		page.Items = []map[string]any{}
	}
	if next != "" {
		page.NextCursor = &next
	}
	if c, ok := r.Context().Value(ctxKey{}).(*callInfo); ok {
		c.rows = len(page.Items)
	}
	writeJSON(w, page)
}
