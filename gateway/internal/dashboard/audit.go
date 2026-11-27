package dashboard

import (
	"context"
	"errors"
	"net/http"
	"regexp"

	"github.com/deutschland-schild/schild/contract/audit"
	"github.com/deutschland-schild/schild/gateway/internal/auditlog"
	"github.com/deutschland-schild/schild/gateway/internal/store"
)

// The audit log in the dashboard (MVP-36, contracts/audit.md). Every
// writing operation notes its entry in the transaction of its change:
// s.Audit.Tx around the calls of the store, or s.Audit.OnChange when the
// app writes the value. GET /audit reads the log.

// who is the actor of a dashboard call: the user and the short id of the
// session, never its token.
func (s *Server) who(r *http.Request) auditlog.Actor {
	if se := sessionOf(r); se != nil {
		return auditlog.Dashboard(se.User, auditlog.SessionID(se.TokenHash))
	}
	return auditlog.Actor{Kind: auditlog.WayDashboard}
}

// from is the address a call came from, as the dashboard resolves it.
func (s *Server) from(r *http.Request) string {
	ip, _ := s.caller(r)
	if !ip.IsValid() {
		return ""
	}
	return ip.String()
}

// entry starts the entry of an operation of the dashboard API.
func (s *Server) entry(r *http.Request, action, operation string) auditlog.Entry {
	return auditlog.Entry{Action: action, Operation: auditlog.WayDashboard + ":" + operation, Actor: s.who(r), Address: s.from(r), Time: s.now()}
}

// refused counts a call that was refused: a failed sign-in, a wrong setup
// code or current password, too many attempts. It names no user: what was
// typed there may be a password.
func (s *Server) refused(r *http.Request, action, operation string) {
	s.Audit.Refused(auditlog.RefusedCall{Action: action, Operation: auditlog.WayDashboard + ":" + operation,
		Actor: auditlog.Actor{Kind: auditlog.WayDashboard}, Address: s.from(r)})
}

// written answers an error of a change whose entry is written after it (a
// change that is not in schild.db): the change stands, and the answer says
// so.
func (s *Server) written(w http.ResponseWriter, err error) bool {
	if err == nil {
		return true
	}
	if s.Log != nil {
		s.Log.Error("audit log: the entry of a change could not be written; the change stands", "err", err)
	}
	problem(w, http.StatusInternalServerError, "audit_not_written", "Die Änderung ist gemacht, ihr Eintrag im Protokoll ließ sich aber nicht schreiben. Details stehen im Server-Log.", nil)
	return false
}

var (
	auditActionRE   = regexp.MustCompile(`^[a-z][a-z_]*\.[a-z][a-z_]*$`)
	auditActorRE    = regexp.MustCompile(`^(tok|pk)_[0-9a-f]{12}$`)
	auditSubjectRE  = regexp.MustCompile(`^[a-z][a-z_]{0,31}$`)
	auditSessionRE  = regexp.MustCompile(`^[0-9a-f]{8}$`)
	auditUUIDRE     = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	auditIncidentRE = regexp.MustCompile(`^[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}$`)
	auditWebsiteRE  = regexp.MustCompile(`^[a-z0-9_][a-z0-9_.-]*$`)
)

// AuditPage is the answer of listAudit.
type AuditPage struct {
	Items      []map[string]any `json:"items"`
	NextCursor *string          `json:"next_cursor"`
}

// listAudit answers GET /audit: the audit log, newest first.
func (s *Server) listAudit(w http.ResponseWriter, r *http.Request) {
	q := &query{r: r}
	f := auditlog.Filter{
		From: q.time("from"), To: q.time("to"),
		Website:   q.str("website", 253, auditWebsiteRE),
		Class:     q.enum("class", audit.ClassChange, audit.ClassCredential, audit.ClassPrivacy, audit.ClassAccess, audit.ClassRefused),
		Action:    q.str("action", 64, auditActionRE),
		Way:       q.enum("way", auditlog.WayDashboard, auditlog.WayAgent, auditlog.WayIntegration, auditlog.WayCLI, auditlog.WayConfig, auditlog.WaySystem),
		Actor:     q.str("actor", 16, auditActorRE),
		Subject:   q.str("subject", 32, auditSubjectRE),
		SubjectID: q.str("subject_id", 253, nil),
		Session:   q.str("session", 8, auditSessionRE),
		Event:     q.str("event", 36, auditUUIDRE),
		Incident:  q.str("incident", 9, auditIncidentRE),
	}
	limit := q.limit()
	cursor := r.URL.Query().Get("cursor")
	if len(cursor) > 64 {
		q.errs = append(q.errs, FieldError{Pointer: "#/query/cursor", Detail: "ungültig"})
	}
	if q.failed(w) {
		return
	}
	items, next, err := s.Audit.List(r.Context(), f, cursor, limit)
	if err != nil {
		if errors.Is(err, auditlog.ErrCursor) {
			invalid(w, "Ungültige Anfrage.", FieldError{Pointer: "#/query/cursor", Detail: "ungültig"})
			return
		}
		s.internal(w, err)
		return
	}
	page := AuditPage{Items: items, NextCursor: strp(next)}
	if page.Items == nil {
		page.Items = []map[string]any{}
	}
	writeJSON(w, 200, page)
}

// op names the operation of a writing route (its operationId in the API
// document) and puts the origin of its change into the context of every
// call. The names are what the audit log is checked against: every writing
// route is an operation of an action, or one that is listed as not audited
// (contracts/audit-actions.json).
func (s *Server) op(operation string, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h(w, r.WithContext(context.WithValue(s.origin(r, operation), opKey{}, operation)))
	}
}

type opKey struct{}

// opOf is the operation of a call.
func opOf(r *http.Request) string {
	o, _ := r.Context().Value(opKey{}).(string)
	return o
}

// origin puts the origin of a change into the context of a call: the
// operation, the session and the address. The app notes the entry where it
// makes the change (auditlog.Origin).
func (s *Server) origin(r *http.Request, operation string) context.Context {
	return auditlog.WithOrigin(r.Context(), s.originOf(r, operation))
}

func (s *Server) originOf(r *http.Request, operation string) auditlog.Origin {
	return auditlog.Origin{Operation: auditlog.WayDashboard + ":" + operation, Actor: s.who(r), Address: s.from(r)}
}

// allowState is an own IP as the audit log records it (allowlist.add,
// allowlist.remove).
func allowState(e *store.AllowEntry) map[string]any {
	if e == nil {
		return nil
	}
	m := map[string]any{"label": e.Label, "level": e.Level, "expires": e.Expires}
	if e.Expires == "" {
		m["expires"] = "never"
	}
	for k, v := range map[string]string{"ip": e.IP, "cidr": e.CIDR, "host": e.Host} {
		if v != "" {
			m[k] = v
		}
	}
	return m
}

// AllowState is allowState for the other ways an own IP is set or removed
// (commands on the host, the end of its time).
func AllowState(e *store.AllowEntry) map[string]any { return allowState(e) }

// auditWebsite is the website of an entry: the site of an event or
// incident when it is the id of a website, "" for what is global.
func auditWebsite(site string) string {
	if len(site) > 253 || !auditWebsiteRE.MatchString(site) {
		return ""
	}
	return site
}
