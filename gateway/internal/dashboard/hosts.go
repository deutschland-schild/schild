package dashboard

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/deutschland-schild/schild/gateway/internal/hosts"
	"github.com/deutschland-schild/schild/gateway/internal/ratelog"
)

// Server section of the dashboard (contracts v0.3, MVP-11). Host reports
// are shown here only; they never go into signals, feedback or anything
// else that leaves the server.

func (s *Server) hostRoutes(a func(string, http.HandlerFunc)) {
	a("GET "+apiPrefix+"/hosts", s.listHosts)
	a("POST "+apiPrefix+"/hosts/local/check", s.runLocalCheck)
	a("GET "+apiPrefix+"/hosts/{host_id}", s.getHost)
	a("POST "+apiPrefix+"/hosts/{host_id}/findings/accept", s.acceptHostFinding)
	a("POST "+apiPrefix+"/hosts/{host_id}/findings/reopen", s.reopenHostFinding)
	a("GET "+apiPrefix+"/agents", s.listAgents)
	a("POST "+apiPrefix+"/agents/enrolments", s.createEnrolment)
	a("POST "+apiPrefix+"/agents/{agent_id}/confirm", s.confirmAgent)
	a("POST "+apiPrefix+"/agents/{agent_id}/revoke", s.revokeAgent)
}

// EnrolmentInput is the request of createEnrolment.
type EnrolmentInput struct {
	Label      string `json:"label,omitempty"`
	TTLMinutes int    `json:"ttl_minutes,omitempty"`
}

// AgentConfirm is the request of confirmAgent.
type AgentConfirm struct {
	Fingerprint string `json:"fingerprint"`
	Label       string `json:"label,omitempty"`
}

// AgentRevoke is the request of revokeAgent.
type AgentRevoke struct {
	Note string `json:"note,omitempty"`
}

// FindingAccept is the request of acceptHostFinding, FindingRef (without
// the note) the one of reopenHostFinding.
type FindingAccept struct {
	ID      string  `json:"id"`
	Subject *string `json:"subject,omitempty"`
	Note    string  `json:"note,omitempty"`
}

var (
	findingIDRe   = regexp.MustCompile(`^[a-z]+\.[a-z_]+$`)
	hostIDRe      = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	fingerprintRe = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

func hostProblem(w http.ResponseWriter, status int, code, title, detail string, errs []FieldError) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(Problem{Type: "https://schild.invalid/problems/" + code, Title: title, Status: status, Detail: detail, Code: code, Errors: errs})
}

func (s *Server) hostsOff(w http.ResponseWriter) bool {
	if s.Hosts == nil || !s.Hosts.Enabled() {
		problem(w, http.StatusNotFound, "not_found", "Der Server-Check ist nicht eingerichtet (host_check in schild.yaml).", nil)
		return true
	}
	return false
}

func (s *Server) serversSummary(ctx context.Context) *ServersSummary {
	if s.Hosts == nil || !s.Hosts.Enabled() {
		return nil
	}
	sum, err := s.Hosts.Summary(ctx)
	if err != nil {
		if s.Log != nil {
			ratelog.Warn(s.Log, "server card", "err", err)
		}
		return nil
	}
	// host_check is in every starter config (D100); until the check is set
	// up on the host there is nothing to sum up.
	if !sum.Reported && sum.Silent == 0 && (sum.PendingAgents == nil || *sum.PendingAgents == 0) {
		return nil
	}
	return &ServersSummary{Hosts: sum.Hosts, Silent: sum.Silent, Unreadable: sum.Unreadable, PendingAgents: sum.PendingAgents,
		Findings: SeverityCounts{Critical: sum.Findings.Critical, High: sum.Findings.High, Medium: sum.Findings.Medium, Low: sum.Findings.Low, Info: sum.Findings.Info}}
}

func pageParams(w http.ResponseWriter, r *http.Request) (string, int, bool) {
	limit := 50
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 500 {
			invalid(w, "limit muss zwischen 1 und 500 liegen.", FieldError{Pointer: "/limit", Detail: "1 bis 500"})
			return "", 0, false
		}
		limit = n
	}
	return r.URL.Query().Get("cursor"), limit, true
}

func (s *Server) listHosts(w http.ResponseWriter, r *http.Request) {
	if s.Hosts == nil || !s.Hosts.Enabled() {
		// Not configured: an empty page, so the dashboard can say how to set it up.
		writeJSON(w, 200, hosts.HostPage{Items: []hosts.HostSummary{}})
		return
	}
	cursor, limit, ok := pageParams(w, r)
	if !ok {
		return
	}
	status := r.URL.Query().Get("status")
	switch status {
	case "", "ok", "findings", "silent", "waiting", "revoked":
	default:
		invalid(w, "Unbekannter Status.", FieldError{Pointer: "/status", Detail: "ok, findings, silent, waiting oder revoked"})
		return
	}
	hs, err := s.Hosts.Hosts(r.Context())
	if err != nil {
		s.internal(w, err)
		return
	}
	var sel []hosts.HostSummary
	for _, h := range hs {
		if status == "" || h.Status == status {
			sel = append(sel, h)
		}
	}
	items, next, err := hosts.Page(sel, cursor, limit)
	if err != nil {
		invalid(w, "Ungültiger Cursor.", FieldError{Pointer: "/cursor", Detail: "ungültig"})
		return
	}
	writeJSON(w, 200, hosts.HostPage{Items: items, NextCursor: next})
}

func (s *Server) getHost(w http.ResponseWriter, r *http.Request) {
	if s.hostsOff(w) {
		return
	}
	id := r.PathValue("host_id")
	if !hostIDRe.MatchString(id) {
		problem(w, http.StatusNotFound, "not_found", "Diesen Server gibt es nicht.", nil)
		return
	}
	d, err := s.Hosts.Host(r.Context(), id)
	if errors.Is(err, hosts.ErrNotFound) {
		problem(w, http.StatusNotFound, "not_found", "Diesen Server gibt es nicht.", nil)
		return
	}
	if err != nil {
		s.internal(w, err)
		return
	}
	writeJSON(w, 200, d)
}

// findingInput reads and checks the body of accept and reopen.
func (s *Server) findingInput(w http.ResponseWriter, r *http.Request, withNote bool) (hostID, id, subject, note string, ok bool) {
	if s.hostsOff(w) {
		return
	}
	hostID = r.PathValue("host_id")
	if !hostIDRe.MatchString(hostID) {
		problem(w, http.StatusNotFound, "not_found", "Diesen Server gibt es nicht.", nil)
		return
	}
	var in FindingAccept
	if !decode(w, r, &in) {
		return
	}
	if len(in.ID) > 64 || !findingIDRe.MatchString(in.ID) {
		invalid(w, "Unbekannte Prüfung.", FieldError{Pointer: "/id", Detail: "Kennung einer Prüfung, zum Beispiel ports.public_service"})
		return
	}
	if in.Subject != nil {
		if subject = *in.Subject; subject == "" || len(subject) > 128 {
			invalid(w, "Der Gegenstand des Befunds ist leer oder zu lang.", FieldError{Pointer: "/subject", Detail: "1 bis 128 Zeichen"})
			return
		}
	}
	if !withNote && in.Note != "" {
		invalid(w, "Beim Öffnen gibt es keine Notiz.", FieldError{Pointer: "/note", Detail: "nicht erlaubt"})
		return
	}
	if utf8.RuneCountInString(in.Note) > 200 || strings.ContainsFunc(in.Note, unicode.IsControl) {
		invalid(w, "Die Notiz ist eine Zeile mit höchstens 200 Zeichen.", FieldError{Pointer: "/note", Detail: "eine Zeile, höchstens 200 Zeichen"})
		return
	}
	return hostID, in.ID, subject, strings.TrimSpace(in.Note), true
}

func (s *Server) acceptHostFinding(w http.ResponseWriter, r *http.Request) {
	hostID, id, subject, note, ok := s.findingInput(w, r, true)
	if !ok {
		return
	}
	d, err := s.Hosts.AcceptFinding(r.Context(), hostID, id, subject, note)
	switch {
	case errors.Is(err, hosts.ErrNotFound):
		problem(w, http.StatusNotFound, "not_found", "Diesen Befund gibt es im neuesten Bericht nicht mehr. Lade die Seite neu.", nil)
	case errors.Is(err, hosts.ErrConflict):
		hostProblem(w, http.StatusConflict, "conflict", "Zu viele akzeptierte Befunde",
			"Für diesen Server sind schon 200 Befunde akzeptiert. Öffne erst welche wieder, die es nicht mehr braucht.", nil)
	case err != nil:
		s.internal(w, err)
	default:
		writeJSON(w, 200, d)
	}
}

func (s *Server) reopenHostFinding(w http.ResponseWriter, r *http.Request) {
	hostID, id, subject, _, ok := s.findingInput(w, r, false)
	if !ok {
		return
	}
	d, err := s.Hosts.ReopenFinding(r.Context(), hostID, id, subject)
	switch {
	case errors.Is(err, hosts.ErrNotFound):
		problem(w, http.StatusNotFound, "not_found", "Dieser Befund ist nicht als akzeptiert markiert.", nil)
	case err != nil:
		s.internal(w, err)
	default:
		writeJSON(w, 200, d)
	}
}

func (s *Server) runLocalCheck(w http.ResponseWriter, r *http.Request) {
	if s.hostsOff(w) {
		return
	}
	run, err := s.Hosts.RunLocalCheck(r.Context())
	switch {
	case errors.Is(err, hosts.ErrCheckRunning):
		hostProblem(w, http.StatusConflict, "check_running", "Prüfung läuft bereits",
			"Eine Prüfung ist schon angefordert oder läuft. Das Ergebnis erscheint hier, sobald sie fertig ist.", nil)
	case errors.Is(err, hosts.ErrCheckUnavailable):
		hostProblem(w, http.StatusServiceUnavailable, "check_unavailable", "Prüfung von hier aus nicht möglich",
			"Der Server-Check läuft außerhalb des Containers über den systemd-Timer (einmal am Tag). Sofort prüfen kannst du auf dem Server mit: sudo systemctl start schild-check.service. Ist er dort noch nicht eingerichtet: sudo schild check install", nil)
	case err != nil:
		s.internal(w, err)
	default:
		writeJSON(w, http.StatusAccepted, run)
	}
}

func (s *Server) listAgents(w http.ResponseWriter, r *http.Request) {
	if s.Hosts == nil || !s.Hosts.Enabled() {
		writeJSON(w, 200, hosts.AgentPage{Items: []hosts.Agent{}})
		return
	}
	cursor, limit, ok := pageParams(w, r)
	if !ok {
		return
	}
	status := r.URL.Query().Get("status")
	switch status {
	case "", "pending", "enrolled", "revoked":
	default:
		invalid(w, "Unbekannter Status.", FieldError{Pointer: "/status", Detail: "pending, enrolled oder revoked"})
		return
	}
	as, err := s.Hosts.Agents(r.Context(), status)
	if err != nil {
		s.internal(w, err)
		return
	}
	items, next, err := hosts.Page(as, cursor, limit)
	if err != nil {
		invalid(w, "Ungültiger Cursor.", FieldError{Pointer: "/cursor", Detail: "ungültig"})
		return
	}
	writeJSON(w, 200, hosts.AgentPage{Items: items, NextCursor: next})
}

func (s *Server) createEnrolment(w http.ResponseWriter, r *http.Request) {
	if s.hostsOff(w) {
		return
	}
	var in EnrolmentInput
	if !decode(w, r, &in) {
		return
	}
	if len(in.Label) > 64 || (in.TTLMinutes != 0 && (in.TTLMinutes < 5 || in.TTLMinutes > 1440)) {
		invalid(w, "Bezeichnung höchstens 64 Zeichen, Gültigkeit 5 bis 1440 Minuten.")
		return
	}
	e, err := s.Hosts.CreateEnrolment(r.Context(), in.Label, in.TTLMinutes, r.Host)
	if errors.Is(err, hosts.ErrAgentsDisabled) {
		hostProblem(w, http.StatusConflict, "conflict", "Agents sind nicht eingeschaltet",
			"Schalte zuerst host_check.agents.enabled in schild.yaml ein und starte schild neu.", nil)
		return
	}
	if err != nil {
		s.internal(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, e)
}

func (s *Server) agentError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, hosts.ErrNotFound):
		problem(w, http.StatusNotFound, "not_found", "Diesen Agent gibt es nicht.", nil)
	case errors.Is(err, hosts.ErrFingerprintMismatch):
		hostProblem(w, http.StatusConflict, "fingerprint_mismatch", "Fingerabdruck stimmt nicht",
			"Der Fingerabdruck passt nicht zum Schlüssel dieses Agents. Vergleich ihn noch einmal mit der Ausgabe von schild-agent enrol.",
			[]FieldError{{Pointer: "/fingerprint", Detail: "stimmt nicht"}})
	case errors.Is(err, hosts.ErrConfigAgent):
		hostProblem(w, http.StatusConflict, "config_agent", "Agent steht in schild.yaml",
			"Dieser Agent ist in schild.yaml eingetragen. Widerrufe ihn dort mit revoked: true.", nil)
	case errors.Is(err, hosts.ErrConflict):
		problem(w, http.StatusConflict, "conflict", "Der Agent ist nicht mehr in dem Zustand, den du gesehen hast. Lade die Liste neu.", nil)
	default:
		s.internal(w, err)
	}
}

func (s *Server) confirmAgent(w http.ResponseWriter, r *http.Request) {
	if s.hostsOff(w) {
		return
	}
	var in AgentConfirm
	if !decode(w, r, &in) {
		return
	}
	if !fingerprintRe.MatchString(in.Fingerprint) || len(in.Label) > 64 {
		invalid(w, "Der Fingerabdruck hat die Form sha256:<64 Hex-Zeichen>.", FieldError{Pointer: "/fingerprint", Detail: "sha256:<64 hex>"})
		return
	}
	a, err := s.Hosts.Confirm(r.Context(), r.PathValue("agent_id"), in.Fingerprint, in.Label)
	if err != nil {
		s.agentError(w, err)
		return
	}
	writeJSON(w, 200, a)
}

func (s *Server) revokeAgent(w http.ResponseWriter, r *http.Request) {
	if s.hostsOff(w) {
		return
	}
	var in AgentRevoke
	if !decode(w, r, &in) {
		return
	}
	if len(in.Note) > 500 {
		invalid(w, "Die Notiz darf höchstens 500 Zeichen haben.", FieldError{Pointer: "/note", Detail: "höchstens 500 Zeichen"})
		return
	}
	a, err := s.Hosts.Revoke(r.Context(), r.PathValue("agent_id"), in.Note)
	if err != nil {
		s.agentError(w, err)
		return
	}
	writeJSON(w, 200, a)
}
