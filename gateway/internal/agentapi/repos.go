package agentapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"

	contractapi "github.com/deutschland-schild/schild/contract/agentapi"
	"github.com/deutschland-schild/schild/contract/rules"
	"github.com/deutschland-schild/schild/gateway/internal/hub"
	"github.com/deutschland-schild/schild/gateway/internal/ruleset"
)

// The rule repositories and their rules (D73): the same service and shapes
// as the dashboard's, with bearer tokens instead of a session. Every write
// checks its scope itself, so a refusal is in the call log.

func (s *Server) reposOff(w http.ResponseWriter) bool {
	if s.Repos == nil {
		Problem(w, http.StatusNotFound, "not_found", "The rule repositories are not available on this gateway.")
		return true
	}
	return false
}

// RuleProblem answers an error of the rule service with its problem code.
func RuleProblem(w http.ResponseWriter, err error) {
	var se *ruleset.SyncError
	switch {
	case errors.Is(err, ruleset.ErrNotFound):
		Problem(w, http.StatusNotFound, "not_found", "No such rule repository or rule, see listAgentRuleRepositories and listAgentRules.")
	case errors.Is(err, ruleset.ErrNotSupported):
		Problem(w, http.StatusConflict, "not_supported", "This repository has no such operation: crs has no sync, only crowdsec has a reset.")
	case errors.Is(err, ruleset.ErrConfigLimit):
		Problem(w, http.StatusConflict, "config_limit", "This rule is disabled in schild.yaml and can only be enabled there.")
	case errors.Is(err, hub.ErrNoSnapshot):
		Problem(w, http.StatusConflict, "no_snapshot", "This image ships no crowdsec rules to go back to.")
	case errors.As(err, &se):
		Problem(w, http.StatusConflict, "sync_refused", "The rules did not load, the running rules stay: "+se.Code+": "+se.Err.Error())
	case errors.Is(err, ruleset.ErrInvalid):
		Problem(w, http.StatusBadRequest, "invalid", "The state is off, detect or block.")
	case errors.Is(err, ruleset.ErrBusy):
		w.Header().Set("Retry-After", "2")
		Problem(w, http.StatusServiceUnavailable, "busy", "Other rule changes kept running; try again.")
	default:
		Problem(w, http.StatusInternalServerError, "internal", "That did not work. The running rules stay.")
	}
}

// ruleWriter checks the scope of a rule write and returns its actor.
func (s *Server) ruleWriter(w http.ResponseWriter, r *http.Request, op string) (ruleset.Actor, bool) {
	ci, _ := r.Context().Value(ctxKey{}).(*callInfo)
	if ci == nil {
		Problem(w, http.StatusForbidden, "forbidden", "Not part of the agent API.")
		return ruleset.Actor{}, false
	}
	if !contractapi.AllowsWrite(ci.token.Scope, op) {
		need := contractapi.WriteOperations[op]
		Problem(w, http.StatusForbidden, contractapi.CodeScopeRequired, "This token may not do this. Create one on the host: schild token add --scope "+need+" --expires 90d --label NAME")
		return ruleset.Actor{}, false
	}
	if s.reposOff(w) {
		return ruleset.Actor{}, false
	}
	return ruleset.Actor{Kind: rules.ByAgent, TokenID: ci.token.ID, Label: ci.token.Label}, true
}

// readWriteBody reads a JSON body of at most 1 KiB, strict. An empty body
// is an empty object.
func readWriteBody(w http.ResponseWriter, r *http.Request, v any) bool {
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	body, rerr := io.ReadAll(io.LimitReader(r.Body, maxWriteBody+1))
	if rerr != nil || len(body) > maxWriteBody {
		Problem(w, http.StatusBadRequest, "invalid", "The body is limited to 1 KiB.")
		return false
	}
	if len(bytes.TrimSpace(body)) == 0 {
		body = []byte("{}")
	} else if err != nil || mt != "application/json" {
		Problem(w, http.StatusBadRequest, "invalid", "Content-Type must be application/json.")
		return false
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if dec.Decode(v) != nil {
		Problem(w, http.StatusBadRequest, "invalid", "The body is not valid JSON of this operation.")
		return false
	}
	return true
}

// sanitizeRule cleans the text of a rule an agent reads.
func sanitizeRule(x ruleset.Rule) ruleset.Rule {
	x.Msg = contractapi.Sanitize(x.Msg, contractapi.MaxRuleMsg)
	if x.Crowdsec != nil {
		v := *x.Crowdsec
		v.Label, v.Description = contractapi.Sanitize(v.Label, 128), contractapi.Sanitize(v.Description, 512)
		x.Crowdsec = &v
	}
	return x
}

func sanitizeDetail(d ruleset.RuleDetail) ruleset.RuleDetail {
	d.Rule = sanitizeRule(d.Rule)
	d.SecLang = contractapi.Sanitize(d.SecLang, 65536)
	for i := range d.Decisions {
		d.Decisions[i].Note = contractapi.Sanitize(d.Decisions[i].Note, ruleset.MaxNote)
	}
	return d
}

func (s *Server) listRepositories(w http.ResponseWriter, _ *http.Request) {
	if s.reposOff(w) {
		return
	}
	writeJSON(w, s.Repos.Repositories())
}

func (s *Server) getRepository(w http.ResponseWriter, r *http.Request) {
	if s.reposOff(w) {
		return
	}
	v, err := s.Repos.Repository(r.PathValue("repository"))
	if err != nil {
		RuleProblem(w, err)
		return
	}
	writeJSON(w, v)
}

func (s *Server) updateRepository(w http.ResponseWriter, r *http.Request) {
	a, ok := s.ruleWriter(w, r, contractapi.OpUpdateRuleRepository)
	if !ok {
		return
	}
	var p ruleset.RepositoryPatch
	if !readWriteBody(w, r, &p) {
		return
	}
	state, reset, ok := p.Check()
	if !ok {
		Problem(w, http.StatusBadRequest, "invalid", `The body must be {"state": "off|detect|block"} or {"reset_state": true}.`)
		return
	}
	v, err := s.Repos.SetState(r.Context(), r.PathValue("repository"), state, reset, a)
	if err != nil {
		RuleProblem(w, err)
		return
	}
	writeJSON(w, v)
}

func (s *Server) syncRepository(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.ruleWriter(w, r, contractapi.OpSyncRuleRepository); !ok {
		return
	}
	id := r.PathValue("repository")
	if _, err := s.Repos.Sync(r.Context(), id); err != nil {
		RuleProblem(w, err)
		return
	}
	s.getRepository(w, r)
}

func (s *Server) resetRepository(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.ruleWriter(w, r, contractapi.OpResetRuleRepository); !ok {
		return
	}
	if err := s.Repos.Reset(r.Context(), r.PathValue("repository")); err != nil {
		RuleProblem(w, err)
		return
	}
	s.getRepository(w, r)
}

func (s *Server) listRules(w http.ResponseWriter, r *http.Request) {
	if s.reposOff(w) {
		return
	}
	q := r.URL.Query()
	f := ruleset.Filter{Repository: q.Get("repository"), Status: q.Get("status")}
	if f.Repository != "" && !rules.KnownRepository(f.Repository) || f.Status != "" && !validStatus(f.Status) {
		Problem(w, http.StatusBadRequest, "invalid", "repository is crs, crowdsec or local; status is active, settling or disabled.")
		return
	}
	limit := contractapi.MaxRows
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > contractapi.MaxRows {
			Problem(w, http.StatusBadRequest, "invalid", "limit is 1 to 200.")
			return
		}
		limit = n
	} else {
		limit = 50
	}
	page, err := ruleset.Page(s.Repos.Rules(f), q.Get("cursor"), limit)
	if err != nil {
		Problem(w, http.StatusBadRequest, "invalid", "The cursor is not one of this list.")
		return
	}
	for i := range page.Items {
		page.Items[i] = sanitizeRule(page.Items[i])
	}
	writeJSON(w, page)
}

func validStatus(s string) bool {
	for _, x := range rules.Statuses {
		if x == s {
			return true
		}
	}
	return false
}

func (s *Server) getRule(w http.ResponseWriter, r *http.Request) {
	if s.reposOff(w) {
		return
	}
	d, err := s.Repos.Rule(r.PathValue("repository"), r.PathValue("rule"))
	if err != nil {
		RuleProblem(w, err)
		return
	}
	writeJSON(w, sanitizeDetail(d))
}

func (s *Server) updateRule(w http.ResponseWriter, r *http.Request) {
	a, ok := s.ruleWriter(w, r, contractapi.OpUpdateRule)
	if !ok {
		return
	}
	var p ruleset.RulePatch
	if !readWriteBody(w, r, &p) {
		return
	}
	if p.Disabled == nil || len(p.Note) > ruleset.MaxNote {
		Problem(w, http.StatusBadRequest, "invalid", `The body is {"disabled": true|false, "note": "..."} with a note of at most 500 characters.`)
		return
	}
	d, err := s.Repos.SetDisabled(r.Context(), r.PathValue("repository"), r.PathValue("rule"), *p.Disabled,
		contractapi.Sanitize(p.Note, ruleset.MaxNote), a)
	if err != nil {
		RuleProblem(w, err)
		return
	}
	writeJSON(w, sanitizeDetail(d))
}
