package agentapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	contractapi "github.com/deutschland-schild/schild/contract/agentapi"
)

// ErrExceptionRefused wraps the reason of a refused exception; the code is the
// problem code of the answer.
type ErrExceptionRefused struct {
	Code   string
	Status int
	Detail string
}

func (e *ErrExceptionRefused) Error() string { return e.Code + ": " + e.Detail }

// ExceptionDeps are the rule exception writes (D54), implemented by the app.
type ExceptionDeps struct {
	List   func(ctx context.Context) []contractapi.RuleException
	Create func(ctx context.Context, req contractapi.ExceptionRequest, tokenID, label string) (contractapi.RuleException, error)
	// Remove reports false for an unknown id or a rule the exception does not
	// hold. With rules it takes only those out (D86).
	Remove func(ctx context.Context, id int, rules []string, reason, tokenID, label string) (bool, error)
}

func (s *Server) listExceptions(w http.ResponseWriter, r *http.Request) {
	if s.Exceptions == nil {
		Problem(w, http.StatusNotFound, "not_found", "Rule exceptions are not available on this gateway.")
		return
	}
	writeJSON(w, contractapi.ExceptionList{Items: s.Exceptions.List(r.Context()), Max: contractapi.MaxExceptions})
}

// exceptionWriter checks the scope and returns the token of a write.
func (s *Server) exceptionWriter(w http.ResponseWriter, r *http.Request, op string) *callInfo {
	ci, _ := r.Context().Value(ctxKey{}).(*callInfo)
	if ci == nil {
		Problem(w, http.StatusForbidden, "forbidden", "Not part of the agent API.")
		return nil
	}
	if !contractapi.AllowsWrite(ci.token.Scope, op) {
		Problem(w, http.StatusForbidden, contractapi.CodeScopeRequired, "This token may not set exceptions. Create one on the host: schild token add --scope exceptions:write --expires 90d --label NAME")
		return nil
	}
	if s.Exceptions == nil {
		Problem(w, http.StatusNotFound, "not_found", "Rule exceptions are not available on this gateway.")
		return nil
	}
	return ci
}

func readExceptionBody(w http.ResponseWriter, r *http.Request, v any) bool {
	body, err := io.ReadAll(io.LimitReader(r.Body, contractapi.MaxExceptionBody+1))
	if err != nil || len(body) > contractapi.MaxExceptionBody || r.Header.Get("Content-Type") != "application/json" {
		Problem(w, http.StatusBadRequest, "invalid", "Send application/json, at most 2 KiB.")
		return false
	}
	if json.Unmarshal(body, v) != nil {
		Problem(w, http.StatusBadRequest, "invalid", "The body is not valid JSON of this operation.")
		return false
	}
	return true
}

func refuseException(w http.ResponseWriter, err error) {
	var ref *ErrExceptionRefused
	if errors.As(err, &ref) {
		Problem(w, ref.Status, ref.Code, ref.Detail)
		return
	}
	Problem(w, http.StatusInternalServerError, "internal", "The exception could not be stored. Nothing changed.")
}

func (s *Server) createException(w http.ResponseWriter, r *http.Request) {
	ci := s.exceptionWriter(w, r, contractapi.OpCreateException)
	if ci == nil {
		return
	}
	var req contractapi.ExceptionRequest
	if !readExceptionBody(w, r, &req) {
		return
	}
	if req.Repository == "local" {
		Problem(w, http.StatusConflict, contractapi.CodeNotSupported, "Local rules get no exception: they are the operator's own file in rules.d.")
		return
	}
	if !contractapi.ValidException(req) || !validReason(req.Reason) {
		Problem(w, http.StatusBadRequest, "invalid", fmt.Sprintf("Name website, path, target (ARGS:name, REQUEST_COOKIES:name or REQUEST_HEADERS:name, no whole collection), repository crs or crowdsec, 1 to %d of its rule ids (CRS detection rules 910000 to 948999, crowdsec base ids) and a reason.", contractapi.MaxExceptionRules))
		return
	}
	req.Reason = contractapi.Sanitize(req.Reason, contractapi.MaxReason)
	ex, err := s.Exceptions.Create(r.Context(), req, ci.token.ID, ci.token.Label)
	if err != nil {
		refuseException(w, err)
		return
	}
	writeJSON(w, ex)
}

func (s *Server) removeException(w http.ResponseWriter, r *http.Request) {
	ci := s.exceptionWriter(w, r, contractapi.OpRemoveException)
	if ci == nil {
		return
	}
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		Problem(w, http.StatusNotFound, "not_found", "No exception with this id.")
		return
	}
	var req contractapi.ExceptionRemoveRequest
	if !readExceptionBody(w, r, &req) {
		return
	}
	if !validReason(req.Reason) {
		Problem(w, http.StatusBadRequest, "invalid", "The reason has at most 300 characters and no control characters.")
		return
	}
	if !contractapi.ValidRuleList(req.Rules) {
		Problem(w, http.StatusBadRequest, "invalid", fmt.Sprintf("rules names 1 to %d rule ids of the exception, each once; leave it out to remove the whole exception.", contractapi.MaxExceptionRules))
		return
	}
	ok, err := s.Exceptions.Remove(r.Context(), id, req.Rules, contractapi.Sanitize(req.Reason, contractapi.MaxReason), ci.token.ID, ci.token.Label)
	if err != nil {
		refuseException(w, err)
		return
	}
	if !ok {
		Problem(w, http.StatusNotFound, "not_found", "No exception with this id, or it does not hold these rules (see listAgentExceptions).")
		return
	}
	writeJSON(w, contractapi.ExceptionList{Items: s.Exceptions.List(r.Context()), Max: contractapi.MaxExceptions})
}

// hintWindow bounds listAgentFalsePositiveHints: the request ring keeps 48 h.
const hintWindow = 48 * time.Hour

func (s *Server) listHints(w http.ResponseWriter, r *http.Request) {
	if s.ringOff(w) {
		return
	}
	from, to, ok := window(w, r, hintWindow)
	if !ok {
		return
	}
	site, ok := s.siteParam(w, r)
	if !ok {
		return
	}
	out, err := s.Hints(r.Context(), site, from, to)
	if err != nil {
		Problem(w, http.StatusInternalServerError, "internal", "The request ring could not be read.")
		return
	}
	writeJSON(w, out)
}
