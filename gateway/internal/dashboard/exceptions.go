package dashboard

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"unicode/utf8"

	contractapi "github.com/deutschland-schild/schild/contract/agentapi"
)

// ExceptionRefused is why an exception was not set or removed; the code is one
// of the agent API (contract/agentapi), the wording is the dashboard's.
type ExceptionRefused struct {
	Code   string
	Status int
}

func (e *ExceptionRefused) Error() string { return "rule exception refused: " + e.Code }

// exceptionRefusals words the refusals of createRuleException.
var exceptionRefusals = map[string]string{
	"not_found":                      "Diese Website gibt es hier nicht.",
	contractapi.CodeWebsiteNoHosts:   "Diese Website hat keine eigenen Adressen. Eine Ausnahme würde für jede Website dieses Gateways gelten.",
	contractapi.CodeUnknownRule:      "Mindestens eine dieser Regeln läuft auf diesem Gateway nicht. Prüf die Nummern unter Regeln.",
	contractapi.CodeExceptionCap:     fmt.Sprintf("Mehr als %d Ausnahmen hält ein Gateway nicht. Entfern zuerst eine, die du nicht mehr brauchst.", contractapi.MaxExceptions),
	contractapi.CodeExceptionRefused: "Die Regeln ließen sich mit dieser Ausnahme nicht bauen. Es gelten weiter die bisherigen Regeln.",
}

// listRuleExceptions shows the exceptions in force, set here or through the
// agent API (D83).
func (s *Server) listRuleExceptions(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.exceptionList(r))
}

func (s *Server) exceptionList(r *http.Request) contractapi.ExceptionList {
	items := []contractapi.RuleException{}
	if s.Exceptions != nil {
		items = s.Exceptions(r.Context())
	}
	return contractapi.ExceptionList{Items: items, Max: contractapi.MaxExceptions}
}

// exceptionReason: the operator says why, in one line.
func exceptionReason(reason string) bool {
	if reason == "" || utf8.RuneCountInString(reason) > contractapi.MaxReason {
		return false
	}
	for _, c := range reason {
		if c < 0x20 || c == 0x7f {
			return false
		}
	}
	return true
}

// exceptionFields names what is wrong with a request, field by field: each
// field is put into a request that is right otherwise and checked with the rule
// of the agent API (contractapi.ValidException).
func exceptionFields(req contractapi.ExceptionRequest) []FieldError {
	probe := func(with func(*contractapi.ExceptionRequest)) bool {
		x := contractapi.ExceptionRequest{Website: "w", Path: "/", Target: "ARGS:a", Repository: contractapi.ExceptionCRS, Rules: []string{"942100"}}
		with(&x)
		return contractapi.ValidException(x)
	}
	var errs []FieldError
	if !probe(func(x *contractapi.ExceptionRequest) { x.Website = req.Website }) {
		errs = append(errs, FieldError{Pointer: "/website", Detail: "fehlt"})
	}
	if !probe(func(x *contractapi.ExceptionRequest) { x.Path = req.Path }) {
		errs = append(errs, FieldError{Pointer: "/path", Detail: "beginnt mit / und nennt den genauen Pfad, {name} steht für einen Abschnitt"})
	}
	if !probe(func(x *contractapi.ExceptionRequest) { x.Target = req.Target }) {
		errs = append(errs, FieldError{Pointer: "/target", Detail: "ein benanntes Feld, Cookie oder Header, nicht alle auf einmal"})
	}
	if req.Repository != contractapi.ExceptionCRS && req.Repository != contractapi.ExceptionCrowdsec {
		errs = append(errs, FieldError{Pointer: "/repository", Detail: "crs oder crowdsec"})
	} else if !probe(func(x *contractapi.ExceptionRequest) { x.Repository, x.Rules = req.Repository, req.Rules }) {
		errs = append(errs, FieldError{Pointer: "/rules", Detail: fmt.Sprintf("1 bis %d Regelnummern dieser Quelle, jede nur einmal", contractapi.MaxExceptionRules)})
	}
	if !exceptionReason(req.Reason) {
		errs = append(errs, FieldError{Pointer: "/reason", Detail: fmt.Sprintf("eine Zeile, höchstens %d Zeichen", contractapi.MaxReason)})
	}
	return errs
}

func (s *Server) refuseException(w http.ResponseWriter, err error) {
	var ref *ExceptionRefused
	if !errors.As(err, &ref) {
		s.internal(w, err)
		return
	}
	detail := exceptionRefusals[ref.Code]
	if detail == "" {
		detail = "Das geht hier nicht."
	}
	problem(w, ref.Status, ref.Code, detail, nil)
}

// createRuleException sets an exception as the agent API does (D84), without a token.
func (s *Server) createRuleException(w http.ResponseWriter, r *http.Request) {
	var req contractapi.ExceptionRequest
	if !decode(w, r, &req) {
		return
	}
	if s.CreateException == nil {
		problem(w, http.StatusNotFound, "not_found", "Ausnahmen gibt es auf diesem Gateway nicht.", nil)
		return
	}
	if req.Repository == "local" {
		problem(w, http.StatusConflict, contractapi.CodeNotSupported, "Eigene Regeln bekommen keine Ausnahme: Du änderst sie direkt in deiner Datei.", nil)
		return
	}
	if errs := exceptionFields(req); len(errs) > 0 {
		invalid(w, "So lässt sich die Ausnahme nicht anlegen.", errs...)
		return
	}
	req.Reason = contractapi.Sanitize(req.Reason, contractapi.MaxReason)
	x, err := s.CreateException(r.Context(), req)
	if err != nil {
		s.refuseException(w, err)
		return
	}
	writeJSON(w, http.StatusOK, x)
}

// removeRuleException takes one back, whoever set it.
func (s *Server) removeRuleException(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil || s.RemoveException == nil {
		problem(w, http.StatusNotFound, "not_found", "Diese Ausnahme gibt es nicht.", nil)
		return
	}
	ok, err := s.RemoveException(r.Context(), id, nil)
	if err != nil {
		s.refuseException(w, err)
		return
	}
	if !ok {
		problem(w, http.StatusNotFound, "not_found", "Diese Ausnahme gibt es nicht mehr.", nil)
		return
	}
	writeJSON(w, http.StatusOK, s.exceptionList(r))
}

// removeRuleExceptionRule takes one rule out of an exception (D86); the
// exception stays for its other rules.
func (s *Server) removeRuleExceptionRule(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.PathValue("id"))
	rule := r.PathValue("rule")
	if err != nil || s.RemoveException == nil || !contractapi.ValidRuleList([]string{rule}) {
		problem(w, http.StatusNotFound, "not_found", "Diese Ausnahme gibt es nicht.", nil)
		return
	}
	ok, err := s.RemoveException(r.Context(), id, []string{rule})
	if err != nil {
		s.refuseException(w, err)
		return
	}
	if !ok {
		problem(w, http.StatusNotFound, "not_found", "Diese Regel ist in der Ausnahme nicht mehr enthalten.", nil)
		return
	}
	writeJSON(w, http.StatusOK, s.exceptionList(r))
}
