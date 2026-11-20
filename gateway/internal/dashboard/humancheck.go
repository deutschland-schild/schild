package dashboard

import (
	"context"
	"errors"
	"net/http"
	"time"

	hc "github.com/deutschland-schild/schild/contract/humancheck"
	"github.com/deutschland-schild/schild/gateway/internal/humancheck"
)

// HumanCheckPolicyView is the browser verification policy of a website in the API.
type HumanCheckPolicyView struct {
	Mode              string         `json:"mode"`
	UnderAttack       hc.UnderAttack `json:"under_attack"`
	UnderAttackActive bool           `json:"under_attack_active"`
	Except            []string       `json:"except,omitempty"`
	ClearanceTTLS     int            `json:"clearance_ttl_s"`
	Difficulty        int            `json:"difficulty"`
	UpdatedAt         string         `json:"updated_at,omitempty"`
	Actor             string         `json:"actor,omitempty"`
}

// HumanCheckState is the response of GET and PUT /websites/{website}/human-check.
type HumanCheckState struct {
	Website string               `json:"website"`
	Policy  HumanCheckPolicyView `json:"policy"`
	Counts  humancheck.Counters  `json:"counts"`
}

// HumanCheckInput is the request body of PUT /websites/{website}/human-check.
type HumanCheckInput struct {
	Mode          string         `json:"mode"`
	UnderAttack   hc.UnderAttack `json:"under_attack,omitempty"`
	Except        []string       `json:"except,omitempty"`
	ClearanceTTLS int            `json:"clearance_ttl_s,omitempty"`
	Difficulty    int            `json:"difficulty,omitempty"`
}

// HumanCheckFuncs connects the dashboard with the gateway's human check.
type HumanCheckFuncs struct {
	Entry  func(website string) *humancheck.Entry
	Counts func() humancheck.Counters
	Set    func(ctx context.Context, website string, in HumanCheckInput, user string) (*humancheck.Entry, error)
	Remove func(ctx context.Context, website, user string) error
}

func (s *Server) humanCheckRoutes(a func(string, http.HandlerFunc)) {
	a("GET "+apiPrefix+"/websites/{website}/human-check", s.getHumanCheck)
	a("PUT "+apiPrefix+"/websites/{website}/human-check", s.setHumanCheck)
	a("DELETE "+apiPrefix+"/websites/{website}/human-check", s.removeHumanCheck)
}

func humanCheckState(website string, e *humancheck.Entry, counts humancheck.Counters, now time.Time) HumanCheckState {
	p := hc.Policy{
		Website:       website,
		Mode:          hc.ModeOff,
		UnderAttack:   hc.UnderAttack{Scope: hc.UnderAttackOff},
		ClearanceTTLS: hc.DefaultClearanceS,
		Difficulty:    hc.DefaultDifficulty,
	}
	var updatedAt, actor string
	if e != nil {
		p = e.Policy
		if p.UnderAttack.Scope == "" {
			p.UnderAttack.Scope = hc.UnderAttackOff
		}
		if p.ClearanceTTLS == 0 {
			p.ClearanceTTLS = hc.DefaultClearanceS
		}
		if p.Difficulty == 0 {
			p.Difficulty = hc.DefaultDifficulty
		}
		updatedAt = ts(e.UpdatedAt)
		actor = e.Actor
	}
	return HumanCheckState{
		Website: website,
		Policy: HumanCheckPolicyView{
			Mode:              p.Mode,
			UnderAttack:       p.UnderAttack,
			UnderAttackActive: p.UnderAttack.Active(now),
			Except:            p.Except,
			ClearanceTTLS:     p.ClearanceTTLS,
			Difficulty:        p.Difficulty,
			UpdatedAt:         updatedAt,
			Actor:             actor,
		},
		Counts: counts,
	}
}

func (s *Server) humanCheckOff(w http.ResponseWriter) bool {
	if s.HumanCheck.Entry == nil {
		problem(w, http.StatusConflict, "conflict", "Die Browser-Prüfung ist auf diesem Server nicht verfügbar.", nil)
		return true
	}
	return false
}

func (s *Server) getHumanCheck(w http.ResponseWriter, r *http.Request) {
	ws, ok := s.website(w, r)
	if !ok || s.humanCheckOff(w) {
		return
	}
	var counts humancheck.Counters
	if s.HumanCheck.Counts != nil {
		counts = s.HumanCheck.Counts()
	}
	writeJSON(w, http.StatusOK, humanCheckState(ws.ID, s.HumanCheck.Entry(ws.ID), counts, s.now()))
}

func (s *Server) setHumanCheck(w http.ResponseWriter, r *http.Request) {
	ws, ok := s.website(w, r)
	if !ok || s.humanCheckOff(w) {
		return
	}
	var in HumanCheckInput
	if !decode(w, r, &in) {
		return
	}
	user := ""
	if se := sessionOf(r); se != nil {
		user = se.User
	}
	e, err := s.HumanCheck.Set(r.Context(), ws.ID, in, user)
	var fe *hc.FieldError
	switch {
	case errors.As(err, &fe):
		invalid(w, fe.Error(), FieldError{Pointer: "/" + fe.Field, Detail: fe.Msg})
		return
	case err != nil:
		s.internal(w, err)
		return
	}
	var counts humancheck.Counters
	if s.HumanCheck.Counts != nil {
		counts = s.HumanCheck.Counts()
	}
	writeJSON(w, http.StatusOK, humanCheckState(ws.ID, e, counts, s.now()))
}

func (s *Server) removeHumanCheck(w http.ResponseWriter, r *http.Request) {
	ws, ok := s.website(w, r)
	if !ok || s.humanCheckOff(w) {
		return
	}
	user := ""
	if se := sessionOf(r); se != nil {
		user = se.User
	}
	if err := s.HumanCheck.Remove(r.Context(), ws.ID, user); err != nil {
		s.internal(w, err)
		return
	}
	var counts humancheck.Counters
	if s.HumanCheck.Counts != nil {
		counts = s.HumanCheck.Counts()
	}
	writeJSON(w, http.StatusOK, humanCheckState(ws.ID, nil, counts, s.now()))
}
