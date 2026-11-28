package dashboard

import (
	"context"
	"errors"
	"net/http"

	"github.com/deutschland-schild/schild/contract/access"
	"github.com/deutschland-schild/schild/gateway/internal/accesslock"
)

// AccessProtection is the access lock of a website in the API (D56).
type AccessProtection struct {
	Scope       string   `json:"scope"`
	Paths       []string `json:"paths,omitempty"`
	Except      []string `json:"except,omitempty"`
	Password    bool     `json:"password"`
	Addresses   []string `json:"addresses,omitempty"`
	OwnNetworks bool     `json:"own_networks"`
	Message     string   `json:"message"`
	UpdatedAt   string   `json:"updated_at"`
	Actor       string   `json:"actor"`
}

// MaintenanceMode is the maintenance mode of a website in the API (D98).
type MaintenanceMode struct {
	On        bool   `json:"on"`
	Message   string `json:"message"`
	UpdatedAt string `json:"updated_at,omitempty"`
	Actor     string `json:"actor,omitempty"`
}

// MaintenanceInput is the body of setMaintenance.
type MaintenanceInput struct {
	On      bool   `json:"on"`
	Message string `json:"message,omitempty"`
}

// AccessProtectionState is getAccessProtection, setAccessProtection and
// setMaintenance.
type AccessProtectionState struct {
	Website     string            `json:"website"`
	Protection  *AccessProtection `json:"protection"`
	Maintenance MaintenanceMode   `json:"maintenance"`
}

// AccessProtectionInput is the body of setAccessProtection.
type AccessProtectionInput struct {
	Scope          string   `json:"scope"`
	Paths          []string `json:"paths,omitempty"`
	Except         []string `json:"except,omitempty"`
	Password       *string  `json:"password,omitempty"`
	RemovePassword bool     `json:"remove_password,omitempty"`
	Addresses      []string `json:"addresses,omitempty"`
	OwnNetworks    bool     `json:"own_networks"`
	Message        string   `json:"message,omitempty"`
}

// AccessFuncs connect the dashboard with the access lock of the app.
type AccessFuncs struct {
	Entry  func(website string) *accesslock.Entry
	Set    func(ctx context.Context, website string, in AccessProtectionInput, user string) (*accesslock.Entry, error)
	Remove func(ctx context.Context, website, user string) error
	// Maintenance and SetMaintenance: the maintenance mode (D98); nil on a
	// gateway without it.
	Maintenance    func(website string) *accesslock.Maintenance
	SetMaintenance func(ctx context.Context, website string, on bool, message, user string) (*accesslock.Maintenance, error)
}

func (s *Server) accessRoutes(a func(string, http.HandlerFunc)) {
	a("GET "+apiPrefix+"/websites/{website}/access", s.getAccessProtection)
	a("PUT "+apiPrefix+"/websites/{website}/access", s.op("setAccessProtection", s.setAccessProtection))
	a("DELETE "+apiPrefix+"/websites/{website}/access", s.op("removeAccessProtection", s.removeAccessProtection))
	a("PUT "+apiPrefix+"/websites/{website}/maintenance", s.op("setMaintenance", s.setMaintenance))
}

func (s *Server) accessState(website string, e *accesslock.Entry) AccessProtectionState {
	st := AccessProtectionState{Website: website}
	if s.Access.Maintenance != nil {
		if m := s.Access.Maintenance(website); m != nil {
			st.Maintenance = MaintenanceMode{On: true, Message: m.Message, UpdatedAt: ts(m.UpdatedAt), Actor: m.Actor}
		}
	}
	if e == nil {
		return st
	}
	p := e.Protection
	st.Protection = &AccessProtection{Scope: p.Scope, Paths: p.Paths, Except: p.Except, Password: p.Password, Addresses: p.Addresses,
		OwnNetworks: p.OwnNetworks, Message: p.Message, UpdatedAt: ts(e.UpdatedAt), Actor: e.Actor}
	return st
}

func (s *Server) accessOff(w http.ResponseWriter) bool {
	if s.Access.Entry == nil {
		problem(w, http.StatusConflict, "conflict", "Der Passwortschutz ist auf diesem Server nicht verfügbar.", nil)
		return true
	}
	return false
}

func (s *Server) getAccessProtection(w http.ResponseWriter, r *http.Request) {
	ws, ok := s.website(w, r)
	if !ok || s.accessOff(w) {
		return
	}
	writeJSON(w, http.StatusOK, s.accessState(ws.ID, s.Access.Entry(ws.ID)))
}

// setMaintenance switches the maintenance mode of a website (D98).
func (s *Server) setMaintenance(w http.ResponseWriter, r *http.Request) {
	ws, ok := s.website(w, r)
	if !ok || s.accessOff(w) {
		return
	}
	if s.Access.SetMaintenance == nil {
		problem(w, http.StatusConflict, "conflict", "Der Wartungsmodus ist auf diesem Server nicht verfügbar.", nil)
		return
	}
	var in MaintenanceInput
	if !decode(w, r, &in) {
		return
	}
	user := ""
	if se := sessionOf(r); se != nil {
		user = se.User
	}
	_, err := s.Access.SetMaintenance(r.Context(), ws.ID, in.On, in.Message, user)
	var fe *access.FieldError
	switch {
	case errors.As(err, &fe) && fe.Field == "website":
		problem(w, http.StatusConflict, "conflict", "Nicht jede Anfrage dieser Website läuft durch Schild. Der Wartungsmodus würde nicht überall greifen.", nil)
		return
	case errors.As(err, &fe):
		invalid(w, fe.Error(), FieldError{Pointer: "/" + fe.Field, Detail: fe.Msg})
		return
	case err != nil:
		s.internal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, s.accessState(ws.ID, s.Access.Entry(ws.ID)))
}

func (s *Server) setAccessProtection(w http.ResponseWriter, r *http.Request) {
	ws, ok := s.website(w, r)
	if !ok || s.accessOff(w) {
		return
	}
	var in AccessProtectionInput
	if !decode(w, r, &in) {
		return
	}
	user := ""
	if se := sessionOf(r); se != nil {
		user = se.User
	}
	e, err := s.Access.Set(r.Context(), ws.ID, in, user)
	var fe *access.FieldError
	switch {
	case errors.As(err, &fe) && fe.Field == "website":
		problem(w, http.StatusConflict, "conflict", "Nicht jede Anfrage dieser Website läuft durch Schild. Der Passwortschutz würde nicht überall greifen.", nil)
		return
	case errors.As(err, &fe):
		invalid(w, fe.Error(), FieldError{Pointer: "/" + fe.Field, Detail: fe.Msg})
		return
	case err != nil:
		s.internal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, s.accessState(ws.ID, e))
}

func (s *Server) removeAccessProtection(w http.ResponseWriter, r *http.Request) {
	ws, ok := s.website(w, r)
	if !ok || s.accessOff(w) {
		return
	}
	user := ""
	if se := sessionOf(r); se != nil {
		user = se.User
	}
	if err := s.Access.Remove(r.Context(), ws.ID, user); err != nil {
		s.internal(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
