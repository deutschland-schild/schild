package dashboard

import (
	"context"
	"errors"
	"net/http"

	cc "github.com/deutschland-schild/schild/contract/crawlers"
)

// CrawlerFuncs connect the dashboard with crawler control (D57, MVP-29).
// Get and Set answer an error for an unknown website; Set answers a
// *cc.FieldError for an invalid policy (Field "website": not every request
// of the website runs through schild).
type CrawlerFuncs struct {
	Get func(website string) (cc.State, error)
	Set func(ctx context.Context, website string, in cc.Input, user string) (cc.State, error)
}

func (s *Server) crawlerRoutes(a func(string, http.HandlerFunc)) {
	a("GET "+apiPrefix+"/websites/{website}/crawlers", s.getCrawlerPolicy)
	a("PUT "+apiPrefix+"/websites/{website}/crawlers", s.setCrawlerPolicy)
}

func (s *Server) crawlersOff(w http.ResponseWriter) bool {
	if s.Crawlers.Get == nil {
		problem(w, http.StatusConflict, "conflict", "KI-Crawler lassen sich auf diesem Server nicht steuern.", nil)
		return true
	}
	return false
}

func (s *Server) getCrawlerPolicy(w http.ResponseWriter, r *http.Request) {
	ws, ok := s.website(w, r)
	if !ok || s.crawlersOff(w) {
		return
	}
	st, err := s.Crawlers.Get(ws.ID)
	if err != nil {
		s.internal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) setCrawlerPolicy(w http.ResponseWriter, r *http.Request) {
	ws, ok := s.website(w, r)
	if !ok || s.crawlersOff(w) {
		return
	}
	var in cc.Input
	if !decode(w, r, &in) {
		return
	}
	user := ""
	if se := sessionOf(r); se != nil {
		user = se.User
	}
	st, err := s.Crawlers.Set(r.Context(), ws.ID, in, user)
	var fe *cc.FieldError
	switch {
	case errors.As(err, &fe) && fe.Field == "website":
		problem(w, http.StatusConflict, "conflict", "Nicht jede Anfrage dieser Website läuft durch Schild. Eine Crawler-Regel würde nicht überall greifen.", nil)
		return
	case errors.As(err, &fe):
		ptr := "/" + fe.Field
		if fe.Key != "" {
			ptr += "/" + fe.Key
		}
		invalid(w, fe.Error(), FieldError{Pointer: ptr, Detail: fe.Msg})
		return
	case err != nil:
		s.internal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, st)
}
