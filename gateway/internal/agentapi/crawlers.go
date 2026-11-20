package agentapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"

	contractapi "github.com/deutschland-schild/schild/contract/agentapi"
	cc "github.com/deutschland-schild/schild/contract/crawlers"
)

// CrawlerDeps are crawler control (D57, MVP-29), implemented by the app.
// Set answers ErrUnknownWebsite for an unknown website and a
// *cc.FieldError for a refused change (Field "website": not every request
// of the website runs through schild).
type CrawlerDeps struct {
	List func(site string) cc.AgentList
	Set  func(ctx context.Context, req cc.SetRequest, tokenID, label string) (cc.AgentPolicy, error)
	// Known reports whether a website id exists.
	Known func(website string) bool
}

// ErrUnknownWebsite: no website with this id.
var ErrUnknownWebsite = errors.New("unknown website")

func (s *Server) getCrawlers(w http.ResponseWriter, r *http.Request) {
	if s.Crawlers == nil {
		Problem(w, http.StatusNotFound, "not_found", "Crawler control is not available on this gateway.")
		return
	}
	site := r.URL.Query().Get("site")
	if site != "" && (s.Crawlers.Known == nil || !s.Crawlers.Known(site)) {
		Problem(w, http.StatusNotFound, "not_found", "No website with this id; see listWebsites.")
		return
	}
	writeJSON(w, s.Crawlers.List(site))
}

func (s *Server) setCrawlers(w http.ResponseWriter, r *http.Request) {
	ci, _ := r.Context().Value(ctxKey{}).(*callInfo)
	if ci == nil {
		Problem(w, http.StatusForbidden, "forbidden", "Not part of the agent API.")
		return
	}
	if !contractapi.AllowsWrite(ci.token.Scope, contractapi.OpSetCrawlers) {
		Problem(w, http.StatusForbidden, contractapi.CodeScopeRequired, "This token may not change the crawler policy. Create one on the host: schild token add --scope crawlers:write --expires 90d --label NAME")
		return
	}
	if s.Crawlers == nil {
		Problem(w, http.StatusNotFound, "not_found", "Crawler control is not available on this gateway.")
		return
	}
	var req cc.SetRequest
	if !readCrawlerBody(w, r, &req) {
		return
	}
	if req.Website == "" || req.Reason == "" || !validReason(req.Reason) {
		Problem(w, http.StatusBadRequest, "invalid", "Name website, exactly one of category, bot, impersonators or preset, and a reason (at most 300 characters, no control characters).")
		return
	}
	req.Reason = contractapi.Sanitize(req.Reason, contractapi.MaxReason)
	out, err := s.Crawlers.Set(r.Context(), req, ci.token.ID, ci.token.Label)
	var fe *cc.FieldError
	switch {
	case errors.Is(err, ErrUnknownWebsite):
		Problem(w, http.StatusNotFound, "not_found", "No website with this id; see listWebsites.")
		return
	case errors.As(err, &fe) && fe.Field == "website":
		Problem(w, http.StatusConflict, "conflict", "Not every request of this website runs through schild; a crawler rule would not hold everywhere.")
		return
	case errors.As(err, &fe):
		Problem(w, http.StatusBadRequest, "invalid", fe.Error())
		return
	case err != nil:
		Problem(w, http.StatusInternalServerError, "internal", "The crawler policy could not be stored. Nothing changed.")
		return
	}
	writeJSON(w, out)
}

// maxCrawlerBody bounds the body of setAgentCrawlers.
const maxCrawlerBody = 2 << 10

// readCrawlerBody reads the JSON body of a crawler write; unknown fields
// are refused (nothing is charged, nothing else is set).
func readCrawlerBody(w http.ResponseWriter, r *http.Request, v any) bool {
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mt != "application/json" {
		Problem(w, http.StatusBadRequest, "invalid", "Content-Type must be application/json.")
		return false
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxCrawlerBody+1))
	if err != nil || len(body) > maxCrawlerBody {
		Problem(w, http.StatusBadRequest, "invalid", "The body is limited to 2 KiB.")
		return false
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if dec.Decode(v) != nil {
		Problem(w, http.StatusBadRequest, "invalid", "The body is not valid JSON of setAgentCrawlers.")
		return false
	}
	return true
}
