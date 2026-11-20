package agentapi

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"time"

	contractapi "github.com/deutschland-schild/schild/contract/agentapi"
	"github.com/deutschland-schild/schild/contract/bots"
	cm "github.com/deutschland-schild/schild/contract/monitoring"
	cr "github.com/deutschland-schild/schild/contract/requests"
	"github.com/deutschland-schild/schild/gateway/internal/reqring"
)

// v0.5 (MVP-22, D35): queryRequests, getRequestContext and getBotOverview
// for agents. Visitor keys are re-keyed as p1- pseudonyms with the
// gateway-local key; host, path and referrer are untrusted text
// (Sanitize'd). No bulk export: at most 1 h and 10000 records per call.

// Agent bounds of the ring operations.
const (
	agentWindow   = time.Hour
	agentMaxScan  = 10000
	agentMaxCtx   = 200
	agentMaxStrip = 61
)

var (
	agentRuleRe = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,32}$`)
	agentCCRe   = regexp.MustCompile(`^[A-Z]{2}$`)
)

func agentIndex(list []string, v string) int {
	for i, x := range list {
		if x == v {
			return i
		}
	}
	return -1
}

// agentRequest re-keys and sanitises one record.
func (s *Server) agentRequest(x cr.Record) contractapi.Request {
	return contractapi.Request{T: x.T, Site: x.Site, Host: contractapi.Sanitize(x.Host, 253), Path: contractapi.Sanitize(x.Path, 512),
		PathKind: x.PathKind, Method: x.Method, Status: x.Status, Outcome: x.Outcome, AnomalyScore: x.AnomalyScore, Rules: x.Rules,
		EventID: x.EventID, Country: x.Country, ASN: x.ASN, NetClass: x.NetClass, Browser: x.Browser, OS: x.OS, Device: x.Device,
		Bot: x.Bot, BotCategory: x.BotCategory, Verification: x.Verification, Referrer: contractapi.Sanitize(x.Referrer, 253),
		DurationMS: x.DurationMS, BytesOut: x.BytesOut, PageView: x.PageView, Visitor: contractapi.VisitorPseudonym(s.key, x.Visitor)}
}

func (s *Server) ringOff(w http.ResponseWriter) bool {
	if s.Requests == nil {
		requestsOff(w, nil)
		return true
	}
	return false
}

func (s *Server) ringFailed(w http.ResponseWriter, err error) {
	var inv *reqring.ErrInvalid
	switch {
	case errors.As(err, &inv):
		invalid(w, inv.Param, inv.Msg)
	case errors.Is(err, reqring.ErrBusy), errors.Is(err, context.DeadlineExceeded):
		Problem(w, http.StatusTooManyRequests, "rate_limited", "Another request ring query is running; try again shortly.")
	default:
		Problem(w, http.StatusInternalServerError, "internal", "")
	}
}

func (s *Server) queryRequests(w http.ResponseWriter, r *http.Request) {
	from, to, ok := window(w, r, agentWindow)
	if !ok {
		return
	}
	limit, ok := limitOf(w, r)
	if !ok {
		return
	}
	site, ok := s.siteParam(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	f := reqring.AnyFilter()
	f.Site = site
	if v := q.Get("rule"); v != "" {
		if !agentRuleRe.MatchString(v) {
			invalid(w, "rule", "rule id")
			return
		}
		f.Rule = v
	}
	if v := q.Get("outcome"); v != "" {
		if f.Outcome = agentIndex(cr.Outcomes, v); f.Outcome < 0 {
			invalid(w, "outcome", "RequestOutcome")
			return
		}
	}
	if v := q.Get("status_class"); v != "" {
		if len(v) != 3 || v[1:] != "xx" || v[0] < '1' || v[0] > '5' {
			invalid(w, "status_class", "1xx to 5xx")
			return
		}
		f.StatusClass = int(v[0] - '0')
	}
	if v := q.Get("country"); v != "" {
		if !agentCCRe.MatchString(v) {
			invalid(w, "country", "two upper-case letters")
			return
		}
		f.Country = v
	}
	if v := q.Get("bot_category"); v != "" {
		if f.BotCategory = agentIndex(cm.BotCategories, v); f.BotCategory < 0 {
			invalid(w, "bot_category", "BotCategory")
			return
		}
	}
	if v := q.Get("verification"); v != "" {
		i := agentIndex(bots.Verifications, v)
		if i < 0 {
			invalid(w, "verification", "BotVerification")
			return
		}
		f.Verif = i + 1
	}
	cur := q.Get("cursor")
	if len(cur) > 256 {
		invalid(w, "cursor", "bad cursor")
		return
	}
	if s.ringOff(w) {
		return
	}
	p, err := s.Requests.Query(r.Context(), reqring.QueryParams{From: from, To: to, Filter: f, Cursor: cur, Limit: limit, MaxWindow: agentWindow,
		MaxScan: agentMaxScan}, s.now())
	if err != nil {
		s.ringFailed(w, err)
		return
	}
	out := contractapi.RequestPage{From: p.From, To: p.To, Items: []contractapi.Request{}, NextCursor: p.NextCursor, Scanned: p.Scanned,
		ScanCapped: p.ScanCapped, SampleRate: p.SampleRate}
	for _, x := range p.Items {
		out.Items = append(out.Items, s.agentRequest(x))
	}
	writeJSON(w, out)
}

func (s *Server) getRequestContext(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("event_id")
	if !uuidRe.MatchString(id) {
		Problem(w, http.StatusNotFound, "not_found", "No such event.")
		return
	}
	if s.ringOff(w) {
		return
	}
	e, err := s.St.GetEvent(r.Context(), id)
	if err != nil || e == nil {
		Problem(w, http.StatusNotFound, "not_found", "No such event.")
		return
	}
	c, err := s.Requests.Context(r.Context(), id, e.Time, s.now())
	if err != nil {
		s.ringFailed(w, err)
		return
	}
	out := contractapi.RequestContext{EventID: c.EventID, State: c.State, From: c.From, To: c.To, VisitorRequests: []contractapi.Request{},
		Truncated: c.Truncated, SiteStrip: []contractapi.StripPoint{}}
	if c.Anchor != nil {
		a := s.agentRequest(*c.Anchor)
		out.Anchor = &a
	}
	for _, x := range c.VisitorRequests {
		if len(out.VisitorRequests) == agentMaxCtx {
			out.Truncated = true
			break
		}
		out.VisitorRequests = append(out.VisitorRequests, s.agentRequest(x))
	}
	if v := c.VisitorSummary; v != nil {
		out.VisitorSummary = &contractapi.VisitorSummary{Requests: v.Requests, PageViews: v.PageViews, Status2xx: v.Status2xx, Alerts: v.Alerts, Pattern: v.Pattern}
	}
	if c.State != "expired" {
		from, _ := time.Parse(time.RFC3339Nano, c.From)
		to, _ := time.Parse(time.RFC3339Nano, c.To)
		site := e.Site
		if c.Anchor != nil {
			site = c.Anchor.Site
		}
		if s.Sites != nil {
			if _, ok := s.Sites.View().Website(site); !ok {
				site = ""
			}
		}
		for _, p := range s.Monitor.Strip(site, from, to) {
			if len(out.SiteStrip) == agentMaxStrip {
				break
			}
			out.SiteStrip = append(out.SiteStrip, contractapi.StripPoint{T: p.T, Requests: p.Requests, Stopped: p.Stopped, WouldBlock: p.WouldBlock, Detections: p.Detections})
		}
		if s.SitesAffected != nil {
			if sa := s.SitesAffected(r.Context(), e.IP, e.Site, e.Time); sa != nil {
				out.SitesAffected = &contractapi.SitesAffected{Sites: sa.Sites, Count: sa.Count, Total: sa.Total}
			}
		}
	}
	writeJSON(w, out)
}

func (s *Server) getBotOverview(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	now := s.now()
	to := now
	var from time.Time // default: 24 h before to
	var err error
	if v := q.Get("to"); v != "" {
		if to, err = time.Parse(time.RFC3339, v); err != nil {
			invalid(w, "to", "RFC 3339 time")
			return
		}
	}
	if v := q.Get("from"); v != "" {
		if from, err = time.Parse(time.RFC3339, v); err != nil {
			invalid(w, "from", "RFC 3339 time")
			return
		}
	} else {
		from = to.Add(-24 * time.Hour)
	}
	if !from.Before(to) {
		invalid(w, "from", "from must be before to")
		return
	}
	site, ok := s.siteParam(w, r)
	if !ok || s.ringOff(w) {
		return
	}
	if lo, _ := s.Requests.Window(now); from.Before(lo) {
		from = lo
	}
	var dir reqring.BotDirectory
	if s.Bots != nil {
		dir = s.Bots
	}
	o, err := s.Requests.BotOverview(r.Context(), dir, site, from, to)
	if err != nil {
		s.ringFailed(w, err)
		return
	}
	writeJSON(w, o)
}
