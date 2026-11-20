package agentapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	contractapi "github.com/deutschland-schild/schild/contract/agentapi"
	"github.com/deutschland-schild/schild/contract/crowdsec"
	"github.com/deutschland-schild/schild/contract/events"
	"github.com/deutschland-schild/schild/gateway/internal/store"
)

// Events and incidents for agents: bounded time windows by index range,
// newest first, cursor pagination, at most 10000 rows read per request. No
// full IP address: clients appear as keyed pseudonym and /24 or /48.

var (
	typeRe     = regexp.MustCompile(`^schild\.[a-z]+\.[a-z_]+\.v1$`)
	uuidRe     = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	incidentRe = regexp.MustCompile(`^[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}$`)
	outcomes   = map[string]bool{"passed": true, "blocked": true, "would_block": true}
)

func invalid(w http.ResponseWriter, param, detail string) {
	Problem(w, http.StatusBadRequest, "invalid", param+": "+detail)
}

// window parses the required from/to of a list operation.
func window(w http.ResponseWriter, r *http.Request, maxSpan time.Duration) (from, to time.Time, ok bool) {
	q := r.URL.Query()
	var err error
	if from, err = time.Parse(time.RFC3339, q.Get("from")); err != nil {
		invalid(w, "from", "required RFC 3339 time")
		return
	}
	if to, err = time.Parse(time.RFC3339, q.Get("to")); err != nil {
		invalid(w, "to", "required RFC 3339 time")
		return
	}
	if !from.Before(to) || to.Sub(from) > maxSpan {
		Problem(w, http.StatusBadRequest, "invalid", fmt.Sprintf("to - from must be positive and at most %s", maxSpan))
		return
	}
	return from, to, true
}

func limitOf(w http.ResponseWriter, r *http.Request) (int, bool) {
	v := r.URL.Query().Get("limit")
	if v == "" {
		return 50, true
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 || n > contractapi.MaxRows {
		invalid(w, "limit", "1 to 200")
		return 0, false
	}
	return n, true
}

// cursor "<ms>_<seq or id>".
func parseCursor(c string) (int64, string, error) {
	if c == "" {
		return 0, "", nil
	}
	a, b, ok := strings.Cut(c, "_")
	n, err := strconv.ParseInt(a, 10, 64)
	if !ok || err != nil || n <= 0 || len(c) > 256 {
		return 0, "", errors.New("bad cursor")
	}
	return n, b, nil
}

// client returns pseudonym and network of a stored address (empty when it
// was truncated beyond /24 or /48 or is missing).
func (s *Server) client(ip string) (pseudonym, network string) {
	if ip == "" {
		return "", ""
	}
	if a, err := netip.ParseAddr(ip); err == nil {
		return contractapi.ClientPseudonym(s.key, a), contractapi.ClientNet(a)
	}
	if p, err := netip.ParsePrefix(ip); err == nil {
		a := p.Addr().Unmap()
		if (a.Is4() && p.Bits() >= 24) || (a.Is6() && p.Bits() >= 48) {
			return "", contractapi.ClientNet(a)
		}
	}
	return "", ""
}

type eventBody struct {
	Data struct {
		Client struct {
			Geo struct {
				Country  string `json:"country"`
				ASN      uint32 `json:"asn"`
				ASOrg    string `json:"as_org"`
				NetClass string `json:"net_class"`
			} `json:"geo"`
		} `json:"client"`
		Rules []struct {
			ID         int    `json:"id"`
			Repository string `json:"repository"`
			Msg        string `json:"msg"`
			Severity   string `json:"severity"`
			Crowdsec   *struct {
				Name    string   `json:"name"`
				Version string   `json:"version"`
				Label   string   `json:"label"`
				CVEs    []string `json:"cves"`
			} `json:"crowdsec"`
		} `json:"rules"`
		Sampled    bool     `json:"sampled"`
		DurationMS *float64 `json:"duration_ms"`
		WAFMS      *float64 `json:"waf_ms"`
		// WouldBlockReason (v0.5, D36 open items), request events only.
		WouldBlockReason string `json:"would_block_reason"`
	} `json:"data"`
}

var countryRe = regexp.MustCompile(`^[A-Z]{2}$`)
var netClasses = map[string]bool{"residential": true, "mobile": true, "cgnat": true, "hosting": true, "business": true, "education": true,
	"government": true, "tor": true, "vpn": true, "proxy": true, "unknown": true}

func (s *Server) event(e *store.EventRow, detail bool) contractapi.Event {
	out := contractapi.Event{ID: e.ID, Time: ts(e.Time), Type: e.Type, Score: e.Score, Incident: e.Incident, Site: e.Site}
	if outcomes[e.Outcome] {
		out.Outcome = e.Outcome
	}
	out.ClientPseudonym, out.ClientNet = s.client(e.IP)
	if e.Method != "" && len(e.Method) <= 16 && strings.ToUpper(e.Method) == e.Method {
		out.Method = e.Method
	}
	out.Host = contractapi.Sanitize(e.Host, contractapi.MaxHost)
	out.Path = contractapi.Sanitize(e.Path, contractapi.MaxPath)
	out.UserAgent = contractapi.Sanitize(e.UA, contractapi.MaxUserAgent)
	if e.Status >= 100 && e.Status <= 599 {
		out.Status = e.Status
	}
	for _, r := range e.Rules {
		if len(out.Rules) < 128 && len(r) <= 32 {
			out.Rules = append(out.Rules, r)
		}
	}
	if !strings.HasPrefix(e.Type, "schild.request.") && e.Summary != "" {
		out.Summary = contractapi.Sanitize(e.Summary, 300)
	}
	if !incidentRe.MatchString(out.Incident) {
		out.Incident = ""
	}
	var b eventBody
	if json.Unmarshal(e.Body, &b) == nil {
		d := b.Data
		g := d.Client.Geo
		if countryRe.MatchString(g.Country) {
			nc := g.NetClass
			if !netClasses[nc] {
				nc = "unknown"
			}
			out.Geo = &contractapi.Geo{Country: g.Country, ASN: g.ASN, ASOrg: contractapi.Sanitize(g.ASOrg, 256), NetClass: nc}
		}
		out.Sampled = d.Sampled
		if out.Outcome == "would_block" && strings.HasPrefix(e.Type, "schild.request.") && slices.Contains(events.WouldBlockReasons, d.WouldBlockReason) {
			out.WouldBlockReason = d.WouldBlockReason
		}
		if d.DurationMS != nil && *d.DurationMS >= 0 {
			out.DurationMS = d.DurationMS
		}
		if d.WAFMS != nil && *d.WAFMS >= 0 {
			out.WAFMS = d.WAFMS
		}
		if detail {
			for _, m := range d.Rules {
				if len(out.Matches) == 128 {
					break
				}
				id := strconv.Itoa(m.ID)
				if len(id) > 32 {
					continue
				}
				repo := m.Repository
				if repo != "crs" && repo != "local" && repo != "crowdsec" {
					continue
				}
				match := contractapi.RuleMatch{ID: id, Repository: repo, Msg: contractapi.Sanitize(m.Msg, contractapi.MaxRuleMsg), Severity: trimTo(m.Severity, 16)}
				if repo == "crowdsec" {
					if m.Crowdsec == nil {
						continue
					}
					match.ID = strconv.Itoa(crowdsec.BaseID(m.Crowdsec.Name))
					match.Crowdsec = &contractapi.CrowdsecRule{Name: m.Crowdsec.Name, Version: m.Crowdsec.Version, Label: contractapi.Sanitize(m.Crowdsec.Label, 128), CVEs: m.Crowdsec.CVEs}
				}
				out.Matches = append(out.Matches, match)
			}
		}
	}
	return out
}

func trimTo(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func (s *Server) listEvents(w http.ResponseWriter, r *http.Request) {
	from, to, ok := window(w, r, contractapi.EventWindow)
	if !ok {
		return
	}
	limit, ok := limitOf(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	typ, outcome := q.Get("type"), q.Get("outcome")
	site, ok := s.siteParam(w, r)
	if !ok {
		return
	}
	if typ != "" && !typeRe.MatchString(typ) {
		invalid(w, "type", "event type")
		return
	}
	if outcome != "" && !outcomes[outcome] {
		invalid(w, "outcome", "passed, blocked or would_block")
		return
	}
	bms, bseq, err := parseCursor(q.Get("cursor"))
	if err != nil {
		invalid(w, "cursor", "bad cursor")
		return
	}
	seq, _ := strconv.ParseInt(bseq, 10, 64)
	page := contractapi.EventPage{Items: []contractapi.Event{}}
	scanned, more := 0, false
	for {
		chunk := min(1000, contractapi.MaxScanRows-scanned)
		rows, err := s.St.EventsInRange(r.Context(), from, to, site, bms, seq, chunk)
		if err != nil {
			Problem(w, http.StatusInternalServerError, "internal", "")
			return
		}
		full := false
		for _, e := range rows {
			scanned++
			bms, seq = e.Time.UnixMilli(), e.Seq
			if (typ == "" || e.Type == typ) && (outcome == "" || e.Outcome == outcome) {
				page.Items = append(page.Items, s.event(e, false))
				if full = len(page.Items) == limit; full {
					break
				}
			}
		}
		if full {
			more = true
			break
		}
		if len(rows) < chunk {
			break
		}
		if scanned >= contractapi.MaxScanRows {
			more, page.ScanCapped = true, true
			break
		}
	}
	if more {
		c := fmt.Sprintf("%d_%d", bms, seq)
		page.NextCursor = &c
	}
	if c, ok := r.Context().Value(ctxKey{}).(*callInfo); ok {
		c.rows = scanned
	}
	writeJSON(w, page)
}

func (s *Server) getEvent(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !uuidRe.MatchString(id) {
		Problem(w, http.StatusNotFound, "not_found", "No such event.")
		return
	}
	e, err := s.St.GetEvent(r.Context(), id)
	if err != nil {
		Problem(w, http.StatusNotFound, "not_found", "No such event.")
		return
	}
	writeJSON(w, s.event(e, true))
}

func (s *Server) incident(ctx context.Context, in *store.Incident) contractapi.Incident {
	out := contractapi.Incident{Incident: in.Incident, Status: in.Status, Time: ts(in.Time), EventID: in.EventID, Sources: []string{}}
	if out.Status != "unblocked" {
		out.Status = "blocked"
	}
	out.ClientPseudonym, out.ClientNet = s.client(in.IP)
	out.Reason = contractapi.Sanitize(in.Reason, contractapi.MaxReason)
	for _, src := range in.Sources {
		if len(out.Sources) < 32 {
			out.Sources = append(out.Sources, trimTo(src, 64))
		}
	}
	if !in.UnblockedAt.IsZero() {
		u := ts(in.UnblockedAt)
		out.UnblockedAt = &u
	}
	out.Site = in.Site
	// D38: aggregated incidents (count of blocked requests, first and last).
	out.Count, out.FirstSeen, out.LastSeen = max(in.Count, 1), ts(in.Time), ts(in.Time)
	if !in.FirstSeen.IsZero() {
		out.FirstSeen = ts(in.FirstSeen)
	}
	if !in.LastSeen.IsZero() {
		out.LastSeen = ts(in.LastSeen)
	}
	if s.SitesAffected != nil {
		if sa := s.SitesAffected(ctx, in.IP, in.Site, in.Time); sa != nil {
			out.SitesAffected = &contractapi.SitesAffected{Sites: sa.Sites, Count: sa.Count, Total: sa.Total}
		}
	}
	if s.IncidentBlock != nil {
		if b := s.IncidentBlock(ctx, in); b != nil {
			b.AgentReason = contractapi.Sanitize(b.AgentReason, contractapi.MaxReason)
			out.Block = b
		}
	}
	return out
}

func (s *Server) listIncidents(w http.ResponseWriter, r *http.Request) {
	from, to, ok := window(w, r, contractapi.IncidentWindow)
	if !ok {
		return
	}
	limit, ok := limitOf(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	st := q.Get("status")
	if st != "" && st != "blocked" && st != "unblocked" {
		invalid(w, "status", "blocked or unblocked")
		return
	}
	site, ok := s.siteParam(w, r)
	if !ok {
		return
	}
	bms, bid, err := parseCursor(q.Get("cursor"))
	if err != nil {
		invalid(w, "cursor", "bad cursor")
		return
	}
	page := contractapi.IncidentPage{Items: []contractapi.Incident{}}
	scanned, more := 0, false
	for {
		chunk := min(500, contractapi.MaxScanRows-scanned)
		rows, err := s.St.IncidentsInRange(r.Context(), from, to, store.IncidentFilter{Site: site}, bms, bid, chunk)
		if err != nil {
			Problem(w, http.StatusInternalServerError, "internal", "")
			return
		}
		full := false
		for _, in := range rows {
			scanned++
			bms, bid = in.Time.UnixMilli(), in.Incident
			if st == "" || in.Status == st {
				page.Items = append(page.Items, s.incident(r.Context(), in))
				if full = len(page.Items) == limit; full {
					break
				}
			}
		}
		if full {
			more = true
			break
		}
		if len(rows) < chunk {
			break
		}
		if scanned >= contractapi.MaxScanRows {
			more, page.ScanCapped = true, true
			break
		}
	}
	if more {
		c := fmt.Sprintf("%d_%s", bms, bid)
		page.NextCursor = &c
	}
	if c, ok := r.Context().Value(ctxKey{}).(*callInfo); ok {
		c.rows = scanned
	}
	writeJSON(w, page)
}

func (s *Server) getIncident(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("incident")
	if !incidentRe.MatchString(id) {
		Problem(w, http.StatusNotFound, "not_found", "No such incident.")
		return
	}
	in, err := s.St.GetIncident(r.Context(), id)
	if err != nil {
		Problem(w, http.StatusNotFound, "not_found", "No such incident.")
		return
	}
	writeJSON(w, s.incident(r.Context(), in))
}
