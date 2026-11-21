package dashboard

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	contractapi "github.com/deutschland-schild/schild/contract/agentapi"
	"github.com/deutschland-schild/schild/contract/config"
	"github.com/deutschland-schild/schild/contract/events"
	cm "github.com/deutschland-schild/schild/contract/monitoring"
	"github.com/deutschland-schild/schild/contract/rules"
	"github.com/deutschland-schild/schild/contract/websites"
	"github.com/deutschland-schild/schild/gateway/internal/behaviour"
	"github.com/deutschland-schild/schild/gateway/internal/decide"
	"github.com/deutschland-schild/schild/gateway/internal/monitoring"
	"github.com/deutschland-schild/schild/gateway/internal/sites"
	"github.com/deutschland-schild/schild/gateway/internal/store"
)

// v0.5 (D36): the website-first dashboard - listWebsites, getWebsite, the
// website overview (KPIs, Echtzeit, annotations, Letzte Alarme), the
// incident list and the read-only agent API call log.

func (s *Server) websiteRoutes(a func(string, http.HandlerFunc)) {
	a("GET "+apiPrefix+"/websites", s.listWebsites)
	a("GET "+apiPrefix+"/websites/{website}", s.getWebsite)
	a("GET "+apiPrefix+"/websites/{website}/kpis", s.getWebsiteKpis)
	a("GET "+apiPrefix+"/websites/{website}/realtime", s.getWebsiteRealtime)
	a("GET "+apiPrefix+"/websites/{website}/annotations", s.listAnnotations)
	a("GET "+apiPrefix+"/websites/{website}/alerts", s.listAlerts)
	a("GET "+apiPrefix+"/incidents", s.listIncidents)
	a("GET "+apiPrefix+"/agent-api", s.getAgentAPI)
	a("PUT "+apiPrefix+"/agent-api", s.setAgentAPI)
	a("GET "+apiPrefix+"/agent-api/calls", s.listAgentCalls)
	s.accessRoutes(a)
	s.humanCheckRoutes(a)
	s.crawlerRoutes(a)
	// The request ring (MVP-22); without it every operation answers 409
	// requests_off, so the UI can tell "not here" from "not found".
	s.requestRoutes(a)
}

func requestsOff(w http.ResponseWriter, _ *http.Request) {
	problem(w, http.StatusConflict, "requests_off", "Schild hebt die einzelnen Anfragen auf diesem Server nicht auf (Anfrage-Speicher aus).", nil)
}

// view is the website view (one website "default" without a registry).
func (s *Server) view() *sites.View {
	if s.Sites != nil {
		return s.Sites.View()
	}
	return sites.NewView(websites.Input{Mode: websites.ModeProxy})
}

var websiteIDRe = regexp.MustCompile(`^(_any|(_|[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)(\.(_|[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?))*)$`)

// siteParam reads the site filter: a website id of this gateway ("" none).
func (s *Server) siteParam(q *query) string {
	v := q.r.URL.Query().Get("site")
	if v == "" {
		return ""
	}
	if _, ok := s.view().Website(v); !ok || len(v) > 253 {
		q.errs = append(q.errs, FieldError{Pointer: "#/query/site", Detail: "keine Website dieses Servers"})
		return ""
	}
	return v
}

// website reads the {website} path parameter; 404 when unknown.
func (s *Server) website(w http.ResponseWriter, r *http.Request) (websites.Website, bool) {
	id := r.PathValue("website")
	ws, ok := s.view().Website(id)
	if !ok || !websiteIDRe.MatchString(id) {
		problem(w, http.StatusNotFound, "not_found", "Diese Website gibt es auf diesem Server nicht.", nil)
		return websites.Website{}, false
	}
	return ws, true
}

// SitesAffected lists the websites the client of ip touched in the 24 h
// up to t (the incident's or event's own time, inclusive), the event's own
// website first. Nothing after t counts (D36 fix round 1, finding B.4.4 d:
// the window reached one minute past t, so the first incident of a scan
// named websites attacked only afterwards).
func (s *Server) SitesAffected(ctx context.Context, ip, own string, t time.Time) *websites.SitesAffected {
	if ip == "" {
		return nil
	}
	v := s.view()
	list, n, err := s.St.SitesOfIP(ctx, ip, t.Add(-24*time.Hour), t.Add(time.Millisecond), 64)
	if err != nil {
		return nil
	}
	out := &websites.SitesAffected{Sites: []string{}, Total: max(v.Protected, 1)}
	if own != "" {
		out.Sites = append(out.Sites, own)
	}
	sort.Strings(list)
	for _, x := range list {
		if x != own && len(out.Sites) < 32 {
			out.Sites = append(out.Sites, x)
		}
	}
	out.Count = n
	if own != "" && !contains(list, own) {
		out.Count++
	}
	if out.Count == 0 {
		return nil
	}
	out.Total = max(out.Total, min(out.Count, 500))
	return out
}

func contains(l []string, x string) bool {
	for _, v := range l {
		if v == x {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------- list

// serverState is this gateway for the status rules and runs_on.
func (s *Server) serverState(now time.Time) (websites.Server, websites.ServerHealth) {
	node := s.Config().NodeName
	state := "ok"
	if s.Gate == nil || !s.Gate.Ready() {
		state = websites.ReasonNotReady
	}
	gs := "active"
	codes := s.reasons(now)
	for _, c := range codes {
		if c == "waf_down" {
			gs = "off"
		}
	}
	if gs == "active" && len(codes) > 0 {
		gs = "degraded"
	}
	hints := []cm.HealthHint{}
	if s.Monitor != nil {
		hints = append(hints, s.Monitor.ServerHints(now)...)
	}
	srv := websites.Server{Node: node, State: state, Baseline: gs, Hints: []websites.Hint{}}
	for _, h := range hints {
		srv.Hints = append(srv.Hints, websites.Hint{Code: h.Code, Level: h.Level, Object: h.Object})
	}
	if len(hints) > 32 {
		hints = hints[:32]
	}
	return srv, websites.ServerHealth{Node: node, This: true, Status: websites.ServerStatus(srv), Baseline: gs, Hints: hints}
}

func (s *Server) summary(v *sites.View, w websites.Website, srv websites.Server, health websites.ServerHealth, now time.Time) websites.Summary {
	out := websites.Summary{ID: w.ID, Label: w.Label, Hosts: w.Hosts, HostsTotal: len(w.Hosts), Source: v.Source, Protection: w.Protection, Tracked: w.Tracked,
		RunsOn: []websites.ServerHealth{health}}
	if out.Hosts == nil {
		out.Hosts = []string{}
	}
	if len(out.Hosts) > websites.MaxHostsListed {
		out.Hosts = out.Hosts[:websites.MaxHostsListed]
	}
	in := websites.StatusInput{Protection: w.Protection, Tracked: w.Tracked, Monitoring: s.Monitor != nil, Servers: []websites.Server{srv}}
	if s.Monitor != nil && w.Tracked && w.Protection != websites.Unprotected {
		n := s.Monitor.Site(v.SlotOf(w.ID), now)
		switch {
		case n.HasData:
			out.Now = n.Now
			win := n.Window
			in.Traffic = &win
		case now.Sub(s.Monitor.Started()) >= websites.WindowS*time.Second:
			// No request for this website since schild started, and the
			// status window lies after that start: that is a quiet website,
			// not an unknown one. Before, every quiet website read "unknown"
			// after a restart until its next visitor.
			in.Traffic = &websites.Traffic{}
		}
		for _, h := range n.Hints {
			in.SiteHints = append(in.SiteHints, websites.Hint{Code: h.Code, Level: h.Level, Object: h.Object})
		}
	}
	st := websites.Status(in)
	out.Status, out.Reasons = st.Status, st.Reasons
	if len(out.Reasons) > 64 {
		out.Reasons = out.Reasons[:64]
	}
	return out
}

// WebsiteList is listWebsites (also the agent API).
func (s *Server) WebsiteList(now time.Time) websites.List {
	v := s.view()
	srv, health := s.serverState(now)
	out := websites.List{GeneratedAt: ts(now), Node: srv.Node, Server: &health, Websites: []websites.Summary{}}
	for _, w := range v.Websites() {
		if len(out.Websites) == 500 {
			break
		}
		out.Websites = append(out.Websites, s.summary(v, w, srv, health, now))
	}
	if n := v.Untracked(); n > 0 {
		o := &websites.Other{Websites: n}
		if s.Monitor != nil {
			if sn := s.Monitor.Site(sites.OtherSlot, now); sn.HasData {
				o.Now = sn.Now
			}
		}
		out.Other = o
	}
	return out
}

// WebsiteDetail is getWebsite (also the agent API); ok false for an
// unknown id.
func (s *Server) WebsiteDetail(ctx context.Context, id string, now time.Time) (websites.Detail, bool) {
	v := s.view()
	w, ok := v.Website(id)
	if !ok {
		return websites.Detail{}, false
	}
	srv, health := s.serverState(now)
	d := websites.Detail{GeneratedAt: ts(now), Website: s.summary(v, w, srv, health, now)}
	if s.Monitor != nil && w.Tracked && w.Protection != websites.Unprotected {
		if tc, cov, err := s.Monitor.TotalsCovered(id, now.Add(-24*time.Hour), now, now); err == nil && tc != nil {
			d.Traffic24h = tc
			d.Traffic24hPartial = cov.Partial
			if !cov.Since.IsZero() {
				d.Traffic24hSince = ts(cov.Since)
			}
		}
	}
	if n, err := s.St.CountIncidents(ctx, now.Add(-24*time.Hour), now.Add(time.Second), id); err == nil {
		d.Incidents24h = n
	}
	return d, true
}

func (s *Server) listWebsites(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, s.WebsiteList(s.now()))
}

func (s *Server) getWebsite(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.website(w, r); !ok {
		return
	}
	d, _ := s.WebsiteDetail(r.Context(), r.PathValue("website"), s.now())
	writeJSON(w, 200, d)
}

// ---------------------------------------------------------------- overview

func (s *Server) monitoringOff(w http.ResponseWriter) bool {
	if s.Monitor == nil {
		problem(w, http.StatusConflict, "monitoring_off", "Die Auslastungsanzeige ist ausgeschaltet (monitoring.enabled: false in schild.yaml).", nil)
		return true
	}
	return false
}

func (s *Server) monitoringFailed(w http.ResponseWriter, err error) {
	var inv *monitoring.ErrInvalid
	switch {
	case errors.As(err, &inv):
		invalid(w, inv.Msg, FieldError{Pointer: "#/query/" + inv.Param, Detail: inv.Msg})
	case errors.Is(err, monitoring.ErrFilterUnavailable):
		problem(w, http.StatusConflict, "filter_unavailable", s.Monitor.FilterUnavailableText(),
			[]FieldError{{Pointer: "#/query/filter", Detail: "braucht die Einzelanfragen"}})
	case errors.Is(err, monitoring.ErrRingBusy):
		problem(w, http.StatusTooManyRequests, "rate_limited", "Eine andere Abfrage der Einzelanfragen läuft gerade. Versuch es gleich noch einmal.", nil)
	case errors.Is(err, monitoring.ErrUnknownSite):
		problem(w, http.StatusNotFound, "not_found", "Diese Website gibt es auf diesem Server nicht.", nil)
	default:
		s.internal(w, err)
	}
}

func (s *Server) getWebsiteKpis(w http.ResponseWriter, r *http.Request) {
	ws, ok := s.website(w, r)
	if !ok {
		return
	}
	q := &query{r: r}
	from, to := q.time("from"), q.time("to")
	if from.IsZero() {
		q.errs = append(q.errs, FieldError{Pointer: "#/query/from", Detail: "Pflichtfeld"})
	}
	if to.IsZero() {
		q.errs = append(q.errs, FieldError{Pointer: "#/query/to", Detail: "Pflichtfeld"})
	}
	if !from.IsZero() && !to.IsZero() && !from.Before(to) {
		q.errs = append(q.errs, FieldError{Pointer: "#/query/from", Detail: "from muss vor to liegen"})
	}
	if q.failed(w) || s.monitoringOff(w) {
		return
	}
	filters := r.URL.Query()["filter"]
	now := s.now()
	span := to.Sub(from)
	cur, err := s.Monitor.Kpis(ws.ID, from, to, filters, now)
	if err != nil {
		s.monitoringFailed(w, err)
		return
	}
	prev, err := s.Monitor.Kpis(ws.ID, from.Add(-span), from, filters, now)
	if err != nil {
		s.monitoringFailed(w, err)
		return
	}
	out := websites.Kpis{Site: ws.ID, From: ts(from), To: ts(to), PreviousFrom: ts(from.Add(-span)), PreviousTo: ts(from), Source: s.Monitor.KpisSource(filters, from, to, now), Current: cur, Previous: prev}
	if len(filters) > 0 {
		out.Filters = filters
	}
	writeJSON(w, 200, out)
}

func (s *Server) getWebsiteRealtime(w http.ResponseWriter, r *http.Request) {
	ws, ok := s.website(w, r)
	if !ok || s.monitoringOff(w) {
		return
	}
	out, err := s.Monitor.Realtime(ws.ID, s.now())
	if err != nil {
		s.monitoringFailed(w, err)
		return
	}
	writeJSON(w, 200, out)
}

// ---------------------------------------------------------------- annotations

func (s *Server) listAnnotations(w http.ResponseWriter, r *http.Request) {
	ws, ok := s.website(w, r)
	if !ok {
		return
	}
	q := &query{r: r}
	from, to := q.time("from"), q.time("to")
	if from.IsZero() || to.IsZero() || !from.Before(to) {
		q.errs = append(q.errs, FieldError{Pointer: "#/query/from", Detail: "from und to, from vor to"})
	}
	if q.failed(w) {
		return
	}
	ctx := r.Context()
	now := s.now()
	var items []websites.Annotation
	// Waves of this website (events of type distributed.detected and
	// .ended, partial index events_wave).
	if rows, err := s.St.WaveEvents(ctx, ws.ID, from.UnixMilli(), to.UnixMilli(), 400); err == nil {
		for _, e := range rows {
			a := websites.Annotation{T: ts(e.Time), Ref: e.ID}
			var body struct {
				Data struct {
					Detector  string `json:"detector"`
					Senders   int64  `json:"senders"`
					WaveID    string `json:"wave_id"`
					DurationS int64  `json:"duration_s"`
				} `json:"data"`
			}
			_ = json.Unmarshal(e.Body, &body)
			a.Detector = body.Data.Detector
			if e.Type == events.DistributedDetected {
				a.Kind, a.Count = websites.AnnWaveDetected, body.Data.Senders
			} else {
				a.Kind = websites.AnnWaveEnded
				if body.Data.WaveID != "" {
					a.Ref = body.Data.WaveID
				}
				a.DurationS = body.Data.DurationS
			}
			if a.Detector == "" {
				a.Detector = ""
			}
			items = append(items, a)
		}
	}
	// Incidents of this website (index incidents(site, time)), counted in
	// bins so that a dense attack becomes a few markers instead of pushing
	// every other marker out (D36 fix round 1, finding B.4.4 b).
	var incidents []websites.Annotation
	bin := max(to.Sub(from)/annIncidentBudget, time.Second)
	if bins, err := s.St.IncidentBins(ctx, ws.ID, from, to, bin); err == nil {
		incidents = incidentAnnotations(bins)
	}
	// Long blocks of data-centre addresses (gateway-wide, D29 amendment).
	if rows, err := s.St.ListBlocks(ctx); err == nil {
		for _, b := range rows {
			since, err1 := time.Parse(time.RFC3339, b.Since)
			if err1 != nil || since.Before(from) || !since.Before(to) {
				continue
			}
			items = append(items, websites.Annotation{T: b.Since, Until: b.Until, Kind: websites.AnnBlockLong, Ref: b.Incident, NetClass: b.NetClass, DurationS: int64(b.DurationS),
				Count: int64(max(b.Level, 1))}) // the ladder step (D36 open items)
		}
	}
	// Mode and configuration changes, restarts, gaps (gateway-wide).
	if cs, err := s.St.ConfigChanges(ctx, from, to, 200); err == nil {
		for _, c := range cs {
			a := websites.Annotation{T: ts(c.Time), Kind: websites.AnnConfigChanged, ConfigSHA256: c.SHA256}
			if c.ModeFrom != "" && c.ModeTo != "" && c.ModeFrom != c.ModeTo {
				a.Kind, a.ModeFrom, a.ModeTo = websites.AnnModeChanged, c.ModeFrom, c.ModeTo
			}
			items = append(items, a)
		}
	}
	// Changes of the state of a rule repository (gateway-wide, D73).
	if rows, _, err := s.St.ListEvents(ctx, store.EventFilter{Type: events.RuleRepositorySwitched, From: from, To: to}, 0, 50); err == nil {
		for _, e := range rows {
			var body struct {
				Data events.RepositorySwitched `json:"data"`
			}
			if json.Unmarshal(e.Body, &body) != nil {
				continue
			}
			d := body.Data
			items = append(items, websites.Annotation{T: ts(e.Time), Kind: websites.AnnRuleRepository, Ref: e.ID, Repository: d.Repository,
				StateFrom: d.From, StateTo: d.To, Actor: d.Actor, TokenLabel: d.TokenLabel})
		}
	}
	// Blocks set or lifted by an agent (gateway-wide, D42).
	if rows, _, err := s.St.ListEvents(ctx, store.EventFilter{Types: []string{events.BlockSet, events.BlockLifted}, From: from, To: to}, 0, 50); err == nil {
		for _, e := range rows {
			var body struct {
				Data struct {
					Effect     string `json:"effect"`
					Incident   string `json:"incident"`
					TokenLabel string `json:"token_label"`
				} `json:"data"`
			}
			if json.Unmarshal(e.Body, &body) != nil {
				continue
			}
			d := body.Data
			a := websites.Annotation{T: ts(e.Time), Kind: websites.AnnAgentBlockSet, Ref: d.Incident, Actor: rules.ByAgent, TokenLabel: d.TokenLabel, Effect: d.Effect}
			if e.Type == events.BlockLifted {
				a.Kind = websites.AnnAgentBlockLifted
			}
			items = append(items, a)
		}
	}
	if s.Monitor != nil {
		for _, t := range s.Monitor.Restarts(from, to) {
			items = append(items, websites.Annotation{T: ts(t), Kind: websites.AnnRestart})
		}
		for _, g := range s.Monitor.Gaps(from, to, now, 200) {
			items = append(items, websites.Annotation{T: ts(g.From), Until: ts(g.To), Kind: websites.AnnMonitoringGap})
		}
	}
	out := websites.AnnotationList{Site: ws.ID, From: ts(from), To: ts(to), Items: []websites.Annotation{}}
	items, out.Truncated = budgetAnnotations(append(items, incidents...))
	for _, a := range items {
		if a.Ref != "" && !annRefRe.MatchString(a.Ref) {
			a.Ref = ""
		}
		out.Items = append(out.Items, a)
	}
	writeJSON(w, 200, out)
}

var annRefRe = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,64}$`)

// incidentAnnotations turns incident bins into markers (contracts v0.5,
// D36 fix round 1): a single incident is a marker at its time with its
// number; several are one grouped marker with t = bin start, until = bin
// end, count = incidents in the bin and ref = the newest of them.
func incidentAnnotations(bins []store.IncidentBin) []websites.Annotation {
	out := make([]websites.Annotation, 0, len(bins))
	for _, b := range bins {
		a := websites.Annotation{T: ts(b.Last), Kind: websites.AnnIncident}
		if b.N > 1 {
			a.T, a.Until, a.Count = ts(b.Start), ts(b.End), b.N
		}
		if annRefRe.MatchString(b.Incident) {
			a.Ref = b.Incident
		}
		out = append(out, a)
	}
	return out
}

// annIncidentBudget is the number of incident bins of one range.
const annIncidentBudget = 60

// annReserve is the capacity each kind keeps within MaxAnnotations: waves,
// restarts, configuration and mode changes and gaps are never pushed out
// by incidents (D36 fix round 1, finding B.4.4 b). Capacity a kind does
// not use goes to the others, incidents first.
var annReserve = []struct {
	kinds []string
	n     int
}{
	{[]string{websites.AnnRestart}, 30},
	{[]string{websites.AnnConfigChanged, websites.AnnModeChanged}, 30},
	{[]string{websites.AnnMonitoringGap}, 30},
	{[]string{websites.AnnWaveDetected, websites.AnnWaveEnded}, 30},
	{[]string{websites.AnnBlockLong}, 20},
	{[]string{websites.AnnRuleRepository}, 10},
	{[]string{websites.AnnIncident}, websites.MaxAnnotations - 150},
}

// budgetAnnotations keeps at most MaxAnnotations markers, the newest of
// each kind within its reserve, and sorts them by time; truncated is true
// when one was left out.
func budgetAnnotations(items []websites.Annotation) ([]websites.Annotation, bool) {
	groups := make([][]websites.Annotation, len(annReserve))
	for _, a := range items {
		for i, r := range annReserve {
			if slices.Contains(r.kinds, a.Kind) {
				groups[i] = append(groups[i], a)
				break
			}
		}
	}
	take := make([]int, len(groups))
	left := websites.MaxAnnotations
	for i, g := range groups {
		take[i] = min(len(g), annReserve[i].n)
		left -= take[i]
	}
	// Spare capacity: incidents first, then the others in order.
	order := []int{len(groups) - 1}
	for i := 0; i < len(groups)-1; i++ {
		order = append(order, i)
	}
	for _, i := range order {
		extra := min(len(groups[i])-take[i], left)
		take[i] += extra
		left -= extra
	}
	var out []websites.Annotation
	truncated := false
	for i, g := range groups {
		sort.SliceStable(g, func(a, b int) bool { return g[a].T < g[b].T })
		if len(g) > take[i] {
			truncated = true
			g = g[len(g)-take[i]:] // the newest
		}
		out = append(out, g...)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].T < out[j].T })
	return out, truncated
}

// ---------------------------------------------------------------- alerts

var alertFilterDims = map[string]bool{"path": true, "country": true, "net_class": true, "asn": true, "rule": true, "bot_category": true}

func (s *Server) listAlerts(w http.ResponseWriter, r *http.Request) {
	ws, ok := s.website(w, r)
	if !ok {
		return
	}
	q := &query{r: r}
	from, to := q.time("from"), q.time("to")
	limit := websites.MaxAlerts
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > websites.MaxAlerts {
			q.errs = append(q.errs, FieldError{Pointer: "#/query/limit", Detail: "1 bis 50"})
		} else {
			limit = n
		}
	}
	raw := r.URL.Query()["filter"]
	fs, err := monitoring.ParseFilters(raw)
	if err != nil || len(fs) > 1 {
		q.errs = append(q.errs, FieldError{Pointer: "#/query/filter", Detail: "ein Filter: path, country, net_class, asn, rule oder bot_category"})
	}
	var f *monitoring.Filter
	if err == nil && len(fs) == 1 {
		if !alertFilterDims[fs[0].Dim] {
			q.errs = append(q.errs, FieldError{Pointer: "#/query/filter", Detail: "path, country, net_class, asn, rule oder bot_category"})
		}
		f = &fs[0]
	}
	if q.failed(w) {
		return
	}
	af := store.AlertFilter{Site: ws.ID, From: from, To: to}
	none := false
	if f != nil {
		switch f.Dim {
		case "path":
			af.Path = f.Value
		case "country":
			af.Country = f.Value
		case "asn":
			n, err := strconv.ParseUint(f.Value, 10, 32)
			if err != nil {
				invalid(w, "Ungültige ASN.", FieldError{Pointer: "#/query/filter", Detail: "Zahl"})
				return
			}
			a := uint32(n)
			af.ASN = &a
		case "rule":
			af.Rule = f.Value
		case "net_class":
			af.NetClass = f.Value
		case "bot_category":
			// Bot categories are not part of local events yet (MVP-22):
			// nothing matches, nothing to read.
			none = true
		}
	}
	ctx := r.Context()
	var rows []*store.EventRow
	var err2 error
	if !none {
		rows, err2 = s.St.AlertEvents(ctx, af, 500)
	}
	err = err2
	if err != nil {
		s.internal(w, err)
		return
	}
	out := websites.AlertFeed{Site: ws.ID, Items: []websites.AlertItem{}}
	if len(raw) > 0 {
		out.Filters = raw
	}
	key := s.pseudonymKey(ctx)
	rc := s.reasonContext()
	fps := s.possibleFalsePositives(ws.ID) // D36 amendment (c), from the request ring
	for _, e := range rows {
		if len(out.Items) == limit {
			break
		}
		var b alertBody
		_ = json.Unmarshal(e.Body, &b)
		it, ok := alertOf(e, &b, rc)
		if !ok {
			continue
		}
		if a, err := netip.ParseAddr(e.IP); err == nil && key != nil {
			it.ClientPseudonym = contractapi.ClientPseudonym(key, a)
		}
		if it.Kind == "waf" {
			it.PossibleFalsePositive = markFalsePositive(fps, it.Rules, it.Path)
		}
		out.Items = append(out.Items, it)
	}
	writeJSON(w, 200, out)
}

type alertBody struct {
	Data struct {
		Client struct {
			Geo events.Geo `json:"geo"`
		} `json:"client"`
		Scenario    string `json:"scenario"`
		Mode        string `json:"mode"`
		Action      string `json:"action"`
		WouldAction string `json:"would_action"`
		Reason      string `json:"reason"`
		Route       string `json:"route"`
		Incident    string `json:"incident"`
		// WouldBlockReason of a request event (v0.5, D36 open items).
		WouldBlockReason string `json:"would_block_reason"`
	} `json:"data"`
}

// reasonCtx is what the would_block_reason of behaviour and rate-limit
// alerts is derived from: their events carry mode and reason, but not
// whether the gateway observed, so the current gateway mode stands in for
// it, and the learning period is read from the behaviour engine.
type reasonCtx struct {
	gatewayObserve bool
	learning       func(t time.Time) bool
}

func (s *Server) reasonContext() reasonCtx {
	rc := reasonCtx{learning: func(time.Time) bool { return false }}
	if s.Gate != nil {
		rc.gatewayObserve = s.Gate.Settings().Mode == decide.ModeObserve
	}
	if s.Behaviour != nil {
		lu := s.Behaviour.LearnUntil()
		// Zero means an unknown first start, which keeps learning.
		rc.learning = func(t time.Time) bool { return lu.IsZero() || t.Before(lu) }
	}
	return rc
}

// behaviourWouldReason: why a behaviour hit that would have blocked
// (would_action block, action below it) was passed. Its event keeps mode
// observe when the gateway observes, so gateway_observe is the current
// gateway mode; learning is the stored reason or the learning period at
// the event's time; else the scenario observes (mode observe, or the old
// mode challenge of events before D92). An exempt client never has would_action
// block; allowlist and shared_address are mapped for completeness.
func behaviourWouldReason(t time.Time, mode, reason string, rc reasonCtx) string {
	var rs []string
	if rc.gatewayObserve {
		rs = append(rs, decide.ReasonGatewayObserve)
	}
	if reason == behaviour.ReasonLearning || (rc.learning != nil && rc.learning(t)) {
		rs = append(rs, decide.ReasonLearning)
	}
	if mode != config.BehaviourBlock || reason == "challenge_unavailable" {
		rs = append(rs, decide.ReasonScenarioObserve)
	}
	return decide.FirstReason(append(rs, exemptReason(reason))...)
}

// rateLimitWouldReason: why an exceeded rate limit was only observed.
// Rate limits act from day 0 (no learning); mode is observe when the limit
// or the gateway observes; reason names an exempt client.
func rateLimitWouldReason(mode, reason string, rc reasonCtx) string {
	var rs []string
	if rc.gatewayObserve {
		rs = append(rs, decide.ReasonGatewayObserve)
	}
	if mode != config.BehaviourBlock {
		rs = append(rs, decide.ReasonScenarioObserve)
	}
	return decide.FirstReason(append(rs, exemptReason(reason))...)
}

// exemptReason maps the behaviour reason of an exempt client.
func exemptReason(reason string) string {
	switch reason {
	case behaviour.ReasonAllowlisted, behaviour.ReasonReleased:
		return decide.ReasonAllowlist
	case behaviour.ReasonNetClass:
		return decide.ReasonSharedAddress
	}
	return ""
}

// validReason keeps a stored would_block_reason only when the contract
// knows it.
func validReason(r string) string {
	if r != "" && decide.FirstReason(r) == r {
		return r
	}
	return ""
}

var countryRe2 = regexp.MustCompile(`^[A-Z]{2}$`)

// alertOf maps a detection event to an AlertItem.
func alertOf(e *store.EventRow, b *alertBody, rc reasonCtx) (websites.AlertItem, bool) {
	it := websites.AlertItem{T: ts(e.Time), EventID: e.ID, Path: e.Path, Incident: e.Incident}
	if countryRe2.MatchString(e.Country) {
		it.Country = e.Country
	}
	if nc := b.Data.Client.Geo.NetClass; nc != "" {
		it.NetClass = nc
	}
	switch e.Type {
	case events.RequestBlocked, events.RequestEvaluated:
		if len(e.Rules) == 0 {
			return it, false
		}
		it.Kind, it.Outcome = "waf", "blocked"
		if e.Outcome == "would_block" {
			it.Outcome = "would_block"
			it.WouldBlockReason = validReason(b.Data.WouldBlockReason)
		}
		it.Category = websites.RuleCategory(e.Rules[0])
		for _, r := range e.Rules {
			if len(it.Rules) < 3 && len(r) <= 32 {
				it.Rules = append(it.Rules, r)
			}
		}
	case events.BehaviourTriggered:
		it.Kind, it.Category, it.Scenario = "behaviour", "behaviour", b.Data.Scenario
		switch {
		case b.Data.Action == "block":
			it.Outcome = "blocked"
		case b.Data.WouldAction == "block":
			it.Outcome = "would_block"
			it.WouldBlockReason = behaviourWouldReason(e.Time, b.Data.Mode, b.Data.Reason, rc)
		default:
			return it, false
		}
		if it.Path == "" {
			it.Path = b.Data.Route
		}
		if it.Incident == "" {
			it.Incident = b.Data.Incident
		}
	case events.RateLimitExceeded:
		it.Kind, it.Category = "rate_limit", "rate_limit"
		if b.Data.Action == "observe" {
			it.Outcome = "would_rate_limit"
			it.WouldBlockReason = rateLimitWouldReason(b.Data.Mode, b.Data.Reason, rc)
		} else {
			it.Outcome = "rate_limited"
		}
		if it.Path == "" {
			it.Path = b.Data.Route
		}
	default:
		return it, false
	}
	if len(it.Path) > 512 || strings.ContainsFunc(it.Path, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		it.Path = ""
	}
	if it.Incident != "" && !incRe.MatchString(it.Incident) {
		it.Incident = ""
	}
	return it, true
}

func (s *Server) pseudonymKey(ctx context.Context) []byte {
	k, err := s.St.PseudonymKey(ctx)
	if err != nil {
		return nil
	}
	return k
}

// ---------------------------------------------------------------- incidents

// IncidentPage is listIncidents.
type IncidentPage struct {
	Items      []Incident `json:"items"`
	NextCursor *string    `json:"next_cursor"`
}

func (s *Server) listIncidents(w http.ResponseWriter, r *http.Request) {
	q := &query{r: r}
	from, to := q.time("from"), q.time("to")
	status := q.enum("status", "blocked", "unblocked")
	site := s.siteParam(q)
	limit := q.limit()
	now := s.now()
	if to.IsZero() {
		to = now.Add(time.Second)
	}
	if from.IsZero() {
		from = to.Add(-7 * 24 * time.Hour)
	}
	if !from.Before(to) || to.Sub(from) > 31*24*time.Hour {
		q.errs = append(q.errs, FieldError{Pointer: "#/query/from", Detail: "höchstens 31 Tage, from vor to"})
	}
	var bms int64
	var bid string
	if c := r.URL.Query().Get("cursor"); c != "" {
		ms, id, ok := strings.Cut(strings.TrimPrefix(c, "i"), "_")
		n, err := strconv.ParseInt(ms, 10, 64)
		if !ok || err != nil || !strings.HasPrefix(c, "i") || !incRe.MatchString(id) {
			q.errs = append(q.errs, FieldError{Pointer: "#/query/cursor", Detail: "ungültig"})
		}
		bms, bid = n, id
	}
	if q.failed(w) {
		return
	}
	rows, err := s.St.IncidentsInRange(r.Context(), from, to, store.IncidentFilter{Site: site, Status: status}, bms, bid, limit+1)
	if err != nil {
		s.internal(w, err)
		return
	}
	page := IncidentPage{Items: []Incident{}}
	if len(rows) > limit {
		rows = rows[:limit]
		last := rows[len(rows)-1]
		c := "i" + strconv.FormatInt(last.Time.UnixMilli(), 10) + "_" + last.Incident
		page.NextCursor = &c
	}
	for _, in := range rows {
		page.Items = append(page.Items, s.incidentView(r.Context(), in))
	}
	writeJSON(w, 200, page)
}

// ---------------------------------------------------------------- agent calls

// AgentTokenInfo, AgentCall and AgentCallLog are listAgentCalls.
type AgentTokenInfo struct {
	ID         string  `json:"id"`
	Scope      string  `json:"scope"`
	Label      string  `json:"label,omitempty"`
	CreatedAt  string  `json:"created_at"`
	ExpiresAt  string  `json:"expires_at"`
	RevokedAt  *string `json:"revoked_at"`
	LastUsedAt *string `json:"last_used_at"`
}

type AgentCall struct {
	TokenID string `json:"token_id"`
	Time    string `json:"time"`
	Op      string `json:"op"`
	Status  int    `json:"status"`
	Rows    int    `json:"rows"`
	Bytes   int64  `json:"bytes"`
}

type AgentCallLog struct {
	Enabled    bool             `json:"enabled"`
	LogDays    int              `json:"log_days"`
	Tokens     []AgentTokenInfo `json:"tokens"`
	Items      []AgentCall      `json:"items"`
	NextCursor *string          `json:"next_cursor"`
}

var (
	tokenIDRe = regexp.MustCompile(`^tok_[0-9a-f]{12}$`)
	opRe      = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}$`)
)

func (s *Server) listAgentCalls(w http.ResponseWriter, r *http.Request) {
	q := &query{r: r}
	from, to := q.time("from"), q.time("to")
	token := q.str("token", 16, tokenIDRe)
	limit, cursor := q.limit(), q.cursor()
	if q.failed(w) {
		return
	}
	now := s.now()
	if to.IsZero() {
		to = now.Add(time.Second)
	}
	if from.IsZero() {
		from = to.Add(-30 * 24 * time.Hour)
	}
	c := s.Config().AgentAPI
	out := AgentCallLog{Enabled: s.agentAPIState(r.Context()).Enabled, LogDays: min(max(c.LogDays, 1), 90), Tokens: []AgentTokenInfo{}, Items: []AgentCall{}}
	ctx := r.Context()
	toks, err := s.St.ListAgentTokens(ctx)
	if err != nil {
		s.internal(w, err)
		return
	}
	last, _ := s.St.LastAgentUse(ctx)
	for _, t := range toks {
		if len(out.Tokens) == 256 || !tokenIDRe.MatchString(t.ID) {
			continue
		}
		info := AgentTokenInfo{ID: t.ID, Scope: t.Scope, Label: t.Label, CreatedAt: ts(t.Created), ExpiresAt: ts(t.Expires), RevokedAt: tsp(t.RevokedAt)}
		if len(info.Label) > 64 {
			info.Label = info.Label[:64]
		}
		if u, ok := last[t.ID]; ok {
			info.LastUsedAt = tsp(u)
		}
		out.Tokens = append(out.Tokens, info)
	}
	calls, seqs, err := s.St.AgentCallsInRange(ctx, from, to, token, cursor, limit+1)
	if err != nil {
		s.internal(w, err)
		return
	}
	if len(calls) > limit {
		calls, seqs = calls[:limit], seqs[:limit]
		out.NextCursor = nextCursor(seqs[len(seqs)-1])
	}
	for _, c := range calls {
		if !tokenIDRe.MatchString(c.TokenID) || !opRe.MatchString(c.Op) {
			continue
		}
		out.Items = append(out.Items, AgentCall{TokenID: c.TokenID, Time: ts(c.Time), Op: c.Op, Status: min(max(c.Status, 100), 599), Rows: max(c.Rows, 0), Bytes: max(c.Bytes, 0)})
	}
	writeJSON(w, 200, out)
}
