package dashboard

import (
	"context"
	"encoding/json"
	"errors"
	"hash/fnv"
	"math"
	"net/http"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/deutschland-schild/schild/contract/bots"
	cm "github.com/deutschland-schild/schild/contract/monitoring"
	cr "github.com/deutschland-schild/schild/contract/requests"
	"github.com/deutschland-schild/schild/gateway/internal/pathtpl"
	"github.com/deutschland-schild/schild/gateway/internal/reqring"
)

// v0.5 (MVP-22, D35): the tag `requests` - single requests of the request
// ring, Kontext around an event, the bot overview and the alert statistics
// per rule and page with "möglicher Fehlalarm" hints.

func (s *Server) requestRoutes(a func(string, http.HandlerFunc)) {
	a("GET "+apiPrefix+"/requests", s.queryRequests)
	a("GET "+apiPrefix+"/requests/context/{event_id}", s.getRequestContext)
	a("GET "+apiPrefix+"/requests/bots", s.getBotOverview)
	a("GET "+apiPrefix+"/requests/alerts/rules", s.getRuleAlerts)
	a("GET "+apiPrefix+"/requests/alerts/pages", s.getPageAlerts)
	a("GET "+apiPrefix+"/requests/alerts/hints", s.listFalsePositiveHints)
}

// ringOff answers 409 requests_off without a ring.
func (s *Server) ringOff(w http.ResponseWriter) bool {
	if s.Requests == nil {
		requestsOff(w, nil)
		return true
	}
	return false
}

// ringFailed maps errors of the ring.
func (s *Server) ringFailed(w http.ResponseWriter, err error) {
	var inv *reqring.ErrInvalid
	switch {
	case errors.As(err, &inv):
		invalid(w, inv.Msg, FieldError{Pointer: "#/query/" + inv.Param, Detail: inv.Msg})
	case errors.Is(err, reqring.ErrBusy), errors.Is(err, context.DeadlineExceeded):
		problem(w, http.StatusTooManyRequests, "rate_limited", "Eine andere Abfrage der Einzelanfragen läuft gerade. Versuch es gleich noch einmal.", nil)
	default:
		s.internal(w, err)
	}
}

var (
	ruleIDRe   = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,32}$`)
	ctrlFreeRe = regexp.MustCompile(`^[^\x00-\x1f\x7f]*$`)
	botIDRe    = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,47}$`)
)

func indexOf(list []string, v string) int {
	for i, x := range list {
		if x == v {
			return i
		}
	}
	return -1
}

// ringFilter reads the queryRequests filters.
func (s *Server) ringFilter(q *query) reqring.Filter {
	f := reqring.AnyFilter()
	f.Site = s.siteParam(q)
	f.Path = q.str("path", 512, ctrlFreeRe)
	f.Rule = q.str("rule", 32, ruleIDRe)
	if v := q.enum("outcome", cr.Outcomes...); v != "" {
		f.Outcome = indexOf(cr.Outcomes, v)
	}
	if v := q.enum("status_class", "1xx", "2xx", "3xx", "4xx", "5xx"); v != "" {
		f.StatusClass = int(v[0] - '0')
	}
	f.Country = q.str("country", 2, countryRe)
	if v := q.enum("bot_category", cm.BotCategories...); v != "" {
		f.BotCategory = indexOf(cm.BotCategories, v)
	}
	if v := q.str("bot", 48, botIDRe); v != "" {
		f.Bot = 1 << 20 // unknown bot: matches nothing
		if s.Bots != nil {
			if id, ok := s.Bots.BotID(v); ok {
				f.Bot = int(id)
			}
		}
	}
	if v := q.enum("verification", bots.Verifications...); v != "" {
		f.Verif = indexOf(bots.Verifications, v) + 1
	}
	if v := q.r.URL.Query().Get("visitor"); v != "" {
		vk, ok := reqring.ParseVisitor(v)
		if !ok {
			q.errs = append(q.errs, FieldError{Pointer: "#/query/visitor", Detail: "ungültiger Besucher-Schlüssel"})
		}
		f.Visitor = vk
	}
	if v := q.r.URL.Query().Get("ip"); v != "" {
		a, err := netip.ParseAddr(v)
		if err != nil {
			q.errs = append(q.errs, FieldError{Pointer: "#/query/ip", Detail: "ungültige Adresse"})
		}
		f.IP = a.Unmap().WithZone("")
	}
	f.UserAgent = strings.ToLower(q.str("user_agent", 1024, ctrlFreeRe))
	return f
}

func (s *Server) queryRequests(w http.ResponseWriter, r *http.Request) {
	q := &query{r: r}
	from, to := q.time("from"), q.time("to")
	if from.IsZero() {
		q.errs = append(q.errs, FieldError{Pointer: "#/query/from", Detail: "Pflichtfeld"})
	}
	if to.IsZero() {
		q.errs = append(q.errs, FieldError{Pointer: "#/query/to", Detail: "Pflichtfeld"})
	}
	f := s.ringFilter(q)
	limit := q.limit()
	cur := q.r.URL.Query().Get("cursor")
	if len(cur) > 256 {
		q.errs = append(q.errs, FieldError{Pointer: "#/query/cursor", Detail: "ungültig"})
	}
	if q.failed(w) || s.ringOff(w) {
		return
	}
	qp := reqring.QueryParams{From: from, To: to, Filter: f, Cursor: cur, Limit: limit}
	if f.IP.IsValid() || f.UserAgent != "" { // D49, D50: one client, over the whole ring
		qp.MaxWindow = (cr.MaxKeepHours + 1) * time.Hour
		if lo, _ := s.Requests.Window(s.now()); qp.From.Before(lo) && lo.Before(qp.To) {
			qp.From = lo
		}
	}
	p, err := s.Requests.Query(r.Context(), qp, s.now())
	if err != nil {
		s.ringFailed(w, err)
		return
	}
	writeJSON(w, 200, p)
}

// RequestContext builds getRequestContext for an event (shared with the
// agent API through the dashboard server): the ring's context plus the
// site strip of the monitoring 10 s ring and sites_affected.
func (s *Server) RequestContext(ctx context.Context, eventID string) (cr.Context, int, error) {
	e, err := s.St.GetEvent(ctx, eventID)
	if err != nil || e == nil {
		return cr.Context{}, http.StatusNotFound, errors.New("not found")
	}
	c, err := s.Requests.Context(ctx, eventID, e.Time, s.now())
	if err != nil {
		return cr.Context{}, 0, err
	}
	if c.State != "expired" {
		from, _ := time.Parse(time.RFC3339Nano, c.From)
		to, _ := time.Parse(time.RFC3339Nano, c.To)
		site := e.Site
		if c.Anchor != nil {
			site = c.Anchor.Site
		}
		if _, ok := s.view().Website(site); !ok {
			site = ""
		}
		c.SiteStrip = s.Monitor.Strip(site, from, to)
		if sa := s.SitesAffected(ctx, e.IP, e.Site, e.Time); sa != nil {
			c.SitesAffected = &cr.SitesAffected{Sites: sa.Sites, Count: sa.Count, Total: sa.Total}
		}
	}
	return c, 0, nil
}

func (s *Server) getRequestContext(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("event_id")
	if !uuidRe.MatchString(id) {
		problem(w, http.StatusNotFound, "not_found", "Dieses Ereignis gibt es nicht.", nil)
		return
	}
	if s.ringOff(w) {
		return
	}
	c, status, err := s.RequestContext(r.Context(), id)
	if status == http.StatusNotFound {
		problem(w, http.StatusNotFound, "not_found", "Dieses Ereignis gibt es nicht (mehr).", nil)
		return
	}
	if err != nil {
		s.ringFailed(w, err)
		return
	}
	writeJSON(w, 200, c)
}

// ringRange reads from and to, defaulting to the last 24 h, clamped to
// the ring's window.
func (s *Server) ringRange(q *query) (time.Time, time.Time) {
	now := s.now()
	from, to := q.time("from"), q.time("to")
	if to.IsZero() || to.After(now) {
		to = now
	}
	if from.IsZero() {
		from = to.Add(-24 * time.Hour)
	}
	if !from.Before(to) {
		q.errs = append(q.errs, FieldError{Pointer: "#/query/from", Detail: "from muss vor to liegen"})
	}
	if s.Requests != nil {
		if lo, _ := s.Requests.Window(now); from.Before(lo) {
			from = lo
		}
	}
	return from, to
}

func (s *Server) getBotOverview(w http.ResponseWriter, r *http.Request) {
	q := &query{r: r}
	site := s.siteParam(q)
	from, to := s.ringRange(q)
	if q.failed(w) || s.ringOff(w) {
		return
	}
	o, err := s.Requests.BotOverview(r.Context(), s.botDir(), site, from, to)
	if err != nil {
		s.ringFailed(w, err)
		return
	}
	writeJSON(w, 200, o)
}

// botDir returns the bot directory (nil interface without one).
func (s *Server) botDir() reqring.BotDirectory {
	if s.Bots == nil {
		return nil
	}
	return s.Bots
}

// ---------------------------------------------------------------- alerts

// alertRange reads from, to and top of the alert operations; detections
// come from the monitoring rings over the whole range (up to 14 d).
func (s *Server) alertRange(q *query) (time.Time, time.Time, int) {
	now := s.now()
	from, to := q.time("from"), q.time("to")
	if to.IsZero() || to.After(now) {
		to = now
	}
	if from.IsZero() {
		from = to.Add(-24 * time.Hour)
	}
	if !from.Before(to) {
		q.errs = append(q.errs, FieldError{Pointer: "#/query/from", Detail: "from muss vor to liegen"})
	}
	top := 20
	if v := q.r.URL.Query().Get("top"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 64 {
			q.errs = append(q.errs, FieldError{Pointer: "#/query/top", Detail: "1 bis 64"})
		} else {
			top = n
		}
	}
	return from, to, top
}

// ringPart returns the part of [from, to) inside the ring's window.
func (s *Server) ringPart(from, to time.Time) (time.Time, bool) {
	if s.Requests == nil {
		return time.Time{}, false
	}
	lo, _ := s.Requests.Window(s.now())
	if o := s.Requests.Oldest(); !o.IsZero() && o.After(lo) {
		lo = o
	}
	if !lo.Before(to) {
		return time.Time{}, false
	}
	return maxTime(from, lo), true
}

func maxTime(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

func ratio(a, b float64) float64 {
	if b <= 0 {
		return 0
	}
	return math.Min(1, a/b)
}

func (s *Server) getRuleAlerts(w http.ResponseWriter, r *http.Request) {
	q := &query{r: r}
	site := s.siteParam(q)
	from, to, top := s.alertRange(q)
	if q.failed(w) || s.monitoringOff(w) {
		return
	}
	now := s.now()
	bd, err := s.Monitor.Breakdown("rule", from, to, site, nil, 64, now)
	if err != nil {
		s.monitoringFailed(w, err)
		return
	}
	out := cr.RuleAlerts{From: ts(from), To: ts(to), Site: site, Resolution: bd.Resolution, Items: []cr.RuleAlert{}}
	var st *reqring.AlertStats
	hints := map[string]bool{}
	if rf, ok := s.ringPart(from, to); ok {
		st, err = s.Requests.Alerts(r.Context(), site, rf, to)
		if err != nil {
			s.ringFailed(w, err)
			return
		}
		f := ts(rf)
		out.RingFrom = &f
		for _, h := range s.hintsOf(r.Context(), st) {
			hints[h.RuleID] = true
		}
	}
	// Rules the request ring saw but the rings do not list yet (the
	// current minute is not written) join with the ring's counts.
	items := bd.Items
	if st != nil {
		listed := map[string]bool{}
		for _, e := range items {
			listed[e.Key] = true
		}
		for id, rs := range st.Rules {
			if !listed[id] {
				items = append(items, cm.TopEntry{Key: id, Requests: round(rs.Detections), Stopped: round(rs.Blocked), WouldBlock: round(rs.WouldBlock)})
			}
		}
		sort.SliceStable(items, func(i, j int) bool { return items[i].Requests > items[j].Requests })
	}
	for _, e := range items {
		ra := cr.RuleAlert{RuleID: e.Key, Detections: e.Requests, Blocked: e.Stopped, WouldBlock: e.WouldBlock, Error: e.Error, Pages: []cr.RulePage{},
			PossibleFalsePositive: hints[e.Key]}
		if st != nil {
			if rs := st.Rules[e.Key]; rs != nil {
				for key, d := range rs.Pages {
					p := st.Pages[key]
					_, path := reqring.SplitPageKey(key)
					rp := cr.RulePage{Path: path, Detections: round(d)}
					if p != nil {
						rp.Requests = round(p.Requests)
						rp.Rate = ratio(d, p.Requests)
					}
					ra.Pages = append(ra.Pages, rp)
				}
				sort.Slice(ra.Pages, func(i, j int) bool { return ra.Pages[i].Detections > ra.Pages[j].Detections })
				if len(ra.Pages) > 20 {
					ra.Pages = ra.Pages[:20]
				}
				for v := range rs.Visitors {
					vs := st.Visitors[v]
					if vs == nil {
						continue
					}
					ra.Clients.Hit++
					if vs.Alerts >= vs.Requests {
						ra.Clients.AlertOnly++
					} else if vs.NormalFor(e.Key) {
						ra.Clients.InSession++
					}
				}
			}
		}
		out.Items = append(out.Items, ra)
		if len(out.Items) == top {
			break
		}
	}
	writeJSON(w, 200, out)
}

func round(v float64) int64 { return int64(math.Round(v)) }

func (s *Server) getPageAlerts(w http.ResponseWriter, r *http.Request) {
	q := &query{r: r}
	site := s.siteParam(q)
	from, to, top := s.alertRange(q)
	if q.failed(w) || s.monitoringOff(w) {
		return
	}
	now := s.now()
	bd, err := s.Monitor.Breakdown("path", from, to, site, nil, 100, now)
	if err != nil {
		s.monitoringFailed(w, err)
		return
	}
	out := cr.PageAlerts{From: ts(from), To: ts(to), Site: site, Resolution: bd.Resolution, Items: []cr.PageAlert{}}
	var st *reqring.AlertStats
	if rf, ok := s.ringPart(from, to); ok {
		st, err = s.Requests.Alerts(r.Context(), site, rf, to)
		if err != nil {
			s.ringFailed(w, err)
			return
		}
		f := ts(rf)
		out.RingFrom = &f
	}
	items := bd.Items
	if st != nil {
		listed := map[string]bool{}
		for _, e := range items {
			listed[e.Key] = true
		}
		extra := map[string]*cm.TopEntry{}
		for key, p := range st.Pages {
			_, path := reqring.SplitPageKey(key)
			if listed[path] || p.Detections == 0 {
				continue
			}
			e := extra[path]
			if e == nil {
				e = &cm.TopEntry{Key: path}
				extra[path] = e
			}
			e.Requests += round(p.Requests)
			e.Detections += round(p.Detections)
			e.Stopped += round(p.Blocked)
			e.WouldBlock += round(p.WouldBlock)
		}
		for _, e := range extra {
			items = append(items, *e)
		}
	}
	for _, e := range items {
		pa := cr.PageAlert{Path: e.Key, Requests: e.Requests, Detections: e.Detections, Rate: ratio(float64(e.Detections), float64(e.Requests)),
			Blocked: e.Stopped, WouldBlock: e.WouldBlock, Error: e.Error}
		if st != nil {
			var agg *reqring.PageStats
			for key, p := range st.Pages {
				if ps, path := reqring.SplitPageKey(key); path == e.Key && (site == "" || ps == site) {
					if agg == nil {
						c := *p
						c.Rules = map[string]float64{}
						for k, v := range p.Rules {
							c.Rules[k] = v
						}
						agg = &c
						continue
					}
					agg.Requests += p.Requests
					agg.ObserveFollowedBy2xx += p.ObserveFollowedBy2xx
					for i := range agg.Status {
						agg.Status[i] += p.Status[i]
					}
					for i := range agg.Hist {
						agg.Hist[i] += p.Hist[i]
					}
					for k, v := range p.Rules {
						agg.Rules[k] += v
					}
				}
			}
			if agg != nil {
				pa.Status = &cr.StatusClasses{S1xx: round(agg.Status[0]), S2xx: round(agg.Status[1]), S3xx: round(agg.Status[2]), S4xx: round(agg.Status[3]), S5xx: round(agg.Status[4])}
				if p95, ok := agg.P95(); ok {
					pa.LatencyP95MS = &p95
				}
				o := round(agg.ObserveFollowedBy2xx)
				pa.ObserveFollowedBy2xx = &o
				pa.Review = o > 0
				for k, v := range agg.Rules {
					pa.Rules = append(pa.Rules, cr.RuleCount{RuleID: k, Detections: round(v)})
				}
				sort.Slice(pa.Rules, func(i, j int) bool { return pa.Rules[i].Detections > pa.Rules[j].Detections })
				if len(pa.Rules) > 10 {
					pa.Rules = pa.Rules[:10]
				}
			}
		}
		if pa.Detections == 0 && !pa.Review {
			continue // pages without alerts are the traffic view's
		}
		out.Items = append(out.Items, pa)
		if len(out.Items) == top {
			break
		}
	}
	sort.SliceStable(out.Items, func(i, j int) bool { return out.Items[i].Rate > out.Items[j].Rate })
	writeJSON(w, 200, out)
}

// ---------------------------------------------------------------- false positives

// Thresholds of a "möglicher Fehlalarm": at least fpMinClients visitors hit
// by the rule on the page, and at least fpShare of them otherwise normal
// visitors (page views, 2xx answers, a browser, no alert of another rule).
const (
	fpMinClients = 3
	fpShare      = 0.6
)

func (s *Server) listFalsePositiveHints(w http.ResponseWriter, r *http.Request) {
	q := &query{r: r}
	site := s.siteParam(q)
	from, to := s.ringRange(q)
	if q.failed(w) || s.ringOff(w) {
		return
	}
	st, err := s.Requests.Alerts(r.Context(), site, from, to)
	if err != nil {
		s.ringFailed(w, err)
		return
	}
	hints := s.hintsOf(r.Context(), st)
	if site == "" || from.Before(s.now().Add(-23*time.Hour)) {
		s.fp.store(site, hints, s.now())
	}
	writeJSON(w, 200, cr.FalsePositiveHintList{From: ts(from), To: ts(to), Items: hints})
}

// FalsePositiveHints is listFalsePositiveHints for the agent API (D54).
func (s *Server) FalsePositiveHints(ctx context.Context, site string, from, to time.Time) (cr.FalsePositiveHintList, error) {
	st, err := s.Requests.Alerts(ctx, site, from, to)
	if err != nil {
		return cr.FalsePositiveHintList{}, err
	}
	return cr.FalsePositiveHintList{From: ts(from), To: ts(to), Items: s.hintsOf(ctx, st)}, nil
}

// hintsOf derives the hints of an alert scan.
func (s *Server) hintsOf(ctx context.Context, st *reqring.AlertStats) []cr.FalsePositiveHint {
	out := []cr.FalsePositiveHint{}
	if st == nil {
		return out
	}
	v := s.view()
	for key, p := range st.Pages {
		site, path := reqring.SplitPageKey(key)
		for rule, vis := range p.AlertVisitors {
			if len(vis) < fpMinClients {
				continue
			}
			if _, err := strconv.Atoi(rule); err != nil {
				continue // ctl:ruleRemove* needs a numeric id
			}
			inSession := 0
			for vk := range vis {
				if vs := st.Visitors[vk]; vs != nil && vs.NormalFor(rule) {
					inSession++
				}
			}
			if float64(inSession) < fpShare*float64(len(vis)) {
				continue
			}
			target := s.targetOf(ctx, p.SampleEvents[rule], rule)
			ex, err := v.Exception(site, rule, path, target, localRuleID(site, rule, path))
			if err != nil {
				ex, err = v.Exception(site, rule, path, "", localRuleID(site, rule, path))
				target = ""
				if err != nil {
					continue
				}
			}
			h := cr.FalsePositiveHint{RuleID: rule, Path: path, Target: target, Detections: round(p.Rules[rule]), ClientsHit: int64(len(vis)),
				ClientsInSession: int64(inSession), Since: reqring.FormatMs(p.FirstAlertOf(rule)), Site: site, Exception: ex}
			if h.Detections < 1 {
				h.Detections = 1
			}
			out = append(out, h)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ClientsInSession != out[j].ClientsInSession {
			return out[i].ClientsInSession > out[j].ClientsInSession
		}
		return out[i].RuleID+out[i].Path < out[j].RuleID+out[j].Path
	})
	if len(out) > cr.MaxFalsePositives {
		out = out[:cr.MaxFalsePositives]
	}
	return out
}

// localRuleID is a stable id for a suggested local rule (1000000 to
// 9999999, outside the CRS range).
func localRuleID(site, rule, path string) int64 {
	h := fnv.New32a()
	h.Write([]byte(site + "\x00" + rule + "\x00" + path))
	return 1_000_000 + int64(h.Sum32()%9_000_000)
}

var targetRe = regexp.MustCompile(`^[A-Z_]+(:[^\x00-\x1F\x7F]{1,200})?$`)

// targetOf returns the matched variable of rule as the sample events
// record it (match_shape.location, e.g. ARGS:comment) when they agree; ""
// otherwise (the exception then removes the rule on the page).
func (s *Server) targetOf(ctx context.Context, evs [][16]byte, rule string) string {
	id, _ := strconv.Atoi(rule)
	target := ""
	for _, ev := range evs {
		e, err := s.St.GetEvent(ctx, reqring.FormatUUIDBytes(ev))
		if err != nil || e == nil {
			continue
		}
		var b struct {
			Data struct {
				Rules []struct {
					ID         int `json:"id"`
					MatchShape *struct {
						Location string `json:"location"`
					} `json:"match_shape"`
				} `json:"rules"`
			} `json:"data"`
		}
		if json.Unmarshal(e.Body, &b) != nil {
			continue
		}
		for _, m := range b.Data.Rules {
			if m.ID != id || m.MatchShape == nil || m.MatchShape.Location == "" {
				continue
			}
			loc := m.MatchShape.Location
			if !targetRe.MatchString(loc) || len(loc) > 256 {
				return ""
			}
			if target != "" && target != loc {
				return "" // the events disagree: no field
			}
			target = loc
		}
	}
	return target
}

// fpCache keeps the hints of the last 24 h per website for
// AlertItem.possible_false_positive (refreshed in the background).
type fpCache struct {
	mu      sync.Mutex
	entries map[string]fpEntry
	running map[string]bool
}

type fpEntry struct {
	at  time.Time
	set map[string]bool // rule \x00 path
}

const fpTTL = 5 * time.Minute

func (c *fpCache) store(site string, hints []cr.FalsePositiveHint, now time.Time) {
	set := map[string]bool{}
	for _, h := range hints {
		set[h.RuleID+"\x00"+h.Path] = true
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil {
		c.entries = map[string]fpEntry{}
	}
	c.entries[site] = fpEntry{at: now, set: set}
}

// possibleFalsePositives returns the hint set of a website for the alert
// feed; a stale or missing set is refreshed in the background (the alert
// feed never waits for a ring scan).
func (s *Server) possibleFalsePositives(site string) map[string]bool {
	if s.Requests == nil {
		return nil
	}
	now := s.now()
	c := &s.fp
	c.mu.Lock()
	e, ok := c.entries[site]
	if (!ok || now.Sub(e.at) > fpTTL) && !c.running[site] {
		if c.running == nil {
			c.running = map[string]bool{}
		}
		c.running[site] = true
		go func() {
			defer func() {
				c.mu.Lock()
				delete(c.running, site)
				c.mu.Unlock()
			}()
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			to := s.now()
			st, err := s.Requests.Alerts(ctx, site, to.Add(-24*time.Hour), to)
			if err != nil {
				return
			}
			c.store(site, s.hintsOf(ctx, st), to)
		}()
	}
	c.mu.Unlock()
	return e.set
}

// markFalsePositive sets AlertItem.possible_false_positive for a WAF alert
// whose rule and path template have a hint of the website.
func markFalsePositive(set map[string]bool, rules []string, path string) bool {
	if len(set) == 0 || path == "" {
		return false
	}
	t := pathtpl.Template(path)
	for _, r := range rules {
		if set[r+"\x00"+t] || set[r+"\x00"+path] {
			return true
		}
	}
	return false
}
