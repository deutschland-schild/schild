package dashboard

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/deutschland-schild/schild/contract/config"
	"github.com/deutschland-schild/schild/contract/events"
	"github.com/deutschland-schild/schild/gateway/internal/behaviour"
	"github.com/deutschland-schild/schild/gateway/internal/store"
	"sort"
)

// v0.4 (MVP-18): distributed attacks ("Wellen"). Address-free views; the
// recent requests in a wave detail are ordinary local events.

// Wave in the API.
type Wave struct {
	ID                  string  `json:"id"`
	Time                string  `json:"time"`
	Detector            string  `json:"detector"`
	Host                string  `json:"host,omitempty"`
	Route               string  `json:"route"`
	Senders             int     `json:"senders"`
	Count               int     `json:"count"`
	Threshold           int     `json:"threshold"`
	WindowS             int     `json:"window_s"`
	Baseline            float64 `json:"baseline,omitempty"`
	Fingerprint         string  `json:"fingerprint,omitempty"`
	FingerprintKind     string  `json:"fingerprint_kind,omitempty"`
	UserAgents          int     `json:"user_agents,omitempty"`
	RequestSig          string  `json:"request_sig,omitempty"`
	WAFRules            []int   `json:"waf_rules,omitempty"`
	Response            string  `json:"response"`
	Mode                string  `json:"mode"`
	Action              string  `json:"action"`
	Reason              string  `json:"reason,omitempty"`
	Until               *string `json:"until,omitempty"`
	Active              bool    `json:"active"`
	EndedAt             *string `json:"ended_at,omitempty"`
	EndReason           string  `json:"end_reason,omitempty"`
	Stopped             int     `json:"stopped"`
	SuggestSecondFactor bool    `json:"suggest_second_factor,omitempty"`
}

// WavePage is a page of waves.
type WavePage struct {
	Items      []Wave  `json:"items"`
	NextCursor *string `json:"next_cursor"`
}

// WaveDetail is one wave with recent requests on its route.
type WaveDetail struct {
	Wave     Wave           `json:"wave"`
	Requests []EventSummary `json:"requests"`
}

// DetectorThresholds in the API.
type DetectorThresholds struct {
	Count   int     `json:"count"`
	WindowS int     `json:"window_s"`
	Factor  float64 `json:"factor,omitempty"`
}

// DetectorSetting is one detector.
type DetectorSetting struct {
	ID            string             `json:"id"`
	Mode          string             `json:"mode"`
	EffectiveMode string             `json:"effective_mode"`
	Thresholds    DetectorThresholds `json:"thresholds"`
	Defaults      DetectorThresholds `json:"defaults"`
	Waves24h      int                `json:"waves_24h"`
}

// DistributedSettings is GET /distributed/settings.
type DistributedSettings struct {
	Detectors       []DetectorSetting      `json:"detectors"`
	LearningDays    int                    `json:"learning_days"`
	LearningUntil   *string                `json:"learning_until"`
	GatewayObserve  bool                   `json:"gateway_observe"`
	RouteTighten    config.RouteTighten    `json:"route_tighten"`
	AccountSlowdown config.AccountSlowdown `json:"account_slowdown"`
	Routes          []string               `json:"routes,omitempty"`
	FingerprintKind string                 `json:"fingerprint_kind"`
}

// DetectorModes is the detectors part of a settings patch.
type DetectorModes struct {
	RouteWave          *string `json:"route_wave,omitempty"`
	AccountWave        *string `json:"account_wave,omitempty"`
	ShapeWave          *string `json:"shape_wave,omitempty"`
	FingerprintCluster *string `json:"fingerprint_cluster,omitempty"`
	Inconsistency      *string `json:"inconsistency,omitempty"`
}

// DetectorThresholdsPatch sets the thresholds of one detector (D97). It
// replaces what the dashboard set before; a field left out falls back to
// schild.yaml or the built-in default, an empty object to all of them.
type DetectorThresholdsPatch struct {
	Count   *int     `json:"count,omitempty"`
	WindowS *int     `json:"window_s,omitempty"`
	Factor  *float64 `json:"factor,omitempty"`
}

// DistributedSettingsPatch is PATCH /distributed/settings.
type DistributedSettingsPatch struct {
	Detectors *DetectorModes `json:"detectors,omitempty"`
	// Thresholds by detector id (D97).
	Thresholds map[string]DetectorThresholdsPatch `json:"thresholds,omitempty"`
}

// detectorThresholds checks a thresholds patch against the bounds of
// schild.schema.json (distributedDetector), so a refused value names its
// field. The config validation of the commit stays the authority.
func detectorThresholds(in map[string]DetectorThresholdsPatch) (map[string]config.DetectorThresholds, []FieldError) {
	out := map[string]config.DetectorThresholds{}
	var errs []FieldError
	for id, p := range in {
		at := "/thresholds/" + id
		if (&config.DistributedDetectors{}).Get(id) == nil {
			errs = append(errs, FieldError{Pointer: at, Detail: "unbekannte Erkennung"})
			continue
		}
		var t config.DetectorThresholds
		if v := p.Count; v != nil {
			if t.Count = *v; *v < 3 || *v > 100000 {
				errs = append(errs, FieldError{Pointer: at + "/count", Detail: "3 bis 100000"})
			}
		}
		if v := p.WindowS; v != nil {
			if t.WindowS = *v; *v < 30 || *v > 3600 {
				errs = append(errs, FieldError{Pointer: at + "/window_s", Detail: "30 bis 3600 Sekunden"})
			}
		}
		if v := p.Factor; v != nil {
			if t.Factor = *v; id != config.DetectorRouteWave || *v < 2 || *v > 1000 {
				errs = append(errs, FieldError{Pointer: at + "/factor", Detail: "nur bei route_wave, 2 bis 1000"})
			}
		}
		out[id] = t
	}
	sort.Slice(errs, func(i, j int) bool { return errs[i].Pointer < errs[j].Pointer })
	return out, errs
}

func (s *Server) distributedRoutes(a func(string, http.HandlerFunc)) {
	a("GET "+apiPrefix+"/distributed/waves", s.listWaves)
	a("GET "+apiPrefix+"/distributed/waves/{wave_id}", s.getWave)
	a("POST "+apiPrefix+"/distributed/waves/{wave_id}/end", s.endWave)
	a("GET "+apiPrefix+"/distributed/settings", s.getDistributedSettings)
	a("PATCH "+apiPrefix+"/distributed/settings", s.updateDistributedSettings)
}

var loginPaths = map[string]bool{"/wp-login.php": true, "/administrator/index.php": true, "/index.php": true, "/user/login": true, "/index.php/login": true,
	"/typo3/login": true, "/typo3/index.php": true, "/login": true, "/signin": true, "/api/login": true, "/auth/login": true}

func waveFromMemory(w behaviour.Wave, now time.Time) Wave {
	v := Wave{ID: w.ID, Time: ts(w.Started), Detector: w.Detector, Host: w.Host, Route: w.Route, Senders: w.Senders, Count: w.Count, Threshold: w.Threshold,
		WindowS: w.WindowS, Baseline: w.Baseline, Fingerprint: w.Fingerprint, FingerprintKind: w.FPKind, UserAgents: w.UserAgents, RequestSig: w.RequestSig,
		WAFRules: w.WAFRules, Response: w.Response, Mode: modeOf(w.Mode), Action: w.Action, Reason: w.Reason, Active: w.Active(now), EndReason: w.EndReason,
		Stopped: w.Stopped, SuggestSecondFactor: w.Detector != config.DetectorShapeWave && loginPaths[w.Route]}
	if w.Action == config.DistributedRespond {
		v.Until = tsp(w.Until)
	}
	v.EndedAt = tsp(w.Ended)
	return v
}

func modeOf(m string) string {
	if m == config.DistributedRespond {
		return m
	}
	return config.DistributedObserve
}

// waveOf builds a wave from its detected event, completed by the in-memory
// state (running, stopped, end) while the process has it.
func (s *Server) waveOf(e *store.EventRow, now time.Time) (Wave, bool) {
	if e.Type != events.DistributedDetected {
		return Wave{}, false
	}
	if s.Behaviour != nil {
		if w, ok := s.Behaviour.WaveByID(e.ID); ok {
			return waveFromMemory(w, now), true
		}
	}
	var ev struct {
		Data events.DistributedDetectedData `json:"data"`
	}
	if json.Unmarshal(e.Body, &ev) != nil {
		return Wave{}, false
	}
	d := ev.Data
	v := Wave{ID: e.ID, Time: ts(e.Time), Detector: d.Detector, Host: d.Host, Route: d.Route, Senders: d.Senders, Count: d.Count, Threshold: d.Threshold,
		WindowS: d.WindowS, Baseline: d.Baseline, Fingerprint: d.Fingerprint, FingerprintKind: d.FingerprintKind, UserAgents: d.UserAgents,
		RequestSig: d.RequestSig, WAFRules: d.WAFRules, Response: d.Response, Mode: d.Mode, Action: d.Action, Reason: d.Reason,
		SuggestSecondFactor: d.Detector != config.DetectorShapeWave && loginPaths[d.Route]}
	if d.Until != "" {
		u := d.Until
		v.Until = &u
	}
	return v, true
}

func (s *Server) listWaves(w http.ResponseWriter, r *http.Request) {
	q := &query{r: r}
	f := store.EventFilter{Type: events.DistributedDetected}
	f.From, f.To = q.time("from"), q.time("to")
	f.Site = s.siteParam(q)
	det := q.enum("detector", config.DetectorIDs...)
	active := q.enum("active", "true", "false")
	limit, cursor := q.limit(), q.cursor()
	if q.failed(w) {
		return
	}
	if det != "" {
		f.SummaryPrefix = "distributed " + det + " "
	}
	rows, next, err := s.St.ListEvents(r.Context(), f, cursor, limit)
	if err != nil {
		s.internal(w, err)
		return
	}
	now := s.now()
	page := WavePage{Items: []Wave{}, NextCursor: nextCursor(next)}
	for _, e := range rows {
		v, ok := s.waveOf(e, now)
		if !ok || (active == "true" && !v.Active) || (active == "false" && v.Active) {
			continue
		}
		page.Items = append(page.Items, v)
	}
	writeJSON(w, 200, page)
}

func (s *Server) loadWave(w http.ResponseWriter, r *http.Request) (*store.EventRow, bool) {
	id := r.PathValue("wave_id")
	notFound := func() { problem(w, 404, "not_found", "Diese Welle gibt es nicht (mehr).", nil) }
	if !uuidRe.MatchString(id) {
		notFound()
		return nil, false
	}
	e, err := s.St.GetEvent(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) || (err == nil && e.Type != events.DistributedDetected) {
		notFound()
		return nil, false
	}
	if err != nil {
		s.internal(w, err)
		return nil, false
	}
	return e, true
}

func (s *Server) getWave(w http.ResponseWriter, r *http.Request) {
	e, ok := s.loadWave(w, r)
	if !ok {
		return
	}
	now := s.now()
	v, _ := s.waveOf(e, now)
	d := WaveDetail{Wave: v, Requests: []EventSummary{}}
	if v.Route != "" && v.Route[0] == '/' {
		win := time.Duration(max(v.WindowS, 60)) * time.Second
		rows, _, err := s.St.ListEvents(r.Context(), store.EventFilter{Path: v.Route, From: e.Time.Add(-win), To: e.Time.Add(5 * time.Minute),
			Types: []string{events.RequestEvaluated, events.RequestBlocked}}, 0, 100)
		if err == nil {
			for _, x := range rows {
				d.Requests = append(d.Requests, summarize(x))
			}
		}
	}
	writeJSON(w, 200, d)
}

func (s *Server) endWave(w http.ResponseWriter, r *http.Request) {
	if !s.behaviourAvailable(w) {
		return
	}
	e, ok := s.loadWave(w, r)
	if !ok {
		return
	}
	wv, known, active := s.Behaviour.EndWave(e.ID)
	if !known || !active {
		problem(w, http.StatusConflict, "not_active", "Diese Reaktion läuft nicht mehr.", nil)
		return
	}
	if s.Log != nil {
		s.Log.Info("distributed response ended in the dashboard", "wave", e.ID, "detector", wv.Detector)
	}
	writeJSON(w, 200, waveFromMemory(wv, s.now()))
}

func (s *Server) distributedSettings(ctx context.Context) DistributedSettings {
	c := s.Config().Behaviour.Distributed
	e := s.Behaviour
	out := DistributedSettings{LearningDays: c.LearningDays, LearningUntil: tsp(e.LearnUntil()), GatewayObserve: s.Config().Mode == "observe",
		RouteTighten: c.Responses.RouteTighten, AccountSlowdown: c.Responses.AccountSlowdown, Routes: c.Routes, FingerprintKind: behaviour.FPHeaders}
	if c.Fingerprint.JA4Header != "" {
		out.FingerprintKind = behaviour.FPJA4
	}
	for _, id := range config.DetectorIDs {
		mode, eff := e.DistributedMode(id)
		t, d := e.DistributedThresholds(id), behaviour.DistributedDefaults[id]
		out.Detectors = append(out.Detectors, DetectorSetting{ID: id, Mode: mode, EffectiveMode: eff, Waves24h: e.Waves24h(id),
			Thresholds: DetectorThresholds{Count: t.Count, WindowS: t.WindowS, Factor: t.Factor},
			Defaults:   DetectorThresholds{Count: d.Count, WindowS: d.WindowS, Factor: d.Factor}})
	}
	return out
}

func (s *Server) getDistributedSettings(w http.ResponseWriter, r *http.Request) {
	if !s.behaviourAvailable(w) {
		return
	}
	writeJSON(w, 200, s.distributedSettings(r.Context()))
}

func (s *Server) updateDistributedSettings(w http.ResponseWriter, r *http.Request) {
	if !s.behaviourAvailable(w) {
		return
	}
	var p DistributedSettingsPatch
	if !decode(w, r, &p) {
		return
	}
	modes := map[string]string{}
	if d := p.Detectors; d != nil {
		for id, v := range map[string]*string{config.DetectorRouteWave: d.RouteWave, config.DetectorAccountWave: d.AccountWave, config.DetectorShapeWave: d.ShapeWave,
			config.DetectorFingerprintCluster: d.FingerprintCluster, config.DetectorInconsistency: d.Inconsistency} {
			if v == nil {
				continue
			}
			if *v != config.DistributedOff && *v != config.DistributedObserve && *v != config.DistributedRespond {
				invalid(w, "Unbekannter Modus.", FieldError{Pointer: "/detectors/" + id, Detail: "off, observe oder respond"})
				return
			}
			modes[id] = *v
		}
	}
	if s.ApplyDistributed == nil {
		problem(w, http.StatusServiceUnavailable, "unavailable", "Diese Einstellung lässt sich hier nicht ändern.", nil)
		return
	}
	thresholds, errs := detectorThresholds(p.Thresholds)
	if len(errs) > 0 {
		invalid(w, "Diese Schwelle ist nicht möglich.", errs...)
		return
	}
	if _, err := s.ApplyDistributed(r.Context(), modes, thresholds); err != nil {
		invalid(w, "Diese Einstellung ist nicht möglich: "+err.Error())
		return
	}
	writeJSON(w, 200, s.distributedSettings(r.Context()))
}
