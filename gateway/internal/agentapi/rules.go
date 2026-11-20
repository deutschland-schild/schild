package agentapi

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	contractapi "github.com/deutschland-schild/schild/contract/agentapi"
	"github.com/deutschland-schild/schild/contract/rules"
	"github.com/deutschland-schild/schild/gateway/internal/waf"
)

// RuleDeps are the request test (D55), implemented by the app.
type RuleDeps struct {
	// Hosts of a website; false for an unknown id.
	Hosts func(website string) ([]string, bool)
	// WAF is the running instance, rule exceptions included.
	WAF  func() *waf.Instance
	Mode func() string
	// Effect is what a rule of a repository does now (contract/rules); nil:
	// crs and local block, crowdsec only detects.
	Effect func(repository string, id int) rules.Rule
}

// probeBudget bounds the evaluation of one sample, probeSlots the samples at once.
const (
	probeBudget = 2 * time.Second
	probeSlots  = 2
)

var probeSem = make(chan struct{}, probeSlots)

// sampleHeaders make a sample look like a browser request unless the agent
// sends its own: a missing User-Agent or Accept is a finding of its own.
var sampleHeaders = map[string]string{
	"User-Agent":      "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0",
	"Accept":          "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
	"Accept-Language": "de-DE,de;q=0.9",
}

func (s *Server) testRequest(w http.ResponseWriter, r *http.Request) {
	if s.Rules == nil {
		Problem(w, http.StatusNotFound, "not_found", "The request test is not available on this gateway.")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, contractapi.MaxTestRequest+1))
	if err != nil || len(body) > contractapi.MaxTestRequest || r.Header.Get("Content-Type") != "application/json" {
		Problem(w, http.StatusBadRequest, "invalid", "Send application/json with a body of at most 64 KiB.")
		return
	}
	var req contractapi.TestRequest
	if json.Unmarshal(body, &req) != nil || !contractapi.ValidTestRequest(req) {
		Problem(w, http.StatusBadRequest, "invalid", "Name website, method and path (with query); content_type, at most 16 headers (no Host, Content-Length, Transfer-Encoding) and a body of at most 64 KiB are optional.")
		return
	}
	// The contract's path pattern lets a broken escape through ("/%zz"), on
	// which httptest.NewRequest below would panic. A server would refuse such
	// a request line with 400 before any rule runs.
	if _, err := url.ParseRequestURI(req.Path); err != nil {
		Problem(w, http.StatusBadRequest, "invalid", "The path is no valid request target (check its percent escapes).")
		return
	}
	hosts, ok := s.Rules.Hosts(req.Website)
	if !ok {
		Problem(w, http.StatusNotFound, "not_found", "No website with this id, see schild_websites.")
		return
	}
	if len(hosts) == 0 {
		Problem(w, http.StatusConflict, contractapi.CodeWebsiteNoHosts, "This website has no hosts; its requests cannot be told apart from those of other websites.")
		return
	}
	select {
	case probeSem <- struct{}{}:
		defer func() { <-probeSem }()
	default:
		w.Header().Set("Retry-After", "1")
		Problem(w, http.StatusTooManyRequests, "rate_limited", "Another sample is being tested. Try again in a second.")
		return
	}
	sample := httptest.NewRequestWithContext(r.Context(), req.Method, req.Path, strings.NewReader(req.Body))
	sample.Host = sampleHost(hosts[0])
	for k, v := range sampleHeaders {
		sample.Header.Set(k, v)
	}
	for k, v := range req.Headers {
		sample.Header.Set(k, v)
	}
	if req.ContentType != "" {
		sample.Header.Set("Content-Type", req.ContentType)
	}
	if req.Body == "" {
		sample.Body, sample.ContentLength = http.NoBody, 0
	}
	inst := s.Rules.WAF()
	a, hits, err := inst.Probe(sample, probeBudget)
	if err != nil {
		if le, ok := waf.IsLimit(err); ok {
			Problem(w, http.StatusUnprocessableEntity, "sample_refused", "A real request like this gets "+strconv.Itoa(le.Status)+" "+le.Code+" before any rule runs.")
			return
		}
		Problem(w, http.StatusServiceUnavailable, "sample_timeout", "The sample took longer than 2 s to evaluate.")
		return
	}
	writeJSON(w, testResult(req, s.Rules.Mode(), a, hits, s.Rules.Effect))
}

// sampleHost is a Host header of a website host: www for a wildcard label.
func sampleHost(h string) string {
	if strings.Contains(h, ":") {
		return "[" + h + "]"
	}
	labels := strings.Split(h, ".")
	for i, l := range labels {
		if l == "*" {
			labels[i] = "www"
		}
	}
	return strings.Join(labels, ".")
}

// matchRepository names the repository of a match and the rule id it has
// there: the base id for crowdsec, the SecRule id for the others.
func matchRepository(m waf.Match) (string, int) {
	switch m.Source {
	case waf.SourceCrowdsec:
		return rules.RepoCrowdsec, m.Hub.BaseID
	case waf.SourceLocal:
		return rules.RepoLocal, m.ID
	}
	return rules.RepoCRS, m.ID
}

// acts reports whether a rule would block with its repository's state and
// status (or would block, in observe).
func acts(effect func(string, int) rules.Rule, repository string, id int) bool {
	if effect == nil {
		return repository != rules.RepoCrowdsec
	}
	e := effect(repository, id).Effect
	return e == rules.EffectBlock || e == rules.EffectWouldBlock
}

// testResult names where each rule hit and groups the hits of crs and
// crowdsec rules on named fields into exception suggestions, one per field
// and repository.
func testResult(req contractapi.TestRequest, mode string, a *waf.Analysis, hits []waf.ProbeHit, effect func(string, int) rules.Rule) contractapi.TestResult {
	res := contractapi.TestResult{Website: req.Website, Anomaly: a.CRSAnomaly, AnomalyThreshold: a.Threshold,
		WouldBlock: a.CRSBlock && acts(effect, rules.RepoCRS, 0) || a.LocalBlock && acts(effect, rules.RepoLocal, 0),
		Matches:    []contractapi.TestMatch{}, Suggestions: []contractapi.ExceptionSuggestion{}}
	where := map[int][]waf.ProbeHit{}
	for _, h := range hits {
		where[h.ID] = append(where[h.ID], h)
	}
	path := contractapi.SuggestPath(req.Path)
	type key struct{ repo, target string }
	byTarget := map[key][]int{}
	var order []key
	for _, m := range a.Matches {
		if m.Source == waf.SourceInternal || m.Exception || (m.ID >= contractapi.ExceptionIDMin && m.ID <= contractapi.ExceptionIDMax) {
			continue // exceptions in force are no finding
		}
		repo, id := matchRepository(m)
		if repo == rules.RepoCrowdsec && acts(effect, repo, id) {
			res.WouldBlock = true
		}
		rule := strconv.Itoa(id)
		suggest := repo == rules.RepoCrowdsec || repo == rules.RepoCRS && m.Points > 0
		seen := map[string]bool{}
		for _, h := range where[m.ID] {
			target := h.Variable
			if h.Key != "" {
				target += ":" + h.Key
			}
			if seen[target] || len(target) > 200 {
				continue
			}
			seen[target] = true
			res.Matches = append(res.Matches, contractapi.TestMatch{Repository: repo, Rule: rule, Msg: m.Msg, Severity: m.Severity, Points: m.Points, Target: target})
			t := contractapi.SuggestTarget(h.Variable, h.Key)
			if t == "" || path == "" || !suggest || !contractapi.IsExceptionRule(repo, id) {
				continue
			}
			k := key{repo, t}
			if _, ok := byTarget[k]; !ok {
				order = append(order, k)
			}
			if !slices.Contains(byTarget[k], id) {
				byTarget[k] = append(byTarget[k], id)
			}
		}
		if len(seen) == 0 {
			res.Matches = append(res.Matches, contractapi.TestMatch{Repository: repo, Rule: rule, Msg: m.Msg, Severity: m.Severity, Points: m.Points})
		}
	}
	for _, k := range order {
		ids := byTarget[k]
		slices.Sort(ids)
		if len(ids) > contractapi.MaxExceptionRules {
			ids = ids[:contractapi.MaxExceptionRules]
		}
		list := make([]string, len(ids))
		for i, id := range ids {
			list[i] = strconv.Itoa(id)
		}
		res.Suggestions = append(res.Suggestions, contractapi.ExceptionSuggestion{Website: req.Website, Path: path, Target: k.target, Repository: k.repo, Rules: list})
	}
	return res
}
