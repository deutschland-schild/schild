package hub

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"os"
	"sort"
	"sync/atomic"
	"time"

	"github.com/deutschland-schild/schild/contract/crowdsec"
	"github.com/deutschland-schild/schild/contract/events"
	"github.com/deutschland-schild/schild/contract/jsonx"
	"github.com/deutschland-schild/schild/contract/keys"
	"github.com/deutschland-schild/schild/contract/msg"
	"github.com/deutschland-schild/schild/gateway/internal/eventlog"
	"github.com/deutschland-schild/schild/gateway/internal/waf"
)

// firstDelay bounds the wait before the first check, so a check never holds
// up a start.
const firstDelay = 60 * time.Second

// crowdsecRepo is the repository id of this source (contract/rules).
const crowdsecRepo = "crowdsec"

// maxListed caps the names of one repository_updated event.
const maxListed = 100

// AroundCheck sets a function that runs around every check of Run: it calls
// check once and sees the rules before and after (the audit log records an
// update that was applied).
func (s *Source) AroundCheck(f func(ctx context.Context, check func())) { s.around.Store(&f) }

// Run checks the hub until ctx ends. A failure waits for the next interval.
func (s *Source) Run(ctx context.Context) {
	t := time.NewTimer(rand.N(firstDelay))
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-s.wake:
		}
		if around := s.around.Load(); around != nil {
			(*around)(ctx, func() { s.Check(ctx) })
		} else {
			s.Check(ctx)
		}
		if !t.Stop() {
			select {
			case <-t.C:
			default:
			}
		}
		t.Reset(jitter(s.cfg().IntervalS))
	}
}

// jitter draws the interval within +-JitterPercent.
func jitter(intervalS int) time.Duration {
	d := time.Duration(intervalS) * time.Second
	spread := d * crowdsec.JitterPercent / 100
	if spread <= 0 {
		return d
	}
	return d - spread + rand.N(2*spread)
}

func (s *Source) url(pin string) string {
	if !keys.Release {
		if u := os.Getenv(crowdsec.TestURLEnv); u != "" {
			return u
		}
	}
	if pin != "" {
		return fmt.Sprintf(crowdsec.PinnedURLFormat, pin)
	}
	return crowdsec.IndexURL
}

func (s *Source) client() *http.Client {
	if s.o.Client != nil {
		return s.o.Client
	}
	return &http.Client{
		Timeout: crowdsec.FetchTimeoutS * time.Second,
		Transport: &http.Transport{Proxy: http.ProxyFromEnvironment, DisableKeepAlives: true, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
			DialContext: (&net.Dialer{Timeout: crowdsec.ConnectTimeoutS * time.Second}).DialContext, TLSHandshakeTimeout: crowdsec.ConnectTimeoutS * time.Second},
		CheckRedirect: stayOnHost,
	}
}

// stayOnHost allows no redirect away from the host of the first request.
func stayOnHost(req *http.Request, via []*http.Request) error {
	if len(via) >= 3 {
		return errors.New("too many redirects")
	}
	if req.URL.Host != via[0].URL.Host || req.URL.Scheme != via[0].URL.Scheme {
		return errors.New("redirect to another host")
	}
	return nil
}

// fetch downloads the index. notModified: 304. code is a refusal.
func (s *Source) fetch(ctx context.Context, url, etag string) (raw []byte, newTag string, notModified bool, code string) {
	ctx, cancel := context.WithTimeout(ctx, crowdsec.FetchTimeoutS*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, "", false, crowdsec.RefuseFetchFailed
	}
	req.Header.Set("User-Agent", crowdsec.UserAgent)
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	resp, err := s.client().Do(req)
	if err != nil {
		return nil, "", false, crowdsec.RefuseFetchFailed
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotModified:
		return nil, etag, true, ""
	default:
		return nil, "", false, crowdsec.RefuseFetchStatus
	}
	// The transport decompresses a gzip answer, so this counts decompressed bytes.
	raw, err = io.ReadAll(io.LimitReader(resp.Body, crowdsec.MaxIndexBytes+1))
	if err != nil {
		return nil, "", false, crowdsec.RefuseFetchFailed
	}
	if len(raw) > crowdsec.MaxIndexBytes {
		return nil, "", false, crowdsec.RefuseIndexSize
	}
	return raw, resp.Header.Get("ETag"), false, ""
}

// Check runs one update. Nothing in it touches the running rules before the
// new set compiled, and nothing in it runs on a request path.
func (s *Source) Check(ctx context.Context) {
	defer func() {
		if v := recover(); v != nil {
			s.o.Log.Error("crowdsec hub: update failed, running rules stay", "panic", v)
		}
	}()
	cfg := s.cfg()
	if cfg.State == crowdsec.StateOff {
		return
	}
	cur := s.running()
	if cfg.Pin != "" {
		if cur != nil && cur.commit == cfg.Pin {
			return
		}
	} else if !*cfg.AutoUpdate {
		return
	}
	etag := ""
	if cfg.Pin == "" && cur != nil && cur.source == crowdsec.SetStored {
		etag = cur.etag
	}
	raw, newTag, notModified, code := s.fetch(ctx, s.url(cfg.Pin), etag)
	if ctx.Err() != nil {
		return
	}
	s.opMu.Lock()
	defer s.opMu.Unlock()
	now := s.now()
	switch {
	case code != "":
		s.refuse(ctx, now, code)
		return
	case notModified:
		s.checked(ctx, now)
		return
	}
	if s.cfg().State == crowdsec.StateOff {
		return
	}
	s.apply(ctx, raw, newTag, cfg.Pin, now)
	s.remember(raw, newTag, cfg.Pin)
}

// apply takes a downloaded index through the update rules (opMu held).
func (s *Source) apply(ctx context.Context, raw []byte, etag, pin string, now time.Time) {
	cur := s.running()
	known := knownOf(cur)
	stamp := msg.FormatTime(now)
	lim := crowdsec.DefaultLimits
	lim.ShrinkBase = s.shrinkBase(pin)
	u := crowdsec.CheckIndex(raw, known, lim, stamp)
	if u.Outcome != "accepted" {
		s.refuse(ctx, now, u.Code)
		return
	}
	rules, skipped := s.screen(u.Rules, u.Skipped)
	if code := bounds(rules, known, lim.ShrinkBase); code != "" {
		s.refuse(ctx, now, code)
		return
	}
	row, set, code := newSet(raw, u, rules, pin, etag, stamp)
	if code != "" {
		s.refuse(ctx, now, code)
		return
	}
	rules, skipped, err := s.compile(rules, skipped)
	if err != nil {
		s.o.Log.Warn("crowdsec hub: set does not compile", "err", err)
		s.refuse(ctx, now, crowdsec.RefuseCompile)
		return
	}
	if code := bounds(rules, known, lim.ShrinkBase); code != "" {
		s.refuse(ctx, now, code)
		return
	}
	sortSkipped(skipped)
	l := &loaded{source: crowdsec.SetStored, etag: etag, indexDigest: u.IndexDigest, commit: pin, fetchedAt: stamp, notSelected: u.NotSelected,
		rules: rules, skipped: skipped, extra: row.IndexSkipped}
	added, changed, removed := diff(known, rules)
	row.CostChecked = true
	if cur != nil && len(added)+len(changed)+len(removed) == 0 {
		// Nothing new for the rules, whatever commit they came from: no build,
		// no event, no cost check (the same rules run). The row moves on, so
		// the next check can use this ETag.
		s.saveSet(ctx, row)
		s.setCurrent(l)
		s.checked(ctx, now)
		return
	}
	if code := s.checkCost(ctx, rules); code != "" {
		if ctx.Err() == nil {
			s.refuse(ctx, now, code)
		}
		return
	}
	if code := s.swap(wafRules(rules)); code != "" {
		s.refuse(ctx, now, code)
		return
	}
	s.setCurrent(l)
	s.saveSet(ctx, row)
	s.mu.Lock()
	s.st.LastChange, s.st.Change = stamp, &Change{Added: len(added), Changed: len(changed), Removed: len(removed)}
	s.mu.Unlock()
	s.checked(ctx, now)
	s.emit(now, events.RepositoryUpdated{Repository: crowdsecRepo, Outcome: "accepted", SetSource: l.source, IndexSHA256: l.indexDigest, HubCommit: l.commit,
		RulesLoaded: len(rules), RulesSkipped: len(skipped)}, added, changed, removed)
	s.o.Log.Info("crowdsec hub rules updated", "index", u.IndexDigest, "commit", pin, "loaded", len(rules), "skipped", len(skipped),
		"added", len(added), "changed", len(changed), "removed", len(removed), "set_size", len(set))
}

// bounds repeats the set bounds of CheckIndex after rules left the set here.
func bounds(rules []crowdsec.SetRule, known map[string]crowdsec.Known, base int) string {
	switch {
	case len(rules) == 0:
		return crowdsec.RefuseEmpty
	case crowdsec.Shrinks(len(rules), base, len(known)):
		return crowdsec.RefuseShrink
	}
	return ""
}

// shrinkBase is what a new set is held against (crowdsec.Limits.ShrinkBase).
func (s *Source) shrinkBase(pin string) int {
	if pin != "" {
		return crowdsec.ShrinkOff // the operator named this commit
	}
	if l := s.image(); l != nil {
		return len(l.rules)
	}
	return 0
}

// checkCost measures a candidate before it goes live (D43): in the background
// of an update, one request at a time, on instances of its own. Returns a
// refusal code. A failure of the measurement itself refuses too: a set nobody
// measured does not go live.
func (s *Source) checkCost(ctx context.Context, rules []crowdsec.SetRule) string {
	var reference []waf.HubRule
	if l := s.image(); l != nil {
		reference = wafRules(l.rules)
	}
	sample, err := s.cost(ctx, reference, wafRules(rules))
	if err != nil {
		s.o.Log.Warn("crowdsec hub: cost check failed", "err", err)
		return crowdsec.RefuseCost
	}
	v := crowdsec.CheckSetCost(sample)
	s.o.Log.Info("crowdsec hub cost check", "outcome", v.Outcome, "added_ns", v.AddedNS, "allowed_ns", v.AllowedNS,
		"baseline_ns", sample.BaselineNS, "reference_ns", sample.ReferenceNS, "rounds", sample.Rounds)
	return v.Code
}

func knownOf(l *loaded) map[string]crowdsec.Known {
	if l == nil {
		return nil
	}
	m := make(map[string]crowdsec.Known, len(l.rules))
	for i := range l.rules {
		r := &l.rules[i]
		m[r.Name] = crowdsec.Known{Digest: r.Digest, FirstSeen: r.FirstSeen, ChangedAt: r.ChangedAt}
	}
	return m
}

// diff compares what really runs: rules skipped here do not count as added.
func diff(known map[string]crowdsec.Known, rules []crowdsec.SetRule) (added, changed, removed []string) {
	loaded := make(map[string]bool, len(rules))
	for i := range rules {
		r := &rules[i]
		loaded[r.Name] = true
		switch k, ok := known[r.Name]; {
		case !ok:
			added = append(added, r.Name)
		case k.Digest != r.Digest:
			changed = append(changed, r.Name)
		}
	}
	for n := range known {
		if !loaded[n] {
			removed = append(removed, n)
		}
	}
	sort.Strings(removed)
	return added, changed, removed
}

// outOfSet: codes of items a set cannot hold (crowdsec.ParseSet, the schema).
var outOfSet = map[string]bool{crowdsec.SkipDigest: true, crowdsec.SkipDeprecated: true, crowdsec.SkipNameMismatch: true,
	crowdsec.SkipBadName: true, crowdsec.SkipTooLong: true}

// BuildSet writes the set of a checked index: every selected item as it came,
// with the history of the loaded rules. rules may be fewer than u.Rules.
func BuildSet(raw []byte, u *crowdsec.Update, rules []crowdsec.SetRule, commit, stamp string) (*crowdsec.Set, []crowdsec.SkippedRule, error) {
	doc, err := jsonx.ParseObject(raw)
	if err != nil {
		return nil, nil, err
	}
	items, _ := doc["appsec-rules"].(map[string]any)
	history := make(map[string]*crowdsec.SetRule, len(rules))
	for i := range rules {
		history[rules[i].Name] = &rules[i]
	}
	outside := map[string]bool{}
	var extra []crowdsec.SkippedRule
	names := make([]string, 0, len(u.Rules)+len(u.Skipped))
	for i := range u.Rules {
		names = append(names, u.Rules[i].Name)
	}
	for _, sk := range u.Skipped {
		if outOfSet[sk.Code] {
			outside[sk.Name] = true
			extra = append(extra, sk)
			continue
		}
		names = append(names, sk.Name)
	}
	sort.Strings(names)
	set := &crowdsec.Set{Schema: crowdsec.SetSchemaVersion, IndexDigest: u.IndexDigest, HubCommit: commit, FetchedAt: stamp, NotSelected: u.NotSelected, Rules: []crowdsec.SetItem{}}
	for _, n := range names {
		it, _ := items[n].(map[string]any)
		content, _ := it["content"].(string)
		version, _ := it["version"].(string)
		desc, _ := it["description"].(string)
		if len(desc) > 4096 {
			desc = ""
		}
		body, err := base64.StdEncoding.DecodeString(content)
		if err != nil {
			return nil, nil, err
		}
		sum := sha256.Sum256(body)
		item := crowdsec.SetItem{Name: n, Version: version, Digest: hex.EncodeToString(sum[:]), Content: content, Description: desc, FirstSeen: stamp, ChangedAt: stamp}
		if h := history[n]; h != nil {
			item.FirstSeen, item.ChangedAt = h.FirstSeen, h.ChangedAt
		}
		set.Rules = append(set.Rules, item)
	}
	return set, extra, nil
}

// newSet builds and proves the row of a set: what ParseSet refuses here would
// not load after a restart either.
func newSet(raw []byte, u *crowdsec.Update, rules []crowdsec.SetRule, pin, etag, stamp string) (storedRow, []byte, string) {
	set, extra, err := BuildSet(raw, u, rules, pin, stamp)
	if err != nil {
		return storedRow{}, nil, crowdsec.RefuseMalformed
	}
	b, err := json.Marshal(set)
	if err != nil {
		return storedRow{}, nil, crowdsec.RefuseMalformed
	}
	if len(b) > crowdsec.MaxSetFileBytes {
		return storedRow{}, nil, crowdsec.RefuseSetTooLarge
	}
	if _, err := crowdsec.ParseSet(b); err != nil {
		return storedRow{}, nil, crowdsec.RefuseMalformed
	}
	return storedRow{Set: b, ETag: etag, IndexSkipped: extra}, b, ""
}

func (s *Source) saveSet(ctx context.Context, row storedRow) {
	b, err := json.Marshal(row)
	if err == nil {
		err = s.o.Store.Put(ctx, crowdsec.StoreKey, b)
	}
	if err != nil {
		s.o.Log.Error("crowdsec hub: set not stored, it runs until the next restart", "err", err)
	}
}

// swap builds an instance in the background and swaps it. One build at a time;
// after the timeout the build is abandoned and the running instance stays. An
// abandoned build keeps the slot until it really ended. Returns a refusal code.
func (s *Source) swap(rules []waf.HubRule) string {
	timer := time.NewTimer(s.timeout)
	defer timer.Stop()
	select {
	case s.sem <- struct{}{}:
	case <-timer.C:
		return crowdsec.RefuseCompileTime
	}
	var decided atomic.Int32 // 1: the build goes live, 2: abandoned
	done := make(chan error, 1)
	go func() {
		defer func() {
			if v := recover(); v != nil {
				done <- fmt.Errorf("panic: %v", v)
			}
			<-s.sem
		}()
		for range 3 {
			inst, gen, err := s.o.Builder.PrepareHub(rules)
			if err != nil {
				done <- err
				return
			}
			if !decided.CompareAndSwap(0, 1) {
				inst.Close()
				return
			}
			if s.o.Builder.CommitHub(inst, gen, rules) {
				done <- nil
				return
			}
			if !decided.CompareAndSwap(1, 0) {
				return
			}
		}
		done <- errors.New("the WAF kept changing during the build")
	}()
	select {
	case err := <-done:
		if err != nil {
			s.o.Log.Warn("crowdsec hub: WAF build failed, running rules stay", "err", err)
			return crowdsec.RefuseCompile
		}
		return ""
	case <-timer.C:
		if decided.CompareAndSwap(0, 2) {
			return crowdsec.RefuseCompileTime
		}
		if err := <-done; err != nil {
			return crowdsec.RefuseCompile
		}
		return ""
	}
}

// checked notes a check that ended without a refusal.
func (s *Source) checked(ctx context.Context, now time.Time) {
	s.mu.Lock()
	s.st.LastCheck, s.st.Failing = msg.FormatTime(now), false
	s.mu.Unlock()
	s.saveStatus(ctx)
}

// refuse notes a refusal; the running set stays. It writes one event when the
// reason changes: the same refusal hour after hour is nothing new.
func (s *Source) refuse(ctx context.Context, now time.Time, code string) {
	stamp := msg.FormatTime(now)
	s.mu.Lock()
	again := s.st.Failing && s.st.Refusal != nil && s.st.Refusal.Code == code
	s.st.LastCheck, s.st.Failing, s.st.Refusal = stamp, true, &Refusal{At: stamp, Code: code}
	l := s.cur
	s.mu.Unlock()
	s.saveStatus(ctx)
	if again {
		return
	}
	s.o.Log.Warn("crowdsec hub: update refused, running rules stay", "code", code)
	ev := events.RepositoryUpdated{Repository: crowdsecRepo, Outcome: "refused", Code: code, SetSource: crowdsec.SetNone}
	if l != nil {
		ev.SetSource, ev.IndexSHA256, ev.HubCommit, ev.RulesLoaded, ev.RulesSkipped = l.source, l.indexDigest, l.commit, len(l.rules), len(l.skipped)
	}
	s.emit(now, ev, nil, nil, nil)
}

func (s *Source) saveStatus(ctx context.Context) {
	s.mu.Lock()
	b, err := json.Marshal(s.st)
	s.mu.Unlock()
	if err == nil {
		err = s.o.Store.Put(ctx, statusKey, b)
	}
	if err != nil {
		s.o.Log.Warn("crowdsec hub: status not stored", "err", err)
	}
}

func (s *Source) emit(now time.Time, ev events.RepositoryUpdated, added, changed, removed []string) {
	if s.o.Events == nil {
		return
	}
	cut := func(x []string) []string {
		if len(x) > maxListed {
			ev.Truncated = true
			return x[:maxListed]
		}
		return x
	}
	ev.Added, ev.Changed, ev.Removed = cut(added), cut(changed), cut(removed)
	sum := "crowdsec rules updated"
	switch ev.Outcome {
	case "refused":
		sum = "crowdsec update refused: " + ev.Code
	case "reset":
		sum = "crowdsec rules reset to the image snapshot"
	}
	s.o.Events.Emit(events.RuleRepositoryUpdated, now, ev, eventlog.Index{Summary: sum})
}
