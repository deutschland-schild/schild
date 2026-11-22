package behaviour

import (
	"encoding/binary"
	"encoding/hex"
	"strconv"
	"strings"
	"time"

	"github.com/deutschland-schild/schild/contract/config"
)

// The detectors of distributed attacks in a group (MVP-18 in MVP-27, D105).
// A wave is a sum over many senders, and behind a balancer every node sees a
// part of them: with n nodes a threshold would mean n times as much. So what
// the detectors compare travels with the counts of shared.go, once a
// second: per route the failed and passed attempts and the hashes of the
// senders, per request shape, fingerprint and account the hashes of the
// senders. A node adds them to its own aggregates (counters by sum, the
// sketches of senders by union: the hashes go into the same HyperLogLog)
// and decides nothing; the next request that reaches it meets the sum.
//
// A wave is recorded once. The node that detects it writes the event and
// tells the others (WaveNote); they hold the same wave under the same id
// without an event of their own, so its response acts on every node. Nodes
// that detect the same wave within the second a note travels (behind a
// balancer that spreads the senders, that is the usual case) name it the
// same: in a group the id of a wave is derived from its detector, website,
// route or shape and the five minutes it started in, under the hash key of
// the group. Their events carry one id, and a store holds an event once.
// Only a wave detected across the end of such five minutes gets two ids;
// then the earlier wave stays, the other leaves memory, and the two events
// name their nodes by their source.
//
// Not shared: whether a sender is new to a route (each node keeps its own
// filter of senders seen), and how many requests a response stopped.

// DistCounts is what the detectors of one node counted in about a second.
type DistCounts struct {
	Routes   []RouteCount   `json:"routes,omitempty"`
	Shapes   []ShapeCount   `json:"shapes,omitempty"`
	FPs      []FPCount      `json:"fps,omitempty"`
	Accounts []AccountCount `json:"accounts,omitempty"`
	Waves    []WaveNote     `json:"waves,omitempty"`
}

// RouteCount: attempts on one route of one website (route_wave,
// inconsistency).
type RouteCount struct {
	Host      string   `json:"host"`
	Route     string   `json:"route"`
	Failed    int      `json:"failed,omitempty"`
	Passed    int      `json:"passed,omitempty"`
	New       int      `json:"new,omitempty"`
	IncFailed int      `json:"inc_failed,omitempty"`
	IncAll    int      `json:"inc_all,omitempty"`
	Senders   []uint64 `json:"senders,omitempty"`
}

// ShapeCount: senders of one request shape (shape_wave).
type ShapeCount struct {
	Sig     string   `json:"sig"`
	Senders []uint64 `json:"senders,omitempty"`
}

// FPCount: senders and user agents of one fingerprint on one route
// (fingerprint_cluster).
type FPCount struct {
	FP      string   `json:"fp"`
	Host    string   `json:"host"`
	Route   string   `json:"route"`
	Senders []uint64 `json:"senders,omitempty"`
	UAs     []uint32 `json:"uas,omitempty"`
}

// AccountCount: failed attempts on one account (account_wave). Flagged: the
// telling node counts the account as attacked.
type AccountCount struct {
	User    uint64   `json:"user"`
	Failed  int      `json:"failed,omitempty"`
	Senders []uint64 `json:"senders,omitempty"`
	Flagged bool     `json:"flagged,omitempty"`
}

// WaveNote is a wave as one node tells it: started, extended or ended.
type WaveNote struct {
	ID          string   `json:"id"`
	Detector    string   `json:"detector"`
	Host        string   `json:"host,omitempty"`
	Key         string   `json:"key"`
	Route       string   `json:"route,omitempty"`
	Action      string   `json:"action"`
	Started     int64    `json:"started_ms"`
	Until       int64    `json:"until_ms"`
	Ended       int64    `json:"ended_ms,omitempty"`
	EndReason   string   `json:"end_reason,omitempty"`
	Senders     int      `json:"senders,omitempty"`
	Count       int      `json:"count,omitempty"`
	Threshold   int      `json:"threshold,omitempty"`
	WindowS     int      `json:"window_s,omitempty"`
	Baseline    float64  `json:"baseline,omitempty"`
	Fingerprint string   `json:"fingerprint,omitempty"`
	FPKind      string   `json:"fp_kind,omitempty"`
	UserAgents  int      `json:"user_agents,omitempty"`
	RequestSig  string   `json:"request_sig,omitempty"`
	WAFRules    []int    `json:"waf_rules,omitempty"`
	Incident    string   `json:"incident,omitempty"`
	ClusterFPs  []string `json:"cluster_fps,omitempty"`
	Strong      bool     `json:"strong,omitempty"`
}

// Bounds of what the detectors of one node tell per second. What is over
// counts on its node only (NotShared).
const (
	shareDistEntries = 200  // targets per kind
	shareDistSenders = 32   // sender hashes per target
	shareDistBudget  = 4000 // sender hashes in all
	shareDistWaves   = 32
	shareDistText    = 512
	shareDistUAs     = 16
)

// distShare is the part of the sharer the detectors fill. Guarded by
// sharer.mu.
type distShare struct {
	routes   map[string]*RouteCount
	shapes   map[string]*ShapeCount
	fps      map[string]*FPCount
	accounts map[uint64]*AccountCount
	waves    map[string]*WaveNote
	senders  int
}

func (d *distShare) empty() bool {
	return len(d.routes)+len(d.shapes)+len(d.fps)+len(d.accounts)+len(d.waves) == 0
}

// sender adds a sender hash to a list, within the bounds.
func (sh *sharer) sender(list *[]uint64, s uint64) {
	for _, x := range *list {
		if x == s {
			return
		}
	}
	if len(*list) >= shareDistSenders || sh.dist.senders >= shareDistBudget {
		sh.notShared.Add(1)
		return
	}
	*list = append(*list, s)
	sh.dist.senders++
}

func (sh *sharer) distRoute(h, route string, f func(*RouteCount)) {
	sh.mu.Lock()
	defer sh.mu.Unlock()
	k := h + "|" + route
	c := sh.dist.routes[k]
	if c == nil {
		if len(sh.dist.routes) >= shareDistEntries {
			sh.notShared.Add(1)
			return
		}
		if sh.dist.routes == nil {
			sh.dist.routes = map[string]*RouteCount{}
		}
		c = &RouteCount{Host: h, Route: route}
		sh.dist.routes[k] = c
	}
	f(c)
}

func (sh *sharer) distShape(sig string, sender uint64) {
	sh.mu.Lock()
	defer sh.mu.Unlock()
	c := sh.dist.shapes[sig]
	if c == nil {
		if len(sh.dist.shapes) >= shareDistEntries {
			sh.notShared.Add(1)
			return
		}
		if sh.dist.shapes == nil {
			sh.dist.shapes = map[string]*ShapeCount{}
		}
		c = &ShapeCount{Sig: sig}
		sh.dist.shapes[sig] = c
	}
	sh.sender(&c.Senders, sender)
}

func (sh *sharer) distFP(fp, h, route string, sender uint64, ua uint32) {
	sh.mu.Lock()
	defer sh.mu.Unlock()
	k := fp + "|" + h + "|" + route
	c := sh.dist.fps[k]
	if c == nil {
		if len(sh.dist.fps) >= shareDistEntries {
			sh.notShared.Add(1)
			return
		}
		if sh.dist.fps == nil {
			sh.dist.fps = map[string]*FPCount{}
		}
		c = &FPCount{FP: fp, Host: h, Route: route}
		sh.dist.fps[k] = c
	}
	sh.sender(&c.Senders, sender)
	for _, x := range c.UAs {
		if x == ua {
			return
		}
	}
	if len(c.UAs) < shareDistUAs {
		c.UAs = append(c.UAs, ua)
	}
}

func (sh *sharer) distAccount(user, sender uint64, flagged bool) {
	sh.mu.Lock()
	defer sh.mu.Unlock()
	c := sh.dist.accounts[user]
	if c == nil {
		if len(sh.dist.accounts) >= shareDistEntries {
			sh.notShared.Add(1)
			return
		}
		if sh.dist.accounts == nil {
			sh.dist.accounts = map[uint64]*AccountCount{}
		}
		c = &AccountCount{User: user}
		sh.dist.accounts[user] = c
	}
	c.Failed++
	c.Flagged = c.Flagged || flagged
	sh.sender(&c.Senders, sender)
}

// noteWave tells the other nodes a wave as it is now. key is the route, or
// the request shape of a shape_wave. Called with dist.mu held.
func (e *Engine) noteWave(w *Wave, key string) {
	sh := e.share.Load()
	if sh == nil {
		return
	}
	n := &WaveNote{ID: w.ID, Detector: w.Detector, Host: w.Host, Key: key, Route: w.Route, Action: w.Action, Started: w.Started.UnixMilli(), Until: w.Until.UnixMilli(),
		EndReason: w.EndReason, Senders: w.Senders, Count: w.Count, Threshold: w.Threshold, WindowS: w.WindowS, Baseline: w.Baseline, Fingerprint: w.Fingerprint, FPKind: w.FPKind,
		UserAgents: w.UserAgents, RequestSig: w.RequestSig, WAFRules: capInts(w.WAFRules, 32), Incident: w.Incident, Strong: w.strongCluster}
	if !w.Ended.IsZero() {
		n.Ended = w.Ended.UnixMilli()
	}
	for fp := range w.clusterFPs {
		n.ClusterFPs = append(n.ClusterFPs, fp)
	}
	sh.mu.Lock()
	defer sh.mu.Unlock()
	if _, ok := sh.dist.waves[w.ID]; !ok && len(sh.dist.waves) >= shareDistWaves {
		sh.notShared.Add(1)
		return
	}
	if sh.dist.waves == nil {
		sh.dist.waves = map[string]*WaveNote{}
	}
	sh.dist.waves[w.ID] = n
}

// takeDist returns what the detectors noted and starts anew. Called with
// sharer.mu held.
func (sh *sharer) takeDist() *DistCounts {
	if sh.dist.empty() {
		return nil
	}
	d := sh.dist
	sh.dist = distShare{}
	out := &DistCounts{}
	for _, c := range d.routes {
		out.Routes = append(out.Routes, *c)
	}
	for _, c := range d.shapes {
		out.Shapes = append(out.Shapes, *c)
	}
	for _, c := range d.fps {
		out.FPs = append(out.FPs, *c)
	}
	for _, c := range d.accounts {
		out.Accounts = append(out.Accounts, *c)
	}
	for _, w := range d.waves {
		out.Waves = append(out.Waves, *w)
	}
	return out
}

// knownRoute reports whether this node counts on a route itself: a login
// route of a preset that is on, or a route the operator marked. What a node
// is told of another route is left out.
func knownRoute(c *compiled, route string) bool {
	for i := range loginRoutes {
		if lr := &loginRoutes[i]; lr.Path == route && c.presets[lr.Preset] {
			return true
		}
	}
	for _, src := range c.dist.routeSrc {
		if src == route {
			return true
		}
	}
	return false
}

func (e *Engine) knownHost(h string) bool {
	return h != "" && len(h) <= 253 && (e.KnownHost == nil || e.KnownHost(h))
}

func cut[T any](xs []T, n int) []T { return xs[:min(len(xs), n)] }

// applyDist adds what the detectors of another node counted to this node's
// aggregates. It decides nothing and writes no event; waves another node
// detected are held here under their id.
func (e *Engine) applyDist(c *compiled, dc *DistCounts) {
	if dc == nil {
		return
	}
	now := e.now()
	n := now.UnixNano()
	budget := shareDistBudget
	senders := func(xs []uint64) []uint64 {
		xs = cut(xs, min(shareDistSenders, budget))
		budget -= len(xs)
		return xs
	}
	rt, it := c.dist.thr[config.DetectorRouteWave], c.dist.thr[config.DetectorInconsistency]
	for i := range cut(dc.Routes, shareDistEntries) {
		rc := &dc.Routes[i]
		if !e.knownHost(rc.Host) || !knownRoute(c, rc.Route) {
			continue
		}
		ss := senders(rc.Senders)
		e.d.routes.with(rc.Host+"|"+rc.Route, true, func(s *routeState) {
			s.roll(n, rt)
			s.lastSeen = n
			for _, x := range ss {
				s.senders.add(x)
			}
			s.newSenders += float64(bounded(rc.New))
			s.successes += float64(bounded(rc.Passed))
			s.failures += float64(bounded(rc.Failed))
			if s.incStart == 0 || n-s.incStart >= int64(it.WindowS)*int64(time.Second) {
				s.incStart, s.incFails, s.incAll = n, 0, 0
			}
			s.incAll += bounded(rc.IncAll)
			s.incFails += min(bounded(rc.IncFailed), bounded(rc.IncAll))
		})
	}
	if c.dist.mode[config.DetectorShapeWave] != config.DistributedOff {
		t := c.dist.thr[config.DetectorShapeWave]
		for i := range cut(dc.Shapes, shareDistEntries) {
			sc := &dc.Shapes[i]
			if sc.Sig == "" || len(sc.Sig) > shareDistText {
				continue
			}
			ss := senders(sc.Senders)
			e.d.shapes.with(sc.Sig, true, func(s *shapeState) {
				if s.senders == nil {
					s.senders = newHLL(6)
				}
				if s.start == 0 || n-s.start >= int64(t.WindowS)*int64(time.Second) {
					s.start = n
					s.senders.reset()
				}
				s.lastSeen = n
				for _, x := range ss {
					s.senders.add(x)
				}
			})
		}
	}
	if c.dist.mode[config.DetectorFingerprintCluster] != config.DistributedOff {
		t := c.dist.thr[config.DetectorFingerprintCluster]
		for i := range cut(dc.FPs, shareDistEntries) {
			fc := &dc.FPs[i]
			if fc.FP == "" || len(fc.FP) > shareDistText || !e.knownHost(fc.Host) || !knownRoute(c, fc.Route) {
				continue
			}
			ss := senders(fc.Senders)
			e.d.fps.with(fc.FP+"|"+fc.Host+"|"+fc.Route, true, func(s *fpState) {
				if s.senders == nil {
					s.senders = newHLL(6)
				}
				if s.start == 0 || n-s.start >= int64(t.WindowS)*int64(time.Second) {
					s.start = n
					s.senders.reset()
					s.uas = s.uas[:0]
				}
				s.lastSeen = n
				for _, x := range ss {
					s.senders.add(x)
				}
			uas:
				for _, ua := range cut(fc.UAs, shareDistUAs) {
					for _, x := range s.uas {
						if x == ua {
							continue uas
						}
					}
					if len(s.uas) < 16 {
						s.uas = append(s.uas, ua)
					}
				}
			})
		}
	}
	if c.dist.mode[config.DetectorAccountWave] != config.DistributedOff {
		t := c.dist.thr[config.DetectorAccountWave]
		size := int64(t.WindowS) * int64(time.Second)
		for i := range cut(dc.Accounts, shareDistEntries) {
			ac := &dc.Accounts[i]
			ss := senders(ac.Senders)
			failed := bounded(ac.Failed)
			e.d.accounts.with(ac.User, true, func(a *accountState) {
				if a.start == 0 || n-a.start >= size {
					a.start, a.failures, a.nSenders = n, 0, 0
				}
				a.lastSeen = n
				a.failures += failed
				for _, x := range ss {
					a.addSender(x)
				}
				if a.flagged > n || ac.Flagged {
					// An attacked account waits for the group: the attempts
					// on the other nodes double the wait here too.
					a.attempts = min(a.attempts+max(failed, 1), 64)
					a.next = n + int64(c.dist.accountWait(a.attempts))
					a.flagged = n + size
				}
			})
		}
	}
	for i := range cut(dc.Waves, shareDistWaves) {
		e.adoptWave(c, &dc.Waves[i], now)
	}
}

// accountWait is the wait of an attacked account after its n-th failed
// attempt.
func (d *distCompiled) accountWait(n int) time.Duration {
	return min(time.Duration(d.slowdown.StartS)*time.Second<<min(max(n, 1)-1, 16), time.Duration(d.slowdown.MaxS)*time.Second, AccountWaitCap)
}

// addSender notes a sender of failed attempts on an account.
func (a *accountState) addSender(sender uint64) {
	for i := 0; i < min(a.nSenders, len(a.senders)); i++ {
		if a.senders[i] == sender {
			return
		}
	}
	if a.nSenders < len(a.senders) {
		a.senders[a.nSenders] = sender
	}
	a.nSenders++
}

func validWaveID(id string) bool {
	if len(id) != 36 {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if !(c == '-' || c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// adoptWave holds a wave another node detected, under its id: its response
// acts here too, and no event is written here. The node decides again with
// what it holds: a detector that is off here adopts nothing, and a node
// that observes (test profile, learning, detector on observe) enforces
// nothing.
func (e *Engine) adoptWave(c *compiled, wn *WaveNote, now time.Time) {
	resp, ok := detectorResponse[wn.Detector]
	if !ok || !validWaveID(wn.ID) || c.dist.mode[wn.Detector] == config.DistributedOff || wn.Key == "" || len(wn.Key) > shareDistText ||
		len(wn.Route) > shareDistText || len(wn.Fingerprint) > shareDistText || len(wn.RequestSig) > shareDistText || len(wn.Incident) > 9 || len(wn.FPKind) > 32 {
		return
	}
	h := wn.Host
	if wn.Detector == config.DetectorShapeWave {
		h = ""
	} else if !e.knownHost(h) || !knownRoute(c, wn.Key) {
		return
	}
	maxDur := time.Duration(c.dist.tighten.MaxMinutes) * time.Minute
	started, until := time.UnixMilli(wn.Started), time.UnixMilli(wn.Until)
	if started.After(now.Add(time.Minute)) || now.Sub(started) > maxDur+Cooldown || until.Before(started) {
		return
	}
	until = minTime(until, started.Add(maxDur))
	k := waveKey(wn.Detector, h, wn.Key)
	d := e.d
	d.mu.Lock()
	defer d.mu.Unlock()
	if w := d.waves[wn.ID]; w != nil {
		// A wave this node holds: it was extended or ended elsewhere.
		if w.Detector != wn.Detector {
			return
		}
		if until.After(w.Until) && w.Ended.IsZero() {
			w.Until = until
		}
		w.Senders, w.Count = max(w.Senders, bounded(wn.Senders)), max(w.Count, bounded(wn.Count))
		for _, fp := range cut(wn.ClusterFPs, 16) {
			if len(w.clusterFPs) < 16 && len(fp) <= shareDistText {
				w.clusterFPs[fp] = true
			}
		}
		w.strongCluster = w.strongCluster || wn.Strong
		if wn.Ended != 0 && w.Ended.IsZero() {
			// Ended on another node (by the operator): no event here.
			w.Ended, w.EndReason = time.UnixMilli(wn.Ended), "operator"
		}
		return
	}
	if wn.Ended != 0 {
		return // over before this node heard of it
	}
	if cur := d.byKey[k]; cur != nil && cur.Ended.IsZero() && now.Before(cur.Until.Add(Cooldown)) {
		// Two nodes detected the same wave within the second a note travels.
		// The earlier one stays, on every node; the other leaves memory (its
		// event stays, under the name of its node).
		if cur.Started.Before(started) || (cur.Started.Equal(started) && cur.ID < wn.ID) {
			return
		}
		e.dropWave(cur.ID)
	}
	action := config.DistributedObserve
	if wn.Action == config.DistributedRespond && c.dist.mode[wn.Detector] == config.DistributedRespond && e.distAction(c, now) == config.DistributedRespond {
		action = config.DistributedRespond
	}
	w := &Wave{ID: wn.ID, Detector: wn.Detector, Host: h, Route: wn.Route, Response: resp, Mode: c.dist.mode[wn.Detector], Action: action,
		Started: started, Until: until, Senders: bounded(wn.Senders), Count: bounded(wn.Count), Threshold: max(bounded(wn.Threshold), 1), WindowS: max(bounded(wn.WindowS), 1),
		Baseline: wn.Baseline, Fingerprint: wn.Fingerprint, FPKind: wn.FPKind, UserAgents: bounded(wn.UserAgents), RequestSig: wn.RequestSig,
		WAFRules: append([]int(nil), cut(wn.WAFRules, 32)...), clusterFPs: map[string]bool{}, strongCluster: wn.Strong, foreign: true}
	if action == config.DistributedObserve {
		w.Reason = e.distReason(c, now)
	} else if wn.Detector == config.DetectorShapeWave {
		w.Incident = wn.Incident
	}
	for _, fp := range cut(wn.ClusterFPs, 16) {
		if len(fp) <= shareDistText {
			w.clusterFPs[fp] = true
		}
	}
	e.storeWave(w, k, now)
	e.stats.add("wave:"+wn.Detector, now, 1)
}

// waveIDBucket: nodes that detect a wave within the same five minutes name
// it the same. Two waves of one target lie further apart: a wave runs for
// at least a minute and is followed by its cooldown.
const waveIDBucket = 5 * time.Minute

// groupWaveID is the id of a wave in a group.
func groupWaveID(detector, host, key string, started time.Time) string {
	return derivedID("schild-wave", detector, host, key, strconv.FormatInt(started.UnixNano()/int64(waveIDBucket), 10))
}

// derivedID is a UUID-shaped id from the keyed hash of its parts: the same
// on every node of a group (SetHashKey), not guessable outside it.
func derivedID(parts ...string) string {
	s := strings.Join(parts, "\x00")
	var b [16]byte
	binary.BigEndian.PutUint64(b[:8], keyedString("a\x00"+s))
	binary.BigEndian.PutUint64(b[8:], keyedString("b\x00"+s))
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

// groupIncident is the incident number of a wave in a group: every node
// that detects the wave shows the same number on its block page.
func groupIncident(waveID string) string {
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789" // as events.NewIncident
	h := keyedString("schild-wave-incident\x00" + waveID)
	out := make([]byte, 0, 9)
	for i := 0; i < 8; i++ {
		if i == 4 {
			out = append(out, '-')
		}
		out = append(out, alphabet[(h>>(8*i))&0xff%uint64(len(alphabet))])
	}
	return string(out)
}
