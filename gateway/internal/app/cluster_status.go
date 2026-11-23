package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	contract "github.com/deutschland-schild/schild/contract/cluster"
	"github.com/deutschland-schild/schild/contract/config"
	"github.com/deutschland-schild/schild/contract/firewall"
	"github.com/deutschland-schild/schild/gateway/internal/behaviour"
	"github.com/deutschland-schild/schild/gateway/internal/buildinfo"
	"github.com/deutschland-schild/schild/gateway/internal/dashboard"
)

// The group in the dashboard (MVP-27, D105): the mode this gateway runs in,
// the members as this node sees them, and a hint when the configuration of
// the nodes differs. Everything is read from this node; the answer to the
// dashboard asks no other node.

const (
	tellConfig = "config"
	// configTellEvery is how often a node tells the others its versions;
	// configFresh is how long the last word of a node counts.
	configTellEvery = 5 * time.Second
	configFresh     = time.Minute
	// vitalsFresh is how long the vitals a node told are shown.
	vitalsFresh = 20 * time.Second
	// Bounds of what a node is told.
	maxVersionText = 128
)

// nodeVersions is what a gateway tells the others about itself: the version
// of its configuration and of its build. A hint for the operator; nothing
// is decided by it and no configuration travels.
type nodeVersions struct {
	Config  string `json:"config"`
	Version string `json:"version"`
	// Vitals: how the node is doing right now, for the page of the group.
	// Absent from a node of an older build.
	Vitals *dashboard.GroupVitals `json:"vitals,omitempty"`
	// Now is the clock of the node when it sent this, so the others see
	// how far the clocks are apart. Absent from a node of an older build.
	Now string `json:"now,omitempty"`
	// State: per class a keyed hash of what is in force on the node
	// (cluster_fingerprint.go). Absent from a node of an older build.
	State map[string]string `json:"state,omitempty"`
	// StateAt: the points the hashes of State were computed at, per class
	// and for the vector ("v"); a class without a point is not compared
	// (cluster_fingerprint.go). Absent from a node of an older build.
	StateAt map[string]string `json:"state_at,omitempty"`
}

type toldVersions struct {
	nodeVersions
	at time.Time
	// skew is the sender's clock minus this node's at the moment the word
	// arrived (the time on the way counts in, a few milliseconds); hasSkew
	// is false when the sender named no time.
	skew    time.Duration
	hasSkew bool
	// noted, notedSkew: what was last written into the node's store.
	noted     time.Time
	notedSkew time.Duration
}

func absDur(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

const (
	// clockSkewHint is from where the dashboard names a clock that is off:
	// "the later change wins" needs clocks that agree within seconds.
	clockSkewHint = 10 * time.Second
	// maxClockSkew bounds what a node says about its clock.
	maxClockSkew = 366 * 24 * time.Hour
)

type groupVersions struct {
	mu   sync.Mutex
	told map[string]toldVersions
}

// groupConfigVersion is the config version a node tells its group: SHA-256
// over schild.yaml as loaded, without the keys that differ from node to
// node by design (node_name, listen.dashboard, listen.metrics,
// cluster.name, cluster.listen, cluster.advertise) and with cluster.peers
// in order, and over rules.d. A file that does not parse hashes as its
// bytes.
func groupConfigVersion(raw []byte, localRules string) string {
	h := sha256.New()
	var doc map[string]any
	if j, err := config.YAMLToJSON(raw); err == nil && json.Unmarshal(j, &doc) == nil {
		delete(doc, "node_name")
		if l, ok := doc["listen"].(map[string]any); ok {
			delete(l, "dashboard")
			delete(l, "metrics")
			if len(l) == 0 {
				delete(doc, "listen")
			}
		}
		if c, ok := doc["cluster"].(map[string]any); ok {
			delete(c, "name")
			delete(c, "listen")
			delete(c, "advertise")
			if ps, ok := c["peers"].([]any); ok {
				slices.SortFunc(ps, func(x, y any) int { return strings.Compare(fmt.Sprint(x), fmt.Sprint(y)) })
			}
		}
		// encoding/json writes the keys of a map in order.
		j, _ = json.Marshal(doc)
		h.Write(j)
	} else {
		h.Write(raw)
	}
	h.Write([]byte{0})
	h.Write([]byte(localRules))
	return hex.EncodeToString(h.Sum(nil))
}

// startGroupVersions tells the other gateways this node's versions and
// keeps what they tell.
func (a *App) startGroupVersions(ctx context.Context) {
	a.groupVersions.told = map[string]toldVersions{}
	a.Cluster.OnTell(tellConfig, func(from string, body []byte) {
		var v nodeVersions
		if len(body) > 2048 || json.Unmarshal(body, &v) != nil || !hexText(v.Config, 64) || len(v.Version) > maxVersionText {
			return
		}
		v.Vitals = cleanVitals(v.Vitals, time.Now())
		v.State = cleanState(v.State)
		v.StateAt = cleanStatePoints(v.StateAt)
		// Compared now, at the moment the word describes.
		defer a.noteMemberState(context.Background(), from, v.State, v.StateAt)
		a.groupVersions.mu.Lock()
		defer a.groupVersions.mu.Unlock()
		// The mesh takes a Tell from members only; the map is bounded all
		// the same.
		if _, ok := a.groupVersions.told[from]; !ok && len(a.groupVersions.told) >= 4*clusterMaxGateways {
			return
		}
		told := toldVersions{nodeVersions: v, at: time.Now()}
		if t, err := time.Parse(time.RFC3339Nano, v.Now); err == nil {
			if d := t.Sub(told.at); d > -maxClockSkew && d < maxClockSkew {
				told.skew, told.hasSkew = d, true
			}
		}
		// Kept in the store too, for `schild cluster status`: when it moved
		// by a second or more, and once a minute at least.
		if prev, ok := a.groupVersions.told[from]; told.hasSkew && (!ok || !prev.hasSkew || told.at.Sub(prev.noted) > time.Minute || absDur(told.skew-prev.notedSkew) >= time.Second) {
			if a.Cluster.NoteClock(from, told.skew) == nil {
				told.noted, told.notedSkew = told.at, told.skew
			}
		} else if ok {
			told.noted, told.notedSkew = prev.noted, prev.notedSkew
		}
		a.groupVersions.told[from] = told
	})
	a.goLoop(ctx, "cluster-versions", tick(configTellEvery, func() {
		if a.Cluster.Removed() {
			return
		}
		a.watchState(ctx)
		a.tellVersions(ctx)
		a.groupVersions.mu.Lock()
		for id := range a.groupVersions.told {
			if !a.Cluster.IsMember(id) {
				delete(a.groupVersions.told, id)
			}
		}
		a.groupVersions.mu.Unlock()
	}))
}

// tellVersions tells the gateways this node reaches its versions and how
// it is doing.
func (a *App) tellVersions(ctx context.Context) {
	node := a.Cluster
	if node == nil || node.Removed() {
		return
	}
	body, err := json.Marshal(a.ownVersions())
	if err != nil {
		return
	}
	node.Tell(ctx, tellConfig, body)
}

// setDraining marks this node as leaving traffic and says so to the group
// at once: the loop that tells every five seconds may have ended by then.
func (a *App) setDraining() {
	a.draining.Store(true)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	a.tellVersions(ctx)
}

const clusterMaxGateways = 16

func hexText(s string, n int) bool {
	if len(s) != n {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

func (a *App) ownVersions() nodeVersions {
	now := time.Now()
	v := nodeVersions{Version: buildinfo.String(), Vitals: a.ownVitals(now), Now: now.UTC().Format(time.RFC3339Nano)}
	if p := a.groupConfig.Load(); p != nil {
		v.Config = *p
	}
	a.stateWatch.mu.Lock()
	if own := a.stateWatch.own; own != nil {
		v.State = make(map[string]string, len(own.hashes))
		for class, h := range own.hashes {
			v.State[class] = h
		}
		v.StateAt = make(map[string]string, len(own.points))
		for key, p := range own.points {
			v.StateAt[key] = p
		}
	}
	a.stateWatch.mu.Unlock()
	return v
}

// ownVitals is how this node is doing right now: whether the balancer may
// send it traffic, and the numbers of the last minute. Read from the
// monitor of this node; nothing of it is stored or decided on.
func (a *App) ownVitals(now time.Time) *dashboard.GroupVitals {
	v := &dashboard.GroupVitals{At: dashboard.Stamp(now), Service: "not_ready", StartedAt: dashboard.Stamp(a.started)}
	switch {
	case a.draining.Load():
		v.Service = "draining"
	case a.Gate != nil && a.Gate.Ready():
		v.Service = "ready"
	}
	if a.Monitor == nil {
		return v
	}
	n, err := a.Monitor.Now("", now)
	if err != nil {
		return v
	}
	v.RequestsPerS = n.Traffic.RequestsPerS
	v.StoppedShare, v.LatencyP95MS = n.Traffic.StoppedShare, n.Traffic.LatencyTotalP95MS
	if s := n.Server; s != nil {
		v.CPUUsage, v.MemoryUsedRatio = s.CPUUsage, s.MemoryUsedRatio
		if s.Disk != nil {
			r := s.Disk.UsedRatio
			v.DiskUsedRatio = &r
		}
	}
	return cleanVitals(v, now)
}

// cleanVitals bounds what another node said of itself: a value outside its
// range is dropped, the time is the one of this node. Nil for a word that
// names no known service state.
func cleanVitals(v *dashboard.GroupVitals, now time.Time) *dashboard.GroupVitals {
	if v == nil || (v.Service != "ready" && v.Service != "draining" && v.Service != "not_ready") {
		return nil
	}
	out := dashboard.GroupVitals{At: dashboard.Stamp(now), Service: v.Service}
	if t, err := time.Parse(time.RFC3339, v.StartedAt); err == nil && !t.After(now.Add(time.Minute)) {
		out.StartedAt = dashboard.Stamp(t)
	}
	if v.RequestsPerS >= 0 && v.RequestsPerS < 1e9 {
		out.RequestsPerS = v.RequestsPerS
	}
	ratio := func(p *float64) *float64 {
		if p == nil || !(*p >= 0 && *p <= 1) {
			return nil
		}
		r := *p
		return &r
	}
	out.StoppedShare, out.CPUUsage, out.MemoryUsedRatio, out.DiskUsedRatio = ratio(v.StoppedShare), ratio(v.CPUUsage), ratio(v.MemoryUsedRatio), ratio(v.DiskUsedRatio)
	if p := v.LatencyP95MS; p != nil && *p >= 0 && *p < 1e7 {
		ms := *p
		out.LatencyP95MS = &ms
	}
	return &out
}

// GroupStatus is what the dashboard shows of the mode this gateway runs in
// (getGroupStatus). A gateway without cluster.enabled never comes here.
func (a *App) GroupStatus() dashboard.GroupStatus {
	now := time.Now()
	node := a.Cluster
	if node == nil {
		// cluster.enabled and no node: only before the loops start. A
		// gateway whose node cannot run does not start (openCluster).
		return dashboard.GroupStatus{Mode: "single", State: "no_group", GeneratedAt: dashboard.Stamp(now)}
	}
	st, err := node.Live()
	if err != nil {
		a.log.Warn("cluster: status not read", "err", err)
		st = nil
	}
	out := dashboard.GroupStatus{Mode: "group", GeneratedAt: dashboard.Stamp(now), Group: node.Group(),
		Node: &dashboard.GroupNode{ID: node.ID(), Name: node.Name(), Role: contract.RoleGateway}}
	if st == nil {
		out.State = "interrupted"
		return out
	}
	own := a.ownVersions()
	a.groupVersions.mu.Lock()
	told := make(map[string]toldVersions, len(a.groupVersions.told))
	for id, v := range a.groupVersions.told {
		told[id] = v
	}
	a.groupVersions.mu.Unlock()

	var gateways, removed []dashboard.GroupMember
	others, reached := 0, 0
	differing := []string{}
	for _, m := range st.Members {
		row := dashboard.GroupMember{ID: m.ID, Name: m.Member.Name, Role: m.Member.Role, Address: m.Member.Address,
			LastOut: dashboard.StampPtr(m.OutOK), LastIn: dashboard.StampPtr(m.InOK)}
		switch {
		case m.Removed:
			row.State, row.LastOut, row.LastIn = "removed", nil, nil
			removed = append(removed, row)
			continue
		case m.Self:
			row.State, row.Version, row.Config, row.Vitals = "self", own.Version, "same", own.Vitals
			gateways = append(gateways, row)
			continue
		}
		others++
		behind := int(m.Behind)
		row.Behind = &behind
		switch {
		case m.Error != "":
			row.State, row.Error = "unreachable", firewall.OneLine(m.Error, 300)
		case m.OutOK.IsZero() || now.Sub(m.OutOK) > 15*time.Second:
			row.State = "no_contact"
		default:
			row.State = "ok"
			reached++
		}
		row.Config = "unknown"
		if v, ok := told[m.ID]; ok {
			row.Version = v.Version
			if now.Sub(v.at) < vitalsFresh {
				row.Vitals = v.Vitals
			}
			if v.hasSkew && now.Sub(v.at) < configFresh {
				ms := v.skew.Milliseconds()
				row.ClockSkewMS = &ms
			}
			row.SharedState = a.memberState(m.ID, v.State, row.State == "ok" && now.Sub(v.at) < vitalsFresh, now)
			if now.Sub(v.at) < configFresh && own.Config != "" {
				row.Config = "same"
				if v.Config != own.Config {
					row.Config = "differs"
					differing = append(differing, row.Name)
				}
			}
		}
		gateways = append(gateways, row)
	}
	out.Members = append(gateways, removed...)
	if len(out.Members) > dashboard.MaxGroupMembers {
		out.Members = out.Members[:dashboard.MaxGroupMembers]
	}
	switch {
	case node.Removed():
		out.State = "removed"
	case others > 0 && reached == 0:
		out.State = "interrupted"
		if !node.Synced() && now.Sub(a.started) < firstSyncWait() {
			out.State = "syncing"
		}
	case !node.Synced():
		out.State = "syncing"
	case reached < others:
		out.State = "degraded"
	default:
		out.State = "active"
	}
	out.Shared = &dashboard.GroupShared{Blocks: st.Records[contract.ClassBlocks], Settings: st.Records[contract.ClassSettings], Access: st.Records[contract.ClassAccess],
		Logins: st.Records[contract.ClassLogins]}
	out.Counters = &dashboard.GroupCounters{Taken: st.Counters["applied"], Refused: st.Counters["rejected"], Deferred: st.Counters["deferred"], Unread: st.Counters["unread"]}
	out.Replaced = &st.Replaced
	if len(own.Config) >= 12 {
		sort.Strings(differing)
		if len(differing) > clusterMaxGateways {
			differing = differing[:clusterMaxGateways]
		}
		out.Config = &dashboard.GroupConfig{Version: own.Config[:12], Differing: differing}
	}
	return out
}

// blockNode names the node that decided the block of a client, as the
// group's record says: its name, and whether it is this node.
func (a *App) blockNode(key behaviour.Key, incident string) (name string, self, ok bool) {
	a.groupBlocks.mu.Lock()
	defer a.groupBlocks.mu.Unlock()
	k, found := a.groupBlocks.known[key]
	if !found || k.incident != incident || k.node == "" {
		return "", false, false
	}
	return k.node, k.self, true
}

// erasedInGroup tells the group that an address was erased here, waits a
// moment for the gateways to say they hold the erasure and names them.
func (a *App) erasedInGroup(ctx context.Context, ip netip.Addr, keepIncidents bool) *dashboard.ErasureNodes {
	node := a.Cluster
	if node == nil {
		return nil
	}
	out := &dashboard.ErasureNodes{Reached: []string{node.Name()}, Open: []string{}}
	seq := a.publishErasure(ip, keepIncidents)
	if seq == 0 {
		// Not handed over (the log says so): no other node holds it.
		_, open := node.Acked(^uint64(0))
		out.Open = append(out.Open, open...)
		return out
	}
	node.WaitAcked(ctx, seq, 2*time.Second)
	reached, open := node.Acked(seq)
	out.Reached = append(out.Reached, reached...)
	out.Open = append(out.Open, open...)
	return out
}

// clusterReasons are the baseline reasons of the overview that come from
// the group: a gateway this node does not reach, a configuration that
// differs, a clock that is off. Hints for the operator; nothing is decided
// by them.
func (a *App) clusterReasons() []string {
	if a.Cluster == nil {
		return nil
	}
	st := a.GroupStatus()
	var out []string
	if st.State == "degraded" || st.State == "interrupted" {
		out = append(out, "cluster_peers_unreachable")
	}
	if a.clockOut.Load() {
		out = append(out, "cluster_clock_out_of_service")
	}
	if a.stateDiffers(time.Now()) {
		out = append(out, "cluster_state_differs")
	}
	if a.warmFailed.Load() {
		out = append(out, "cluster_counts_not_taken")
	}
	if st.Config != nil && len(st.Config.Differing) > 0 {
		out = append(out, "cluster_config_drift")
	}
	for _, m := range st.Members {
		if m.ClockSkewMS != nil && (*m.ClockSkewMS >= clockSkewHint.Milliseconds() || *m.ClockSkewMS <= -clockSkewHint.Milliseconds()) {
			out = append(out, "cluster_clock_skew")
			break
		}
	}
	return out
}
