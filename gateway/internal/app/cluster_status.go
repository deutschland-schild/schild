package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"sort"
	"sync"
	"time"

	contract "github.com/deutschland-schild/schild/contract/cluster"
	"github.com/deutschland-schild/schild/contract/config"
	"github.com/deutschland-schild/schild/contract/firewall"
	"github.com/deutschland-schild/schild/gateway/internal/behaviour"
	"github.com/deutschland-schild/schild/gateway/internal/buildinfo"
	"github.com/deutschland-schild/schild/gateway/internal/dashboard"
)

// The group in the dashboard (MVP-27, D103): the mode this gateway runs in,
// the members as this node sees them, and a hint when the configuration of
// the nodes differs. Everything is read from this node; the answer to the
// dashboard asks no other node.

const (
	tellConfig = "config"
	// configTellEvery is how often a node tells the others its versions;
	// configFresh is how long the last word of a node counts.
	configTellEvery = 5 * time.Second
	configFresh     = time.Minute
	// Bounds of what a node is told.
	maxVersionText = 128
)

// nodeVersions is what a gateway tells the others about itself: the version
// of its configuration and of its build. A hint for the operator; nothing
// is decided by it and no configuration travels.
type nodeVersions struct {
	Config  string `json:"config"`
	Version string `json:"version"`
}

type toldVersions struct {
	nodeVersions
	at time.Time
}

type groupVersions struct {
	mu   sync.Mutex
	told map[string]toldVersions
}

// groupConfigVersion is the config version a node tells its group: SHA-256
// over schild.yaml as loaded, without the keys that differ from node to
// node by design (node_name, cluster.listen, cluster.advertise), and over
// rules.d. A file that does not parse hashes as its bytes.
func groupConfigVersion(raw []byte, localRules string) string {
	h := sha256.New()
	var doc map[string]any
	if j, err := config.YAMLToJSON(raw); err == nil && json.Unmarshal(j, &doc) == nil {
		delete(doc, "node_name")
		if c, ok := doc["cluster"].(map[string]any); ok {
			delete(c, "listen")
			delete(c, "advertise")
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
		if len(body) > 1024 || json.Unmarshal(body, &v) != nil || !hexText(v.Config, 64) || len(v.Version) > maxVersionText {
			return
		}
		a.groupVersions.mu.Lock()
		defer a.groupVersions.mu.Unlock()
		// The mesh takes a Tell from members only; the map is bounded all
		// the same.
		if _, ok := a.groupVersions.told[from]; !ok && len(a.groupVersions.told) >= 4*clusterMaxGateways {
			return
		}
		a.groupVersions.told[from] = toldVersions{nodeVersions: v, at: time.Now()}
	})
	a.goLoop(ctx, "cluster-versions", tick(configTellEvery, func() {
		if a.Cluster.Removed() {
			return
		}
		body, err := json.Marshal(a.ownVersions())
		if err != nil {
			return
		}
		a.Cluster.Tell(ctx, tellConfig, body)
		a.groupVersions.mu.Lock()
		for id := range a.groupVersions.told {
			if !a.Cluster.IsMember(id) {
				delete(a.groupVersions.told, id)
			}
		}
		a.groupVersions.mu.Unlock()
	}))
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
	v := nodeVersions{Version: buildinfo.String()}
	if p := a.groupConfig.Load(); p != nil {
		v.Config = *p
	}
	return v
}

// GroupStatus is what the dashboard shows of the mode this gateway runs in
// (getGroupStatus). A gateway without cluster.enabled never comes here.
func (a *App) GroupStatus() dashboard.GroupStatus {
	now := time.Now()
	node := a.Cluster
	if node == nil {
		// cluster.enabled, but no group: it runs alone (startCluster says why).
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
	edges := a.EdgeReports()

	var gateways, edgeRows, removed []dashboard.GroupMember
	others, reached := 0, 0
	differing := []string{}
	for _, m := range st.Members {
		row := dashboard.GroupMember{ID: m.ID, Name: m.Member.Name, Role: m.Member.Role, LastOut: dashboard.StampPtr(m.OutOK), LastIn: dashboard.StampPtr(m.InOK)}
		if m.Member.Role != contract.RoleEdge {
			row.Address = m.Member.Address
		}
		switch {
		case m.Removed:
			row.State, row.LastOut, row.LastIn = "removed", nil, nil
			removed = append(removed, row)
			continue
		case m.Self:
			row.State, row.Version, row.Config = "self", own.Version, "same"
			gateways = append(gateways, row)
			continue
		case m.Member.Role == contract.RoleEdge:
			// An edge asks one gateway at a time: here only when it asked this one.
			row.State = "asks_elsewhere"
			if !m.InOK.IsZero() && now.Sub(m.InOK) < time.Minute {
				row.State = "ok"
				if r, ok := edges[m.ID]; ok {
					held := r.Held
					row.BlocksHeld, row.Error = &held, firewall.OneLine(r.Error, 300)
				}
			}
			edgeRows = append(edgeRows, row)
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
	out.Members = append(append(gateways, edgeRows...), removed...)
	if len(out.Members) > dashboard.MaxGroupMembers {
		out.Members = out.Members[:dashboard.MaxGroupMembers]
	}
	switch {
	case node.Removed():
		out.State = "removed"
	case node.Paused():
		out.State = "paused"
		if t, err := time.Parse(time.RFC3339, st.Paused); err == nil {
			out.PausedSince = dashboard.StampPtr(t)
		}
	case others > 0 && reached == 0:
		out.State = "interrupted"
		if !node.Synced() && now.Sub(a.started) < firstSyncWait {
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
		Logins: st.Records[contract.ClassLogins], ShareData: a.Config().Cluster.SharesData()}
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
