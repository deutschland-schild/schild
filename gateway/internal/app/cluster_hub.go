package app

import (
	"context"
	"encoding/json"
	"sync/atomic"
	"time"

	"github.com/deutschland-schild/schild/gateway/internal/hub"
	"github.com/deutschland-schild/schild/gateway/internal/ratelog"
)

// The group of MVP-27 (D105) runs one set of CrowdSec Hub rules. Every node
// may download the hub index; the node that took a new one says so, and the
// others fetch it from that node and take it through their own update
// (hub/share.go): the same checks as for a download, under the time of the
// first download. The rules are then the same on every node, first seen at
// the same moment, and none waits for its own daily check.
//
// Own rules (rules.d) are files of the deployment and are not shared (D105).

// hubIndex is what the group needs of the hub source.
type hubIndex interface {
	SharedIndex() (hub.IndexInfo, []byte, bool)
	WantsIndex(hub.IndexInfo) bool
	TakeIndex(ctx context.Context, in hub.IndexInfo, gz []byte) error
}

// hubReset is the part of the hub source that makes a reset hold for the
// group.
type hubReset interface {
	SetOnReset(func(at time.Time))
	ResetOfGroup(ctx context.Context, at time.Time) error
}

// hubResetKey holds when the hub rules were last reset to the image
// snapshot, on any node of the group.
const hubResetKey = "crowdsec_hub_reset_v1"

const (
	tellHub     = "hub"
	askHubIndex = "hub_index"
	// hubAnnounce is how often a node says again which index it runs; a
	// change is said within hubLook.
	hubAnnounce = 30 * time.Second
	hubLook     = 2 * time.Second
)

func (a *App) hubOfGroup() hubIndex {
	if p := a.hubShare.Load(); p != nil {
		return *p
	}
	return nil
}

// startGroupHub shares the hub index with the group.
func (a *App) startGroupHub(ctx context.Context) {
	if a.hubShare.Load() == nil {
		var h hubIndex = a.Repos.Hub()
		a.hubShare.Store(&h)
	}
	// A reset of the rules holds for the group: the node that was reset
	// writes when under a key of the store, which is shared like every
	// other, and each node that takes it resets too (hub/share.go).
	if h, ok := any(a.Repos.Hub()).(hubReset); ok && a.Repos.Hub() != nil {
		h.SetOnReset(func(at time.Time) {
			if err := a.Store.Put(context.Background(), hubResetKey, []byte(at.UTC().Format(time.RFC3339))); err != nil {
				a.log.Warn("cluster: the reset of the hub rules was not noted for the group; it holds on this node", "err", err)
			}
		})
		follow := func(ctx context.Context, v []byte) {
			at, err := time.Parse(time.RFC3339, string(v))
			if err != nil {
				return
			}
			if err := h.ResetOfGroup(ctx, at); err != nil {
				a.log.Warn("cluster: the hub rules were reset on another node; this node could not follow", "err", err)
			}
		}
		a.OnSharedKey(hubResetKey, follow)
		if v, err := a.Store.Get(ctx, hubResetKey); err == nil {
			follow(ctx, v)
		}
	}
	node := a.Cluster
	var taking atomic.Bool
	node.OnAsk(askHubIndex, func(_ string, body []byte) ([]byte, error) {
		var q hub.IndexInfo
		if err := json.Unmarshal(body, &q); err != nil {
			return nil, err
		}
		info, gz, ok := a.hubOfGroup().SharedIndex()
		if !ok || info.Digest != q.Digest {
			return []byte{}, nil // it moved on; the asker hears of the new one
		}
		return gz, nil
	})
	node.OnTell(tellHub, func(from string, body []byte) {
		var in hub.IndexInfo
		if json.Unmarshal(body, &in) != nil || !a.hubOfGroup().WantsIndex(in) {
			return
		}
		// One at a time, and not in the goroutine of the mesh: taking an
		// index measures its cost and builds the rules.
		if !taking.CompareAndSwap(false, true) {
			return
		}
		go func() {
			defer taking.Store(false)
			actx, cancel := context.WithTimeout(ctx, 30*time.Second)
			q, _ := json.Marshal(in)
			gz, err := node.Ask(actx, from, askHubIndex, q)
			cancel()
			if err != nil || len(gz) == 0 {
				return
			}
			if err := a.hubOfGroup().TakeIndex(ctx, in, gz); err != nil {
				ratelog.Warn(a.log, "cluster: hub rules of another node not taken, this node keeps its own and asks the hub itself", "from", node.PeerName(from), "err", err)
				return
			}
			a.log.Info("cluster: took the hub rules another node downloaded", "from", node.PeerName(from), "index", in.Digest)
		}()
	})
	var last string
	var said time.Time
	a.goLoop(ctx, "cluster-hub", tick(hubLook, func() {
		info, _, ok := a.hubOfGroup().SharedIndex()
		if !ok || node.Removed() {
			return
		}
		if info.Digest == last && time.Since(said) < hubAnnounce {
			return
		}
		body, err := json.Marshal(info)
		if err != nil {
			return
		}
		last, said = info.Digest, time.Now()
		node.Tell(ctx, tellHub, body)
	}))
}
