package cluster

import (
	"context"
	"crypto/ed25519"
	"errors"
	"time"
)

// maxResyncPages bounds one Resync: pages of a sync answer.
const maxResyncPages = 64

// Resync asks a member once more for everything it holds, from the first
// record on, and takes what this node lacks or holds an older value of. The
// vector normally spares both sides that work; this is for the case that
// the two disagree although their vectors say they are in step (the state
// hashes of the app differ for a while). What this node holds already is
// compared and left as it is, so the call changes nothing on a node that
// is in step. It returns how many records it applied.
func (n *Node) Resync(ctx context.Context, id string) (applied int, err error) {
	if n.paused.Load() || n.Removed() {
		return 0, nil
	}
	n.pmu.Lock()
	p := n.peers[id]
	n.pmu.Unlock()
	if p == nil {
		return 0, errors.New("cluster: no such member to ask again")
	}
	key := p.key
	c := meshClient(n.cert, func(k ed25519.PublicKey) bool { return k.Equal(key) }, 15*time.Second)
	defer c.CloseIdleConnections()
	vec := map[string]uint64{}
	n.retake.Add(1)
	defer n.retake.Add(-1)
	for page := 0; page < maxResyncPages && ctx.Err() == nil; page++ {
		var resp syncResponse
		if err := postJSON(ctx, c, "https://"+p.address+pathSync, syncRequest{Group: n.group, Vector: vec, WaitMS: 0}, &resp); err != nil {
			return applied, err
		}
		got, err := n.take(resp.Records, resp.Covered)
		applied += got
		if err != nil {
			return applied, err
		}
		moved := false
		for origin, seq := range resp.Covered {
			if seq > vec[origin] {
				vec[origin] = seq
				moved = true
			}
		}
		if !resp.More || !moved {
			break
		}
	}
	return applied, nil
}
