package app

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	contract "github.com/deutschland-schild/schild/contract/cluster"
)

// A fingerprint of the state (initiator, 2026-11-22). The records of a
// group say what was written; the fingerprint says what is in force. Each
// gateway hashes, per class, the entries it runs with and tells the others
// the four hashes with its versions (kind `config`, every 5 s). Equal
// hashes mean the same state; hashes that differ for longer than a change
// takes to travel mean that a node did not take or did not apply what the
// group holds. That is shown, named on the overview, and repaired.
//
// What is hashed, so that two nodes in step cannot differ:
//
//   - settings, access, logins: every entry of every shared thing as this
//     node holds it in schild.db (the same cut into entries the sync uses),
//     as thing, entry key and the SHA-256 of the entry's value in one
//     canonical JSON form. Sorted, so neither the order of a list nor the
//     way a node wrote its JSON counts. Keys that are per node never appear.
//   - blocks: the block records of the group this node holds that are not
//     lifted and end more than 5 s from now, as client key and incident. A
//     node's own allowlist from schild.yaml may keep it from running a block
//     the group holds; that is per node by design and not hashed.
//
// The hash is HMAC-SHA-256 under the hash key of the group, cut to 8 bytes:
// it says "same" or "not the same" and nothing about the content, also not
// to someone who can guess a password or an address.

var (
	// stateDiffShown: a difference younger than this is a change on its way.
	stateDiffShown = 10 * time.Second
	// stateDiffRepair: from here a difference is named on the overview and
	// repaired.
	stateDiffRepair = 30 * time.Second
	// stateRepairEvery bounds the repairs towards one member.
	stateRepairEvery = time.Minute
)

// stateBlockMargin: a block that ends this soon is left out, so two nodes
// that look a moment apart hash the same.
const stateBlockMargin = 5 * time.Second

var stateClasses = []string{contract.ClassBlocks, contract.ClassSettings, contract.ClassAccess, contract.ClassLogins}

type stateWatch struct {
	mu sync.Mutex
	// own: the hashes of this node, as of ownAt.
	own   map[string]string
	ownAt time.Time
	// since: member id + "/" + class -> since when its hash differs.
	since map[string]time.Time
	// repaired: member id -> the last repair towards it.
	repaired  map[string]time.Time
	repairing atomic.Bool
	// Repairs counts the repairs that ran (tests).
	repairs atomic.Int64
	// kept: the hashes last computed, and what they were computed from
	// (stateHashes). computed counts the computations (tests).
	kept                map[string]string
	keptGen, keptRecGen uint64
	keptAt, keptUntil   time.Time
	computed            atomic.Int64
}

// canonSum is the SHA-256 of a value in one JSON form, of its bytes when it
// is no JSON.
func canonSum(v []byte) string {
	if t := bytes.TrimSpace(v); len(t) > 0 && json.Valid(t) {
		var x any
		d := json.NewDecoder(bytes.NewReader(t))
		d.UseNumber()
		if d.Decode(&x) == nil {
			if b, err := json.Marshal(x); err == nil {
				return sum(b)
			}
		}
	}
	return sum(v)
}

func (a *App) stateMAC(class string, lines []string) string {
	sort.Strings(lines)
	m := hmac.New(sha256.New, a.groupHashKey[:])
	m.Write([]byte("schild-state:" + class + "\n"))
	for _, l := range lines {
		m.Write([]byte(l))
		m.Write([]byte{'\n'})
	}
	return hex.EncodeToString(m.Sum(nil)[:8])
}

// stateHashKept is how long hashes are kept at most while nothing changed.
var stateHashKept = time.Minute

// stateHashes returns the hashes of this node. They are computed anew only
// when something changed that they are made of: the store of this node
// (stateGen, moved by the loop of the shared things on every commit to
// schild.db), the records the node holds (Node.StoreGen), or the time, when
// a block that was hashed comes within stateBlockMargin of its end. An idle
// node used to read and hash every entry every 5 s.
func (a *App) stateHashes(ctx context.Context, now time.Time) map[string]string {
	node := a.Cluster
	if node == nil {
		return nil
	}
	w := &a.stateWatch
	gen, recGen := a.stateGen.Load(), node.StoreGen()
	w.mu.Lock()
	if w.kept != nil && w.keptGen == gen && w.keptRecGen == recGen && now.Before(w.keptUntil) && !now.Before(w.keptAt) {
		out := w.kept
		w.mu.Unlock()
		return out
	}
	w.mu.Unlock()
	out, until := a.computeStateHashes(ctx, now)
	w.computed.Add(1)
	w.mu.Lock()
	// Kept under the numbers read before the computing: a write in between
	// moves them, and the next call computes again.
	w.kept, w.keptGen, w.keptRecGen, w.keptAt, w.keptUntil = out, gen, recGen, now, until
	w.mu.Unlock()
	return out
}

// computeStateHashes hashes the state now. until is when the hashes stop
// to hold although nothing was written: a hashed block comes within the
// margin of its end, or stateHashKept passed.
func (a *App) computeStateHashes(ctx context.Context, now time.Time) (hashes map[string]string, until time.Time) {
	node := a.Cluster
	until = now.Add(stateHashKept)
	lines := map[string][]string{}
	if recs, err := node.State(contract.ClassBlocks); err == nil {
		for _, rec := range recs {
			if rec.Deleted {
				continue
			}
			ends, err := time.Parse("2006-01-02T15:04:05Z", rec.Expires)
			if err != nil || !ends.After(now.Add(stateBlockMargin)) {
				continue
			}
			if leaves := ends.Add(-stateBlockMargin); leaves.Before(until) {
				until = leaves
			}
			b, err := contract.DecodeBlock(rec)
			if err != nil {
				continue
			}
			lines[contract.ClassBlocks] = append(lines[contract.ClassBlocks], rec.ID+"\x00"+b.Incident)
		}
	}
	a.sharedMu.Lock()
	things := append(append([]sharedThing{}, a.shared...), a.genericThings(ctx, node.Synced())...)
	for _, t := range things {
		blob, err := t.read(ctx)
		if err != nil {
			continue
		}
		entries, err := t.codec.split(blob)
		if err != nil {
			continue
		}
		for k, v := range entries {
			lines[t.class] = append(lines[t.class], t.id+"\x00"+k+"\x00"+canonSum(v))
		}
	}
	a.sharedMu.Unlock()
	out := make(map[string]string, len(stateClasses))
	for _, class := range stateClasses {
		out[class] = a.stateMAC(class, lines[class])
	}
	return out, until
}

// cleanState bounds the hashes another node told.
func cleanState(in map[string]string) map[string]string {
	if len(in) == 0 || len(in) > 8 {
		return nil
	}
	out := map[string]string{}
	for _, class := range stateClasses {
		if h, ok := in[class]; ok && hexText(h, 16) {
			out[class] = h
		}
	}
	return out
}

// watchState runs with the tell of the versions: it hashes this node's
// state, compares it with what the reachable members told, and repairs a
// difference that lasts.
func (a *App) watchState(ctx context.Context) {
	node := a.Cluster
	if node == nil || node.Removed() || node.Paused() || !node.Synced() {
		return
	}
	now := time.Now()
	own := a.stateHashes(ctx, now)
	reach := map[string]bool{}
	for _, id := range node.Reachable() {
		reach[id] = true
	}
	a.groupVersions.mu.Lock()
	told := map[string]map[string]string{}
	for id, v := range a.groupVersions.told {
		if reach[id] && now.Sub(v.at) < vitalsFresh && len(v.State) > 0 {
			told[id] = v.State
		}
	}
	a.groupVersions.mu.Unlock()

	w := &a.stateWatch
	w.mu.Lock()
	w.own, w.ownAt = own, now
	if w.since == nil {
		w.since, w.repaired = map[string]time.Time{}, map[string]time.Time{}
	}
	live := map[string]bool{}
	repair := map[string][]string{}
	for id, st := range told {
		for _, class := range stateClasses {
			h, ok := st[class]
			key := id + "/" + class
			if !ok || h == own[class] {
				continue
			}
			live[key] = true
			if _, was := w.since[key]; !was {
				w.since[key] = now
			}
			if now.Sub(w.since[key]) >= stateDiffRepair && now.Sub(w.repaired[id]) >= stateRepairEvery {
				repair[id] = append(repair[id], class)
			}
		}
	}
	for key := range w.since {
		if !live[key] {
			delete(w.since, key)
		}
	}
	for id := range repair {
		w.repaired[id] = now
	}
	for id := range w.repaired {
		if !node.IsMember(id) {
			delete(w.repaired, id)
		}
	}
	w.mu.Unlock()
	if len(repair) > 0 && w.repairing.CompareAndSwap(false, true) {
		go func() {
			defer w.repairing.Store(false)
			for id, classes := range repair {
				a.repairState(ctx, id, classes)
			}
		}()
	}
}

// repairState brings this node in step with a member whose state differs:
// it asks the member again for everything it holds (the store takes what
// this node lacks and leaves the rest), then applies what the group holds
// of the classes that differ once more. A change made on this node that has
// not left yet is never taken back. At most once a minute per member.
func (a *App) repairState(ctx context.Context, member string, classes []string) {
	node := a.Cluster
	rctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	applied, err := node.Resync(rctx, member)
	again := map[string]bool{}
	for _, class := range classes {
		if class == contract.ClassBlocks {
			if recs, rerr := node.State(contract.ClassBlocks); rerr == nil {
				for _, rec := range recs {
					a.applyGroupRecord(rec)
				}
			}
			continue
		}
		again[class] = true
	}
	if len(again) > 0 {
		a.sharedMu.Lock()
		if a.sharedRepair == nil {
			a.sharedRepair = map[string]bool{}
		}
		for class := range again {
			a.sharedRepair[class] = true
		}
		a.sharedMu.Unlock()
	}
	a.stateWatch.repairs.Add(1)
	if err != nil {
		a.log.Warn("cluster: the state of this node differs from a member's; asking it again failed, what this node holds was applied again", "member", node.PeerName(member), "classes", classes, "err", err)
		return
	}
	a.log.Warn("cluster: the state of this node differed from a member's for 30 s; asked it again and applied the group's state again", "member", node.PeerName(member), "classes", classes, "records_taken", applied)
}

// repairThing notes, for one thing, every entry whose value on this node is
// not the group's although this node believes it is in step, so the next
// round applies the group's. Called with sharedMu held.
func (a *App) repairThing(ctx context.Context, t sharedThing) {
	blob, err := t.read(ctx)
	if err != nil {
		return
	}
	local, err := t.codec.split(blob)
	if err != nil {
		return
	}
	recs, err := a.Cluster.State(t.class)
	if err != nil {
		return
	}
	marks := a.marksOf(t)
	pending := a.sharedPending[t.key()]
	seen := map[string]bool{}
	changed := false
	note := func(k string, p pendingEntry) {
		if pending == nil {
			pending = map[string]pendingEntry{}
			a.sharedPending[t.key()] = pending
		}
		if _, queued := pending[k]; !queued {
			pending[k] = p
		}
	}
	for _, rec := range recs {
		if thing, ok := contract.ThingOf(rec.Class, rec.ID); !ok || thing != t.id {
			continue
		}
		v, err := contract.DecodeValue(rec)
		if err != nil {
			continue
		}
		seen[v.K] = true
		cur, here := local[v.K]
		mark, marked := marks[v.K]
		// Changed or removed here and not handed over yet: that stands.
		if (here && marked && mark != sum(cur)) || (here && !marked) || (!here && marked) {
			continue
		}
		if rec.Deleted {
			if here {
				note(v.K, pendingEntry{node: v.Node})
			}
			continue
		}
		val, _ := v.Bytes()
		if val == nil {
			val = []byte{}
		}
		if here && canonSum(cur) == canonSum(val) {
			continue
		}
		// The mark must not call the group's value "no news".
		if marked && mark == sum(val) {
			delete(marks, v.K)
			changed = true
		}
		note(v.K, pendingEntry{v: val, node: v.Node})
	}
	// An entry this node believes shared that the group does not hold at
	// all is handed over again.
	for k, cur := range local {
		if !seen[k] && marks[k] == sum(cur) {
			delete(marks, k)
			changed = true
		}
	}
	if changed {
		a.saveMarks(t)
	}
}

// memberState says per class whether a member's state is this node's:
// same, differs (for longer than a change takes to travel) or unknown.
func (a *App) memberState(id string, told map[string]string, fresh bool, now time.Time) map[string]string {
	w := &a.stateWatch
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.own) == 0 {
		return nil
	}
	out := make(map[string]string, len(stateClasses))
	for _, class := range stateClasses {
		h, ok := told[class]
		switch {
		case !fresh || !ok:
			out[class] = "unknown"
		case h == w.own[class]:
			out[class] = "same"
		default:
			out[class] = "same"
			if since, was := w.since[id+"/"+class]; was && now.Sub(since) >= stateDiffShown {
				out[class] = "differs"
			}
		}
	}
	return out
}

// stateDiffers reports whether the state of a reachable member has differed
// for longer than stateDiffRepair (the overview: cluster_state_differs).
func (a *App) stateDiffers(now time.Time) bool {
	w := &a.stateWatch
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, since := range w.since {
		if now.Sub(since) >= stateDiffRepair {
			return true
		}
	}
	return false
}
