package app

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	contract "github.com/deutschland-schild/schild/contract/cluster"
)

// A fingerprint of the state (initiator, 2026-11-22). The records of a
// group say what was written; the fingerprint says what is in force. Each
// gateway hashes, per class, the entries it runs with and tells the others
// the four hashes with its versions (kind `config`, every 5 s), each with
// the point it was computed at. Equal hashes at the same point mean the
// same state; different hashes at the same point mean that a node did not
// apply what the group holds. That is shown, named on the overview, and
// repaired.
//
// The point makes the comparison exact (third lab run, S1: without it two
// nodes compared hashes of different moments, and under a steady stream of
// changes every look found a change on its way, which after 10 s read as a
// difference and after 30 s started a repair that took nothing). A point
// of a class is a hash over the records that are its state (cluster
// Node.ClassPoint); two nodes with the same point hold the same records of
// that class. Hashes are compared only at the same point. Points that
// differ are a change on its way, or a member that is behind: the page says
// that by other fields, and nothing is concluded from the hashes. There is
// one more sign of a real difference: two nodes that have seen the same
// records (the same vector, Node.VectorPoint) and still do not hold the
// same records of a class.
//
// What is hashed, so that two nodes at the same point cannot differ unless
// one did not apply:
//
//   - settings, access, logins: every entry of every shared thing as this
//     node holds it in schild.db (the same cut into entries the sync uses),
//     as thing, entry key and the SHA-256 of the entry's value in one
//     canonical JSON form. Sorted, so neither the order of a list nor the
//     way a node wrote its JSON counts. Keys that are per node never appear.
//     The hash of such a class has a point only while the node is settled:
//     nothing changed here that has not left yet, and nothing another node
//     changed waits to be put in. Otherwise the node says no point, and
//     nobody compares.
//   - blocks: the block records of the group this node holds that are not
//     lifted and have not ended, as incident number: those of class
//     incident_blocks and, until they are over, those of class blocks that
//     name an incident (contracts/cluster.md section 16). A node's own
//     allowlist from schild.yaml may keep it from running a block the group
//     holds; that is per node by design and not hashed. At the same point
//     two nodes hold the same block records, so this hash differs only
//     together with the point.
//
// The hash is HMAC-SHA-256 under the hash key of the group, cut to 8 bytes:
// it says "same" or "not the same" and nothing about the content, also not
// to someone who can guess a password or an address.

var (
	// stateDiffShown: a difference of the records two nodes hold at the same
	// vector is shown when it was seen again for this long; a difference of
	// what is in force at the same point is shown at once.
	stateDiffShown = 10 * time.Second
	// stateDiffRepair: from here a difference is named on the overview and
	// repaired.
	stateDiffRepair = 30 * time.Second
	// stateRepairEvery bounds the repairs towards one member.
	stateRepairEvery = time.Minute
	// stateCompared: how long "same" holds after the last look at which a
	// member could be compared; after that its state reads unknown.
	stateCompared = time.Minute
	// stateLookEvery bounds how often a word of a member makes this node
	// hash its state anew while it changes.
	stateLookEvery = time.Second
)

// statePointVector is the key of the vector's point next to the classes.
const statePointVector = "v"

// stateHistory is how many of its own points a node remembers: a member's
// word describes a moment a little ago.
const stateHistory = 64

// stateBlocks is the name of the blocks in a node's word of its state. The
// hash under it covers the blocks of both classes (blockClasses), and its
// point the lifts too: a lift takes a block out of the hash.
const stateBlocks = "blocks"

var stateClasses = []string{stateBlocks, contract.ClassSettings, contract.ClassAccess, contract.ClassLogins}

// blockClasses hold the blocks of a group: the records by incident, and
// those of the build before D109 until they are over (contracts/cluster.md
// section 16).
var blockClasses = []string{contract.ClassIncidentBlocks, contract.ClassBlocks}

// stateLook is the state of this node at one moment: the hash of every
// class and the point each was computed at ("": none, the class was not
// settled), with the point of the vector under statePointVector.
type stateLook struct {
	at     time.Time
	hashes map[string]string
	points map[string]string
}

type stateWatch struct {
	mu sync.Mutex
	// own: the last look of this node; past: its looks before, newest last.
	own  *stateLook
	past []*stateLook
	// since: member id + "/" + class -> since when its state differs; soft:
	// the difference is one of records at the same vector, which has to be
	// seen again with every word.
	since map[string]time.Time
	soft  map[string]bool
	// compared: member id + "/" + class -> the last look at which the two
	// could be compared.
	compared map[string]time.Time
	// repaired: member id -> the last repair towards it.
	repaired  map[string]time.Time
	repairing atomic.Bool
	// Repairs counts the repairs that ran (tests).
	repairs atomic.Int64
	// kept: the look last computed, and what it was computed from
	// (stateNow). computed counts the computations (tests).
	kept                *stateLook
	keptGen, keptRecGen uint64
	keptUntil           time.Time
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

// stateHashKept is how long a look is kept at most while nothing changed.
var stateHashKept = time.Minute

// stateHashes returns the hashes of this node now.
func (a *App) stateHashes(ctx context.Context, now time.Time) map[string]string {
	if l := a.stateNow(ctx, now, true); l != nil {
		return l.hashes
	}
	return nil
}

// stateNow returns the look at this node's state. It is computed anew only
// when something changed that it is made of: the store of this node
// (stateGen, moved by the loop of the shared things on every commit to
// schild.db), the records the node holds (Node.StoreGen), or the time, when
// a block that was hashed ends. An idle node used to read and hash every
// entry every 5 s. With fresh false a look younger than stateLookEvery is
// good enough although something changed: a look is a pair of hashes and
// points of one moment, so an older one is still true, only less likely to
// meet a member's point.
func (a *App) stateNow(ctx context.Context, now time.Time, fresh bool) *stateLook {
	node := a.Cluster
	if node == nil {
		return nil
	}
	w := &a.stateWatch
	gen, recGen := a.stateGen.Load(), node.StoreGen()
	w.mu.Lock()
	if k := w.kept; k != nil && !now.Before(k.at) {
		same := w.keptGen == gen && w.keptRecGen == recGen && now.Before(w.keptUntil)
		if same || (!fresh && now.Sub(k.at) < stateLookEvery) {
			w.mu.Unlock()
			return k
		}
	}
	w.mu.Unlock()
	look, until := a.computeStateLook(ctx, now)
	w.computed.Add(1)
	w.mu.Lock()
	// Kept under the numbers read before the computing: a write in between
	// moves them, and the next call computes again.
	w.kept, w.keptGen, w.keptRecGen, w.keptUntil = look, gen, recGen, until
	// Remembered when it says something new.
	if n := len(w.past); n == 0 || !sameLook(w.past[n-1], look) {
		w.past = append(w.past, look)
		if len(w.past) > stateHistory {
			w.past = append(w.past[:0], w.past[len(w.past)-stateHistory:]...)
		}
	} else {
		w.past[n-1] = look
	}
	w.mu.Unlock()
	return look
}

func sameLook(a, b *stateLook) bool {
	if len(a.hashes) != len(b.hashes) || len(a.points) != len(b.points) {
		return false
	}
	for k, v := range a.hashes {
		if b.hashes[k] != v {
			return false
		}
	}
	for k, v := range a.points {
		if b.points[k] != v {
			return false
		}
	}
	return true
}

// statePoints reads the point of the vector and of every class.
func (a *App) statePoints(now time.Time) map[string]string {
	node := a.Cluster
	out := make(map[string]string, len(stateClasses)+1)
	if v, err := node.VectorPoint(); err == nil {
		out[statePointVector] = v
	}
	for _, class := range stateClasses {
		classes := []string{class}
		if class == stateBlocks {
			classes = append([]string{contract.ClassLifts}, blockClasses...)
		}
		if p, err := node.ClassPoint(now, classes...); err == nil {
			out[class] = p
		}
	}
	return out
}

// computeStateLook hashes the state now and names the points. until is
// when the look stops to hold although nothing was written: a hashed block
// ends, or stateHashKept passed.
//
// The points are read before and after the hashing and count only where
// both readings agree and the node took no record meanwhile; and a class
// of settings has a point only when it is settled (see the top of the
// file). So a look never pairs a hash with a point it was not computed at.
func (a *App) computeStateLook(ctx context.Context, now time.Time) (look *stateLook, until time.Time) {
	node := a.Cluster
	until = now.Add(stateHashKept)
	taking := node.Taking()
	before := a.statePoints(now)
	lines := map[string][]string{}
	// The blocks the node holds that are not lifted and not over, as
	// incident number: a lifted block has left the store. A block the node
	// wrote anew holds a record in both classes and counts once.
	hashed := map[string]bool{}
	for _, class := range blockClasses {
		recs, err := node.State(class)
		if err != nil {
			continue
		}
		for _, rec := range recs {
			b, ok := a.groupBlockOf(rec)
			if !ok || !b.info.Until.After(now) || hashed[b.info.Incident] {
				continue
			}
			if b.info.Until.Before(until) {
				until = b.info.Until
			}
			hashed[b.info.Incident] = true
			lines[stateBlocks] = append(lines[stateBlocks], b.info.Incident)
		}
	}
	unsettled := map[string]bool{}
	a.sharedMu.Lock()
	things := append(append([]sharedThing{}, a.shared...), a.genericThings(ctx, node.Synced())...)
	for _, t := range things {
		blob, err := t.read(ctx)
		if err != nil {
			unsettled[t.class] = true
			continue
		}
		entries, err := t.codec.split(blob)
		if err != nil {
			continue
		}
		marks := a.marksOf(t)
		if len(a.sharedPending[t.key()]) > 0 {
			unsettled[t.class] = true
		}
		for k, v := range entries {
			if len(k) > contract.MaxEntryKey || len(v) > contract.MaxData/4*3-2048 {
				continue // too large to share: it holds on this node only
			}
			if marks[k] != sum(v) {
				unsettled[t.class] = true // changed here, not handed over yet
			}
			lines[t.class] = append(lines[t.class], t.id+"\x00"+k+"\x00"+canonSum(v))
		}
		for k := range marks {
			if _, here := entries[k]; !here {
				unsettled[t.class] = true // removed here, not handed over yet
			}
		}
	}
	if a.sharedRepair != nil {
		for class := range a.sharedRepair {
			unsettled[class] = true
		}
	}
	a.sharedMu.Unlock()
	after := a.statePoints(now)
	taking = taking || node.Taking()
	look = &stateLook{at: now, hashes: make(map[string]string, len(stateClasses)), points: map[string]string{}}
	for _, class := range stateClasses {
		look.hashes[class] = a.stateMAC(class, lines[class])
		if p := before[class]; p != "" && p == after[class] && !taking && !unsettled[class] {
			look.points[class] = p
		}
	}
	if p := before[statePointVector]; p != "" && p == after[statePointVector] && !taking {
		look.points[statePointVector] = p
	}
	return look, until
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

// cleanStatePoints bounds the points another node told.
func cleanStatePoints(in map[string]string) map[string]string {
	if len(in) == 0 || len(in) > 8 {
		return nil
	}
	out := map[string]string{}
	for _, key := range append([]string{statePointVector}, stateClasses...) {
		if p, ok := in[key]; ok && hexText(p, 12) {
			out[key] = p
		}
	}
	return out
}

// compareState holds a member's word against this node's looks, class by
// class, and notes what follows. Called with the lock of the watch held.
//
//   - The member names the point of a class and this node was at that
//     point: the hashes say same or differs, exactly.
//   - This node was never at that point, but both saw the same records (the
//     same vector) and this node's class was settled: the two hold
//     different records of the class although nothing is on its way. That
//     is a difference too, a soft one: it has to be seen again with every
//     word, since a record that ends between two looks gives the same
//     picture for a moment.
//   - Anything else is a change on its way or a member that is behind:
//     nothing is concluded.
func (w *stateWatch) compareState(id string, hashes, points map[string]string, now time.Time) {
	if w.since == nil {
		w.since, w.soft, w.compared, w.repaired = map[string]time.Time{}, map[string]bool{}, map[string]time.Time{}, map[string]time.Time{}
	}
	for _, class := range stateClasses {
		key := id + "/" + class
		h, p := hashes[class], points[class]
		verdict := 0 // 0 nothing, 1 same, 2 differs, 3 differs (soft)
		if h != "" && p != "" {
			for i := len(w.past) - 1; i >= 0 && verdict == 0; i-- {
				if l := w.past[i]; l.points[class] == p {
					verdict = 2
					if l.hashes[class] == h {
						verdict = 1
					}
				}
			}
			if v := points[statePointVector]; verdict == 0 && v != "" {
				for i := len(w.past) - 1; i >= 0 && verdict == 0; i-- {
					if l := w.past[i]; l.points[statePointVector] == v && l.points[class] != "" {
						verdict = 3
					}
				}
			}
		}
		switch verdict {
		case 1:
			delete(w.since, key)
			delete(w.soft, key)
			w.compared[key] = now
		case 2:
			if _, was := w.since[key]; !was || w.soft[key] {
				if !was {
					w.since[key] = now
				}
				delete(w.soft, key)
			}
			w.compared[key] = now
		case 3:
			if _, was := w.since[key]; !was {
				w.since[key], w.soft[key] = now, true
			}
			w.compared[key] = now
		default:
			// Not seen again: a soft difference was a moment between two
			// looks. One of what is in force stays until it is refuted.
			if w.soft[key] {
				delete(w.since, key)
				delete(w.soft, key)
			}
		}
	}
}

// noteMemberState compares the word a member just sent, so a member is
// compared at the moment its word describes and not up to 5 s later.
func (a *App) noteMemberState(ctx context.Context, id string, hashes, points map[string]string) {
	node := a.Cluster
	if node == nil || len(hashes) == 0 || len(points) == 0 || node.Removed() || !node.Synced() {
		return
	}
	now := time.Now()
	a.stateNow(ctx, now, false)
	w := &a.stateWatch
	w.mu.Lock()
	w.compareState(id, hashes, points, now)
	w.mu.Unlock()
}

// watchState runs with the tell of the versions: it looks at this node's
// state, compares it with what the reachable members told, and repairs a
// difference that lasts.
func (a *App) watchState(ctx context.Context) {
	node := a.Cluster
	if node == nil || node.Removed() || !node.Synced() {
		return
	}
	now := time.Now()
	own := a.stateNow(ctx, now, true)
	reach := map[string]bool{}
	for _, id := range node.Reachable() {
		reach[id] = true
	}
	type word struct{ hashes, points map[string]string }
	a.groupVersions.mu.Lock()
	told := map[string]word{}
	for id, v := range a.groupVersions.told {
		if reach[id] && now.Sub(v.at) < vitalsFresh && len(v.State) > 0 {
			told[id] = word{v.State, v.StateAt}
		}
	}
	a.groupVersions.mu.Unlock()

	w := &a.stateWatch
	w.mu.Lock()
	w.own = own
	if w.since == nil {
		w.since, w.soft, w.compared, w.repaired = map[string]time.Time{}, map[string]bool{}, map[string]time.Time{}, map[string]time.Time{}
	}
	repair := map[string][]string{}
	for id, t := range told {
		w.compareState(id, t.hashes, t.points, now)
		for _, class := range stateClasses {
			since, was := w.since[id+"/"+class]
			if was && w.shown(id+"/"+class, now) && now.Sub(since) >= stateDiffRepair && now.Sub(w.repaired[id]) >= stateRepairEvery {
				repair[id] = append(repair[id], class)
			}
		}
	}
	// A member that is gone or not reached is not compared; what was noted
	// of it does not stay.
	for key := range w.since {
		if id, _, _ := strings.Cut(key, "/"); told[id].hashes == nil {
			delete(w.since, key)
			delete(w.soft, key)
		}
	}
	for key := range w.compared {
		if id, _, _ := strings.Cut(key, "/"); !node.IsMember(id) {
			delete(w.compared, key)
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

// shown reports whether a noted difference counts: one of what is in force
// at once, one of records at the same vector when it lasted stateDiffShown.
// Called with the lock held.
func (w *stateWatch) shown(key string, now time.Time) bool {
	since, was := w.since[key]
	return was && (!w.soft[key] || now.Sub(since) >= stateDiffShown)
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
		if class == stateBlocks {
			a.applyGroupBlocks()
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
// same, differs or unknown. A change on its way reads same for as long as
// the two could be compared within the last minute; a member that could not
// be compared for longer (changes without a pause, a member that is behind,
// a build that names no points) reads unknown.
func (a *App) memberState(id string, told map[string]string, fresh bool, now time.Time) map[string]string {
	w := &a.stateWatch
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.own == nil {
		return nil
	}
	out := make(map[string]string, len(stateClasses))
	for _, class := range stateClasses {
		key := id + "/" + class
		_, ok := told[class]
		at, was := w.compared[key]
		switch {
		case !fresh || !ok:
			out[class] = "unknown"
		case w.shown(key, now):
			out[class] = "differs"
		case was && now.Sub(at) < stateCompared:
			out[class] = "same"
		default:
			out[class] = "unknown"
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
	for key, since := range w.since {
		if w.shown(key, now) && now.Sub(since) >= stateDiffRepair {
			return true
		}
	}
	return false
}
