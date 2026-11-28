package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"time"

	contractapi "github.com/deutschland-schild/schild/contract/agentapi"
	contract "github.com/deutschland-schild/schild/contract/cluster"
	"github.com/deutschland-schild/schild/gateway/internal/accesslock"
	"github.com/deutschland-schild/schild/gateway/internal/cluster"
	"github.com/deutschland-schild/schild/gateway/internal/crawlers"
	"github.com/deutschland-schild/schild/gateway/internal/dashboard"
	"github.com/deutschland-schild/schild/gateway/internal/humancheck"
	"github.com/deutschland-schild/schild/gateway/internal/ratelog"
	"github.com/deutschland-schild/schild/gateway/internal/store"
)

// The group of MVP-27 (D105): what the dashboard and the agent API set, who
// passes and who may sign in hold on every node.
//
// Each of these things is a value in schild.db (a row of kv, or a small
// table) made of entries: the rows of a list, the single settings of the
// overlay, the policy of one website. Nothing that writes them knows the
// group. A loop cuts every value into its entries (cluster_entries.go),
// compares each with what this node last brought in step with the group,
// and publishes an entry that changed here as a record of its own; an entry
// of another node is put into the value and the value made effective the
// way the start loads it. So a change in the dashboard of one node holds on
// every node within about a second, and none of the many places that store
// a setting had to change.
//
// Two nodes that change different entries of one thing both keep their
// change, also when they could not reach each other meanwhile. Two changes
// of the very same entry settle by the later clock, on every node the same.

type sharedThing struct {
	class, id string
	// codec cuts the value into entries and puts entries back.
	codec entryCodec
	// read returns the value as schild.db holds it; empty: none.
	read func(ctx context.Context) ([]byte, error)
	// write stores a value put together from old (what read returned) and
	// the entries of other nodes, and makes it effective. It stores only
	// when the stored value still is old and returns store.ErrChanged
	// otherwise: a change made on this node between the read and the write
	// (the dashboard, a command on the host) is not written over.
	write func(ctx context.Context, old, v []byte) error
	// hold, when set, is asked before a node hands over a thing it never
	// brought in step with the group: true keeps its entries back for now
	// (holdFirstKeys).
	hold func() bool
	// first names the entries hold is about: those every node makes at its
	// first start.
	first func(entry string) bool
}

func (t sharedThing) key() string { return t.class + "/" + t.id }

func sum(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func (a *App) kvThing(id string, codec entryCodec, apply func(ctx context.Context, old, v []byte) error) sharedThing {
	return sharedThing{class: contract.ClassSettings, id: id, codec: codec,
		read: func(ctx context.Context) ([]byte, error) {
			v, err := a.Store.Get(ctx, id)
			if errors.Is(err, store.ErrNotFound) {
				return nil, nil
			}
			return v, err
		},
		write: func(ctx context.Context, old, v []byte) error {
			if apply != nil {
				return apply(ctx, old, v)
			}
			return a.Store.Swap(ctx, id, old, v)
		}}
}

func (a *App) tableThing(class, id string, pk int, after func(ctx context.Context)) sharedThing {
	return sharedThing{class: class, id: id, codec: tableCodec{pk: pk},
		read: func(ctx context.Context) ([]byte, error) { return a.Store.DumpShared(ctx, id) },
		write: func(ctx context.Context, old, v []byte) error {
			if err := a.Store.SwapShared(ctx, id, old, v); err != nil {
				return err
			}
			if after != nil {
				after(ctx)
			}
			return nil
		}}
}

// sharedThings lists what the group shares as whole values, in the order a
// node takes them at its first sync: settings before what rests on them.
func (a *App) sharedThings() []sharedThing {
	site := objectCodec{depth: 2} // one entry per website, one per other field
	return []sharedThing{
		a.kvThing(dashLimitsKey, listCodec{id: "id"}, a.takeStoredSettings(dashLimitsKey)),
		a.kvThing(overlayKey, objectCodec{depth: 8}, a.takeStoredSettings(overlayKey)),
		a.kvThing(ownersKey, objectCodec{depth: 1}, nil),
		a.kvThing(crawlers.StoreKey, site, a.takeCrawlers),
		a.kvThing(accesslock.StoreKey, site, a.takeAccess),
		a.firstOnce(a.kvThing(humancheck.StoreKey, site, a.takeHumanCheck)),
		a.kvThing(ruleExceptionsKey, listCodec{id: "id"}, a.takeRuleExceptions),
		// The agent API reads this key at its first call: a node that
		// served agents before it joined names clients its own way until
		// its next start.
		a.kvThing("agent_pseudonym_key_v1", wholeCodec{}, nil),
		a.tableThing(contract.ClassAccess, "allowlist", 1, func(ctx context.Context) {
			_ = a.ReloadAllow(ctx)
			a.dropAllowlistedBlocks()
		}),
		// An exception is the same on every node by all it says.
		a.tableThing(contract.ClassAccess, "ip_exceptions", 4, func(ctx context.Context) {
			if xs, err := a.Store.ActiveExceptions(ctx, time.Now()); err == nil {
				a.Gate.Exceptions.Load(xs)
			}
		}),
		a.tableThing(contract.ClassAccess, "rule_decisions", 3, func(ctx context.Context) {
			if err := a.Repos.Reload(ctx); err != nil {
				a.log.Error("cluster: rules not built again after a rule was disabled or enabled on another node; the running rules stay", "err", err)
			}
		}),
		a.tableThing(contract.ClassLogins, "users", 1, func(ctx context.Context) {
			if a.Dashboard != nil {
				if err := a.Dashboard.ClearSetup(ctx); err != nil {
					a.log.Warn("cluster: setup code not cleared after taking logins", "err", err)
				}
			}
		}),
		a.tableThing(contract.ClassLogins, "sessions", 1, nil),
		a.tableThing(contract.ClassLogins, "agent_tokens", 1, nil),
	}
}

// The first keys of the browser check are made by every node at its first
// start, and a group needs one set of them. Handed over by every node at
// once, as any other value is, two nodes that enter a new group in the same
// second each publish theirs (third lab measurement, S2). So a node that
// never brought them in step keeps them back: the node that keeps the
// group's tasks (the lowest id among the gateways that reach each other),
// once it has been that for firstKeysSettle, hands its own over, and the
// others take them. A node that waited firstKeysWait without seeing any
// hands its own over all the same: the keeper may be a node of an earlier
// build, or cut off. Until the group's keys are there a node runs with its
// own, so the browser check works on it from its first request; a website
// of a new group has no browser check switched on yet.
var (
	firstKeysSettle = 3 * time.Second
	firstKeysWait   = 10 * time.Second
)

// firstOnce marks a thing as made once for the group (see above).
func (a *App) firstOnce(t sharedThing) sharedThing {
	t.hold = a.holdFirstKeys
	t.first = func(entry string) bool {
		path, ok := pathOf(entry)
		return ok && path[0] != "entries" // the policies of the websites
	}
	return t
}

// holdFirstKeys reports whether this node keeps back a thing it never
// brought in step. Called with sharedMu held, from the loop of the shared
// things only.
func (a *App) holdFirstKeys() bool {
	node := a.Cluster
	now := time.Now()
	if a.firstKeysSince.IsZero() {
		a.firstKeysSince = now
	}
	_, lead := node.Jobs()
	if !lead.Leads() {
		a.firstKeysLead = time.Time{}
		return now.Sub(a.firstKeysSince) < firstKeysWait
	}
	if a.firstKeysLead.IsZero() {
		a.firstKeysLead = now
	}
	return now.Sub(a.firstKeysLead) < firstKeysSettle
}

// takeStoredSettings stores the settings overlay or the dashboard's rate
// limits of another node and applies both, validated with this node's
// schild.yaml as at the start. A value that does not fit this node's file
// is not stored: the node keeps its settings and says so.
func (a *App) takeStoredSettings(id string) func(ctx context.Context, old, v []byte) error {
	return func(ctx context.Context, old, v []byte) error {
		a.mu.Lock()
		ov, dash := a.overlay, a.dashLimits
		switch id {
		case overlayKey:
			ov = map[string]any{}
			if len(v) > 0 {
				if err := json.Unmarshal(v, &ov); err != nil {
					a.mu.Unlock()
					return err
				}
			}
		case dashLimitsKey:
			dash = nil
			if len(v) > 0 {
				if err := json.Unmarshal(v, &dash); err != nil {
					a.mu.Unlock()
					return err
				}
			}
		}
		next, err := a.mergedWith(ov, dash)
		if err != nil {
			a.mu.Unlock()
			return fmt.Errorf("settings of the group do not fit the schild.yaml of this node (config drift): %w", err)
		}
		if err := a.Store.Swap(ctx, id, old, v); err != nil {
			a.mu.Unlock()
			return err
		}
		prev := a.Config()
		a.overlay, a.dashLimits = ov, dash
		a.cfg.Store(next)
		a.applyRuntime(ctx, prev, next)
		a.mu.Unlock()
		// States and CRS settings of the rule repositories need the rules
		// built again; the registry takes its own lock, so after ours.
		if !reflect.DeepEqual(prev.Rules, next.Rules) {
			a.Metrics.BaselineProtection.Set(boolf(next.Rules.CRS.State != "off"))
			if err := a.Repos.Reload(ctx); err != nil {
				a.log.Error("cluster: rules not built again after a change on another node; the running rules stay", "err", err)
			}
		}
		return nil
	}
}

func (a *App) takeCrawlers(ctx context.Context, old, v []byte) error {
	st := crawlers.NewState()
	if len(v) > 0 {
		if err := json.Unmarshal(v, st); err != nil {
			return err
		}
	}
	if st.Entries == nil {
		st.Entries = map[string]*crawlers.Entry{}
	}
	a.crawlersMu.Lock()
	defer a.crawlersMu.Unlock()
	if err := a.Store.Swap(ctx, crawlers.StoreKey, old, v); err != nil {
		return err
	}
	a.Crawlers.Set(st)
	return nil
}

func (a *App) takeAccess(ctx context.Context, old, v []byte) error {
	st := accesslock.NewState()
	if len(v) > 0 {
		if err := json.Unmarshal(v, st); err != nil {
			return err
		}
	}
	if st.Entries == nil {
		st.Entries = map[string]*accesslock.Entry{}
	}
	a.accessMu.Lock()
	defer a.accessMu.Unlock()
	if err := a.Store.Swap(ctx, accesslock.StoreKey, old, v); err != nil {
		return err
	}
	a.Access.Store(st)
	a.writeAccessActive()
	return nil
}

// takeHumanCheck takes the browser check of the group: its policies and the
// keys behind the cookies, so a visitor who passed on one node passes on
// the next.
func (a *App) takeHumanCheck(ctx context.Context, old, v []byte) error {
	if len(v) == 0 {
		return nil // a node always has its own keys
	}
	st := humancheck.NewState(time.Now().UTC())
	if err := json.Unmarshal(v, st); err != nil {
		return err
	}
	if st.Entries == nil {
		st.Entries = map[string]*humancheck.Entry{}
	}
	if len(st.ChallengeKey) == 0 || len(st.ClearanceKey) == 0 {
		return errors.New("browser check of the group without keys")
	}
	a.humanCheckMu.Lock()
	defer a.humanCheckMu.Unlock()
	if err := a.Store.Swap(ctx, humancheck.StoreKey, old, v); err != nil {
		return err
	}
	a.HumanCheck.Store(st)
	return nil
}

// takeRuleExceptions builds the rules with the exceptions of the group,
// then stores them. A build that fails leaves the running rules and the
// stored exceptions.
func (a *App) takeRuleExceptions(ctx context.Context, old, v []byte) error {
	var next []contractapi.RuleException
	if len(v) > 0 {
		if err := json.Unmarshal(v, &next); err != nil {
			return err
		}
	}
	for i := range next {
		if next[i].SetBy == "" {
			next[i].SetBy = contractapi.SetByAgent
		}
	}
	text, err := renderRuleExceptions(next)
	if err != nil {
		return err
	}
	a.exceptionsMu.Lock()
	defer a.exceptionsMu.Unlock()
	if _, err := a.Composer.SetExceptions(text); err != nil {
		return fmt.Errorf("the rules did not build with the exceptions of the group: %w", err)
	}
	if err := a.Store.Swap(ctx, ruleExceptionsKey, old, v); err != nil {
		if old, rerr := renderRuleExceptions(a.exceptions); rerr == nil {
			_, _ = a.Composer.SetExceptions(old)
		}
		return err
	}
	a.exceptions = next
	return nil
}

// startSharedState wires the shared things and erasures into the node.
func (a *App) startSharedState(ctx context.Context) {
	a.shared = a.sharedThings()
	a.sharedPending = map[string]map[string]pendingEntry{}
	a.sharedMarks = map[string]map[string]string{}
	for _, class := range []string{contract.ClassSettings, contract.ClassAccess, contract.ClassLogins} {
		a.Cluster.On(class, a.noteShared)
	}
	a.Cluster.On(contract.ClassErasure, func(rec *contract.Record) { a.takeErasure(context.Background(), rec) })
	a.Dashboard.Erased = a.erasedInGroup
	a.storeWatch = a.Store.Watch()
	a.goLoop(ctx, "cluster-state", func(ctx context.Context) {
		defer a.storeWatch.Close()
		tick(sharedLookEvery, func() { a.syncShared(ctx) })(ctx)
	})
}

// The loop of the shared things looks four times a second and works only
// when there is something to do: the store of this node changed (a setting
// made here, or by a command on the host that writes into the same file), a
// record of another node arrived, a repair was asked for, the node came in
// step, or a round left work over. Otherwise it reads nothing; an idle node
// used to read every shared value four times a second. After sharedSafety
// it works once all the same, so a signal that was missed cannot stall it.
const sharedLookEvery = 250 * time.Millisecond

var sharedSafety = 15 * time.Second

// pendingEntry is an entry another node changed, waiting to be put into
// its value: v nil means it is gone.
type pendingEntry struct {
	v    []byte
	node string
}

// entryTombstoneKeep is how long the record of a removed entry stays. A
// node that was not in step for longer takes the group's state anew
// (cluster.Node.TakesGroupState, takeGroupThing).
const entryTombstoneKeep = cluster.EntryTombstoneKeep

// maxEntryPublishes bounds the entries of one thing a node hands over per
// round; the rest follows with the next.
const maxEntryPublishes = 500

// noteShared notes an entry another node published. It runs in the
// goroutine of the sync and only notes: the loop puts the entries of a
// thing into its value together, so ten changed rows are one write.
func (a *App) noteShared(rec *contract.Record) {
	v, err := contract.DecodeValue(rec)
	if err != nil {
		return
	}
	thing, ok := contract.ThingOf(rec.Class, rec.ID)
	if !ok {
		return
	}
	p := pendingEntry{node: v.Node}
	if !rec.Deleted {
		val, _ := v.Bytes()
		if val == nil {
			val = []byte{}
		}
		p.v = val
	}
	a.sharedMu.Lock()
	if a.sharedPending[rec.Class+"/"+thing] == nil {
		a.sharedPending[rec.Class+"/"+thing] = map[string]pendingEntry{}
	}
	a.sharedPending[rec.Class+"/"+thing][v.K] = p
	a.sharedMu.Unlock()
}

// marks returns what this node last brought in step with the group of a
// thing: entry key -> hash of its value. Called with sharedMu held.
func (a *App) marksOf(t sharedThing) map[string]string {
	if m, ok := a.sharedMarks[t.key()]; ok {
		return m
	}
	m := map[string]string{}
	if raw := a.Cluster.Mark("entries:" + t.key()); raw != "" {
		_ = json.Unmarshal([]byte(raw), &m)
	}
	a.sharedMarks[t.key()] = m
	return m
}

func (a *App) saveMarks(t sharedThing) {
	raw, err := json.Marshal(a.sharedMarks[t.key()])
	if err == nil {
		err = a.Cluster.SetMark("entries:"+t.key(), string(raw))
	}
	if err != nil {
		a.log.Warn("cluster: marks not written", "thing", t.key(), "err", err)
	}
}

// syncShared brings every shared thing in step with the group: it puts the
// entries other nodes changed into the value, and publishes the entries
// that changed on this node.
func (a *App) syncShared(ctx context.Context) {
	node := a.Cluster
	if node == nil || node.Removed() {
		return
	}
	// The look comes before the reading: what is written while this round
	// reads is seen by the next look.
	if a.storeWatch == nil || a.storeWatch.Changed(ctx) {
		a.stateGen.Add(1)
		a.sharedDue.Store(true)
	}
	a.sharedMu.Lock()
	defer a.sharedMu.Unlock()
	synced := node.Synced()
	now := time.Now()
	if !a.sharedDue.Swap(false) && len(a.sharedPending) == 0 && a.sharedRepair == nil && synced == a.sharedWasSynced && now.Sub(a.sharedRan) < sharedSafety {
		return
	}
	a.sharedRan, a.sharedWasSynced = now, synced
	a.sharedRounds.Add(1)
	repair := a.sharedRepair
	a.sharedRepair = nil
	for _, t := range a.shared {
		if repair[t.class] {
			a.repairThing(ctx, t)
		}
		a.syncThing(ctx, t, synced)
	}
	// Every other key of the store, shared without registration.
	for _, t := range a.genericThings(ctx, synced) {
		if repair[t.class] {
			a.repairThing(ctx, t)
		}
		a.syncThing(ctx, t, synced)
	}
	if synced {
		// Noted in the node's store, not only in memory: after a restart
		// that finds no member it decides whether the node may serve alone.
		if !a.inStepNoted.Swap(true) && node.Mark(markInStep) == "" {
			_ = node.SetMark(markInStep, "1")
		}
		a.sharedApplied.Store(true)
	}
}

// syncThing is syncShared for one thing. Called with sharedMu held.
func (a *App) syncThing(ctx context.Context, t sharedThing, synced bool) {
	node := a.Cluster
	blob, err := t.read(ctx)
	if err != nil {
		a.sharedDue.Store(true) // read again with the next look
		return
	}
	local, err := t.codec.split(blob)
	if err != nil {
		ratelog.Warn(a.log, "cluster: a value of this node is not read as entries, it is not shared", "thing", t.key(), "err", err)
		return
	}
	marks := a.marksOf(t)
	changed := false

	// What other nodes changed since the last round.
	pending := a.sharedPending[t.key()]
	delete(a.sharedPending, t.key())
	// The first time this node is in step with the group: take the entries
	// the group holds and this node never saw. An entry both hold is the
	// group's; what this node held of it is kept.
	if synced && !a.sharedCaught[t.key()] {
		if a.sharedCaught == nil {
			a.sharedCaught = map[string]bool{}
		}
		a.sharedCaught[t.key()] = true
		if node.TakesGroupState() {
			a.takeGroupThing(ctx, t, blob, local)
			return
		}
		if recs, err := node.State(t.class); err == nil {
			for _, rec := range recs {
				if thing, ok := contract.ThingOf(rec.Class, rec.ID); !ok || thing != t.id || rec.Deleted {
					continue
				}
				v, err := contract.DecodeValue(rec)
				if err != nil {
					continue
				}
				if _, seen := marks[v.K]; seen {
					continue
				}
				if _, queued := pending[v.K]; queued {
					continue
				}
				val, _ := v.Bytes()
				if pending == nil {
					pending = map[string]pendingEntry{}
				}
				pending[v.K] = pendingEntry{v: val, node: v.Node}
			}
		}
	}
	// A record that says what this node already brought in step is no news:
	// the same entry carried into a new group by two nodes, or a value set
	// back to what it was. It must not take back a change made on this node
	// that has not left yet (a node publishes only once it is in step).
	//
	// And what was noted is not taken on trust: between the note and this
	// round the record of the entry may have lost. The handler notes a
	// record when it arrives; a record this node publishes a moment later,
	// or one of a third node, may beat it, and then the note names a value
	// that is not the group's any more. Applied all the same, it left this
	// node with a value no record holds while its marks said "in step"
	// (third lab measurement, S2: two nodes wrote the first keys of the
	// browser check in the same second, and one ran with the loser for half
	// a minute, until the repair). So every noted entry is looked up: the
	// record that is the state of the entry now decides, by the clocks, not
	// by which note came first.
	self := node.ID()
	for k, p := range pending {
		rec, err := node.Get(t.class, contract.EntryID(t.id, k))
		if err != nil {
			continue // not read: the note stands as it was
		}
		if rec == nil {
			delete(pending, k) // no record holds the entry any more
			continue
		}
		cur, here := local[k]
		mark, marked := marks[k]
		if rec.Origin == self && ((here && (!marked || mark != sum(cur))) || (!here && marked)) {
			// This node's own record is the state, and the entry changed
			// here since: that change leaves with this round.
			delete(pending, k)
			continue
		}
		v, err := contract.DecodeValue(rec)
		if err != nil {
			continue
		}
		p = pendingEntry{node: v.Node}
		if !rec.Deleted {
			val, _ := v.Bytes()
			if val == nil {
				val = []byte{}
			}
			p.v = val
		}
		if (p.v == nil && !here && !marked) || (p.v != nil && here && sum(cur) == sum(p.v) && marked && mark == sum(cur)) {
			delete(pending, k) // this node holds the state of the entry already
			continue
		}
		pending[k] = p
	}
	for k, p := range pending {
		// A removal is always taken: an entry the group removed never
		// comes back through a node that still holds it.
		if m, seen := marks[k]; p.v != nil && seen && m == sum(p.v) {
			delete(pending, k)
		}
	}
	if len(pending) > 0 {
		set, del := map[string][]byte{}, []string{}
		from := ""
		for k, p := range pending {
			from = p.node
			if p.v == nil {
				del = append(del, k)
			} else {
				set[k] = p.v
			}
		}
		// What the marks say is what this round stored, not what it reads
		// back: a change made on this node between the two is a change of
		// its own and leaves with this round. Marked as in step, it stayed
		// on this node, a value no record holds, until the repair put the
		// value of the group back over it.
		var stored map[string][]byte
		next, err := t.codec.join(blob, set, del)
		if err == nil {
			stored, err = t.codec.split(next)
		}
		if err == nil {
			if a.sharedBeforeWrite != nil {
				a.sharedBeforeWrite(t.key())
			}
			err = t.write(ctx, blob, next)
		}
		if errors.Is(err, store.ErrChanged) {
			// The value changed on this node while this round put it
			// together. Nothing is written and nothing is noted: the entries
			// wait, and the next round reads the value anew.
			if a.sharedPending[t.key()] == nil {
				a.sharedPending[t.key()] = map[string]pendingEntry{}
			}
			for k, p := range pending {
				if _, newer := a.sharedPending[t.key()][k]; !newer {
					a.sharedPending[t.key()][k] = p
				}
			}
			a.sharedDue.Store(true)
			return
		}
		if err != nil {
			// The node keeps its own. It notes the entries as in step all
			// the same: its own value of them must not go to the group as
			// if it were a new change.
			stored = local
			ratelog.Error(a.log, "cluster: a change of another node was not applied, this node keeps its own", "thing", t.key(), "from", from, "err", err)
		} else {
			// Any local entry never brought in step yet that is replaced by
			// the group's value is kept in cluster.db (table replaced).
			for k, p := range pending {
				if _, seen := marks[k]; seen {
					continue
				}
				if cur, here := local[k]; here && (p.v == nil || sum(cur) != sum(p.v)) {
					if kerr := node.Keep(t.key()+" "+k, cur); kerr == nil {
						a.log.Warn("cluster: this node takes the group's value of an entry both held; its own is kept in cluster.db (table replaced)", "thing", t.key(), "entry", k)
					} else {
						a.log.Error("cluster: this node took the group's value of an entry both held, and its own could not be kept in cluster.db (table replaced)", "thing", t.key(), "entry", k, "err", kerr)
					}
				}
			}
			a.log.Info("cluster: took a change of another node", "thing", t.key(), "from", from, "entries", len(pending))
		}
		if blob, err = t.read(ctx); err != nil {
			a.sharedDue.Store(true)
			return
		}
		if local, err = t.codec.split(blob); err != nil {
			a.sharedDue.Store(true)
			return
		}
		for k := range pending {
			if v, ok := stored[k]; ok {
				marks[k] = sum(v)
			} else {
				delete(marks, k)
			}
		}
		changed = true
	}

	// What changed on this node. Before its first sync a node publishes
	// nothing: it does not know yet what the group holds.
	if synced && t.hold != nil && !a.firstKeysDone && len(local) > 0 {
		// Made on every node at its first start and meant to be one for
		// the group: the node that keeps the group's tasks hands its own
		// over, the others wait for it. Once each of these entries was in
		// step, or the wait is over, the thing is handed over like any
		// other: what changes later (the rotation of the keys, run once for
		// the group) leaves at once. Each of them, not one: they arrive one
		// by one, and a node that took the first and then handed over the
		// rest of its own mixed two sets of keys.
		own := false
		for k := range local {
			if _, seen := marks[k]; !seen && t.first(k) {
				own = true
				break
			}
		}
		if own && t.hold() {
			a.sharedDue.Store(true)
			synced = false
		} else {
			a.firstKeysDone = true
		}
	}
	if synced {
		name := node.Name()
		sent := 0
		for k, v := range local {
			h := sum(v)
			if marks[k] == h {
				continue
			}
			if sent >= maxEntryPublishes {
				a.sharedDue.Store(true) // the rest with the next look
				break
			}
			if len(k) > contract.MaxEntryKey || len(v) > contract.MaxData/4*3-2048 {
				ratelog.Warn(a.log, "cluster: an entry is too large to share, it holds on this node only", "thing", t.key(), "bytes", len(v))
				marks[k] = h
				changed = true
				continue
			}
			if _, err := node.Publish(t.class, contract.EntryID(t.id, k), contract.NewValue(k, v, name), false, time.Time{}); err != nil {
				ratelog.Warn(a.log, "cluster: change not handed to the group (it holds on this node)", "thing", t.key(), "err", err)
				a.sharedDue.Store(true)
				break
			}
			marks[k] = h
			changed = true
			sent++
		}
		for k := range marks {
			if _, ok := local[k]; ok {
				continue
			}
			if sent >= maxEntryPublishes {
				a.sharedDue.Store(true)
				break
			}
			// Gone on this node: a tombstone, so it is gone on every node.
			if _, err := node.Publish(t.class, contract.EntryID(t.id, k), &contract.Value{K: k, Node: name}, true, time.Now().Add(entryTombstoneKeep)); err != nil {
				ratelog.Warn(a.log, "cluster: removal not handed to the group (it holds on this node)", "thing", t.key(), "err", err)
				a.sharedDue.Store(true)
				break
			}
			delete(marks, k)
			changed = true
			sent++
		}
	}
	if changed {
		a.saveMarks(t)
		// What this round wrote is looked at once more: the value it stored
		// may differ from what it was handed (a node validates and may keep
		// its own), and the state of the node changed for the fingerprint.
		a.sharedDue.Store(true)
		a.stateGen.Add(1)
	}
}

// takeGroupThing makes a thing the group's state on a node that was not in
// step with its group for longer than a removed entry is remembered
// (entryTombstoneKeep): the entries the group holds are taken, the entries
// it does not hold are removed here, and nothing this node held goes to the
// group. Its own record of an entry the group removed may have outlived the
// removal's tombstone, and handed over again it would bring the entry back
// on every node. What it gives up is kept in cluster.db (table replaced).
// Called with sharedMu held, once per thing, at the first round in step.
func (a *App) takeGroupThing(ctx context.Context, t sharedThing, blob []byte, local map[string][]byte) {
	node := a.Cluster
	recs, err := node.State(t.class)
	if err != nil {
		a.sharedCaught[t.key()] = false
		a.sharedDue.Store(true)
		return
	}
	group := map[string][]byte{}
	for _, rec := range recs {
		if thing, ok := contract.ThingOf(rec.Class, rec.ID); !ok || thing != t.id || rec.Deleted {
			continue
		}
		v, err := contract.DecodeValue(rec)
		if err != nil {
			continue
		}
		val, _ := v.Bytes()
		if val == nil {
			val = []byte{}
		}
		group[v.K] = val
	}
	set, del := map[string][]byte{}, []string{}
	gone := map[string][]byte{} // what this node gives up
	for k, v := range group {
		if cur, here := local[k]; !here || sum(cur) != sum(v) {
			set[k] = v
			if here {
				gone[k] = cur
			}
		}
	}
	for k, cur := range local {
		if _, ok := group[k]; !ok {
			del = append(del, k)
			gone[k] = cur
		}
	}
	if len(set)+len(del) > 0 {
		next, err := t.codec.join(blob, set, del)
		if err == nil {
			if a.sharedBeforeWrite != nil {
				a.sharedBeforeWrite(t.key())
			}
			err = t.write(ctx, blob, next)
		}
		if errors.Is(err, store.ErrChanged) {
			// The value changed on this node meanwhile: once more with the
			// next round, from what it holds then.
			a.sharedCaught[t.key()] = false
			a.sharedDue.Store(true)
			return
		}
		if err != nil {
			ratelog.Error(a.log, "cluster: this node was away too long and the group's value was not applied; it keeps its own and hands none of it over", "thing", t.key(), "err", err)
		} else {
			// Kept after the write, as syncThing does: only what was given up.
			for k, cur := range gone {
				_ = node.Keep(t.key()+" "+k, cur)
			}
			a.log.Warn("cluster: this node was away too long and took the group's value; what it held is kept in cluster.db (table replaced)", "thing", t.key(), "taken", len(set), "dropped", len(del))
		}
		if blob, err = t.read(ctx); err == nil {
			if l, err := t.codec.split(blob); err == nil {
				local = l
			}
		}
	}
	marks := make(map[string]string, len(local))
	for k, v := range local {
		marks[k] = sum(v)
	}
	a.sharedMarks[t.key()] = marks
	a.saveMarks(t)
	a.sharedDue.Store(true)
	a.stateGen.Add(1)
}

// publishErasure tells the group that an address was erased here (Art. 17
// GDPR), after this node erased it. The record stays 31 days, so a node
// that was away erases too, and is gone with the address after that.
// It returns the sequence number of the record; 0: not handed over.
func (a *App) publishErasure(ip netip.Addr, keepIncidents bool) uint64 {
	node := a.Cluster
	if node == nil {
		return 0
	}
	e := contract.Erasure{IP: ip.String(), KeepIncidents: keepIncidents, Node: node.Name()}
	a.erased.note(ip, time.Now())
	rec, err := node.Publish(contract.ClassErasure, e.IP, &e, false, time.Now().Add(contract.ErasureKeepS*time.Second))
	if err != nil {
		a.log.Error("cluster: erasure not handed to the group: erase the address on every other node by hand", "err", err)
		return 0
	}
	// The block records of the client leave the store of this node. The
	// dashboard noted their lifts and forgot the client in the engine.
	a.eraseGroupBlocks(ip, rec)
	return rec.Seq
}

// takeErasure erases an address another node erased: events, incidents,
// sessions, allowlist entries, exceptions, the running block and the
// requests of the address, as the dashboard does on its own node.
func (a *App) takeErasure(ctx context.Context, rec *contract.Record) {
	e, err := contract.DecodeErasure(rec)
	if err != nil {
		return
	}
	ip, err := netip.ParseAddr(e.IP)
	if err != nil {
		return
	}
	// Noted first: a request of the address that a member hands over from
	// now on is not stored (cluster_data.go).
	a.erased.note(ip, contract.HLCTime(rec.HLC))
	// The blocks from before the erasure end with it, on this node and in
	// its records; no lift is written for that, the node that erased wrote
	// them. Before the store is touched: they end also when that fails.
	a.eraseGroupBlocks(ip, rec)
	if _, err := a.Store.DeleteIP(ctx, e.IP, e.KeepIncidents, dashboard.TruncateBody); err != nil {
		a.log.Error("cluster: an address erased on another node was not erased here", "from", e.Node, "err", err)
		return
	}
	if xs, err := a.Store.ActiveExceptions(ctx, time.Now()); err == nil {
		a.Gate.Exceptions.Load(xs)
	}
	_ = a.ReloadAllow(ctx)
	if a.Requests != nil {
		if _, err := a.Requests.ForgetIP(ctx, ip); err != nil {
			a.log.Error("cluster: requests of an address erased on another node were not erased here", "from", e.Node, "err", err)
		}
	}
	a.log.Debug("cluster: erased an address that was erased on a node of the group", "from", e.Node)
}
