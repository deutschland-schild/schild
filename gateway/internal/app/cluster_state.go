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
	"github.com/deutschland-schild/schild/gateway/internal/behaviour"
	"github.com/deutschland-schild/schild/gateway/internal/crawlers"
	"github.com/deutschland-schild/schild/gateway/internal/dashboard"
	"github.com/deutschland-schild/schild/gateway/internal/humancheck"
	"github.com/deutschland-schild/schild/gateway/internal/ratelog"
	"github.com/deutschland-schild/schild/gateway/internal/store"
)

// The group of MVP-27 (D103): what the dashboard and the agent API set, who
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
	// write stores a value of another node and makes it effective.
	write func(ctx context.Context, v []byte) error
}

func (t sharedThing) key() string { return t.class + "/" + t.id }

func sum(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func (a *App) kvThing(id string, codec entryCodec, apply func(ctx context.Context, v []byte) error) sharedThing {
	return sharedThing{class: contract.ClassSettings, id: id, codec: codec,
		read: func(ctx context.Context) ([]byte, error) {
			v, err := a.Store.Get(ctx, id)
			if errors.Is(err, store.ErrNotFound) {
				return nil, nil
			}
			return v, err
		},
		write: func(ctx context.Context, v []byte) error {
			if apply != nil {
				return apply(ctx, v)
			}
			return a.putKV(ctx, id, v)
		}}
}

func (a *App) putKV(ctx context.Context, id string, v []byte) error {
	if len(v) == 0 {
		return a.Store.Delete(ctx, id)
	}
	return a.Store.Put(ctx, id, v)
}

func (a *App) tableThing(class, id string, pk int, after func(ctx context.Context)) sharedThing {
	return sharedThing{class: class, id: id, codec: tableCodec{pk: pk},
		read: func(ctx context.Context) ([]byte, error) { return a.Store.DumpShared(ctx, id) },
		write: func(ctx context.Context, v []byte) error {
			if err := a.Store.RestoreShared(ctx, id, v); err != nil {
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
		a.kvThing(humancheck.StoreKey, site, a.takeHumanCheck),
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
		a.tableThing(contract.ClassLogins, "users", 1, nil),
		a.tableThing(contract.ClassLogins, "sessions", 1, nil),
		a.tableThing(contract.ClassLogins, "agent_tokens", 1, nil),
	}
}

// takeStoredSettings stores the settings overlay or the dashboard's rate
// limits of another node and applies both, validated with this node's
// schild.yaml as at the start. A value that does not fit this node's file
// is not stored: the node keeps its settings and says so.
func (a *App) takeStoredSettings(id string) func(ctx context.Context, v []byte) error {
	return func(ctx context.Context, v []byte) error {
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
		if err := a.putKV(ctx, id, v); err != nil {
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

func (a *App) takeCrawlers(ctx context.Context, v []byte) error {
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
	if err := a.putKV(ctx, crawlers.StoreKey, v); err != nil {
		return err
	}
	a.Crawlers.Set(st)
	return nil
}

func (a *App) takeAccess(ctx context.Context, v []byte) error {
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
	if err := a.putKV(ctx, accesslock.StoreKey, v); err != nil {
		return err
	}
	a.Access.Store(st)
	a.writeAccessActive()
	return nil
}

// takeHumanCheck takes the browser check of the group: its policies and the
// keys behind the cookies, so a visitor who passed on one node passes on
// the next.
func (a *App) takeHumanCheck(ctx context.Context, v []byte) error {
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
	if err := a.Store.Put(ctx, humancheck.StoreKey, v); err != nil {
		return err
	}
	a.HumanCheck.Store(st)
	return nil
}

// takeRuleExceptions builds the rules with the exceptions of the group,
// then stores them. A build that fails leaves the running rules and the
// stored exceptions.
func (a *App) takeRuleExceptions(ctx context.Context, v []byte) error {
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
	if err := a.putKV(ctx, ruleExceptionsKey, v); err != nil {
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
	a.goLoop(ctx, "cluster-state", tick(250*time.Millisecond, func() { a.syncShared(ctx) }))
}

// pendingEntry is an entry another node changed, waiting to be put into
// its value: v nil means it is gone.
type pendingEntry struct {
	v    []byte
	node string
}

// entryTombstoneKeep is how long the record of a removed entry stays. A
// node away for longer has to enter the group anew.
const entryTombstoneKeep = 30 * 24 * time.Hour

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
	if node == nil || node.Removed() || node.Paused() {
		return
	}
	a.sharedMu.Lock()
	defer a.sharedMu.Unlock()
	synced := node.Synced()
	for _, t := range a.shared {
		a.syncThing(ctx, t, synced)
	}
}

// syncThing is syncShared for one thing. Called with sharedMu held.
func (a *App) syncThing(ctx context.Context, t sharedThing, synced bool) {
	node := a.Cluster
	blob, err := t.read(ctx)
	if err != nil {
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
				if cur, here := local[v.K]; here && sum(cur) != sum(val) {
					if err := node.Keep(t.key()+" "+v.K, cur); err == nil {
						a.log.Warn("cluster: this node takes the group's value of an entry both held; its own is kept in cluster.db (table replaced)", "thing", t.key(), "entry", v.K)
					}
				}
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
		next, err := t.codec.join(blob, set, del)
		if err == nil {
			err = t.write(ctx, next)
		}
		if err != nil {
			// The node keeps its own. It notes the entries as in step all
			// the same: its own value of them must not go to the group as
			// if it were a new change.
			ratelog.Error(a.log, "cluster: a change of another node was not applied, this node keeps its own", "thing", t.key(), "from", from, "err", err)
		} else {
			a.log.Info("cluster: took a change of another node", "thing", t.key(), "from", from, "entries", len(pending))
		}
		if blob, err = t.read(ctx); err != nil {
			return
		}
		if local, err = t.codec.split(blob); err != nil {
			return
		}
		for k := range pending {
			if cur, ok := local[k]; ok {
				marks[k] = sum(cur)
			} else {
				delete(marks, k)
			}
		}
		changed = true
	}

	// What changed on this node. Before its first sync a node publishes
	// nothing: it does not know yet what the group holds.
	if synced {
		name := node.Name()
		sent := 0
		for k, v := range local {
			h := sum(v)
			if marks[k] == h {
				continue
			}
			if sent >= maxEntryPublishes {
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
				break
			}
			// Gone on this node: a tombstone, so it is gone on every node.
			if _, err := node.Publish(t.class, contract.EntryID(t.id, k), &contract.Value{K: k, Node: name}, true, time.Now().Add(entryTombstoneKeep)); err != nil {
				ratelog.Warn(a.log, "cluster: removal not handed to the group (it holds on this node)", "thing", t.key(), "err", err)
				break
			}
			delete(marks, k)
			changed = true
			sent++
		}
	}
	if changed {
		a.saveMarks(t)
	}
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
	if _, err := a.Store.DeleteIP(ctx, e.IP, e.KeepIncidents, dashboard.TruncateBody); err != nil {
		a.log.Error("cluster: an address erased on another node was not erased here", "from", e.Node, "err", err)
		return
	}
	if xs, err := a.Store.ActiveExceptions(ctx, time.Now()); err == nil {
		a.Gate.Exceptions.Load(xs)
	}
	// Forget it in the group's list first: the block ends because of the
	// erasure, not because this node lifts it.
	if key, _ := behaviour.KeyOf(ip); key.IsValid() {
		a.groupBlocks.mu.Lock()
		delete(a.groupBlocks.known, key)
		a.groupBlocks.mu.Unlock()
	}
	a.Behaviour.Forget(ip)
	_ = a.ReloadAllow(ctx)
	if a.Requests != nil {
		if _, err := a.Requests.ForgetIP(ctx, ip); err != nil {
			a.log.Error("cluster: requests of an address erased on another node were not erased here", "from", e.Node, "err", err)
		}
	}
	a.log.Debug("cluster: erased an address that was erased on a node of the group", "from", e.Node)
}
