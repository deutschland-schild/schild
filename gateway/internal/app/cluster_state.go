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
	"strings"
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
// Each of these things is one value in schild.db that is replaced as a
// whole (a row of kv, or a small table). Nothing that writes them knows the
// group: a loop compares every value with what this node last brought in
// step with the group and publishes a value that changed here; a value of
// another node is written to schild.db and swapped into memory the way the
// start loads it. So a change in the dashboard of one node holds on every
// node within about a second, and none of the many places that store a
// setting had to change.
//
// Two changes of the same thing on two nodes within that second: the later
// one stands, on every node.

type sharedThing struct {
	class, id string
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

func (a *App) kvThing(id string, apply func(ctx context.Context, v []byte) error) sharedThing {
	return sharedThing{class: contract.ClassSettings, id: id,
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

func (a *App) tableThing(class, id string, after func(ctx context.Context)) sharedThing {
	return sharedThing{class: class, id: id,
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
	return []sharedThing{
		a.kvThing(dashLimitsKey, a.takeStoredSettings(dashLimitsKey)),
		a.kvThing(overlayKey, a.takeStoredSettings(overlayKey)),
		a.kvThing(ownersKey, nil),
		a.kvThing(crawlers.StoreKey, a.takeCrawlers),
		a.kvThing(accesslock.StoreKey, a.takeAccess),
		a.kvThing(humancheck.StoreKey, a.takeHumanCheck),
		a.kvThing(ruleExceptionsKey, a.takeRuleExceptions),
		// The agent API reads this key at its first call: a node that
		// served agents before it joined names clients its own way until
		// its next start.
		a.kvThing("agent_pseudonym_key_v1", nil),
		a.tableThing(contract.ClassAccess, "allowlist", func(ctx context.Context) {
			_ = a.ReloadAllow(ctx)
			a.dropAllowlistedBlocks()
		}),
		a.tableThing(contract.ClassAccess, "ip_exceptions", func(ctx context.Context) {
			if xs, err := a.Store.ActiveExceptions(ctx, time.Now()); err == nil {
				a.Gate.Exceptions.Load(xs)
			}
		}),
		a.tableThing(contract.ClassAccess, "rule_decisions", func(ctx context.Context) {
			if err := a.Repos.Reload(ctx); err != nil {
				a.log.Error("cluster: rules not built again after a rule was disabled or enabled on another node; the running rules stay", "err", err)
			}
		}),
		a.tableThing(contract.ClassLogins, "users", nil),
		a.tableThing(contract.ClassLogins, "sessions", nil),
		a.tableThing(contract.ClassLogins, "agent_tokens", nil),
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

// startSharedState wires the whole values and erasures into the node.
func (a *App) startSharedState(ctx context.Context) {
	a.shared = a.sharedThings()
	for _, class := range []string{contract.ClassSettings, contract.ClassAccess, contract.ClassLogins} {
		a.Cluster.On(class, func(rec *contract.Record) { a.takeShared(context.Background(), rec) })
	}
	a.Cluster.On(contract.ClassErasure, func(rec *contract.Record) { a.takeErasure(context.Background(), rec) })
	a.Dashboard.Erased = a.publishErasure
	a.goLoop(ctx, "cluster-state", tick(time.Second, func() { a.syncShared(ctx) }))
}

// takeShared applies a value another node published.
func (a *App) takeShared(ctx context.Context, rec *contract.Record) {
	v, err := contract.DecodeValue(rec)
	if err != nil {
		return
	}
	val, _ := v.Bytes()
	a.sharedMu.Lock()
	defer a.sharedMu.Unlock()
	for _, t := range a.shared {
		if t.class == rec.Class && t.id == rec.ID {
			if m := a.Cluster.Mark(t.key()); m == "" || strings.HasPrefix(m, ownOnly) {
				if local, err := t.read(ctx); err == nil {
					a.keepReplaced(t, local, val)
				}
			}
			a.writeShared(ctx, t, val, v.Node)
			return
		}
	}
}

// keepReplaced keeps what this node held of a thing before it takes the
// group's value for the first time. Called with sharedMu held.
func (a *App) keepReplaced(t sharedThing, local, group []byte) {
	if len(local) == 0 || emptyDump(local) || sum(local) == sum(group) {
		return
	}
	if err := a.Cluster.Keep(t.key(), local); err != nil {
		a.log.Error("cluster: what this node held before was not kept", "thing", t.key(), "err", err)
		return
	}
	a.log.Warn("cluster: this node takes the group's value at its first sync; what it held before is kept in cluster.db (table replaced)", "thing", t.key())
}

// writeShared stores a value of the group and notes that this node is in
// step with it. Called with sharedMu held.
func (a *App) writeShared(ctx context.Context, t sharedThing, val []byte, from string) bool {
	if err := t.write(ctx, val); err != nil {
		ratelog.Error(a.log, "cluster: a value of the group was not applied, this node keeps its own", "thing", t.key(), "from", from, "err", err)
		return false
	}
	cur, err := t.read(ctx)
	if err != nil {
		return false
	}
	if err := a.Cluster.SetMark(t.key(), sum(cur)); err != nil {
		a.log.Warn("cluster: mark not written", "thing", t.key(), "err", err)
	}
	a.log.Info("cluster: took a change of another node", "thing", t.key(), "from", from)
	return true
}

// syncShared publishes every value that changed on this node since it was
// last in step with the group. A node that was never in step (it just
// joined) takes the group's value first, and keeps a copy of what it
// replaces; only a thing the group does not hold yet is published from it.
func (a *App) syncShared(ctx context.Context) {
	node := a.Cluster
	if node == nil || node.Removed() {
		return
	}
	a.sharedMu.Lock()
	defer a.sharedMu.Unlock()
	name := node.Name()
	for _, t := range a.shared {
		local, err := t.read(ctx)
		if err != nil {
			continue
		}
		h, seen := sum(local), node.Mark(t.key())
		// Until this node took a value of the group for a thing once, its
		// mark says so: what it then gives up is kept (keepReplaced).
		own := seen == "" || strings.HasPrefix(seen, ownOnly)
		if h == strings.TrimPrefix(seen, ownOnly) {
			continue
		}
		if seen == "" {
			if !node.Synced() {
				continue
			}
			rec, err := node.Get(t.class, t.id)
			if err != nil {
				continue
			}
			if rec != nil {
				v, err := contract.DecodeValue(rec)
				if err != nil {
					continue
				}
				val, _ := v.Bytes()
				a.keepReplaced(t, local, val)
				a.writeShared(ctx, t, val, v.Node)
				continue
			}
			if len(local) == 0 || emptyDump(local) {
				// Nothing here, nothing in the group. An empty table is
				// nothing too: a node that just joined must not hand its
				// empty list of users to a group whose first node has not
				// told its own yet.
				continue
			}
		}
		if len(local) > contract.MaxData/4*3-256 {
			ratelog.Warn(a.log, "cluster: a value is too large to share, it holds on this node only", "thing", t.key(), "bytes", len(local))
			continue
		}
		if _, err := node.Publish(t.class, t.id, contract.NewValue(local, name), false, time.Time{}); err != nil {
			ratelog.Warn(a.log, "cluster: change not handed to the group (it holds on this node)", "thing", t.key(), "err", err)
			continue
		}
		if own {
			h = ownOnly + h
		}
		_ = node.SetMark(t.key(), h)
	}
}

// ownOnly starts the mark of a thing this node published and never took
// from the group.
const ownOnly = "own:"

// emptyDump reports whether a table dump holds no rows.
func emptyDump(b []byte) bool {
	var d struct {
		Rows []json.RawMessage `json:"rows"`
	}
	return json.Unmarshal(b, &d) == nil && d.Rows != nil && len(d.Rows) == 0
}

// publishErasure tells the group that an address was erased here (Art. 17
// GDPR), after this node erased it. The record stays 31 days, so a node
// that was away erases too, and is gone with the address after that.
func (a *App) publishErasure(ip netip.Addr, keepIncidents bool) {
	node := a.Cluster
	if node == nil {
		return
	}
	e := contract.Erasure{IP: ip.String(), KeepIncidents: keepIncidents, Node: node.Name()}
	if _, err := node.Publish(contract.ClassErasure, e.IP, &e, false, time.Now().Add(contract.ErasureKeepS*time.Second)); err != nil {
		a.log.Error("cluster: erasure not handed to the group: erase the address on every other node by hand", "err", err)
	}
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
