package auditlog

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/deutschland-schild/schild/contract/audit"
	"github.com/deutschland-schild/schild/contract/jsonx"
	"github.com/deutschland-schild/schild/gateway/internal/store"
)

// Schema of an entry.
const Schema = "schild.audit/0.1"

const timeFormat = "2006-01-02T15:04:05Z"

// Ways an entry is made through.
const (
	WayDashboard   = "dashboard"
	WayAgent       = "agent"
	WayIntegration = "integration"
	WayCLI         = "cli"
	WayConfig      = "config"
	WaySystem      = "system"
)

// Actor of an entry: who made the change.
type Actor struct {
	Kind string
	// User and Session of the dashboard; Session is the short id, never
	// the token.
	User, Session string
	// ID and Label of an agent token.
	ID, Label string
	// Account of the host, as a command saw it.
	Account string
}

// Dashboard is the actor of a dashboard session.
func Dashboard(user, session string) Actor {
	return Actor{Kind: WayDashboard, User: user, Session: session}
}

// Agent is the actor of an agent token.
func Agent(id, label string) Actor { return Actor{Kind: WayAgent, ID: id, Label: label} }

// CLI is the actor of a command on the host.
func CLI(account string) Actor { return Actor{Kind: WayCLI, Account: account} }

// Config is the actor of an applied configuration.
func Config() Actor { return Actor{Kind: WayConfig} }

// System is the actor of what schild does itself.
func System() Actor { return Actor{Kind: WaySystem} }

func (a Actor) object() map[string]any {
	m := map[string]any{"kind": a.Kind}
	put := func(k, v string, n int) {
		if v = audit.Text(v, n); v != "" {
			m[k] = v
		}
	}
	switch a.Kind {
	case WayDashboard:
		put("user", a.User, 128)
		put("session", a.Session, 8)
	case WayAgent:
		put("id", a.ID, 64)
		put("label", a.Label, 64)
	case WayCLI:
		put("account", a.Account, 128)
	}
	return m
}

// Entry is one entry to write. The class, the kind of the subject and the
// fields whose values are recorded come from the action
// (contracts/audit-actions.json).
type Entry struct {
	Action    string
	Operation string // <way>:<operation id, command or source>
	Actor     Actor
	// Address the call came from; "" on the host.
	Address string
	// Subject is the id of what changed, never an address; "" when the
	// kind alone names it.
	Subject string
	// Website the change belongs to; "" for what is global.
	Website string
	// Event or Incident the call named as its cause; at most one.
	Event, Incident string
	// Before and After are the state of what changed as JSON objects (a
	// struct, a map), nil for not there. Only their difference is stored.
	Before, After any
	// IfChanged: the entry is of a setting, and a call that leaves the
	// state as it was writes none.
	IfChanged bool
	// Reason is text the caller gave, untrusted.
	Reason string
	// Time of the change; zero is now.
	Time time.Time
}

// SessionID is the short id of a session for an entry: eight hex characters
// of the hash of its token, never the token.
func SessionID(tokenHash string) string {
	if len(tokenHash) < 8 {
		return ""
	}
	return strings.ToLower(tokenHash[:8])
}

// object turns a state into a JSON object as the contract compares it.
func object(v any) (map[string]any, error) {
	if v == nil {
		return nil, nil
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	if string(raw) == "null" {
		return nil, nil
	}
	return jsonx.ParseObject(raw)
}

// build makes the entry with its id and checks it as the contract does.
func (l *Log) build(e Entry, id string, now time.Time) (map[string]any, []byte, error) {
	a := audit.Lookup(e.Action)
	if a == nil {
		return nil, nil, fmt.Errorf("audit: unknown action %q", e.Action)
	}
	t := e.Time
	if t.IsZero() {
		t = now
	}
	m := map[string]any{
		"schema": Schema, "id": id, "time": t.UTC().Format(timeFormat), "node": audit.Text(l.Node(), 128),
		"class": a.Class, "action": a.Action, "operation": e.Operation, "result": audit.ResultDone, "actor": e.Actor.object(),
	}
	subject := map[string]any{"kind": a.Subject}
	if e.Subject != "" {
		subject["id"] = e.Subject
	}
	m["subject"] = subject
	if e.Address != "" {
		m["address"] = e.Address
	}
	if e.Website != "" {
		m["website"] = e.Website
	}
	switch {
	case e.Event != "":
		m["cause"] = map[string]any{"event": e.Event}
	case e.Incident != "":
		m["cause"] = map[string]any{"incident": e.Incident}
	}
	before, err := object(e.Before)
	if err != nil {
		return nil, nil, fmt.Errorf("audit: %s: before: %w", e.Action, err)
	}
	after, err := object(e.After)
	if err != nil {
		return nil, nil, fmt.Errorf("audit: %s: after: %w", e.Action, err)
	}
	if before != nil || after != nil {
		c := audit.Diff(a, before, after)
		switch {
		case len(c.Fields) > 0 || c.MoreFields > 0:
			m["change"] = c
		case e.IfChanged:
			// The state is the same before and after: the call changed
			// nothing, and there is no entry.
			return nil, nil, errNoChange
		}
	}
	if r := audit.Text(strings.TrimSpace(e.Reason), 500); r != "" {
		m["reason"] = r
	}
	raw, err := json.Marshal(m)
	if err != nil {
		return nil, nil, err
	}
	parsed, _, err := audit.ParseEntry(raw, true)
	if err != nil {
		return nil, nil, fmt.Errorf("audit: %s by %s: %w", e.Action, e.Operation, err)
	}
	return parsed, raw, nil
}

// errNoChange: the state before and after an entry is the same.
var errNoChange = errors.New("audit: nothing changed")

// Rec collects the entries of one change.
type Rec struct {
	entries []Entry
}

// Add notes an entry; it is written when the transaction of the change
// ends.
func (r *Rec) Add(e ...Entry) {
	if r != nil {
		r.entries = append(r.entries, e...)
	}
}

// ErrNoLog: the gateway runs without an audit log (tests of a part).
var ErrNoLog = errors.New("audit: no log")

// Tx runs a change and writes its entries in one transaction of schild.db:
// f makes the change with the context it gets and notes its entries. An
// error of f, or an entry that cannot be written, rolls the change back.
// Inside f only the store is called (store.InTx).
//
// A nil log runs f alone: a part under test without a log.
func (l *Log) Tx(ctx context.Context, f func(ctx context.Context, rec *Rec) error) error {
	if l == nil {
		return f(ctx, &Rec{})
	}
	var entries []Entry
	err := l.st.InTx(ctx, func(ctx context.Context) error {
		rec := &Rec{}
		if err := f(ctx, rec); err != nil {
			return err
		}
		entries = rec.entries
		return l.put(ctx, entries)
	})
	if err == nil {
		l.spend(entries)
		l.wake()
	}
	return err
}

// Write writes entries of a change that is not in schild.db (the rules of a
// repository, a node removed from the group): before the answer, in a
// transaction of their own.
func (l *Log) Write(ctx context.Context, entries ...Entry) error {
	if l == nil || len(entries) == 0 {
		return nil
	}
	err := l.st.InTx(ctx, func(ctx context.Context) error { return l.put(ctx, entries) })
	if err == nil {
		l.spend(entries)
		l.wake()
	}
	return err
}

// put writes entries into the outbox, in the transaction of ctx. An entry
// of a setting whose state is the same before and after is left out
// (Entry.IfChanged).
func (l *Log) put(ctx context.Context, entries []Entry) error {
	now := l.now()
	for _, e := range entries {
		a := audit.Lookup(e.Action)
		if a == nil {
			return fmt.Errorf("audit: unknown action %q", e.Action)
		}
		// Built once without a number: an entry that says nothing, or does
		// not pass, draws none.
		if _, _, err := l.build(e, "0000000000000000-"+audit.Letter(a.Class)+"-1", now); errors.Is(err, errNoChange) {
			continue
		} else if err != nil {
			return err
		}
		id, err := l.st.NextAuditID(ctx, audit.Letter(a.Class))
		if err != nil {
			return err
		}
		_, raw, err := l.build(e, id, now)
		if err != nil {
			return err
		}
		t := e.Time
		if t.IsZero() {
			t = now
		}
		if err := l.st.PutAudit(ctx, store.AuditRow{ID: id, TimeMS: t.UnixMilli(), Class: a.Class, Body: raw}); err != nil {
			return err
		}
	}
	return nil
}

// wake asks the running gateway to move the outbox.
func (l *Log) wake() {
	if l.kick == nil {
		return
	}
	select {
	case l.kick <- struct{}{}:
	default:
	}
}

// OnChange returns a context for a change that code between the caller and
// the store makes (a setting the app keeps under a key, a rule decision):
// when that code writes the value, f is told what it was and what it is
// now, and the entries f notes are written in the transaction of that
// write. The code in between holds its own locks as before
// (store.OnChange). f is called for every such write under the context and
// notes nothing for a key that is not its own.
//
// A nil log returns ctx as it is.
func (l *Log) OnChange(ctx context.Context, f func(c store.Change, rec *Rec) error) context.Context {
	if l == nil {
		return ctx
	}
	return store.OnChange(ctx, func(ctx context.Context, c store.Change) error {
		rec := &Rec{}
		if err := f(c, rec); err != nil {
			return err
		}
		if len(rec.entries) == 0 {
			return nil
		}
		if err := l.put(ctx, rec.entries); err != nil {
			return err
		}
		entries := rec.entries
		store.AfterCommit(ctx, func() {
			l.spend(entries)
			l.wake()
		})
		return nil
	})
}

// Origin is where a change comes from: the call that asked for it. A
// handler puts it into the context (WithOrigin); the code that makes the
// change, often several calls further down and under its own lock, takes it
// from there and notes the entry with the state before and after, which
// only it knows (Origin.Entry). A change without an origin in its context
// came from no call of this node (a member of the group handed it over, the
// start read it) and writes no entry.
type Origin struct {
	// Operation is <way>:<operation id, command or source>.
	Operation string
	Actor     Actor
	Address   string
	// Reason is text the caller gave, untrusted.
	Reason string
	// Event or Incident the call named as its cause.
	Event, Incident string
}

type originKey struct{}

// WithOrigin returns a context that carries the origin of a change.
func WithOrigin(ctx context.Context, o Origin) context.Context {
	return context.WithValue(ctx, originKey{}, o)
}

// OriginOf returns the origin of a change, false without one.
func OriginOf(ctx context.Context) (Origin, bool) {
	o, ok := ctx.Value(originKey{}).(Origin)
	return o, ok
}

// Entry starts the entry of an action from this origin.
func (o Origin) Entry(action string) Entry {
	return Entry{Action: action, Operation: o.Operation, Actor: o.Actor, Address: o.Address, Reason: o.Reason, Event: o.Event, Incident: o.Incident}
}

// Changed runs a change the caller of ctx asked for and writes its entry in
// one transaction: write makes the change with the context it gets, calling
// the store alone, and entry builds the entry from the origin of ctx. The
// code that calls Changed may hold its own lock; the transaction is around
// write alone. Without an origin in ctx, or with a nil log, write runs
// without an entry.
func (l *Log) Changed(ctx context.Context, action string, entry func(e *Entry), write func(ctx context.Context) error) error {
	o, ok := OriginOf(ctx)
	if l == nil || !ok {
		return write(ctx)
	}
	return l.Tx(ctx, func(ctx context.Context, rec *Rec) error {
		e := o.Entry(action)
		entry(&e)
		rec.Add(e)
		return write(ctx)
	})
}
