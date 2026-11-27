package auditlog

import (
	"context"
	"encoding/json"
	"net/netip"
	"sync"
	"time"

	"github.com/deutschland-schild/schild/contract/audit"
)

// Refused calls (contracts/audit.md section 5): one entry per action,
// operation, token, client (IPv4 address, IPv6 /64) and UTC minute, with a
// count. An entry is written with its first call, its count follows every
// refusedFlush and at the end of its minute, so a crash loses at most that
// much counting. The request path only counts in memory.

const refusedFlush = 10 * time.Second

// RefusedCall is one call that was refused.
type RefusedCall struct {
	// Action the call tried (agent_api.call when the token is unknown).
	Action    string
	Operation string
	Actor     Actor
	Address   string
}

type refusedKey struct {
	action, operation, actor, client string
	minute                           int64
}

type refusedEntry struct {
	call        RefusedCall
	id          string
	first, last time.Time
	count       int64
	// written is the count audit.db holds.
	written int64
}

type refused struct {
	mu   sync.Mutex
	open map[refusedKey]*refusedEntry
	// minute and clients: how many entries with a client the current minute
	// has (audit.MaxOpenRefused).
	minute  int64
	clients int
	wake    chan struct{}
}

func clientKey(s string) string {
	a, err := netip.ParseAddr(s)
	if err != nil || a.Zone() != "" {
		return ""
	}
	a = a.Unmap()
	if a.Is4() {
		return a.String()
	}
	p, _ := a.Prefix(64)
	return p.Addr().String()
}

// Refused counts a refused call. It never waits for the database.
func (l *Log) Refused(c RefusedCall) {
	if l == nil || l.db == nil || l.kick == nil || audit.Lookup(c.Action) == nil {
		return
	}
	now := l.now()
	r := &l.refused
	r.mu.Lock()
	if r.open == nil {
		r.open = map[refusedKey]*refusedEntry{}
	}
	m := now.Unix() / 60
	if m != r.minute {
		r.minute, r.clients = m, 0
	}
	k := refusedKey{c.Action, c.Operation, c.Actor.ID, clientKey(c.Address), m}
	e := r.open[k]
	if e == nil && k.client != "" && r.clients >= audit.MaxOpenRefused {
		k.client, c.Address = "", ""
		e = r.open[k]
	}
	fresh := e == nil
	if fresh {
		if k.client != "" {
			r.clients++
		} else {
			c.Address = ""
		}
		e = &refusedEntry{call: c, first: now, last: now}
		r.open[k] = e
	}
	e.count++
	if now.After(e.last) {
		e.last = now
	}
	wake := r.wake
	r.mu.Unlock()
	if fresh {
		select {
		case wake <- struct{}{}:
		default:
		}
	}
}

func (l *Log) refusedBody(e *refusedEntry) ([]byte, map[string]any, error) {
	a := audit.Lookup(e.call.Action)
	m := map[string]any{
		"schema": Schema, "id": e.id, "time": e.first.UTC().Format(timeFormat), "node": audit.Text(l.Node(), 128),
		"class": audit.ClassRefused, "action": a.Action, "operation": e.call.Operation, "result": audit.ResultRefused,
		"actor": e.call.Actor.object(), "subject": map[string]any{"kind": a.Subject},
		"count": e.count, "last": e.last.UTC().Format(timeFormat),
	}
	if e.call.Address != "" {
		m["address"] = e.call.Address
	}
	raw, err := json.Marshal(m)
	if err != nil {
		return nil, nil, err
	}
	parsed, _, err := audit.ParseEntry(raw, true)
	return raw, parsed, err
}

// flushRefused writes new entries and changed counts, and closes the
// entries of minutes that are over (all of them with final).
func (l *Log) flushRefused(ctx context.Context, final bool) {
	r := &l.refused
	now := l.now()
	cur := now.Unix() / 60
	type job struct {
		k     refusedKey
		e     refusedEntry
		close bool
	}
	var jobs []job
	r.mu.Lock()
	for k, e := range r.open {
		over := final || k.minute < cur
		if e.id == "" || e.written != e.count || over {
			jobs = append(jobs, job{k, *e, over})
		}
	}
	r.mu.Unlock()
	for _, j := range jobs {
		e := j.e
		fresh := e.id == ""
		if fresh {
			id, err := l.st.NextAuditID(ctx, audit.LetterRefused)
			if err != nil {
				l.warn("audit log: a refused call is not written", err)
				continue
			}
			e.id = id
		}
		raw, parsed, err := l.refusedBody(&e)
		if err != nil {
			l.warn("audit log: a refused call is not written", err)
			r.mu.Lock()
			delete(r.open, j.k)
			r.mu.Unlock()
			continue
		}
		if fresh {
			_, err = insert(ctx, l.db, columns(parsed), raw, true, !j.close, now)
		} else if j.close {
			// A closed entry gets the next place in the order the group
			// asks in, so no member passes it while it still counts.
			_, err = l.db.ExecContext(ctx, `UPDATE entries SET seq = (SELECT MAX(seq) FROM entries) + 1, open = 0, body = ? WHERE id = ?`, raw, e.id)
		} else {
			_, err = l.db.ExecContext(ctx, `UPDATE entries SET body = ? WHERE id = ? AND open = 1`, raw, e.id)
		}
		if err != nil {
			l.warn("audit log: a refused call is not written", err)
		}
		r.mu.Lock()
		if cur := r.open[j.k]; cur != nil {
			cur.id = e.id
			if err == nil {
				cur.written = e.count
				// Counted again while this was written: the entry stays.
				if j.close && cur.count == e.count {
					delete(r.open, j.k)
				}
			}
		}
		r.mu.Unlock()
		if err == nil && j.close {
			l.copyOut([][]byte{raw})
		}
	}
}

// closeOpenRefused closes the entries a process before this one left open.
func (l *Log) closeOpenRefused(ctx context.Context, _ bool) error {
	rows, err := l.db.QueryContext(ctx, `SELECT id FROM entries WHERE open = 1 ORDER BY seq`)
	if err != nil {
		return err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, id := range ids {
		if _, err := l.db.ExecContext(ctx, `UPDATE entries SET seq = (SELECT MAX(seq) FROM entries) + 1, open = 0 WHERE id = ?`, id); err != nil {
			return err
		}
	}
	return nil
}

func (l *Log) warn(msg string, err error) {
	if l.opts.Log != nil {
		l.opts.Log.Warn(msg, "err", err)
	}
}

// budget counts the entries each agent token wrote in the last hour.
type budget struct {
	mu     sync.Mutex
	tokens map[string][]time.Time
}

// BudgetLeft reports whether a token may write another entry
// (audit.TokenEntriesPerHour), and after how many seconds when not.
func (l *Log) BudgetLeft(tokenID string) (ok bool, retryAfter int) {
	if l == nil {
		return true, 0
	}
	now := l.now()
	b := &l.budget
	b.mu.Lock()
	defer b.mu.Unlock()
	ts := b.tokens[tokenID]
	cut := 0
	for cut < len(ts) && now.Sub(ts[cut]) >= time.Hour {
		cut++
	}
	ts = ts[cut:]
	if len(ts) == 0 {
		delete(b.tokens, tokenID)
	} else {
		b.tokens[tokenID] = ts
	}
	if len(ts) < audit.TokenEntriesPerHour {
		return true, 0
	}
	return false, max(1, int(time.Hour.Seconds()-now.Sub(ts[0]).Seconds()+0.999))
}

// spend counts the entries of agent tokens that were written.
func (l *Log) spend(entries []Entry) {
	now := l.now()
	b := &l.budget
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, e := range entries {
		if e.Actor.Kind != WayAgent || e.Actor.ID == "" {
			continue
		}
		if b.tokens == nil {
			b.tokens = map[string][]time.Time{}
		}
		b.tokens[e.Actor.ID] = append(b.tokens[e.Actor.ID], now)
	}
}
