package app

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/deutschland-schild/schild/gateway/internal/auditlog"
	"net/netip"
	"sort"
	"time"

	"github.com/deutschland-schild/schild/contract/access"
	"github.com/deutschland-schild/schild/contract/events"
	"github.com/deutschland-schild/schild/contract/websites"
	"github.com/deutschland-schild/schild/gateway/internal/accesslock"
	"github.com/deutschland-schild/schild/gateway/internal/control"
	"github.com/deutschland-schild/schild/gateway/internal/dashboard"
	"github.com/deutschland-schild/schild/gateway/internal/eventlog"
	"github.com/deutschland-schild/schild/gateway/internal/passhash"
	"github.com/deutschland-schild/schild/gateway/internal/store"
)

// Actors of an access change.
const (
	AccessByDashboard = "dashboard"
	AccessByCLI       = "cli"
)

// ErrAccessWebsite: the website is unknown here.
var ErrAccessWebsite = errors.New("unknown website")

// AccessChange is one change of the access lock of a website (D56).
type AccessChange struct {
	Protection access.Protection
	// Password: a new shared password; nil keeps the stored one.
	Password       *string
	RemovePassword bool
	Actor, User    string
}

// newAccess loads the protections from schild.db and wires the lock into
// the gate. A gateway without protections still gets the lock: it costs one
// map lookup per request.
func (a *App) newAccess(ctx context.Context) error {
	a.Access = accesslock.New()
	st := accesslock.NewState()
	raw, err := a.Store.Get(ctx, accesslock.StoreKey)
	switch {
	case errors.Is(err, store.ErrNotFound):
	case err != nil:
		return fmt.Errorf("access lock: %w", err)
	default:
		if err := json.Unmarshal(raw, st); err != nil {
			return fmt.Errorf("access lock: %w", err)
		}
		if st.Entries == nil {
			st.Entries = map[string]*accesslock.Entry{}
		}
		// D98: what the maintenance switch stored as a protection before is
		// the maintenance mode now. Same effect, and the website is free for a
		// protection of its own.
		moved := false
		for id, e := range st.Entries {
			if accesslock.IsMaintenance(e.Protection) {
				if st.Maintenance == nil {
					st.Maintenance = map[string]*accesslock.Maintenance{}
				}
				st.Maintenance[id] = &accesslock.Maintenance{Message: e.Protection.Message, UpdatedAt: e.UpdatedAt, Actor: e.Actor, User: e.User}
				delete(st.Entries, id)
				moved = true
			}
		}
		if moved {
			if b, err := json.Marshal(st); err == nil {
				if err := a.Store.Put(ctx, accesslock.StoreKey, b); err != nil {
					return fmt.Errorf("access lock: %w", err)
				}
			}
		}
	}
	a.Access.Store(st)
	a.Access.OnResult = func(r string) { a.Metrics.AccessLogins.WithLabelValues(r).Inc() }
	a.Access.OnLogin = func(website string, p netip.Prefix, now time.Time) {
		if p.IsValid() {
			a.Events.Emit(events.AccessLogin, now, events.AccessLoginData{Website: website, AddressPrefix: p.String()},
				eventlog.Index{Site: website, Summary: "access login " + website})
		}
	}
	a.Access.OnLockout = func(website string, p netip.Prefix, until time.Time) {
		if p.IsValid() {
			a.Events.Emit(events.AccessPrefixLocked, time.Now(), events.AccessPrefixLockedData{Website: website, AddressPrefix: p.String(), Until: until.UTC().Format(time.RFC3339)},
				eventlog.Index{Site: website, Summary: "access login locked for " + p.String()})
		}
		a.log.Warn("access lock: too many wrong passwords, prefix locked out", "website", website, "prefix", p.String(), "until", until)
	}
	a.Gate.Access = a.Access
	a.writeAccessActive()
	return nil
}

// AccessEntry returns the protection of website, nil without one.
func (a *App) AccessEntry(website string) *accesslock.Entry { return a.Access.Lookup(website) }

// SetAccess sets or changes the protection of a website. It is in force
// before it returns and every session of the website ends. A validation
// error is an *access.FieldError.
func (a *App) SetAccess(ctx context.Context, website string, c AccessChange) (*accesslock.Entry, error) {
	a.accessMu.Lock()
	defer a.accessMu.Unlock()
	w, ok := a.Sites.View().Website(website)
	if !ok {
		return nil, ErrAccessWebsite
	}
	if w.Protection != websites.Protected {
		return nil, &access.FieldError{Field: "website", Msg: "not every request of this website runs through schild"}
	}
	now := time.Now().UTC()
	cur := a.Access.State()
	old := cur.Entries[website]
	hash := ""
	switch {
	case c.Password != nil:
		if n := len(*c.Password); n < access.MinPasswordLen || n > access.MaxPasswordLen {
			return nil, &access.FieldError{Field: "password", Msg: "8 to 128 characters"}
		}
		hash = passhash.Hash(*c.Password)
	case c.RemovePassword:
	case old != nil:
		hash = old.Hash
	}
	p := c.Protection
	p.Website, p.Password = website, hash != ""
	if err := p.CheckShape(); err != nil {
		return nil, err
	}
	next := cur.Clone()
	e := &accesslock.Entry{Protection: p, Hash: hash, Epoch: newEpoch(old), UpdatedAt: now, Actor: c.Actor, User: c.User}
	next.Entries[website] = e
	if err := a.storeAccess(ctx, next, one("access_lock.set", website, website, accessState(old), accessState(e))); err != nil {
		return nil, err
	}
	a.Events.Emit(events.AccessProtectionSet, now, events.AccessProtectionChange{Website: website, Scope: p.Scope, Paths: p.Paths, Except: p.Except,
		Password: p.Password, Addresses: len(p.Addresses), OwnNetworks: p.OwnNetworks, Actor: c.Actor, User: c.User},
		eventlog.Index{Site: website, Summary: "access lock " + p.Scope + " set on " + website})
	a.log.Info("access lock set", "website", website, "scope", p.Scope, "actor", c.Actor)
	return e, nil
}

// RemoveAccess ends the protection of a website; false when there was none.
func (a *App) RemoveAccess(ctx context.Context, website, actor, user string) (bool, error) {
	a.accessMu.Lock()
	defer a.accessMu.Unlock()
	return a.removeAccess(ctx, website, actor, user, "removed")
}

func (a *App) removeAccess(ctx context.Context, website, actor, user, reason string) (bool, error) {
	cur := a.Access.State()
	old := cur.Entries[website]
	if old == nil {
		return false, nil
	}
	next := cur.Clone()
	delete(next.Entries, website)
	if err := a.storeAccess(ctx, next, one("access_lock.remove", website, website, accessState(old), nil)); err != nil {
		return false, err
	}
	a.Events.Emit(events.AccessProtectionRemoved, time.Now(), events.AccessProtectionEnded{Website: website, Scope: old.Protection.Scope, Actor: actor, User: user, Reason: reason},
		eventlog.Index{Site: website, Summary: "access lock on " + website + " " + reason})
	a.log.Info("access lock ended", "website", website, "reason", reason, "actor", actor)
	return true, nil
}

// MaintenanceOf returns the maintenance mode of website, nil when it is off.
func (a *App) MaintenanceOf(website string) *accesslock.Maintenance {
	return a.Access.MaintenanceOf(website)
}

// SetMaintenance switches the maintenance mode of a website on (or changes
// its text) or off (D98). It is in force before it returns and leaves the
// protection of the website as it is. A validation error is an
// *access.FieldError.
func (a *App) SetMaintenance(ctx context.Context, website string, on bool, message, actor, user string) (*accesslock.Maintenance, error) {
	a.accessMu.Lock()
	defer a.accessMu.Unlock()
	cur := a.Access.State()
	old := cur.Maintenance[website]
	now := time.Now().UTC()
	if !on {
		if old == nil {
			return nil, nil
		}
		next := cur.Clone()
		delete(next.Maintenance, website)
		if err := a.storeAccess(ctx, next, one("maintenance.set", website, website, maintenanceState(old), maintenanceState(nil))); err != nil {
			return nil, err
		}
		a.Events.Emit(events.AccessProtectionRemoved, now, events.AccessProtectionEnded{Website: website, Scope: access.ScopeSite, Actor: actor, User: user, Reason: "removed"},
			eventlog.Index{Site: website, Summary: "maintenance mode off for " + website})
		a.log.Info("maintenance mode off", "website", website, "actor", actor)
		return nil, nil
	}
	w, ok := a.Sites.View().Website(website)
	if !ok {
		return nil, ErrAccessWebsite
	}
	if w.Protection != websites.Protected {
		return nil, &access.FieldError{Field: "website", Msg: "not every request of this website runs through schild"}
	}
	m := &accesslock.Maintenance{Message: message, UpdatedAt: now, Actor: actor, User: user}
	if err := m.Protection(website).CheckShape(); err != nil {
		return nil, err
	}
	next := cur.Clone()
	if next.Maintenance == nil {
		next.Maintenance = map[string]*accesslock.Maintenance{}
	}
	next.Maintenance[website] = m
	if err := a.storeAccess(ctx, next, one("maintenance.set", website, website, maintenanceState(old), maintenanceState(m))); err != nil {
		return nil, err
	}
	if old == nil {
		a.Events.Emit(events.AccessProtectionSet, now, events.AccessProtectionChange{Website: website, Scope: access.ScopeSite, OwnNetworks: true, Actor: actor, User: user},
			eventlog.Index{Site: website, Summary: "maintenance mode on for " + website})
		a.log.Info("maintenance mode on", "website", website, "actor", actor)
	}
	return m, nil
}

// accessState is what access_lock.set and access_lock.remove record of a
// protection. The password stands there by its hash, which the audit log
// never records: it shows that the password changed, not what it is.
func accessState(e *accesslock.Entry) map[string]any {
	if e == nil {
		return nil
	}
	m := asMap(e.Protection)
	delete(m, "website")
	delete(m, "password")
	if e.Hash != "" {
		m["password"] = e.Hash
	}
	return m
}

// maintenanceState is what maintenance.set records.
func maintenanceState(m *accesslock.Maintenance) map[string]any {
	if m == nil {
		return map[string]any{"on": false}
	}
	out := map[string]any{"on": true}
	if m.Message != "" {
		out["message"] = m.Message
	}
	return out
}

// storeAccess writes next to schild.db with the entries of the change,
// then swaps it in and rewrites the file for the front. Called with
// accessMu held.
func (a *App) storeAccess(ctx context.Context, next *accesslock.State, entries func(o auditlog.Origin) []auditlog.Entry) error {
	raw, err := json.Marshal(next)
	if err == nil {
		err = a.putAudited(ctx, accesslock.StoreKey, raw, entries)
	}
	if err != nil {
		return fmt.Errorf("access lock not stored: %w", err)
	}
	a.Access.Store(next)
	a.writeAccessActive()
	return nil
}

// writeAccessActive writes <storage>/access/active.json for `schild front`.
// A failure is logged: the gate holds the lock either way, only a front
// with schild down would not know.
func (a *App) writeAccessActive() {
	if a.dataDir == "" {
		return
	}
	if err := access.WriteActive(a.dataDir, a.Access.State().Active()); err != nil {
		a.log.Error("access lock: file for schild front not written", "err", err)
	}
}

// AccessList returns the protections in force, by website.
func (a *App) AccessList() []control.AccessInfo {
	st := a.Access.State()
	out := make([]control.AccessInfo, 0, len(st.Entries))
	for id, e := range st.Entries {
		p := e.Protection
		out = append(out, control.AccessInfo{Website: id, Scope: p.Scope, Paths: p.Paths, Except: p.Except, Password: p.Password,
			Addresses: p.Addresses, OwnNetworks: p.OwnNetworks})
	}
	for id := range st.Maintenance {
		out = append(out, control.AccessInfo{Website: id, Scope: access.ScopeSite, OwnNetworks: true, Maintenance: true})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Website != out[j].Website {
			return out[i].Website < out[j].Website
		}
		return out[i].Maintenance && !out[j].Maintenance
	})
	return out
}

// newEpoch returns a random epoch other than the one of old.
func newEpoch(old *accesslock.Entry) uint64 {
	var b [8]byte
	for {
		_, _ = rand.Read(b[:])
		e := binary.BigEndian.Uint64(b[:])
		if old == nil || e != old.Epoch {
			return e
		}
	}
}

// dashboardAccess connects the dashboard with the access lock.
func (a *App) dashboardAccess() dashboard.AccessFuncs {
	return dashboard.AccessFuncs{
		Entry: a.AccessEntry,
		Set: func(ctx context.Context, website string, in dashboard.AccessProtectionInput, user string) (*accesslock.Entry, error) {
			return a.SetAccess(ctx, website, AccessChange{Protection: access.Protection{Scope: in.Scope, Paths: in.Paths, Except: in.Except,
				Addresses: in.Addresses, OwnNetworks: in.OwnNetworks, Message: in.Message},
				Password: in.Password, RemovePassword: in.RemovePassword, Actor: AccessByDashboard, User: user})
		},
		Remove: func(ctx context.Context, website, user string) error {
			_, err := a.RemoveAccess(ctx, website, AccessByDashboard, user)
			return err
		},
		Maintenance: a.MaintenanceOf,
		SetMaintenance: func(ctx context.Context, website string, on bool, message, user string) (*accesslock.Maintenance, error) {
			return a.SetMaintenance(ctx, website, on, message, AccessByDashboard, user)
		},
	}
}

// accessControl answers the access operations of the control socket.
func (a *App) accessControl(ctx context.Context, req control.Request) control.Response {
	switch req.Op {
	case control.OpAccessSet:
		if req.Access == nil {
			return control.Response{Error: "no protection given"}
		}
		s := req.Access
		c := AccessChange{Protection: access.Protection{Scope: s.Scope, Paths: s.Paths, Except: s.Except, Addresses: s.Addresses,
			OwnNetworks: s.OwnNetworks, Message: s.Message}, Actor: AccessByCLI, User: req.HostUser}
		if s.Password != "" {
			c.Password = &s.Password
		}
		if _, err := a.SetAccess(ctx, req.Website, c); err != nil {
			return control.Response{Error: err.Error()}
		}
	case control.OpAccessRemove:
		if _, ok := a.Sites.View().Website(req.Website); !ok && a.Access.Lookup(req.Website) == nil && a.Access.MaintenanceOf(req.Website) == nil {
			return control.Response{Error: ErrAccessWebsite.Error()}
		}
		removed, err := a.RemoveAccess(ctx, req.Website, AccessByCLI, req.HostUser)
		if err != nil {
			return control.Response{Error: err.Error()}
		}
		// The way back in from the host ends the maintenance mode too (D98):
		// whoever is locked out must not need to know which of the two it was.
		if a.Access.MaintenanceOf(req.Website) != nil {
			if _, err := a.SetMaintenance(ctx, req.Website, false, "", AccessByCLI, req.HostUser); err != nil {
				return control.Response{Error: err.Error()}
			}
			removed = true
		}
		return control.Response{OK: true, Removed: removed, Access: a.AccessList()}
	}
	return control.Response{OK: true, Access: a.AccessList()}
}
