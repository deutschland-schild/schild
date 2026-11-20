// Package settings holds the lab's effective configuration: lab.yaml plus
// the changes made in the dashboard (scoring thresholds, ingest limits,
// retention, issuer and client quotas and revocations).
//
// Dashboard changes are validated with the same validator as lab.yaml
// (contract/config.ParseLabJSON) and kept as an overlay in the lab store, so
// a read-only lab.yaml (container image, config map) keeps working; the
// overlay is applied on every start. require_human_approval stays fixed.
package settings

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/deutschland-schild/schild/contract/config"
	"github.com/deutschland-schild/schild/contract/msg"
	"github.com/deutschland-schild/schild/lab/internal/store"
)

// Overlay is what the dashboard changed.
type Overlay struct {
	Scoring   map[string]any           `json:"scoring,omitempty"`
	Ingest    map[string]any           `json:"ingest,omitempty"`
	Retention map[string]any           `json:"retention,omitempty"`
	Issuers   map[string]*AccessChange `json:"issuers,omitempty"`
	Clients   map[string]*AccessChange `json:"clients,omitempty"`
}

// AccessChange is a quota or revocation set in the dashboard.
type AccessChange struct {
	QuotaPerDay *int   `json:"quota_per_day,omitempty"`
	Revoked     bool   `json:"revoked,omitempty"`
	RevokedAt   string `json:"revoked_at,omitempty"`
	RevokedBy   string `json:"revoked_by,omitempty"`
}

// Manager owns the effective configuration.
type Manager struct {
	mu      sync.Mutex
	base    *config.LabConfig
	cfg     *config.LabConfig
	overlay Overlay
	db      *store.DB
	// OnChange is called with the new effective config after every change.
	OnChange func(*config.LabConfig)
}

// Load applies the stored overlay to base.
func Load(base *config.LabConfig, db *store.DB) (*Manager, error) {
	m := &Manager{base: base, db: db}
	if err := db.View(func(tx *bolt.Tx) error {
		_, err := store.GetJSON(tx, store.Settings, []byte("overlay"), &m.overlay)
		return err
	}); err != nil {
		return nil, err
	}
	cfg, err := m.build(m.overlay)
	if err != nil {
		return nil, fmt.Errorf("settings overlay no longer valid: %w", err)
	}
	m.cfg = cfg
	return m, nil
}

// Config returns the effective configuration (do not modify).
func (m *Manager) Config() *config.LabConfig {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cfg
}

// Overlay returns a copy of the dashboard changes.
func (m *Manager) Access() (issuers, clients map[string]AccessChange) {
	m.mu.Lock()
	defer m.mu.Unlock()
	issuers, clients = map[string]AccessChange{}, map[string]AccessChange{}
	for k, v := range m.overlay.Issuers {
		issuers[k] = *v
	}
	for k, v := range m.overlay.Clients {
		clients[k] = *v
	}
	return issuers, clients
}

// build applies an overlay to the base config and validates the result.
func (m *Manager) build(o Overlay) (*config.LabConfig, error) {
	raw, err := json.Marshal(m.base)
	if err != nil {
		return nil, err
	}
	var v map[string]any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, err
	}
	stripNulls(v)
	merge := func(key string, patch map[string]any) {
		if len(patch) == 0 {
			return
		}
		cur, _ := v[key].(map[string]any)
		if cur == nil {
			cur = map[string]any{}
		}
		for k, x := range patch {
			cur[k] = x
		}
		v[key] = cur
	}
	merge("scoring", o.Scoring)
	merge("ingest", o.Ingest)
	merge("retention", o.Retention)
	if is, ok := v["issuers"].([]any); ok {
		for _, x := range is {
			i := x.(map[string]any)
			if ch := o.Issuers[i["id"].(string)]; ch != nil {
				if ch.QuotaPerDay != nil {
					i["quota_per_day"] = *ch.QuotaPerDay
				}
				if ch.Revoked {
					i["revoked"] = true
				}
			}
		}
	}
	if cs, ok := v["clients"].([]any); ok {
		for _, x := range cs {
			c := x.(map[string]any)
			if ch := o.Clients[c["keyid"].(string)]; ch != nil {
				if ch.QuotaPerDay != nil {
					c["quota_per_day"] = *ch.QuotaPerDay
				}
				if ch.Revoked {
					c["revoked"] = true
				}
			}
		}
	}
	out, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return config.ParseLabJSON(out)
}

func stripNulls(v any) {
	switch t := v.(type) {
	case map[string]any:
		for k, x := range t {
			if x == nil {
				delete(t, k)
				continue
			}
			stripNulls(x)
		}
	case []any:
		for _, x := range t {
			stripNulls(x)
		}
	}
}

// change applies fn to a copy of the overlay, validates, persists and
// publishes the result.
func (m *Manager) change(fn func(*Overlay) error) (*config.LabConfig, error) {
	m.mu.Lock()
	raw, _ := json.Marshal(m.overlay)
	var o Overlay
	_ = json.Unmarshal(raw, &o)
	if err := fn(&o); err != nil {
		m.mu.Unlock()
		return nil, err
	}
	cfg, err := m.build(o)
	if err != nil {
		m.mu.Unlock()
		return nil, err
	}
	if err := m.db.Update(func(tx *bolt.Tx) error {
		return store.PutJSON(tx, store.Settings, []byte("overlay"), &o)
	}); err != nil {
		m.mu.Unlock()
		return nil, err
	}
	m.overlay, m.cfg = o, cfg
	cb := m.OnChange
	m.mu.Unlock()
	if cb != nil {
		cb(cfg)
	}
	return cfg, nil
}

// Patch is the API LabSettingsPatch (without confirm).
type Patch struct {
	Scoring   map[string]any `json:"scoring"`
	Ingest    map[string]any `json:"ingest"`
	Retention map[string]any `json:"retention"`
}

// Apply validates and stores a settings patch.
func (m *Manager) Apply(p Patch) (*config.LabConfig, error) {
	allowed := map[string][]string{
		"scoring":   {"min_issuers", "max_issuer_share", "window_minutes", "min_score"},
		"ingest":    {"rate_per_client_per_min", "retry_after_ms"},
		"retention": {"signals_days"},
	}
	check := func(section string, patch map[string]any) error {
		for k := range patch {
			ok := false
			for _, a := range allowed[section] {
				ok = ok || a == k
			}
			if !ok {
				return fmt.Errorf("%s.%s cannot be changed here", section, k)
			}
		}
		return nil
	}
	for s, x := range map[string]map[string]any{"scoring": p.Scoring, "ingest": p.Ingest, "retention": p.Retention} {
		if err := check(s, x); err != nil {
			return nil, err
		}
	}
	return m.change(func(o *Overlay) error {
		set := func(dst *map[string]any, src map[string]any) {
			if len(src) == 0 {
				return
			}
			if *dst == nil {
				*dst = map[string]any{}
			}
			for k, v := range src {
				(*dst)[k] = v
			}
		}
		set(&o.Scoring, p.Scoring)
		set(&o.Ingest, p.Ingest)
		set(&o.Retention, p.Retention)
		return nil
	})
}

func (m *Manager) exists(issuer, keyid string) error {
	cfg := m.Config()
	if issuer != "" {
		for _, i := range cfg.Issuers {
			if i.ID == issuer {
				return nil
			}
		}
		return fmt.Errorf("unknown issuer %s", issuer)
	}
	for _, c := range cfg.Clients {
		if c.KeyID == keyid {
			return nil
		}
	}
	return fmt.Errorf("unknown client %s", keyid)
}

// ErrNotFound marks unknown issuers or clients.
type ErrNotFound struct{ What string }

func (e ErrNotFound) Error() string { return e.What }

// SetIssuerQuota changes an issuer's daily quota.
func (m *Manager) SetIssuerQuota(id string, quota int) error {
	if err := m.exists(id, ""); err != nil {
		return ErrNotFound{err.Error()}
	}
	_, err := m.change(func(o *Overlay) error {
		if o.Issuers == nil {
			o.Issuers = map[string]*AccessChange{}
		}
		if o.Issuers[id] == nil {
			o.Issuers[id] = &AccessChange{}
		}
		o.Issuers[id].QuotaPerDay = &quota
		return nil
	})
	return err
}

// SetClientQuota changes a client key's daily quota.
func (m *Manager) SetClientQuota(keyid string, quota int) error {
	if err := m.exists("", keyid); err != nil {
		return ErrNotFound{err.Error()}
	}
	_, err := m.change(func(o *Overlay) error {
		if o.Clients == nil {
			o.Clients = map[string]*AccessChange{}
		}
		if o.Clients[keyid] == nil {
			o.Clients[keyid] = &AccessChange{}
		}
		o.Clients[keyid].QuotaPerDay = &quota
		return nil
	})
	return err
}

// RevokeIssuer revokes an issuer: all its clients stop counting at once.
func (m *Manager) RevokeIssuer(id, by string, now time.Time) error {
	if err := m.exists(id, ""); err != nil {
		return ErrNotFound{err.Error()}
	}
	_, err := m.change(func(o *Overlay) error {
		if o.Issuers == nil {
			o.Issuers = map[string]*AccessChange{}
		}
		if o.Issuers[id] == nil {
			o.Issuers[id] = &AccessChange{}
		}
		o.Issuers[id].Revoked, o.Issuers[id].RevokedAt, o.Issuers[id].RevokedBy = true, msg.FormatTime(now), by
		return nil
	})
	return err
}

// RevokeClient revokes one client key.
func (m *Manager) RevokeClient(keyid, by string, now time.Time) error {
	if err := m.exists("", keyid); err != nil {
		return ErrNotFound{err.Error()}
	}
	_, err := m.change(func(o *Overlay) error {
		if o.Clients == nil {
			o.Clients = map[string]*AccessChange{}
		}
		if o.Clients[keyid] == nil {
			o.Clients[keyid] = &AccessChange{}
		}
		o.Clients[keyid].Revoked, o.Clients[keyid].RevokedAt, o.Clients[keyid].RevokedBy = true, msg.FormatTime(now), by
		return nil
	})
	return err
}
