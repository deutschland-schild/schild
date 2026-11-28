package app

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/deutschland-schild/schild/contract/config"
	"github.com/deutschland-schild/schild/contract/rules"
	"github.com/deutschland-schild/schild/gateway/internal/auditlog"
	"github.com/deutschland-schild/schild/gateway/internal/buildinfo"
	"github.com/deutschland-schild/schild/gateway/internal/dashboard"
	"github.com/deutschland-schild/schild/gateway/internal/store"
)

// What schild writes into the audit log by itself (contracts/audit.md
// section 2): the configuration it applied (config.apply), an own IP and a
// token that expired (system:expiry), rules it loaded without a call
// (system:hub_update, system:sighup), and its entry into a group
// (system:cluster).

// Sources of config.apply.
const (
	configSourceYAML      = "schild_yaml"
	configSourceCaddyfile = "caddyfile"
	// configDigestKey is the place of the digest of the whole source among
	// the digests of its keys.
	configDigestKey = ""
)

// auditConfigApplied writes config.apply when schild.yaml or the Caddyfile
// that runs is another one than at the last start of this node: the digest
// before and after and the names of the keys that changed, no values. The
// names come from a keyed digest per key, kept in schild.db; the key of the
// digests is drawn per log, so a digest says nothing outside of it.
func (a *App) auditConfigApplied(ctx context.Context, cfg *config.Site) {
	a.auditSource(ctx, configSourceYAML, flattenConfig(a.base))
	if cfg.CaddyIngress() {
		if raw, err := os.ReadFile(cfg.Ingress.Caddyfile); err == nil {
			a.auditSource(ctx, configSourceCaddyfile, map[string][]byte{"/": raw})
		}
	}
}

// flattenConfig turns a configuration into its keys, each a JSON pointer,
// with the JSON of its value. A list is one key.
func flattenConfig(m map[string]any) map[string][]byte {
	out := map[string][]byte{}
	var walk func(v any, ptr string)
	walk = func(v any, ptr string) {
		if obj, ok := v.(map[string]any); ok {
			for k, x := range obj {
				walk(x, ptr+"/"+strings.NewReplacer("~", "~0", "/", "~1").Replace(k))
			}
			return
		}
		raw, _ := json.Marshal(v)
		out[ptr] = raw
	}
	walk(m, "")
	return out
}

func (a *App) auditSource(ctx context.Context, source string, keys map[string][]byte) {
	if a.Audit == nil {
		return
	}
	err := a.Audit.Tx(ctx, func(ctx context.Context, rec *auditlog.Rec) error {
		keyHex, err := a.Store.AuditState(ctx, store.AuditConfigKey)
		if err != nil {
			return err
		}
		if keyHex == "" {
			var k [32]byte
			_, _ = rand.Read(k[:])
			keyHex = hex.EncodeToString(k[:])
			if err := a.Store.SetAuditState(ctx, store.AuditConfigKey, keyHex); err != nil {
				return err
			}
		}
		key, _ := hex.DecodeString(keyHex)
		digest := func(parts ...[]byte) string {
			h := hmac.New(sha256.New, key)
			for _, p := range parts {
				h.Write(p)
				h.Write([]byte{0})
			}
			return hex.EncodeToString(h.Sum(nil))[:32]
		}
		now := map[string]string{}
		names := make([]string, 0, len(keys))
		for k := range keys {
			names = append(names, k)
		}
		sort.Strings(names)
		var all [][]byte
		for _, k := range names {
			now[k] = digest([]byte(k), keys[k])
			all = append(all, []byte(k), keys[k])
		}
		now[configDigestKey] = digest(all...)
		old, err := a.Store.AuditConfig(ctx, source)
		if err != nil {
			return err
		}
		if old[configDigestKey] == now[configDigestKey] {
			return nil
		}
		// The names of the keys that changed stand in the entry as fields
		// without a value: the action lists /digest alone.
		before, after := map[string]any{}, map[string]any{"digest": now[configDigestKey]}
		if len(old) > 0 {
			before["digest"] = old[configDigestKey]
			put := func(m map[string]any, ptr, v string) {
				parts := strings.Split(strings.TrimPrefix(ptr, "/"), "/")
				for _, p := range parts[:len(parts)-1] {
					next, _ := m[p].(map[string]any)
					if next == nil {
						next = map[string]any{}
						m[p] = next
					}
					m = next
				}
				m[parts[len(parts)-1]] = v
			}
			if source == configSourceYAML {
				for k, d := range now {
					if k != configDigestKey && old[k] != d {
						put(map[string]any(after), "keys"+k, d)
					}
				}
				for k, d := range old {
					if k == configDigestKey {
						continue
					}
					if _, still := now[k]; !still {
						put(map[string]any(before), "keys"+k, d)
					} else if now[k] != d {
						put(map[string]any(before), "keys"+k, d)
					}
				}
			}
		}
		operation := "config:schild_yaml"
		if source == configSourceCaddyfile {
			operation = "config:caddyfile"
		}
		rec.Add(auditlog.Entry{Action: "config.apply", Operation: operation, Actor: auditlog.Config(), Subject: source, Before: before, After: after})
		return a.Store.SetAuditConfig(ctx, source, now)
	})
	if err != nil {
		a.log.Error("audit log: the applied configuration is not recorded", "source", source, "err", err)
	}
}

// allowExpired writes allowlist.remove for the own IPs whose time is over,
// in the transaction that removes them (store.Retention.Expired).
func (a *App) allowExpired(ctx context.Context, gone []store.AllowEntry) error {
	var entries []auditlog.Entry
	for i := range gone {
		entries = append(entries, auditlog.Entry{Action: "allowlist.remove", Operation: "system:expiry", Actor: auditlog.System(),
			Subject: gone[i].ID, Before: dashboard.AllowState(&gone[i])})
	}
	return a.Audit.Write(ctx, entries...)
}

// auditTokensExpired writes token.expire for every agent token whose time
// is over, once: a token is looked up long after it ended. In a group the
// tokens are shared; the node that sees the end first writes the entry, and
// a node that holds that entry writes none.
func (a *App) auditTokensExpired(ctx context.Context) {
	if a.Audit == nil {
		return
	}
	tokens, err := a.Store.ListAgentTokens(ctx)
	if err != nil {
		return
	}
	now := time.Now().UTC()
	for _, t := range tokens {
		if !t.RevokedAt.IsZero() || now.Before(t.Expires) {
			continue
		}
		mark := "token_expired:" + t.ID
		if v, err := a.Store.AuditState(ctx, mark); err != nil || v != "" {
			continue
		}
		have, _, err := a.Audit.List(ctx, auditlog.Filter{Action: "token.expire", Subject: "token", SubjectID: t.ID}, "", 1)
		if err != nil {
			continue
		}
		err = a.Audit.Tx(ctx, func(ctx context.Context, rec *auditlog.Rec) error {
			if len(have) == 0 {
				rec.Add(auditlog.Entry{Action: "token.expire", Operation: "system:expiry", Actor: auditlog.System(), Subject: t.ID, Time: t.Expires,
					Before: map[string]any{"scope": t.Scope, "label": t.Label, "expires": t.Expires.UTC().Format(time.RFC3339)}})
			}
			return a.Store.SetAuditState(ctx, mark, "1")
		})
		if err != nil {
			a.log.Warn("audit log: the end of a token is not recorded", "token", t.ID, "err", err)
		}
	}
}

// ruleSetOf is what the rule_repository actions record of the rules a
// repository runs.
func (a *App) ruleSetOf(id string) map[string]any {
	v, err := a.Repos.Repository(id)
	if err != nil {
		return nil
	}
	return dashboard.RuleSetState(v)
}

// auditRulesLoaded writes rule_repository.sync for rules the gateway loaded
// without a call: an update of the crowdsec rules in the background
// (system:hub_update) or rules.d after SIGHUP (system:sighup). load loads
// them; no entry when the rules that run are the same afterwards.
func (a *App) auditRulesLoaded(ctx context.Context, repository, operation string, load func()) {
	before := a.ruleSetOf(repository)
	mark := a.ruleSetMark(repository)
	load()
	after := a.ruleSetOf(repository)
	if a.Audit == nil || (reflect.DeepEqual(before, after) && mark == a.ruleSetMark(repository)) {
		return
	}
	if err := a.Audit.Write(ctx, auditlog.Entry{Action: "rule_repository.sync", Operation: operation, Actor: auditlog.System(), Subject: repository,
		Before: before, After: after}); err != nil {
		a.log.Error("audit log: loaded rules are not recorded; they run", "repository", repository, "err", err)
	}
}

// ruleSetMark names the set of rules a repository runs, so a new set with
// as many rules as the one before still counts as another one.
func (a *App) ruleSetMark(repository string) string {
	v, err := a.Repos.Repository(repository)
	if err != nil {
		return ""
	}
	switch {
	case repository == rules.RepoLocal:
		h := sha256.Sum256([]byte(a.Repos.LocalText()))
		return hex.EncodeToString(h[:8])
	case v.Crowdsec != nil:
		return v.Crowdsec.SetSource + "/" + v.Crowdsec.IndexSHA256 + "/" + v.Crowdsec.HubCommit
	}
	return ""
}

// auditClusterJoined writes cluster.join once for this node and its group:
// the node entered the group.
func (a *App) auditClusterJoined(ctx context.Context) {
	node := a.Cluster
	if a.Audit == nil || node == nil || node.Removed() {
		return
	}
	mark := "joined:" + node.Group() + ":" + node.ID()
	if v, err := a.Store.AuditState(ctx, mark); err != nil || v != "" {
		return
	}
	err := a.Audit.Tx(ctx, func(ctx context.Context, rec *auditlog.Rec) error {
		rec.Add(auditlog.Entry{Action: "cluster.join", Operation: "system:cluster", Actor: auditlog.System(), Subject: node.ID(),
			After: map[string]any{"name": node.Name(), "version": buildinfo.String()}})
		return a.Store.SetAuditState(ctx, mark, "1")
	})
	if err != nil {
		a.log.Warn("audit log: the entry into the group is not recorded", "err", err)
	}
}
