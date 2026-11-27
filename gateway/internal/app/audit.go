package app

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"

	"github.com/deutschland-schild/schild/contract/config"
	"github.com/deutschland-schild/schild/contract/rules"
	"github.com/deutschland-schild/schild/gateway/internal/auditlog"
)

// openAudit opens the audit log of this gateway (MVP-36): audit.db in the
// data directory, a file of its own outside retention.max_size_mb and the
// disk budget. It never keeps the gateway from starting because of its
// size; a file that cannot be read is kept under another name and a new log
// starts (auditlog.Open).
func (a *App) openAudit(ctx context.Context, cfg *config.Site) error {
	stream, err := auditStream(cfg.Audit.Stream)
	if err != nil {
		// The copy never holds the gateway back: said once, and the log
		// itself is written.
		a.log.Error("audit.stream cannot be opened: the audit log is written, the copy is not", "stream", cfg.Audit.Stream, "err", err)
	}
	a.auditStream = stream
	l, err := auditlog.Open(ctx, a.Store, filepath.Join(a.dataDir, auditlog.FileName), auditlog.Options{
		Node:     a.eventNode(cfg),
		KeepDays: func() int64 { return a.Config().Audit.Days() },
		Stream:   stream,
		Log:      a.log,
		Now:      a.opts.Now,
	})
	if err != nil {
		return fmt.Errorf("open audit log in %s: %w", a.dataDir, err)
	}
	a.Audit = l
	return nil
}

// auditStream opens the copy of the audit log: stdout, or a file that is
// appended to (mode 0600: an entry holds addresses and names).
func auditStream(target string) (io.Writer, error) {
	switch target {
	case "":
		return nil, nil
	case "stdout":
		return os.Stdout, nil
	}
	return os.OpenFile(target, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
}

// closeAudit closes the audit log and the file of its copy.
func (a *App) closeAudit() {
	_ = a.Audit.Close()
	if c, ok := a.auditStream.(io.Closer); ok && a.auditStream != io.Writer(os.Stdout) {
		_ = c.Close()
	}
}

// retainAudit deletes the audit entries that are past their age
// (audit.keep_days; contracts/audit.md section 6).
func (a *App) retainAudit(ctx context.Context) {
	n, err := a.Audit.Retain(ctx)
	if err != nil {
		a.log.Error("audit log retention", "err", err)
		return
	}
	if n > 0 {
		a.log.Info("audit log: entries past audit.keep_days deleted", "deleted", n)
	}
}

// putAudited writes a value the app keeps under a key and the entries of
// the change in one transaction of schild.db (contracts/audit.md section
// 4). entries builds them from the origin of the change, which the handler
// of the call put into ctx. A change without an origin (a member of the
// group handed it over, the start read it) writes the value alone. The
// caller may hold its own lock: the transaction is around this write only.
func (a *App) putAudited(ctx context.Context, key string, raw []byte, entries func(o auditlog.Origin) []auditlog.Entry) error {
	return a.writeAudited(ctx, entries, func(ctx context.Context) error { return a.Store.Put(ctx, key, raw) })
}

// writeAudited is putAudited for any write of the store.
func (a *App) writeAudited(ctx context.Context, entries func(o auditlog.Origin) []auditlog.Entry, write func(ctx context.Context) error) error {
	o, ok := auditlog.OriginOf(ctx)
	if !ok || entries == nil {
		return write(ctx)
	}
	return a.Audit.Tx(ctx, func(ctx context.Context, rec *auditlog.Rec) error {
		rec.Add(entries(o)...)
		return write(ctx)
	})
}

// one is the entries of a change with a single entry.
func one(action, subject, website string, before, after any) func(o auditlog.Origin) []auditlog.Entry {
	return func(o auditlog.Origin) []auditlog.Entry {
		e := o.Entry(action)
		e.Subject, e.Website, e.Before, e.After = subject, website, before, after
		e.IfChanged = true
		return []auditlog.Entry{e}
	}
}

// asMap is a value as the JSON object it marshals to.
func asMap(v any) map[string]any {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return nil
	}
	return m
}

// modesAndThresholds splits {"<id>": {"mode": ..., "thresholds": {...}}}
// into the modes and the thresholds by id, as behaviour.set and
// distributed.set record them.
func modesAndThresholds(v any) (modes, thresholds map[string]any) {
	modes, thresholds = map[string]any{}, map[string]any{}
	for id, x := range asMap(v) {
		m, _ := x.(map[string]any)
		if mode, ok := m["mode"]; ok {
			modes[id] = mode
		}
		if t, ok := m["thresholds"].(map[string]any); ok && len(t) > 0 {
			thresholds[id] = t
		}
	}
	return modes, thresholds
}

// behaviourState is what behaviour.set records of a configuration: the mode
// and the thresholds of every scenario and the modes of the preset limits,
// as they are in force.
func behaviourState(c *config.Site) map[string]any {
	modes, thresholds := modesAndThresholds(c.Behaviour.Scenarios)
	return map[string]any{"scenarios": modes, "thresholds": thresholds, "preset_limit_modes": c.Behaviour.PresetLimitModes}
}

// distributedState is what distributed.set records.
func distributedState(c *config.Site) map[string]any {
	modes, thresholds := modesAndThresholds(c.Behaviour.Distributed.Detectors)
	return map[string]any{"detectors": modes, "thresholds": thresholds}
}

// limitState is what the rate_limit actions record of a limit.
func limitState(l config.RateLimit) map[string]any {
	m := map[string]any{"route": l.Route, "limit": l.Limit, "per": l.Per, "burst": l.Burst, "mode": l.Mode}
	if len(l.Methods) > 0 {
		m["methods"] = l.Methods
	}
	if l.Site != "" {
		m["site"] = l.Site
	}
	if l.Label != "" {
		m["label"] = l.Label
	}
	return m
}

// limitEntries are the entries of a new list of dashboard rate limits: one
// per limit that was added, changed or removed.
func limitEntries(o auditlog.Origin, old, now []config.RateLimit) []auditlog.Entry {
	byID := func(ls []config.RateLimit) map[string]config.RateLimit {
		m := map[string]config.RateLimit{}
		for _, l := range ls {
			m[l.ID] = l
		}
		return m
	}
	was, is := byID(old), byID(now)
	var out []auditlog.Entry
	add := func(action, id string, before, after any) {
		e := o.Entry(action)
		e.Subject, e.Before, e.After = id, before, after
		e.IfChanged = true
		out = append(out, e)
	}
	for _, l := range now {
		if prev, ok := was[l.ID]; !ok {
			add("rate_limit.add", l.ID, nil, limitState(l))
		} else if !reflect.DeepEqual(limitState(prev), limitState(l)) {
			add("rate_limit.update", l.ID, limitState(prev), limitState(l))
		}
	}
	for _, l := range old {
		if _, ok := is[l.ID]; !ok {
			add("rate_limit.remove", l.ID, limitState(l), nil)
		}
	}
	return out
}

// repoConfigState is what rule_repository.set records of a repository: its
// state and, for the CRS, paranoia level and threshold, as they are in
// force.
func repoConfigState(c *config.Site, repository string) map[string]any {
	switch repository {
	case rules.RepoCRS:
		return map[string]any{"state": c.Rules.CRS.State, "paranoia_level": c.Rules.CRS.ParanoiaLevel, "inbound_anomaly_threshold": c.Rules.CRS.InboundAnomalyThreshold}
	case rules.RepoCrowdsec:
		return map[string]any{"state": c.Rules.Crowdsec.State}
	case rules.RepoLocal:
		return map[string]any{"state": c.Rules.Local.State}
	}
	return map[string]any{}
}
