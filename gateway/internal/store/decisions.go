package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

// Rule decisions (D73): one table for every rule repository. A rule is
// disabled by a person or an agent (kind disabled, no version), or one
// version of an update is approved or rejected (one record per rule: the
// latest replaces the other). Rules disabled in schild.yaml are not stored.
const decisionsSchema = `
CREATE TABLE rule_decisions (
  repository  TEXT NOT NULL,
  rule        TEXT NOT NULL,
  kind        TEXT NOT NULL,
  version     TEXT NOT NULL DEFAULT '',
  by          TEXT NOT NULL,
  token_id    TEXT NOT NULL DEFAULT '',
  token_label TEXT NOT NULL DEFAULT '',
  note        TEXT NOT NULL DEFAULT '',
  at          INTEGER NOT NULL,
  PRIMARY KEY (repository, rule, kind)
);
`

// Decision kinds.
const (
	DecisionDisabled = "disabled"
	DecisionApproved = "approved"
	DecisionRejected = "rejected"
)

// RuleDecision is one row of rule_decisions.
type RuleDecision struct {
	Repository string
	Rule       string
	Kind       string
	Version    string
	By         string // dashboard | agent
	TokenID    string
	TokenLabel string
	Note       string
	At         time.Time
}

// RuleDecisions returns every stored decision.
func (s *Store) RuleDecisions(ctx context.Context) ([]RuleDecision, error) {
	rows, err := s.q(ctx).QueryContext(ctx, `SELECT repository, rule, kind, version, by, token_id, token_label, note, at FROM rule_decisions ORDER BY repository, rule, kind`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RuleDecision
	for rows.Next() {
		var d RuleDecision
		var at int64
		if err := rows.Scan(&d.Repository, &d.Rule, &d.Kind, &d.Version, &d.By, &d.TokenID, &d.TokenLabel, &d.Note, &at); err != nil {
			return nil, err
		}
		d.At = time.Unix(at, 0).UTC()
		out = append(out, d)
	}
	return out, rows.Err()
}

// RuleDecisionKey is the key a change of a rule decision is told under
// (OnChange).
func RuleDecisionKey(repository, rule, kind string) string {
	return "rule_decisions/" + repository + "/" + rule + "/" + kind
}

func (s *Store) ruleDecision(ctx context.Context, repository, rule, kind string) ([]byte, error) {
	var d RuleDecision
	var at int64
	err := s.q(ctx).QueryRowContext(ctx, `SELECT repository, rule, kind, version, by, token_id, token_label, note, at FROM rule_decisions WHERE repository = ? AND rule = ? AND kind = ?`,
		repository, rule, kind).Scan(&d.Repository, &d.Rule, &d.Kind, &d.Version, &d.By, &d.TokenID, &d.TokenLabel, &d.Note, &at)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	d.At = time.Unix(at, 0).UTC()
	return json.Marshal(d)
}

// PutRuleDecision stores a decision. An approval or a rejection replaces the
// other one of the same rule: a rule has one record for one version. With a
// hook in ctx (OnChange) the write and the hook are one transaction.
func (s *Store) PutRuleDecision(ctx context.Context, d RuleDecision) error {
	return s.InTx(ctx, func(ctx context.Context) error {
		hook := hookOf(ctx)
		var old []byte
		if hook != nil {
			var err error
			if old, err = s.ruleDecision(ctx, d.Repository, d.Rule, d.Kind); err != nil {
				return err
			}
		}
		if d.Kind == DecisionApproved || d.Kind == DecisionRejected {
			if _, err := s.q(ctx).ExecContext(ctx, `DELETE FROM rule_decisions WHERE repository = ? AND rule = ? AND kind IN (?, ?)`,
				d.Repository, d.Rule, DecisionApproved, DecisionRejected); err != nil {
				return err
			}
		}
		if _, err := s.q(ctx).ExecContext(ctx, `INSERT OR REPLACE INTO rule_decisions (repository, rule, kind, version, by, token_id, token_label, note, at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, d.Repository, d.Rule, d.Kind, d.Version, d.By, d.TokenID, d.TokenLabel, d.Note, d.At.Unix()); err != nil {
			return err
		}
		if hook == nil {
			return nil
		}
		now, err := json.Marshal(d)
		if err != nil {
			return err
		}
		return hook(ctx, Change{Key: RuleDecisionKey(d.Repository, d.Rule, d.Kind), Old: old, New: now})
	})
}

// DeleteRuleDecision removes one decision; a missing one is no error.
func (s *Store) DeleteRuleDecision(ctx context.Context, repository, rule, kind string) error {
	del := func(ctx context.Context) error {
		_, err := s.q(ctx).ExecContext(ctx, `DELETE FROM rule_decisions WHERE repository = ? AND rule = ? AND kind = ?`, repository, rule, kind)
		return err
	}
	hook := hookOf(ctx)
	if hook == nil {
		return del(ctx)
	}
	return s.InTx(ctx, func(ctx context.Context) error {
		old, err := s.ruleDecision(ctx, repository, rule, kind)
		if err != nil {
			return err
		}
		if err := del(ctx); err != nil {
			return err
		}
		if old == nil {
			return nil // nothing was there: no change to tell
		}
		return hook(ctx, Change{Key: RuleDecisionKey(repository, rule, kind), Old: old})
	})
}
