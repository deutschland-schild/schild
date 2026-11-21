package store

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// Tables a group of gateways shares as a whole (MVP-27, D103): the rows of
// one node replace the rows of the others. They are small and changed by a
// person or an agent, not by traffic.
var sharedTables = map[string]struct {
	table string
	cols  []string
	order string
}{
	"allowlist":      {"allowlist", []string{"id", "ip", "cidr", "host", "label", "level", "expires", "created_ms", "source"}, "id"},
	"ip_exceptions":  {"exceptions", []string{"id", "ip", "sources", "expires_ms", "incident"}, "id"},
	"rule_decisions": {"rule_decisions", []string{"repository", "rule", "kind", "version", "by", "token_id", "token_label", "note", "at"}, "repository, rule, kind"},
	"users":          {"users", []string{"name", "hash", "role", "created_ms"}, "name"},
	"sessions":       {"sessions", []string{"token_hash", "user", "csrf", "created_ms", "expires_ms"}, "token_hash"},
	"agent_tokens":   {"agent_tokens", []string{"id", "hash", "scope", "label", "created_ms", "expires_ms", "revoked_ms"}, "id"},
}

type sharedDump struct {
	Columns []string `json:"columns"`
	Rows    [][]any  `json:"rows"`
}

func quoted(cols []string) string {
	q := make([]string, len(cols))
	for i, c := range cols {
		q[i] = `"` + c + `"`
	}
	return strings.Join(q, ", ")
}

// DumpShared returns the rows of a shared table as JSON, the same bytes for
// the same rows on every node.
func (s *Store) DumpShared(ctx context.Context, name string) ([]byte, error) {
	t, ok := sharedTables[name]
	if !ok {
		return nil, fmt.Errorf("store: %q is no shared table", name)
	}
	rows, err := s.db.QueryContext(ctx, "SELECT "+quoted(t.cols)+" FROM "+t.table+" ORDER BY "+t.order)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	d := sharedDump{Columns: t.cols, Rows: [][]any{}}
	for rows.Next() {
		vals := make([]any, len(t.cols))
		ptrs := make([]any, len(t.cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		for i, v := range vals {
			if b, ok := v.([]byte); ok {
				vals[i] = string(b)
			}
		}
		d.Rows = append(d.Rows, vals)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return json.Marshal(d)
}

// RestoreShared replaces the rows of a shared table with a dump of another
// node, in one transaction. A dump with other columns (another version of
// schild) is refused and nothing changes.
func (s *Store) RestoreShared(ctx context.Context, name string, dump []byte) error {
	t, ok := sharedTables[name]
	if !ok {
		return fmt.Errorf("store: %q is no shared table", name)
	}
	var d sharedDump
	dec := json.NewDecoder(bytes.NewReader(dump))
	dec.UseNumber()
	if err := dec.Decode(&d); err != nil {
		return fmt.Errorf("store: dump of %s: %w", name, err)
	}
	if strings.Join(d.Columns, ",") != strings.Join(t.cols, ",") {
		return fmt.Errorf("store: dump of %s has other columns (another version of schild)", name)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, "DELETE FROM "+t.table); err != nil {
		return err
	}
	ins := "INSERT INTO " + t.table + "(" + quoted(t.cols) + ") VALUES(" + strings.TrimSuffix(strings.Repeat("?, ", len(t.cols)), ", ") + ")"
	for _, row := range d.Rows {
		if len(row) != len(t.cols) {
			return fmt.Errorf("store: dump of %s: a row has %d values", name, len(row))
		}
		for i, v := range row {
			if n, ok := v.(json.Number); ok {
				x, err := n.Int64()
				if err != nil {
					return fmt.Errorf("store: dump of %s: %w", name, err)
				}
				row[i] = x
			}
		}
		if _, err := tx.ExecContext(ctx, ins, row...); err != nil {
			return err
		}
	}
	if name == "allowlist" {
		if err := bumpAllowVersion(ctx, tx); err != nil {
			return err
		}
	}
	return tx.Commit()
}
