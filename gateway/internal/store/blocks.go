package store

import (
	"context"
	"database/sql"
	"net/netip"
	"time"

	"github.com/deutschland-schild/schild/contract/events"
)

// D29 amendment (2026-10-29): behaviour blocks over 24 h (7 days for
// data-centre addresses that come back) are kept here with their expiry and
// reloaded at start, so a restart never ends them early. Rows are removed
// when the block ends, is released, the address is deleted (Art. 17) or
// allowlisted.

const blocksSchema = `
CREATE TABLE kept_blocks (
  client_key TEXT PRIMARY KEY,
  key_bits INTEGER NOT NULL,
  net_class TEXT NOT NULL,
  source TEXT NOT NULL,
  level INTEGER NOT NULL,
  duration_s INTEGER NOT NULL,
  since_ms INTEGER NOT NULL,
  until_ms INTEGER NOT NULL,
  incident TEXT NOT NULL DEFAULT ''
);
`

// PutBlock keeps (or replaces) the block of one client key, as one this
// gateway decided.
func (s *Store) PutBlock(ctx context.Context, b events.ActiveBlock) error {
	return s.putBlock(ctx, b, true)
}

// PutTakenBlock keeps a block a node took from its group: another node
// decided it, and this one never writes it to the group as its own.
func (s *Store) PutTakenBlock(ctx context.Context, b events.ActiveBlock) error {
	return s.putBlock(ctx, b, false)
}

func (s *Store) putBlock(ctx context.Context, b events.ActiveBlock, own bool) error {
	since, err := time.Parse(time.RFC3339, b.Since)
	if err != nil {
		return err
	}
	until, err := time.Parse(time.RFC3339, b.Until)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT OR REPLACE INTO kept_blocks(client_key, key_bits, net_class, source, level, duration_s, since_ms, until_ms, incident, own)
VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, b.ClientKey, b.KeyBits, b.NetClass, b.Source, b.Level, b.DurationS, ms(since), ms(until), b.Incident, own)
	return err
}

// OwnKeptBlocks marks every kept block as a decision of this gateway: on a
// gateway that is in no group each one is, also a row a build before the
// mark kept. So a gateway that joins a group later hands its long blocks to
// the group.
func (s *Store) OwnKeptBlocks(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `UPDATE kept_blocks SET own = 1 WHERE own = 0`)
	return err
}

// TakenBlocks returns the client keys of the kept blocks this gateway did
// not decide itself, as far as it knows: those it took from its group, and
// those a build before the mark kept.
func (s *Store) TakenBlocks(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT client_key FROM kept_blocks WHERE own = 0`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// DeleteBlock removes the kept block of a client key.
func (s *Store) DeleteBlock(ctx context.Context, clientKey string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM kept_blocks WHERE client_key = ?`, clientKey)
	return err
}

// ListBlocks returns every kept block (also ended ones; the caller drops
// those).
func (s *Store) ListBlocks(ctx context.Context) ([]events.ActiveBlock, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT client_key, key_bits, net_class, source, level, duration_s, since_ms, until_ms, incident FROM kept_blocks ORDER BY until_ms`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []events.ActiveBlock
	for rows.Next() {
		var b events.ActiveBlock
		var since, until int64
		if err := rows.Scan(&b.ClientKey, &b.KeyBits, &b.NetClass, &b.Source, &b.Level, &b.DurationS, &since, &until, &b.Incident); err != nil {
			return nil, err
		}
		b.Since = time.UnixMilli(since).UTC().Format(time.RFC3339)
		b.Until = time.UnixMilli(until).UTC().Format(time.RFC3339)
		out = append(out, b)
	}
	return out, rows.Err()
}

// blockKeyOf is the client key of a kept block for ip: the address for
// IPv4, the first address of the /64 for IPv6.
func blockKeyOf(ip string) string {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return ""
	}
	a = a.Unmap()
	if a.Is4() {
		return a.String()
	}
	p, _ := a.WithZone("").Prefix(64)
	return p.Addr().String()
}

func deleteBlockTx(ctx context.Context, tx *sql.Tx, ip string) error {
	k := blockKeyOf(ip)
	if k == "" {
		return nil
	}
	_, err := tx.ExecContext(ctx, `DELETE FROM kept_blocks WHERE client_key = ?`, k)
	return err
}
