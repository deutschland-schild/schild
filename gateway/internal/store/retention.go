package store

import (
	"context"
	"net/netip"
	"time"

	"github.com/deutschland-schild/schild/gateway/internal/clientip"
)

// Retention limits (schild.yaml retention, concept 24 V1).
type Retention struct {
	RawIPDays     int
	EventsDays    int
	MaxSizeMB     int
	SummariesDays int
}

// RetentionResult counts what one run changed.
type RetentionResult struct {
	Truncated    int
	Deleted      int
	DeletedSize  int
	SummariesOld int
	// KeptBlocks, Allow: ended kept blocks and expired allowlist entries
	// deleted (D38).
	KeptBlocks int
	Allow      int
	// Cap is the size-cap pass (nil with max_size_mb 0).
	Cap *CapResult
}

// TruncateFunc rewrites the stored CloudEvent JSON with a shortened address.
type TruncateFunc func(body []byte, short string) []byte

// ApplyRetention truncates raw IPs, deletes old events, incidents and
// summaries, ended kept blocks and expired allowlist rows, and runs one
// size-cap pass (D38).
func (s *Store) ApplyRetention(ctx context.Context, now time.Time, r Retention, trunc TruncateFunc) (*RetentionResult, error) {
	res := &RetentionResult{}
	ipCut := ms(now.Add(-time.Duration(r.RawIPDays) * 24 * time.Hour))
	for {
		n, err := s.truncateBatch(ctx, ipCut, trunc)
		if err != nil {
			return res, err
		}
		res.Truncated += n
		if n == 0 {
			break
		}
	}
	// Incidents keep only the truncated address after the raw-IP period too.
	rows, err := s.db.QueryContext(ctx, "SELECT incident, ip FROM incidents WHERE time_ms < ?", ipCut)
	if err != nil {
		return res, err
	}
	type pair struct{ id, ip string }
	var ps []pair
	for rows.Next() {
		var p pair
		if err := rows.Scan(&p.id, &p.ip); err != nil {
			rows.Close()
			return res, err
		}
		ps = append(ps, p)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return res, err
	}
	for _, p := range ps {
		if a, err := netip.ParseAddr(p.ip); err == nil {
			if short := clientip.Truncate(a).String(); short != p.ip {
				if _, err := s.db.ExecContext(ctx, "UPDATE incidents SET ip = ? WHERE incident = ?", short, p.id); err != nil {
					return res, err
				}
			}
		}
	}

	evCut := ms(now.Add(-time.Duration(r.EventsDays) * 24 * time.Hour))
	if x, err := s.db.ExecContext(ctx, "DELETE FROM events WHERE time_ms < ?", evCut); err == nil {
		n, _ := x.RowsAffected()
		res.Deleted = int(n)
	} else {
		return res, err
	}
	if _, err := s.db.ExecContext(ctx, "DELETE FROM incidents WHERE time_ms < ?", evCut); err != nil {
		return res, err
	}
	if _, err := s.db.ExecContext(ctx, "DELETE FROM exceptions WHERE expires_ms < ?", ms(now)); err != nil {
		return res, err
	}
	if _, err := s.db.ExecContext(ctx, "DELETE FROM sessions WHERE expires_ms < ?", ms(now)); err != nil {
		return res, err
	}
	sumCut := now.Add(-time.Duration(r.SummariesDays)*24*time.Hour).Unix() / 3600
	if x, err := s.db.ExecContext(ctx, "DELETE FROM summaries WHERE hour < ?", sumCut); err == nil {
		n, _ := x.RowsAffected()
		res.SummariesOld = int(n)
	} else {
		return res, err
	}
	// D38: kept behaviour blocks that ended and allowlist entries past their
	// expiry.
	if x, err := s.db.ExecContext(ctx, "DELETE FROM kept_blocks WHERE until_ms < ?", ms(now)); err == nil {
		n, _ := x.RowsAffected()
		res.KeptBlocks = int(n)
	} else {
		return res, err
	}
	n, err := s.pruneAllow(ctx, now)
	res.Allow = n
	if err != nil {
		return res, err
	}
	// Size cap (D38, capacity.go).
	if r.MaxSizeMB > 0 {
		c, err := s.SizeCap(ctx, r.MaxSizeMB)
		res.Cap = c
		if c != nil {
			res.DeletedSize = c.Total() - c.Calls
		}
		if err != nil {
			return res, err
		}
	}
	_, _ = s.db.ExecContext(ctx, "PRAGMA incremental_vacuum")
	return res, nil
}

// pruneAllow deletes stored allowlist entries whose expiry passed (config
// entries are not stored). It bumps the allowlist version when it deleted
// one.
func (s *Store) pruneAllow(ctx context.Context, now time.Time) (int, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT id, expires FROM allowlist WHERE expires NOT IN ('', 'never')")
	if err != nil {
		return 0, err
	}
	var gone []string
	for rows.Next() {
		var id, exp string
		if err := rows.Scan(&id, &exp); err != nil {
			rows.Close()
			return 0, err
		}
		if t, err := time.Parse(time.RFC3339, exp); err == nil && !t.After(now) {
			gone = append(gone, id)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	if len(gone) == 0 {
		return 0, nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	if err := deleteIn(ctx, tx, "allowlist", "id", gone); err != nil {
		return 0, err
	}
	if err := bumpAllowVersion(ctx, tx); err != nil {
		return 0, err
	}
	return len(gone), tx.Commit()
}

func (s *Store) truncateBatch(ctx context.Context, cut int64, trunc TruncateFunc) (int, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT seq, ip, body FROM events WHERE ip_truncated = 0 AND time_ms < ? LIMIT 2000", cut)
	if err != nil {
		return 0, err
	}
	type upd struct {
		seq   int64
		ip    string
		body  []byte
		short string
	}
	var ups []upd
	for rows.Next() {
		var u upd
		if err := rows.Scan(&u.seq, &u.ip, &u.body); err != nil {
			rows.Close()
			return 0, err
		}
		u.short = u.ip
		if a, err := netip.ParseAddr(u.ip); err == nil {
			u.short = clientip.Truncate(a).String()
		}
		if trunc != nil && u.ip != "" {
			u.body = trunc(u.body, u.short)
		}
		ups = append(ups, u)
	}
	rows.Close()
	// A read that broke off must not pass for "nothing left to truncate".
	if err := rows.Err(); err != nil {
		return 0, err
	}
	if len(ups) == 0 {
		return 0, nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	for _, u := range ups {
		if _, err := tx.ExecContext(ctx, "UPDATE events SET ip = ?, ip_key = ?, ip_truncated = 1, body = ? WHERE seq = ?", u.short, ipKey(u.short), u.body, u.seq); err != nil {
			return 0, err
		}
	}
	return len(ups), tx.Commit()
}
