package hosts

import (
	"context"
	"encoding/json"

	"github.com/deutschland-schild/schild/gateway/internal/hostcheck"
)

// Accepted findings (D102). An admin marks an open finding of a host as
// accepted, for example a port that a firewall in front of the server
// closes, which the check on the host cannot see. The stored report is
// never changed: the acceptance lives in a table of its own and is applied
// when the gateway counts the findings of the newest report.
//
// It holds for later reports as long as the finding keeps its check id
// and subject and does not come back with a higher severity than the one
// that was accepted. Like the reports, it never leaves this gateway.

// MaxAccepted bounds the accepted findings of one host.
const MaxAccepted = 200

const acceptSchema = `
CREATE TABLE IF NOT EXISTS host_accepted (
  host_id TEXT NOT NULL,
  finding_id TEXT NOT NULL,
  subject TEXT NOT NULL DEFAULT '',
  severity TEXT NOT NULL,
  note TEXT NOT NULL DEFAULT '',
  accepted_ms INTEGER NOT NULL,
  PRIMARY KEY (host_id, finding_id, subject)
);
`

// AcceptedFinding is one entry of HostDetail.accepted.
type AcceptedFinding struct {
	ID         string  `json:"id"`
	Subject    *string `json:"subject"`
	Severity   string  `json:"severity"`
	Note       *string `json:"note"`
	AcceptedAt string  `json:"accepted_at"`
	Active     bool    `json:"active"`
}

type findingKey struct{ id, subject string }

type acceptedRow struct {
	key        findingKey
	severity   string
	note       string
	acceptedMS int64
}

// reportFinding is what counting needs of a finding.
type reportFinding struct {
	ID       string  `json:"id"`
	Subject  *string `json:"subject"`
	Severity string  `json:"severity"`
	Status   string  `json:"status"`
}

func (f reportFinding) key() findingKey {
	k := findingKey{id: f.ID}
	if f.Subject != nil {
		k.subject = *f.Subject
	}
	return k
}

func reportFindings(body []byte) []reportFinding {
	var r struct {
		Findings []reportFinding `json:"findings"`
	}
	if body == nil || json.Unmarshal(body, &r) != nil {
		return nil
	}
	return r.Findings
}

func (g *Gateway) acceptedRows(ctx context.Context, hostID string) ([]acceptedRow, error) {
	rows, err := g.db.QueryContext(ctx, `SELECT finding_id, subject, severity, note, accepted_ms FROM host_accepted
		WHERE host_id = ? ORDER BY accepted_ms DESC, finding_id, subject`, hostID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []acceptedRow
	for rows.Next() {
		var r acceptedRow
		if err := rows.Scan(&r.key.id, &r.key.subject, &r.severity, &r.note, &r.acceptedMS); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// covers reports whether an acceptance at severity accepted covers a
// finding of severity now: the same or lower, never higher.
func covers(accepted, now string) bool {
	return hostcheck.SeverityRank(now) <= hostcheck.SeverityRank(accepted)
}

// applyAccepted counts the open findings of a report without the accepted
// ones and returns the keys of the acceptances in force.
func applyAccepted(body []byte, rows []acceptedRow) (SeverityCounts, map[findingKey]bool) {
	by := make(map[findingKey]string, len(rows))
	for _, r := range rows {
		by[r.key] = r.severity
	}
	var c SeverityCounts
	active := map[findingKey]bool{}
	for _, f := range reportFindings(body) {
		if f.Status != "finding" {
			continue
		}
		if sev, ok := by[f.key()]; ok && covers(sev, f.Severity) {
			active[f.key()] = true
			continue
		}
		switch f.Severity {
		case "critical":
			c.Critical++
		case "high":
			c.High++
		case "medium":
			c.Medium++
		case "low":
			c.Low++
		default:
			c.Info++
		}
	}
	return c, active
}

// accepted returns the accepted findings of a host for the API, newest
// first, each with whether it is in force for the newest report.
func (g *Gateway) accepted(ctx context.Context, hostID string, body []byte) ([]AcceptedFinding, error) {
	rows, err := g.acceptedRows(ctx, hostID)
	if err != nil {
		return nil, err
	}
	_, active := applyAccepted(body, rows)
	out := []AcceptedFinding{}
	for _, r := range rows {
		a := AcceptedFinding{ID: r.key.id, Severity: r.severity, AcceptedAt: ts(fromMS(r.acceptedMS)), Active: active[r.key]}
		if r.key.subject != "" {
			s := r.key.subject
			a.Subject = &s
		}
		if r.note != "" {
			n := r.note
			a.Note = &n
		}
		out = append(out, a)
	}
	return out, nil
}

func (g *Gateway) hostExists(ctx context.Context, hostID string) error {
	hs, err := g.Hosts(ctx)
	if err != nil {
		return err
	}
	for _, h := range hs {
		if h.ID == hostID {
			return nil
		}
	}
	return ErrNotFound
}

// AcceptFinding marks an open finding of the newest report of a host as
// accepted. The severity comes from the report, never from the caller.
// ErrNotFound: no such host or no open finding with this id and subject.
func (g *Gateway) AcceptFinding(ctx context.Context, hostID, id, subject, note string) (*HostDetail, error) {
	if err := g.hostExists(ctx, hostID); err != nil {
		return nil, err
	}
	body, err := g.newestBody(ctx, hostID)
	if err != nil {
		return nil, err
	}
	severity := ""
	for _, f := range reportFindings(body) {
		if f.Status == "finding" && f.key() == (findingKey{id, subject}) {
			severity = f.Severity
		}
	}
	if severity == "" {
		return nil, ErrNotFound
	}
	tx, err := g.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var n, have int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM host_accepted WHERE host_id = ?", hostID).Scan(&n); err != nil {
		return nil, err
	}
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM host_accepted WHERE host_id = ? AND finding_id = ? AND subject = ?", hostID, id, subject).Scan(&have); err != nil {
		return nil, err
	}
	if have == 0 && n >= MaxAccepted {
		return nil, ErrConflict
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO host_accepted(host_id, finding_id, subject, severity, note, accepted_ms) VALUES(?, ?, ?, ?, ?, ?)
		ON CONFLICT(host_id, finding_id, subject) DO UPDATE SET severity = excluded.severity, note = excluded.note, accepted_ms = excluded.accepted_ms`,
		hostID, id, subject, severity, note, ms(g.now())); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return g.Host(ctx, hostID)
}

// ReopenFinding takes an acceptance back. ErrNotFound: no such host or
// acceptance.
func (g *Gateway) ReopenFinding(ctx context.Context, hostID, id, subject string) (*HostDetail, error) {
	if err := g.hostExists(ctx, hostID); err != nil {
		return nil, err
	}
	res, err := g.db.ExecContext(ctx, "DELETE FROM host_accepted WHERE host_id = ? AND finding_id = ? AND subject = ?", hostID, id, subject)
	if err != nil {
		return nil, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil, ErrNotFound
	}
	return g.Host(ctx, hostID)
}
