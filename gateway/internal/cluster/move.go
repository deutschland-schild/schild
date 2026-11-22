package cluster

import (
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	contract "github.com/deutschland-schild/schild/contract/cluster"
)

// A node moves to another group when the secret of its configuration names
// another group than the one its directory holds: the group secret became
// known and was replaced, and the same new file was deployed to every node.
// Nobody wipes a directory by hand for that. The node keeps its key (so its
// id, and with it the names of its events and the cursors of the other
// nodes, stay), sets itself up in the new group and carries over what it
// held of the old one: every live record of every class but members,
// tombstones too. The old directory is kept aside.
//
// A carried record is signed by this node for the new group and keeps the
// clock of the record it comes from. So it is exactly as old in the new
// group as it was in the old one: a change another node made in the new
// group meanwhile is later and wins, and a lift or an erasure a node carries
// in later still beats the block or the value an earlier node carried.

const (
	// asideMark names a directory of a group this node left:
	// <dir>.replaced-<UTC time>.
	asideMark = ".replaced-"
	// asideKeep is how many of them stay; older ones are removed.
	asideKeep = 2
	// carryBatch bounds one transaction of the carry-over.
	carryBatch = 2000
)

// Moved is what a move to another group did.
type Moved struct {
	From, To string
	// Carried counts the records taken along, Skipped those that were not:
	// their time was over, or this version cannot read them.
	Carried, Skipped int
	// Aside is where the directory of the group before is kept.
	Aside string
}

// move replaces the directory of a node that belongs to another group than
// gk's. The new directory is built next to the old one and takes its place
// only when it is complete: a failure on the way leaves the node in the
// group it was in.
func move(dir, name, address string, secret []byte, now func() time.Time) (*Moved, error) {
	if now == nil {
		now = time.Now
	}
	gk, err := contract.GroupKey(secret)
	if err != nil {
		return nil, err
	}
	old, err := openState(dir, false, now)
	if err != nil {
		return nil, err
	}
	defer old.close()
	stamp := now().UTC().Format("20060102T150405Z")
	fresh := dir + ".moving-" + stamp
	if err := os.RemoveAll(fresh); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(fresh, 0o700); err != nil {
		return nil, err
	}
	done := false
	defer func() {
		if !done {
			_ = os.RemoveAll(fresh)
		}
	}()
	key, err := os.ReadFile(filepath.Join(dir, keyFile))
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(fresh, keyFile), key, 0o600); err != nil {
		return nil, err
	}
	s, err := openState(fresh, false, now)
	if err != nil {
		return nil, err
	}
	closed := false
	defer func() {
		if !closed {
			s.close()
		}
	}()
	m, err := memberOf(name, address, s.pub, s.now())
	if err != nil {
		return nil, err
	}
	out := &Moved{From: old.group, To: m.AdmitWith(gk, s.pub)}
	if err := s.enter(out.To, secret); err != nil {
		return nil, err
	}
	// A node that was removed from the group before starts in the new one
	// with nothing: what it holds is of before its removal, and nobody
	// vouches for it.
	carry := true
	if v, err := old.meta("removed"); err == nil && len(v) > 0 {
		carry = false
	}
	if recs, _, err := old.winners(contract.ClassMembers); err != nil {
		return nil, err
	} else {
		for _, r := range recs {
			if r.ID == old.id && r.Deleted {
				carry = false
			}
		}
	}
	if _, err := s.publish(contract.ClassMembers, s.id, m, false, time.Time{}); err != nil {
		return nil, err
	}
	if carry {
		if out.Carried, out.Skipped, err = s.carryFrom(old); err != nil {
			return nil, err
		}
	}
	s.close()
	closed = true
	old.close()

	out.Aside = dir + asideMark + stamp
	if err := os.RemoveAll(out.Aside); err != nil {
		return nil, err
	}
	if err := os.Rename(dir, out.Aside); err != nil {
		return nil, err
	}
	if err := os.Rename(fresh, dir); err != nil {
		// Back to the group before: nothing of it was touched.
		if back := os.Rename(out.Aside, dir); back != nil {
			return nil, fmt.Errorf("cluster: the new directory could not take its place (%w) and the old one is at %s", err, out.Aside)
		}
		return nil, err
	}
	done = true
	pruneAside(dir)
	return out, nil
}

// enter makes an empty state a node of group, with the hash key the secret
// gives every node of it.
func (s *state) enter(group string, secret []byte) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := setMeta(tx, "group", []byte(group)); err != nil {
		return err
	}
	hk := sha256.Sum256(append([]byte("schild-group-hash-key:"), secret...))
	if err := setMeta(tx, metaHashKey, hk[:16]); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.group = group
	return nil
}

// carryFrom takes along what this node held in the group before: the
// records that are the state of every class but members, each signed anew
// for this group under this node's key with the clock it had, and the notes
// the node keeps next to its records (what of its own values it brought in
// step, how far it read the other nodes' events and requests). The bounds
// of a record hold as they did when it was taken.
func (s *state) carryFrom(old *state) (carried, skipped int, err error) {
	nowMS := s.now().UnixMilli()
	rows, err := old.db.Query(`SELECT class, state, expires_ms, raw FROM records WHERE class != ? ORDER BY hlc, origin, seq`, contract.ClassMembers)
	if err != nil {
		return 0, 0, err
	}
	defer rows.Close()
	var seq int64
	if err := s.db.QueryRow(`SELECT seq FROM vector WHERE origin = ?`, s.id).Scan(&seq); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return 0, 0, err
	}
	s.wmu.Lock()
	defer s.wmu.Unlock()
	var tx *sql.Tx
	inTx := 0
	var top uint64
	flush := func() error {
		if tx == nil {
			return nil
		}
		if err := raiseVector(tx, s.id, uint64(seq)); err != nil {
			tx.Rollback()
			return err
		}
		err := tx.Commit()
		tx, inTx = nil, 0
		return err
	}
	for rows.Next() {
		var class string
		var st int
		var expires int64
		var raw []byte
		if err := rows.Scan(&class, &st, &expires, &raw); err != nil {
			return carried, skipped, err
		}
		var r contract.Record
		if st != stateWinner || (expires != 0 && expires < nowMS) || json.Unmarshal(raw, &r) != nil || r.V != contract.Version {
			skipped++
			continue
		}
		data, err := r.Payload()
		if err != nil {
			skipped++
			continue
		}
		rec := &contract.Record{V: contract.Version, Group: s.group, Class: r.Class, ID: r.ID, Origin: s.id, Seq: uint64(seq) + 1, HLC: r.HLC, Deleted: r.Deleted, Expires: r.Expires}
		var payload any
		if data != nil {
			payload = json.RawMessage(data)
		}
		if err := rec.Sign(s.key, payload); err != nil {
			skipped++
			continue
		}
		out, err := json.Marshal(rec)
		if err != nil {
			skipped++
			continue
		}
		if tx == nil {
			if tx, err = s.db.Begin(); err != nil {
				return carried, skipped, err
			}
		}
		if _, err := put(tx, rec, out); err != nil {
			tx.Rollback()
			return carried, skipped, err
		}
		seq++
		carried++
		top = max(top, r.HLC)
		if inTx++; inTx >= carryBatch {
			if err := flush(); err != nil {
				return carried, skipped, err
			}
		}
	}
	if err := rows.Err(); err != nil {
		if tx != nil {
			tx.Rollback()
		}
		return carried, skipped, err
	}
	if err := flush(); err != nil {
		return carried, skipped, err
	}
	// The clock goes on after everything carried and after what this node
	// wrote before, and the notes come along.
	if tx, err = s.db.Begin(); err != nil {
		return carried, skipped, err
	}
	defer tx.Rollback()
	var last int64
	if err := old.db.QueryRow(`SELECT CAST(v AS INTEGER) FROM meta WHERE k = 'hlc'`).Scan(&last); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return carried, skipped, err
	}
	var mine int64
	if err := tx.QueryRow(`SELECT CAST(v AS INTEGER) FROM meta WHERE k = 'hlc'`).Scan(&mine); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return carried, skipped, err
	}
	if err := setMeta(tx, "hlc", []byte(fmt.Sprint(max(uint64(last), uint64(mine), top)))); err != nil {
		return carried, skipped, err
	}
	marks, err := old.db.Query(`SELECT k, v FROM meta WHERE k LIKE 'mark:%'`)
	if err != nil {
		return carried, skipped, err
	}
	defer marks.Close()
	for marks.Next() {
		var k string
		var v []byte
		if err := marks.Scan(&k, &v); err != nil {
			return carried, skipped, err
		}
		if err := setMeta(tx, k, v); err != nil {
			return carried, skipped, err
		}
	}
	if err := marks.Err(); err != nil {
		return carried, skipped, err
	}
	return carried, skipped, tx.Commit()
}

// pruneAside removes the directories of groups left before, but the newest
// asideKeep. Their names sort by time.
func pruneAside(dir string) {
	parent, base := filepath.Dir(dir), filepath.Base(dir)
	entries, err := os.ReadDir(parent)
	if err != nil {
		return
	}
	var aside []string
	for _, e := range entries {
		if e.IsDir() && strings.HasPrefix(e.Name(), base+asideMark) {
			aside = append(aside, e.Name())
		}
	}
	sort.Strings(aside)
	for i := 0; i < len(aside)-asideKeep; i++ {
		_ = os.RemoveAll(filepath.Join(parent, aside[i]))
	}
}
