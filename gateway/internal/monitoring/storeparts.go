package monitoring

import (
	"bytes"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"time"

	cm "github.com/deutschland-schild/schild/contract/monitoring"
)

// storeLayout 3: the gateway core per ring row, website cores and top lists
// as part rows (codecparts.go). A ring of another layout starts over.
const storeLayout = 3

func partTable(r cm.Resolution) string { return tableOf(r) + "_part" }

// openRing creates the tables of a ring. A changed ring length changes the
// slot arithmetic, another layout the rows: that ring starts over. Table names are the constants of
// tableOf and partTable, never input.
func (s *ringStore) openRing(r cm.Ring) error {
	tbl, ptbl := tableOf(r.Resolution), partTable(r.Resolution)
	var v string
	// Only a missing row means a new ring: a failed read (busy, I/O) must
	// not pass for a changed layout, which drops the ring's history.
	if err := s.db.QueryRow(`SELECT v FROM meta WHERE k = ?`, tbl).Scan(&v); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	want := fmt.Sprintf("%d/layout%d", r.Slots(), storeLayout)
	if v != want {
		for _, t := range []string{tbl, ptbl} {
			if _, err := s.db.Exec(`DROP TABLE IF EXISTS ` + t); err != nil {
				return err
			}
		}
	}
	if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS ` + tbl + ` (slot INTEGER PRIMARY KEY, t INTEGER NOT NULL, core BLOB NOT NULL, top BLOB) WITHOUT ROWID`); err != nil {
		return err
	}
	// A rowid table: the parts are blobs of up to some KiB, which WITHOUT
	// ROWID tables store poorly (SQLite: rows over about 1/20 of a page).
	if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS ` + ptbl + ` (owner TEXT NOT NULL, kind INTEGER NOT NULL, slot INTEGER NOT NULL, t INTEGER NOT NULL, z BLOB NOT NULL)`); err != nil {
		return err
	}
	if _, err := s.db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS ` + ptbl + `_key ON ` + ptbl + ` (owner, kind, slot)`); err != nil {
		return err
	}
	if _, err := s.db.Exec(`CREATE INDEX IF NOT EXISTS ` + ptbl + `_slot ON ` + ptbl + ` (slot)`); err != nil {
		return err
	}
	_, err := s.db.Exec(`INSERT OR REPLACE INTO meta (k, v) VALUES (?, ?)`, tbl, want)
	return err
}

// put writes one finished bucket into its ring.
func (s *ringStore) put(r cm.Ring, start time.Time, b *cm.MetricBucket) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := putTx(tx, r, r.Slot(start), start.Unix(), b); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.gen.Add(1)
	return nil
}

// putTx replaces the row and the parts of a slot.
func putTx(tx *sql.Tx, r cm.Ring, slot, t int64, b *cm.MetricBucket) error {
	core, topFlag, parts := splitBucket(b)
	tbl, ptbl := tableOf(r.Resolution), partTable(r.Resolution)
	if _, err := tx.Exec(`INSERT OR REPLACE INTO `+tbl+` (slot, t, core, top) VALUES (?, ?, ?, ?)`, slot, t, core, topFlag); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM `+ptbl+` WHERE slot = ?`, slot); err != nil {
		return err
	}
	if len(parts) == 0 {
		return nil
	}
	st, err := tx.Prepare(`INSERT INTO ` + ptbl + ` (owner, kind, slot, t, z) VALUES (?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer st.Close()
	for _, p := range parts {
		if _, err := st.Exec(p.owner, p.kind, slot, t, p.z); err != nil {
			return err
		}
	}
	return nil
}

// putMerging writes a bucket; a partial bucket is merged with a stored row
// of the same start (the part an earlier process flushed at its shutdown
// into the same slot), so neither part overwrites the other.
func (s *ringStore) putMerging(r cm.Ring, start time.Time, b *cm.MetricBucket) error {
	if b.Partial {
		var prev *cm.MetricBucket
		if err := s.read(r, start, start, readAll, func(t time.Time, x *cm.MetricBucket) {
			if t.Equal(start) {
				prev = x
			}
		}); err != nil {
			return err
		}
		if prev != nil {
			mergeBucket(prev, b)
			prev.T, prev.Resolution, prev.StepS = b.T, b.Resolution, b.StepS
			b = prev
		}
	}
	return s.put(r, start, b)
}

// readParts selects what read decodes: the traffic counters only or the
// whole core (with the websites' cores), and the top lists of one
// dimension, all or none. only limits the websites read, cores and lists:
// "" every website, "-" none, else that website.
type readParts struct {
	core coreParts
	top  bool   // decode top lists
	dim  string // "" = every dimension
	site string // per-website lists: "" none, "*" all, else one website
	only string
	// siteTotals fills Sites with the websites' requests, stopped and
	// would_block from the totals row (partSiteTotals) instead of the
	// website parts. core then decodes the gateway counters only.
	siteTotals bool
}

var (
	readSeries = readParts{core: coreAll}
	readAll    = readParts{core: coreAll, top: true, site: "*"}
)

func readBreakdown(dim string) readParts { return readParts{core: coreTraffic, top: true, dim: dim} }

// read calls fn for every stored bucket whose start is in [from, to] (both
// bucket starts), oldest first; rows of overwritten slots (t outside the
// range) are skipped. Only the selected parts are read and decoded.
func (s *ringStore) read(r cm.Ring, from, to time.Time, parts readParts, fn func(t time.Time, b *cm.MetricBucket)) error {
	if to.Before(from) {
		return nil
	}
	type row struct {
		t         int64
		core, top []byte
	}
	ranges := r.SlotRanges(from, to)
	var rows []row
	for _, sr := range ranges {
		q, err := s.db.Query(`SELECT t, core, top FROM `+tableOf(r.Resolution)+` WHERE slot BETWEEN ? AND ? AND t BETWEEN ? AND ?`, sr[0], sr[1], from.Unix(), to.Unix())
		if err != nil {
			return err
		}
		for q.Next() {
			var x row
			if err := q.Scan(&x.t, &x.core, &x.top); err != nil {
				q.Close()
				return err
			}
			rows = append(rows, x)
		}
		q.Close()
		if err := q.Err(); err != nil {
			return err
		}
	}
	if len(rows) == 0 {
		return nil
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].t < rows[j].t })
	var scratch bytes.Buffer
	intern := map[string]string{}
	buckets := make(map[int64]*cm.MetricBucket, len(rows))
	order := make([]int64, 0, len(rows))
	gatewayTop := parts.top && (parts.site == "" || parts.site == "*")
	hide := int64(0)
	if r.Resolution == cm.Res10m {
		hide = s.hide.Load()
	}
	for _, x := range rows {
		if hide != 0 && x.t == hide {
			continue
		}
		b, err := decodeCore(x.core, parts.core, &scratch, intern)
		if err != nil {
			continue
		}
		if gatewayTop && len(x.top) > 0 {
			b.Top = &cm.BucketTop{}
		}
		buckets[x.t] = b
		order = append(order, x.t)
	}
	// The websites' totals in one row per bucket.
	if parts.siteTotals && parts.only != "-" {
		err := s.partRows(r, ranges, from, to, "", []int{partSiteTotals}, func(_ string, t int64, _ int, z []byte) {
			b := buckets[t]
			if b == nil {
				return
			}
			if ss, err := decodeSiteTotals(z, parts.only, &scratch, intern); err == nil {
				b.Sites = ss
			}
		})
		if err != nil {
			return err
		}
	}
	// The websites (their cores and, with a website selection, their
	// lists), in their order in the bucket.
	needSites := !parts.siteTotals && (parts.core == coreAll || parts.core == coreSites)
	if needSites && parts.only != "-" {
		owner := parts.only
		if owner == "" {
			owner = "*"
		}
		ords := map[int64][]int{}
		err := s.partRows(r, ranges, from, to, owner, []int{partSite}, func(owner string, t int64, _ int, z []byte) {
			b := buckets[t]
			if b == nil || b.Sites == nil {
				return
			}
			top := parts.top && (parts.site == "*" || parts.site == owner)
			st, ord, err := decodeSitePart(z, owner, true, top, parts.dim, &scratch, intern)
			if err != nil {
				return
			}
			b.Sites = append(b.Sites, st)
			ords[t] = append(ords[t], ord)
		})
		if err != nil {
			return err
		}
		for t, o := range ords {
			sort.Sort(byOrd{buckets[t].Sites, o})
		}
	}
	if gatewayTop {
		var kinds []int
		for i, d := range topDims {
			if parts.dim == "" || parts.dim == d {
				kinds = append(kinds, partTop+i)
			}
		}
		err := s.partRows(r, ranges, from, to, "", kinds, func(_ string, t int64, kind int, z []byte) {
			b := buckets[t]
			i := kind - partTop
			if b == nil || b.Top == nil || i < 0 || i >= len(topDims) {
				return
			}
			if es, err := decodeSection(z, &scratch); err == nil {
				*topField(b.Top, topDims[i]) = es
			}
		})
		if err != nil {
			return err
		}
	}
	for _, t := range order {
		fn(time.Unix(t, 0).UTC(), buckets[t])
	}
	return nil
}

// partRows calls fn for the part rows of the given kinds in the slot
// ranges with t in [from, to]: of one owner ("" the gateway) by the
// primary key, or of every owner ("*") by the slot index.
func (s *ringStore) partRows(r cm.Ring, ranges [][2]int64, from, to time.Time, owner string, kinds []int, fn func(owner string, t int64, kind int, z []byte)) error {
	ptbl := partTable(r.Resolution)
	scan := func(q *sql.Rows, err error, withOwner bool, kind int) error {
		if err != nil {
			return err
		}
		defer q.Close()
		want := map[int]bool{}
		for _, k := range kinds {
			want[k] = true
		}
		for q.Next() {
			var o string
			var t int64
			var k int
			var z []byte
			if withOwner {
				err = q.Scan(&o, &k, &t, &z)
			} else {
				o, k = owner, kind
				err = q.Scan(&t, &z)
			}
			if err != nil {
				return err
			}
			if want[k] {
				fn(o, t, k, z)
			}
		}
		return q.Err()
	}
	for _, sr := range ranges {
		if owner == "*" {
			q, err := s.db.Query(`SELECT owner, kind, t, z FROM `+ptbl+` INDEXED BY `+ptbl+`_slot WHERE slot BETWEEN ? AND ? AND t BETWEEN ? AND ?`,
				sr[0], sr[1], from.Unix(), to.Unix())
			if err := scan(q, err, true, 0); err != nil {
				return err
			}
			continue
		}
		for _, k := range kinds {
			q, err := s.db.Query(`SELECT t, z FROM `+ptbl+` WHERE owner = ? AND kind = ? AND slot BETWEEN ? AND ? AND t BETWEEN ? AND ?`,
				owner, k, sr[0], sr[1], from.Unix(), to.Unix())
			if err := scan(q, err, false, k); err != nil {
				return err
			}
		}
	}
	return nil
}

// byOrd sorts the websites of a bucket by their stored position.
type byOrd struct {
	s []cm.SiteTraffic
	o []int
}

func (b byOrd) Len() int           { return len(b.s) }
func (b byOrd) Less(i, j int) bool { return b.o[i] < b.o[j] }
func (b byOrd) Swap(i, j int) {
	b.s[i], b.s[j] = b.s[j], b.s[i]
	b.o[i], b.o[j] = b.o[j], b.o[i]
}
