package scoring

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/deutschland-schild/schild/contract/msg"
	"github.com/deutschland-schild/schild/lab/internal/store"
)

// PatternSummary is the dashboard API PatternSummary.
type PatternSummary struct {
	PatternID      string   `json:"pattern_id"`
	ActionSig      string   `json:"action_sig"`
	Categories     []string `json:"categories"`
	Status         string   `json:"status"`
	Signals        int64    `json:"signals"`
	Issuers        int      `json:"issuers"`
	Clients        int      `json:"clients"`
	MaxIssuerShare float64  `json:"max_issuer_share"`
	RequestSigs    int      `json:"request_sigs"`
	ScoreAvg       float64  `json:"score_avg"`
	TopCountries   []Count  `json:"top_countries"`
	TopASNs        []Count  `json:"top_asns"`
	FirstSeen      string   `json:"first_seen"`
	LastSeen       string   `json:"last_seen"`
	ProposalID     *string  `json:"proposal_id"`
}

// Summarize renders a pattern for the API.
func Summarize(p *Pattern) PatternSummary {
	cats := make([]string, 0, len(p.Categories))
	for c := range p.Categories {
		cats = append(cats, c)
	}
	sort.Strings(cats)
	avg := 0.0
	if p.Signals > 0 {
		avg = math.Round(float64(p.ScoreSum)/float64(p.Signals)*10) / 10
	}
	var prop *string
	if p.ProposalID != "" {
		v := p.ProposalID
		prop = &v
	}
	return PatternSummary{
		PatternID: p.ID, ActionSig: p.ActionSig, Categories: cats, Status: p.Status, Signals: p.Signals,
		Issuers: p.Window.Issuers, Clients: p.Clients, MaxIssuerShare: p.Window.MaxIssuerShare, RequestSigs: p.RequestSigs,
		ScoreAvg: avg, TopCountries: Top(p.Countries, 5, false), TopASNs: Top(p.ASNs, 5, true),
		FirstSeen: msg.FormatTime(p.FirstSeen), LastSeen: msg.FormatTime(p.LastSeen), ProposalID: prop,
	}
}

// PatternFilter selects patterns.
type PatternFilter struct {
	From, To   time.Time
	Q          string
	Category   string
	Country    string
	ASN        *int64
	MinIssuers int
	Status     string
	Sort       string // last_seen | signals | issuers | first_seen
}

// Live recomputes the window statistics of p as of now with cfg, the same
// numbers the rules engine uses for a proposal's evidence (Engine.evidence).
// The stored Window is only as fresh as the pattern's last signal: units age
// out of the window without a write, so every read path that shows or filters
// by the window uses Live. The automatic status (new/watching) follows the
// live window; manual and proposal states are kept.
func Live(tx *bolt.Tx, p *Pattern, now time.Time, cfg Config) {
	p.Window = ComputeWindow(tx, p.ID, now, cfg.Window())
	if p.Status == StatusNew || p.Status == StatusWatching {
		p.Status = StatusNew
		if MeetsTipThreshold(p.Window, cfg) {
			p.Status = StatusWatching
		}
	}
}

// ListPatterns returns a page of patterns (offset cursor) with live window
// statistics as of now (see Live).
func ListPatterns(tx *bolt.Tx, f PatternFilter, now time.Time, cfg Config, offset, limit int) ([]PatternSummary, int) {
	var all []*Pattern
	_ = tx.Bucket(store.Patterns).ForEach(func(_, v []byte) error {
		var p Pattern
		if json.Unmarshal(v, &p) != nil {
			return nil
		}
		Live(tx, &p, now, cfg)
		if !f.From.IsZero() && p.LastSeen.Before(f.From) || !f.To.IsZero() && p.FirstSeen.After(f.To) {
			return nil
		}
		if f.Q != "" && !strings.Contains(p.ActionSig, f.Q) && !anyKeyContains(p.Categories, f.Q) {
			return nil
		}
		if f.Category != "" && p.Categories[f.Category] == 0 {
			return nil
		}
		if f.Country != "" && p.Countries[f.Country] == 0 {
			return nil
		}
		if f.ASN != nil && p.ASNs[strconv.FormatInt(*f.ASN, 10)] == 0 {
			return nil
		}
		if p.Window.Issuers < f.MinIssuers {
			return nil
		}
		if f.Status != "" && p.Status != f.Status {
			return nil
		}
		all = append(all, &p)
		return nil
	})
	less := func(i, j int) bool { return all[i].LastSeen.After(all[j].LastSeen) }
	switch f.Sort {
	case "signals":
		less = func(i, j int) bool { return all[i].Signals > all[j].Signals }
	case "issuers":
		less = func(i, j int) bool {
			if all[i].Window.Issuers != all[j].Window.Issuers {
				return all[i].Window.Issuers > all[j].Window.Issuers
			}
			return all[i].Window.MaxIssuerShare < all[j].Window.MaxIssuerShare
		}
	case "first_seen":
		less = func(i, j int) bool { return all[i].FirstSeen.After(all[j].FirstSeen) }
	}
	sort.SliceStable(all, func(i, j int) bool {
		if less(i, j) != less(j, i) {
			return less(i, j)
		}
		return all[i].ID < all[j].ID
	})
	if offset > len(all) {
		offset = len(all)
	}
	end := min(offset+limit, len(all))
	out := make([]PatternSummary, 0, end-offset)
	for _, p := range all[offset:end] {
		out = append(out, Summarize(p))
	}
	next := -1
	if end < len(all) {
		next = end
	}
	return out, next
}

func anyKeyContains(m map[string]int64, q string) bool {
	for k := range m {
		if strings.Contains(k, q) {
			return true
		}
	}
	return false
}

// PatternDetail is the dashboard API PatternDetail.
type PatternDetail struct {
	Pattern    PatternSummary   `json:"pattern"`
	ByIssuer   []Count          `json:"by_issuer"`
	ByOperator []Count          `json:"by_operator"`
	Countries  []Count          `json:"countries"`
	ASNs       []Count          `json:"asns"`
	NetClasses []Count          `json:"net_classes"`
	Agents     []Count          `json:"agents"`
	WAFRules   []Count          `json:"waf_rules"`
	Timeline   []map[string]any `json:"timeline"`
	Samples    []ReceivedSignal `json:"samples"`
}

// Detail returns the pattern with live window statistics.
func Detail(tx *bolt.Tx, pid string, now time.Time, cfg Config, from, to time.Time) (*PatternDetail, bool) {
	p, ok, err := GetPattern(tx, pid)
	if !ok || err != nil {
		return nil, false
	}
	Live(tx, p, now, cfg)
	byIssuer := map[string]int64{}
	for k, v := range p.Window.ByIssuer {
		byIssuer[k] = int64(v)
	}
	if from.IsZero() {
		from = now.Add(-7 * 24 * time.Hour)
	}
	if to.IsZero() {
		to = now
	}
	d := &PatternDetail{
		Pattern: Summarize(p), ByIssuer: Top(byIssuer, 0, false), ByOperator: []Count{},
		Countries: Top(p.Countries, 20, false), ASNs: Top(p.ASNs, 20, true), NetClasses: Top(p.NetClasses, 0, false),
		Agents: Top(p.Agents, 20, false), WAFRules: Top(p.WAFRules, 20, true), Timeline: Timeline(tx, pid, from, to),
	}
	if d.Timeline == nil {
		d.Timeline = []map[string]any{}
	}
	d.Samples, _ = ListSignals(tx, SignalFilter{PatternID: pid}, "", 20)
	return d, true
}

// SignalFilter selects stored signals.
type SignalFilter struct {
	From, To  time.Time
	PatternID string
	Issuer    string
}

// ListSignals returns stored signals newest first; the cursor is opaque.
func ListSignals(tx *bolt.Tx, f SignalFilter, cursor string, limit int) ([]ReceivedSignal, string) {
	out := []ReceivedSignal{}
	sigs := tx.Bucket(store.Signals)
	var seek []byte
	if cursor != "" {
		if b, err := hex.DecodeString(cursor); err == nil {
			seek = b
		}
	}
	visit := func(key []byte) bool { // returns false to stop
		v := sigs.Get(key)
		if v == nil {
			return true
		}
		var rs ReceivedSignal
		if json.Unmarshal(v, &rs) != nil {
			return true
		}
		at := time.UnixMilli(int64(store.FromU64(key[:8])))
		if !f.To.IsZero() && at.After(f.To) {
			return true
		}
		if !f.From.IsZero() && at.Before(f.From) {
			return false
		}
		if f.Issuer != "" && rs.Issuer != f.Issuer {
			return true
		}
		out = append(out, rs)
		return true
	}
	next := ""
	scanned := 0
	if f.PatternID != "" {
		prefix := []byte(f.PatternID)
		c := tx.Bucket(store.SignalByPattern).Cursor()
		var k []byte
		if seek != nil {
			k, _ = c.Seek(store.Key(prefix, seek))
			k, _ = c.Prev()
		} else {
			k, _ = c.Seek(store.Key(prefix, bytes.Repeat([]byte{0xff}, 16)))
			if k == nil {
				k, _ = c.Last()
			} else {
				k, _ = c.Prev()
			}
		}
		for ; k != nil && bytes.HasPrefix(k, prefix) && len(out) < limit && scanned < 100000; k, _ = c.Prev() {
			scanned++
			key := k[len(prefix):]
			if !visit(key) {
				break
			}
			if len(out) == limit {
				next = hex.EncodeToString(key)
			}
		}
		return out, next
	}
	c := sigs.Cursor()
	var k []byte
	if seek != nil {
		c.Seek(seek)
		k, _ = c.Prev()
	} else {
		k, _ = c.Last()
	}
	for ; k != nil && len(out) < limit && scanned < 100000; k, _ = c.Prev() {
		scanned++
		if !visit(k) {
			break
		}
		if len(out) == limit {
			next = hex.EncodeToString(k)
		}
	}
	return out, next
}

// Prune applies retention: signals older than signalsDays, units older than
// the largest scoring window (7 days), aggregates older than aggregatesDays.
// It deletes at most batch records per call (call repeatedly).
func Prune(db *store.DB, now time.Time, signalsDays, aggregatesDays, batch int) (int, error) {
	n := 0
	err := db.Update(func(tx *bolt.Tx) error {
		cut := uint64(now.Add(-time.Duration(signalsDays) * 24 * time.Hour).UnixMilli())
		c := tx.Bucket(store.Signals).Cursor()
		for k, v := c.First(); k != nil && store.FromU64(k[:8]) < cut && n < batch; k, v = c.First() {
			var rs ReceivedSignal
			if json.Unmarshal(v, &rs) == nil {
				var id struct {
					ID string `json:"id"`
				}
				_ = json.Unmarshal(rs.Payload, &id)
				_ = tx.Bucket(store.SignalIDs).Delete([]byte(id.ID))
				_ = tx.Bucket(store.SignalByPattern).Delete(store.Key([]byte(rs.PatternID), k))
			}
			if err := c.Delete(); err != nil {
				return err
			}
			n++
		}
		// Collect first: deleting while iterating a bbolt cursor skips keys.
		var del [][]byte
		ic := tx.Bucket(store.SignalIDs).Cursor()
		for k, v := ic.First(); k != nil && n+len(del) < batch; k, v = ic.Next() {
			if len(v) == 8 && store.FromU64(v) < cut { // feedback ids
				del = append(del, append([]byte(nil), k...))
			}
		}
		for _, k := range del {
			if err := tx.Bucket(store.SignalIDs).Delete(k); err != nil {
				return err
			}
			n++
		}
		unitCut := uint64(now.Add(-7 * 24 * time.Hour).Unix())
		del = del[:0]
		uc := tx.Bucket(store.Units).Cursor()
		for k, _ := uc.First(); k != nil && n+len(del) < batch; k, _ = uc.Next() {
			if len(k) > 26 && store.FromU64(k[18:26]) < unitCut {
				del = append(del, append([]byte(nil), k...))
			}
		}
		for _, k := range del {
			if err := tx.Bucket(store.Units).Delete(k); err != nil {
				return err
			}
			n++
		}
		aggCut := now.Add(-time.Duration(aggregatesDays) * 24 * time.Hour)
		var stale []string
		_ = tx.Bucket(store.Patterns).ForEach(func(k, v []byte) error {
			var p Pattern
			if json.Unmarshal(v, &p) == nil && p.LastSeen.Before(aggCut) && p.ProposalID == "" {
				stale = append(stale, string(k))
			}
			return nil
		})
		for _, pid := range stale {
			if n >= batch {
				break
			}
			for _, b := range [][]byte{store.Timeline, store.PatternClients, store.PatternReqSigs, store.SignalByPattern} {
				cc := tx.Bucket(b).Cursor()
				for k, _ := cc.Seek([]byte(pid)); k != nil && bytes.HasPrefix(k, []byte(pid)); k, _ = cc.Seek([]byte(pid)) {
					if err := cc.Delete(); err != nil {
						return err
					}
				}
			}
			if err := tx.Bucket(store.Patterns).Delete([]byte(pid)); err != nil {
				return err
			}
			n++
		}
		return nil
	})
	return n, err
}

// RefreshAll recomputes window statistics of every pattern seen inside the
// window (windows shrink as time passes even without new signals).
func RefreshAll(db *store.DB, now time.Time, cfg Config) error {
	var ids []string
	_ = db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(store.Patterns).ForEach(func(k, v []byte) error {
			var p Pattern
			if json.Unmarshal(v, &p) == nil && now.Sub(p.LastSeen) <= cfg.Window()+time.Hour {
				ids = append(ids, string(k))
			}
			return nil
		})
	})
	for len(ids) > 0 {
		n := min(len(ids), 500)
		chunk := ids[:n]
		ids = ids[n:]
		if err := db.Update(func(tx *bolt.Tx) error {
			for _, id := range chunk {
				if err := refresh(tx, id, now, cfg); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			return err
		}
	}
	return nil
}

// KnownIDs calls fn with every processed message id and its receive time
// (startup rebuild of the ingest replay set).
func KnownIDs(db *store.DB, fn func(id string, receivedMS int64)) error {
	return db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(store.SignalIDs).ForEach(func(k, v []byte) error {
			fn(string(k), int64(store.FromU64(v[:8])))
			return nil
		})
	})
}
