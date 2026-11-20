// Package d2export is the lab side of the D2 measurement (concept 23 §2,
// runbook 13.2): per pattern (action signature, never an IP) the first time
// each site sent a signal for it, and the lag from the first site to every
// following site. Labs never receive IPs, so the export cannot contain any.
//
// A "site" is the client key id that signed the signal (one key per site in
// stage 3); the issuer is listed next to it. Several labs receive the same
// signals; Merge combines their exports (earliest first-seen per pattern and
// site wins).
//
// Served on the lab's local metrics listener as GET /export/d2 (no login,
// bound to 127.0.0.1 by default) and by `schild-lab export d2`.
package d2export

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/deutschland-schild/schild/lab/internal/scoring"
	"github.com/deutschland-schild/schild/lab/internal/store"
)

// Schema of the export document.
const Schema = "schild.d2.export/0"

// Options select the signals.
type Options struct {
	From, To time.Time // receive time, [From, To)
	MinScore int       // only tips with score >= MinScore (the lab's scoring.min_score); 0 = all
	Lab      string
}

// SiteSeen is the first signal of one site for one pattern.
type SiteSeen struct {
	Site        string `json:"site"`
	Issuer      string `json:"issuer"`
	FirstSeen   string `json:"first_seen"`   // receive time at the lab
	FirstBucket string `json:"first_bucket"` // the signal's own time_bucket
	Signals     int64  `json:"signals"`
	firstMS     int64
}

// Pattern is one action signature.
type Pattern struct {
	PatternID string     `json:"pattern_id"`
	ActionSig string     `json:"action_sig"`
	Signals   int64      `json:"signals"`
	Sites     []SiteSeen `json:"sites"`  // ordered by first_seen
	LagsS     []float64  `json:"lags_s"` // following sites: first_seen - first_seen of the first site
}

// Site is one client key with its issuer.
type Site struct {
	Site    string `json:"site"`
	Issuer  string `json:"issuer"`
	Signals int64  `json:"signals"`
}

// Summary holds the D2 numbers.
type Summary struct {
	Sites             int     `json:"sites"`
	Patterns          int     `json:"patterns"`
	PatternsMultiSite int     `json:"patterns_multi_site"`
	ShareMultiSite    float64 `json:"share_multi_site"`
	Lags              int     `json:"lags"`
	LagMedianS        float64 `json:"lag_median_s"`
	LagP25S           float64 `json:"lag_p25_s"`
	LagP75S           float64 `json:"lag_p75_s"`
}

// Export is the D2 document.
type Export struct {
	Schema      string    `json:"schema"`
	Labs        []string  `json:"labs"`
	GeneratedAt string    `json:"generated_at"`
	From        string    `json:"from"`
	To          string    `json:"to"`
	MinScore    int       `json:"min_score"`
	Sites       []Site    `json:"sites"`
	Patterns    []Pattern `json:"patterns"`
	Summary     Summary   `json:"summary"`
	Notes       []string  `json:"notes"`
}

func fmtMS(ms int64) string { return time.UnixMilli(ms).UTC().Format("2006-01-02T15:04:05.000Z") }

// Build reads the lab's stored signals.
func Build(db *store.DB, o Options, now time.Time) (*Export, error) {
	if !o.From.Before(o.To) {
		return nil, errors.New("d2: from must be before to")
	}
	pats := map[string]*Pattern{}
	seen := map[string]map[string]*SiteSeen{}
	sites := map[string]*Site{}
	err := db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(store.Signals).Cursor()
		toKey := store.U64(uint64(o.To.UnixMilli()))
		for k, v := c.Seek(store.U64(uint64(o.From.UnixMilli()))); k != nil && bytes.Compare(k[:8], toKey) < 0; k, v = c.Next() {
			var rs scoring.ReceivedSignal
			if json.Unmarshal(v, &rs) != nil {
				continue
			}
			var sig struct {
				ActionSig  string `json:"action_sig"`
				Score      int    `json:"score"`
				TimeBucket string `json:"time_bucket"`
			}
			if json.Unmarshal(rs.Payload, &sig) != nil || sig.ActionSig == "" || sig.Score < o.MinScore {
				continue
			}
			ms := int64(store.FromU64(k[:8]))
			site := rs.KeyID
			if site == "" {
				site = "issuer:" + rs.Issuer
			}
			if sites[site] == nil {
				sites[site] = &Site{Site: site, Issuer: rs.Issuer}
			}
			sites[site].Signals++
			pid := rs.PatternID
			if pid == "" {
				pid = scoring.PatternID(sig.ActionSig)
			}
			p := pats[pid]
			if p == nil {
				p = &Pattern{PatternID: pid, ActionSig: sig.ActionSig}
				pats[pid] = p
				seen[pid] = map[string]*SiteSeen{}
			}
			p.Signals++
			s := seen[pid][site]
			if s == nil {
				s = &SiteSeen{Site: site, Issuer: rs.Issuer, firstMS: ms, FirstSeen: fmtMS(ms), FirstBucket: sig.TimeBucket}
				seen[pid][site] = s
			}
			s.Signals++ // keys are in receive order: the first one is the earliest
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	ex := &Export{Schema: Schema, GeneratedAt: now.UTC().Format(time.RFC3339), From: o.From.UTC().Format(time.RFC3339), To: o.To.UTC().Format(time.RFC3339),
		MinScore: o.MinScore, Labs: []string{}, Sites: []Site{}, Patterns: []Pattern{}}
	if o.Lab != "" {
		ex.Labs = append(ex.Labs, o.Lab)
	}
	for _, s := range sites {
		ex.Sites = append(ex.Sites, *s)
	}
	for pid, p := range pats {
		for _, s := range seen[pid] {
			p.Sites = append(p.Sites, *s)
		}
		ex.Patterns = append(ex.Patterns, *p)
	}
	finish(ex)
	return ex, nil
}

func quantile(xs []float64, q float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	pos := q * float64(len(xs)-1)
	lo, hi := int(math.Floor(pos)), int(math.Ceil(pos))
	return math.Round((xs[lo]+(xs[hi]-xs[lo])*(pos-float64(lo)))*10) / 10
}

// finish orders everything and computes lags and the summary.
func finish(ex *Export) {
	var all []float64
	ex.Summary = Summary{Sites: len(ex.Sites), Patterns: len(ex.Patterns)}
	for i := range ex.Patterns {
		p := &ex.Patterns[i]
		for j := range p.Sites {
			if p.Sites[j].firstMS == 0 {
				if t, err := time.Parse(time.RFC3339Nano, p.Sites[j].FirstSeen); err == nil {
					p.Sites[j].firstMS = t.UnixMilli()
				}
			}
		}
		sort.Slice(p.Sites, func(a, b int) bool {
			if p.Sites[a].firstMS != p.Sites[b].firstMS {
				return p.Sites[a].firstMS < p.Sites[b].firstMS
			}
			return p.Sites[a].Site < p.Sites[b].Site
		})
		p.LagsS = []float64{}
		for j := 1; j < len(p.Sites); j++ {
			lag := float64(p.Sites[j].firstMS-p.Sites[0].firstMS) / 1000
			p.LagsS = append(p.LagsS, lag)
			all = append(all, lag)
		}
		if len(p.Sites) >= 2 {
			ex.Summary.PatternsMultiSite++
		}
	}
	sort.Slice(ex.Patterns, func(a, b int) bool {
		if ex.Patterns[a].Sites[0].firstMS != ex.Patterns[b].Sites[0].firstMS {
			return ex.Patterns[a].Sites[0].firstMS < ex.Patterns[b].Sites[0].firstMS
		}
		return ex.Patterns[a].ActionSig < ex.Patterns[b].ActionSig
	})
	sort.Slice(ex.Sites, func(a, b int) bool { return ex.Sites[a].Site < ex.Sites[b].Site })
	sort.Float64s(all)
	if ex.Summary.Patterns > 0 {
		ex.Summary.ShareMultiSite = math.Round(float64(ex.Summary.PatternsMultiSite)/float64(ex.Summary.Patterns)*1000) / 1000
	}
	ex.Summary.Lags = len(all)
	ex.Summary.LagMedianS, ex.Summary.LagP25S, ex.Summary.LagP75S = quantile(all, 0.5), quantile(all, 0.25), quantile(all, 0.75)
	ex.Notes = []string{
		"site = client key id that signed the signal (one key per site); no IPs exist in a lab",
		"first_seen is the receive time at the lab (client batching adds seconds); first_bucket is the signal's coarse time bucket",
		"only signals with score >= min_score (tips); sampled baseline signals are left out unless min_score is 0",
		"patterns below the client's signal thresholds are invisible here (runbook 13.2); own sites are a lower bound (concept 23 §2)",
		"compare the median lag with the measured time-to-protect (kill criterion D2)",
	}
}

// Merge combines exports of several labs over the same period.
func Merge(exs []*Export) (*Export, error) {
	if len(exs) == 0 {
		return nil, errors.New("d2 merge: no exports")
	}
	out := &Export{Schema: Schema, GeneratedAt: time.Now().UTC().Format(time.RFC3339), From: exs[0].From, To: exs[0].To, MinScore: exs[0].MinScore,
		Labs: []string{}, Sites: []Site{}, Patterns: []Pattern{}}
	sites := map[string]*Site{}
	pats := map[string]*Pattern{}
	seen := map[string]map[string]*SiteSeen{}
	for _, ex := range exs {
		if ex.Schema != Schema {
			return nil, fmt.Errorf("d2 merge: schema %q", ex.Schema)
		}
		if ex.From != out.From || ex.To != out.To || ex.MinScore != out.MinScore {
			return nil, fmt.Errorf("d2 merge: exports cover different periods or min_score (%s..%s/%d vs %s..%s/%d)", ex.From, ex.To, ex.MinScore, out.From, out.To, out.MinScore)
		}
		out.Labs = append(out.Labs, ex.Labs...)
		for _, s := range ex.Sites {
			if cur := sites[s.Site]; cur == nil {
				c := s
				sites[s.Site] = &c
			} else if s.Signals > cur.Signals {
				cur.Signals = s.Signals // the same signals reach every lab: the maximum, not the sum
			}
		}
		for _, p := range ex.Patterns {
			cur := pats[p.PatternID]
			if cur == nil {
				cur = &Pattern{PatternID: p.PatternID, ActionSig: p.ActionSig}
				pats[p.PatternID] = cur
				seen[p.PatternID] = map[string]*SiteSeen{}
			}
			if p.Signals > cur.Signals {
				cur.Signals = p.Signals
			}
			for _, s := range p.Sites {
				t, err := time.Parse(time.RFC3339Nano, s.FirstSeen)
				if err != nil {
					return nil, fmt.Errorf("d2 merge: first_seen %q", s.FirstSeen)
				}
				s.firstMS = t.UnixMilli()
				c := seen[p.PatternID][s.Site]
				switch {
				case c == nil:
					cc := s
					seen[p.PatternID][s.Site] = &cc
				case s.firstMS < c.firstMS:
					sig := max(c.Signals, s.Signals)
					*c = s
					c.Signals = sig
				case s.Signals > c.Signals:
					c.Signals = s.Signals
				}
			}
		}
	}
	for _, s := range sites {
		out.Sites = append(out.Sites, *s)
	}
	for pid, p := range pats {
		for _, s := range seen[pid] {
			p.Sites = append(p.Sites, *s)
		}
		out.Patterns = append(out.Patterns, *p)
	}
	sort.Strings(out.Labs)
	out.Labs = slices.Compact(out.Labs)
	finish(out)
	return out, nil
}

// Handler serves GET /export/d2?from=YYYY-MM-DD&to=YYYY-MM-DD[&min_score=N].
// Default period: the last 7 days; default min_score: minScore().
func Handler(db *store.DB, lab string, minScore func() int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		now := time.Now().UTC()
		q := r.URL.Query()
		o := Options{To: now, Lab: lab, MinScore: minScore()}
		var err error
		if v := q.Get("to"); v != "" {
			if o.To, err = ParseDay(v); err != nil {
				http.Error(w, "to: "+err.Error(), http.StatusBadRequest)
				return
			}
		}
		o.From = o.To.Add(-7 * 24 * time.Hour)
		if v := q.Get("from"); v != "" {
			if o.From, err = ParseDay(v); err != nil {
				http.Error(w, "from: "+err.Error(), http.StatusBadRequest)
				return
			}
		}
		if v := q.Get("min_score"); v != "" {
			if o.MinScore, err = strconv.Atoi(v); err != nil || o.MinScore < 0 || o.MinScore > 100 {
				http.Error(w, "min_score: 0..100", http.StatusBadRequest)
				return
			}
		}
		ex, err := Build(db, o, now)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(ex)
	})
}

// ParseDay parses YYYY-MM-DD (UTC midnight) or RFC 3339.
func ParseDay(s string) (time.Time, error) {
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return t.UTC(), nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("want YYYY-MM-DD or RFC 3339, got %q", s)
	}
	return t.UTC(), nil
}
