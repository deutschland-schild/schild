package scoring

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strconv"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/deutschland-schild/schild/contract/msg"
	"github.com/deutschland-schild/schild/lab/internal/store"
)

// Pattern statuses (lab dashboard API PatternStatus).
const (
	StatusNew       = "new"
	StatusWatching  = "watching"
	StatusProposed  = "proposed"
	StatusPublished = "published"
	StatusIgnored   = "ignored"
)

// PatternID derives the stable id of an action signature.
func PatternID(actionSig string) string {
	h := sha256.Sum256([]byte("schild.pattern/0\n" + actionSig))
	return "p_" + hex.EncodeToString(h[:8])
}

// Window holds the issuer statistics inside the scoring window. These are
// the numbers thresholds use (G2): units are distinct (issuer, request_sig,
// time_bucket) triples, so one issuer with many client keys (Sybil) or many
// repeats still counts once per signature and bucket.
type Window struct {
	Issuers        int            `json:"issuers"`
	Units          int            `json:"units"`
	MaxIssuerShare float64        `json:"max_issuer_share"`
	ByIssuer       map[string]int `json:"by_issuer"`
	ComputedAt     time.Time      `json:"computed_at"`
}

// Pattern is the aggregate of all signals with one action_sig.
type Pattern struct {
	ID          string           `json:"pattern_id"`
	ActionSig   string           `json:"action_sig"`
	Categories  map[string]int64 `json:"categories"`
	Signals     int64            `json:"signals"`
	Tips        int64            `json:"tips"`     // score >= min_score
	Baseline    int64            `json:"baseline"` // sampled comparison traffic
	Clients     int              `json:"clients"`
	RequestSigs int              `json:"request_sigs"`
	ScoreSum    int64            `json:"score_sum"`
	ByIssuer    map[string]int64 `json:"by_issuer"` // lifetime signals per issuer
	Countries   map[string]int64 `json:"countries"`
	ASNs        map[string]int64 `json:"asns"`
	NetClasses  map[string]int64 `json:"net_classes"`
	Agents      map[string]int64 `json:"agents"`
	WAFRules    map[string]int64 `json:"waf_rules"`
	FirstSeen   time.Time        `json:"first_seen"`
	LastSeen    time.Time        `json:"last_seen"`
	Status      string           `json:"status"`
	ProposalID  string           `json:"proposal_id,omitempty"`
	Window      Window           `json:"window"`
}

func newPattern(actionSig string, now time.Time) *Pattern {
	return &Pattern{
		ID: PatternID(actionSig), ActionSig: actionSig, Status: StatusNew, FirstSeen: now, LastSeen: now,
		Categories: map[string]int64{}, ByIssuer: map[string]int64{}, Countries: map[string]int64{}, ASNs: map[string]int64{},
		NetClasses: map[string]int64{}, Agents: map[string]int64{}, WAFRules: map[string]int64{},
	}
}

// GetPattern loads a pattern.
func GetPattern(tx *bolt.Tx, id string) (*Pattern, bool, error) {
	var p Pattern
	ok, err := store.GetJSON(tx, store.Patterns, []byte(id), &p)
	if !ok || err != nil {
		return nil, ok, err
	}
	return &p, true, nil
}

// PutPattern stores a pattern.
func PutPattern(tx *bolt.Tx, p *Pattern) error {
	return store.PutJSON(tx, store.Patterns, []byte(p.ID), p)
}

// SetStatus sets the status and linked proposal of a pattern (rules package).
func SetStatus(tx *bolt.Tx, id, status, proposalID string) error {
	p, ok, err := GetPattern(tx, id)
	if !ok || err != nil {
		return err
	}
	p.Status, p.ProposalID = status, proposalID
	return PutPattern(tx, p)
}

func unitKey(pid string, bucket time.Time, issuer, requestSig string) []byte {
	return store.Key([]byte(pid), store.U64(uint64(bucket.Unix())), []byte(issuer), []byte{0}, []byte(requestSig))
}

// ComputeWindow counts units per issuer for pid with time_bucket >= now-window.
func ComputeWindow(tx *bolt.Tx, pid string, now time.Time, window time.Duration) Window {
	w := Window{ByIssuer: map[string]int{}, ComputedAt: now}
	prefix := []byte(pid)
	start := store.Key(prefix, store.U64(uint64(now.Add(-window).Unix())))
	c := tx.Bucket(store.Units).Cursor()
	for k, _ := c.Seek(start); k != nil && bytes.HasPrefix(k, prefix); k, _ = c.Next() {
		rest := k[len(prefix)+8:]
		i := bytes.IndexByte(rest, 0)
		if i < 0 {
			continue
		}
		w.ByIssuer[string(rest[:i])]++
		w.Units++
	}
	w.Issuers = len(w.ByIssuer)
	for _, n := range w.ByIssuer {
		if s := float64(n) / float64(w.Units); s > w.MaxIssuerShare {
			w.MaxIssuerShare = s
		}
	}
	w.MaxIssuerShare = round3(w.MaxIssuerShare)
	return w
}

func round3(f float64) float64 {
	v, _ := strconv.ParseFloat(strconv.FormatFloat(f, 'f', 3, 64), 64)
	return v
}

// TimelineEntry is one hour of a pattern.
type TimelineEntry struct {
	Signals int64            `json:"signals"`
	Issuers map[string]int64 `json:"issuers"`
}

// Count is a key with a count (API Count).
type Count struct {
	Key   any   `json:"key"`
	Count int64 `json:"count"`
}

// Top returns the n largest entries of m, keys as strings (or integers when
// asInt is set, for ASNs and rule ids).
func Top(m map[string]int64, n int, asInt bool) []Count {
	out := make([]Count, 0, len(m))
	for k, v := range m {
		var key any = k
		if asInt {
			if i, err := strconv.ParseInt(k, 10, 64); err == nil {
				key = i
			}
		}
		out = append(out, Count{Key: key, Count: v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return keyString(out[i].Key) < keyString(out[j].Key)
	})
	if n > 0 && len(out) > n {
		out = out[:n]
	}
	return out
}

func keyString(k any) string {
	b, _ := json.Marshal(k)
	return string(b)
}

// Timeline returns hourly entries of pid in [from, to].
func Timeline(tx *bolt.Tx, pid string, from, to time.Time) []map[string]any {
	var out []map[string]any
	prefix := []byte(pid)
	c := tx.Bucket(store.Timeline).Cursor()
	for k, v := c.Seek(store.Key(prefix, store.U64(uint64(from.Truncate(time.Hour).Unix())))); k != nil && bytes.HasPrefix(k, prefix); k, v = c.Next() {
		at := time.Unix(int64(store.FromU64(k[len(prefix):])), 0).UTC()
		if at.After(to) {
			break
		}
		var e TimelineEntry
		if json.Unmarshal(v, &e) != nil {
			continue
		}
		out = append(out, map[string]any{"bucket": msg.FormatTime(at), "signals": e.Signals, "issuers": len(e.Issuers)})
	}
	return out
}
