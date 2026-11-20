// Package storage holds the v0.5 storage bounds contract (DECISIONS D38,
// contracts/storage-bounds.md): when the schild.db size cap runs, what it
// deletes first, when it gives up and raises a hint instead, how incidents
// are aggregated per client, rule and minute, whether the configured bounds
// fit the file system of storage.path, and the MVP-21 hint
// disk_fill_projection. Everything is integer arithmetic so the Python
// cross-check (contracts/tools/crosscheck.py) computes the same result.
package storage

import (
	"sort"
	"strings"

	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/jsonx"
	"github.com/deutschland-schild/schild/contract/schema"
)

// Schema is the vector input schema (storage-bounds.schema.json).
const Schema = "storage-bounds"

// MaxInputBytes bounds a vector input.
const MaxInputBytes = 1 << 20

// MiB is the unit of retention.max_size_mb.
const MiB = 1 << 20

// Size cap of schild.db (D38).
const (
	// CheckIntervalS: a cap pass runs at start and at least every 10 min.
	CheckIntervalS = 600
	// CheckBytesDivisor: a cap pass also runs as soon as the writers wrote
	// max_size_mb / 10 bytes since the last pass.
	CheckBytesDivisor = 10
	// LowWaterPerMil: a pass that deletes goes down to 95 % of the cap, so
	// the next pass does not follow at once.
	LowWaterPerMil = 950
	// FloorRows: the newest rows of every class are never deleted by the
	// size cap (only by age), so a flood of one kind never empties another.
	FloorRows = 100
	// WALLimitBytes: PRAGMA journal_size_limit of schild.db and metrics.db;
	// the WAL counts against the cap and is checkpointed (TRUNCATE) before
	// and after every pass.
	WALLimitBytes = 64 * MiB
	// OvershootPerMil: between two passes schild.db may exceed the cap by
	// at most the check step (10 %); the disk budget counts it.
	OvershootPerMil = 100
)

// Value classes in deletion order: the size cap deletes the oldest rows of
// the first class first. The agent API call log (ClassAgentCall) is not in
// the order: each pass trims it to its newer half before anything else.
const (
	ClassAgentCall  = "agent_call"
	ClassSampled    = "sampled"     // request events recorded as a sample
	ClassLogged     = "logged"      // passed (not sampled) and logged requests, flagged sessions, anomalies
	ClassWouldBlock = "would_block" // would_block requests, behaviour and rate-limit events that only observed
	ClassBlocked    = "blocked"     // blocked and challenged requests, enforced behaviour and rate-limit events
	ClassIncident   = "incident"    // incident rows (aggregated)
	ClassRecord     = "record"      // waves, rule changes, unblocks, environment changes, advisories, dashboard resets
)

// DeletionOrder lists the classes the size cap deletes from, first to last.
var DeletionOrder = []string{ClassSampled, ClassLogged, ClassWouldBlock, ClassBlocked, ClassIncident, ClassRecord}

// Row kinds of a cap pass.
const (
	KindEvent     = "event"
	KindIncident  = "incident"
	KindAgentCall = "agent_call"
)

// ClassOfEvent maps a stored event to its value class. outcome is the
// request outcome (request events), action what a behaviour, rate-limit or
// distributed event did ("observe" = only shown), sampled the request
// event's sampled flag.
func ClassOfEvent(typ, outcome, action string, sampled bool) string {
	switch typ {
	case "schild.request.evaluated.v1", "schild.request.blocked.v1":
		if sampled {
			return ClassSampled
		}
		switch outcome {
		case "would_block":
			return ClassWouldBlock
		case "blocked", "challenged":
			return ClassBlocked
		}
		return ClassLogged
	case "schild.session.flagged.v1", "schild.environment.anomaly.v1":
		return ClassLogged
	case "schild.behaviour.triggered.v1", "schild.ratelimit.exceeded.v1":
		if action == "observe" {
			return ClassWouldBlock
		}
		return ClassBlocked
	}
	// request.unblocked, environment.changed, advisory.assessed, rule.*,
	// distributed.*, dashboard.access_reset and every later type.
	return ClassRecord
}

// Row is one deletable row of schild.db.
type Row struct {
	ID      string
	Kind    string
	Type    string
	Outcome string
	Action  string
	Sampled bool
	T       int64 // write time, unix ms
	Bytes   int64
}

// Class of the row.
func (r Row) Class() string {
	switch r.Kind {
	case KindIncident:
		return ClassIncident
	case KindAgentCall:
		return ClassAgentCall
	}
	return ClassOfEvent(r.Type, r.Outcome, r.Action, r.Sampled)
}

// CheckDue reports whether a cap pass is due: at least every
// CheckIntervalS seconds, and as soon as written bytes reach a tenth of the
// cap (whichever comes first).
func CheckDue(maxSizeMB, writtenBytes, elapsedS int64) bool {
	return writtenBytes*CheckBytesDivisor >= maxSizeMB*MiB || elapsedS >= CheckIntervalS
}

// CapInput of CapPass.
type CapInput struct {
	MaxSizeMB int64
	BaseBytes int64 // used bytes the pass never deletes
	WALBytes  int64 // WAL after the starting checkpoint
	FloorRows int
	Rows      []Row
}

// CapResult of CapPass.
type CapResult struct {
	UsedBefore  int64    `json:"used_before"`
	Deleted     []string `json:"deleted"`
	UsedAfter   int64    `json:"used_after"`
	Unreachable bool     `json:"unreachable"`
}

// CapPass decides one size-cap pass. used = base + WAL + every row. Nothing
// happens while used <= cap. Above the cap the pass deletes until used <=
// 95 % of the cap: first the older half of the agent call log, then per
// class in DeletionOrder the oldest rows (time, then id) except the newest
// FloorRows of the class. When even that leaves used above the cap the pass
// stops there (Unreachable: hint store_cap_unreachable and one
// rate-limited warning) instead of deleting everything.
func CapPass(in CapInput) CapResult {
	used := in.BaseBytes + in.WALBytes
	byClass := map[string][]Row{}
	for _, r := range in.Rows {
		used += r.Bytes
		byClass[r.Class()] = append(byClass[r.Class()], r)
	}
	res := CapResult{UsedBefore: used, Deleted: []string{}}
	capBytes := in.MaxSizeMB * MiB
	if used <= capBytes {
		res.UsedAfter = used
		return res
	}
	target := capBytes * LowWaterPerMil / 1000
	for _, rs := range byClass {
		sort.SliceStable(rs, func(i, j int) bool {
			if rs[i].T != rs[j].T {
				return rs[i].T < rs[j].T
			}
			return rs[i].ID < rs[j].ID
		})
	}
	del := func(rs []Row, n int) {
		for _, r := range rs[:n] {
			if used <= target {
				return
			}
			used -= r.Bytes
			res.Deleted = append(res.Deleted, r.ID)
		}
	}
	calls := byClass[ClassAgentCall]
	del(calls, len(calls)/2)
	for _, c := range DeletionOrder {
		rs := byClass[c]
		if n := len(rs) - in.FloorRows; n > 0 {
			del(rs, n)
		}
	}
	res.UsedAfter = used
	res.Unreachable = used > capBytes
	return res
}

// Disk budget (D38): the sum of every bound schild keeps on storage.path.
const (
	// ReserveMinBytes, ReservePerMil and ReserveMaxBytes: the budget hint
	// keeps reserve = max(1 GiB, min(5 % of the file system, 20 GiB)) free
	// for everything else. The 20 GiB cap (initiator, 2026-10-29) keeps the
	// reserve sensible on large disks: 5 % of 2 TiB would be 102 GiB.
	ReserveMinBytes = 1 << 30
	ReservePerMil   = 50
	ReserveMaxBytes = 20 << 30
)

// Reserve is max(ReserveMinBytes, min(5 % of total, ReserveMaxBytes)).
func Reserve(fsTotalBytes int64) int64 {
	return max(ReserveMinBytes, min(fsTotalBytes*ReservePerMil/1000, ReserveMaxBytes))
}

// Budget verdicts.
const (
	BudgetOK    = "ok"    // fits
	BudgetHint  = "hint"  // hint storage_budget: growing to the caps would eat the reserve
	BudgetError = "error" // preflight refuses: the caps exceed the file system
)

// BudgetInput of Budget.
type BudgetInput struct {
	MaxSizeMB         int64
	MetricsBoundBytes int64
	RequestsMaxSizeMB int64 // 0: request ring off
	// BodySpoolBytes is waf.body.max_in_flight_bytes (D41): the temp space of
	// bodies lies under storage.path. 0: not counted.
	BodySpoolBytes  int64
	FSTotalBytes    int64
	FSAvailBytes    int64
	SchildUsedBytes int64
}

// BudgetResult of Budget.
type BudgetResult struct {
	BudgetBytes  int64  `json:"budget_bytes"`
	NeedBytes    int64  `json:"need_bytes"`
	ReserveBytes int64  `json:"reserve_bytes"`
	Verdict      string `json:"verdict"`
}

// Budget compares the bounds with the file system of storage.path:
// budget = cap + 10 % overshoot + two WAL limits + metrics.db bound +
// request ring cap + body temp space (D41). error when budget > the file system size (preflight
// refuses to start, code config at /retention/max_size_mb); hint when the
// growth still to come (budget - what the files use now) leaves less than
// the reserve available; else ok.
func Budget(in BudgetInput) BudgetResult {
	capBytes := in.MaxSizeMB * MiB
	b := capBytes + capBytes*OvershootPerMil/1000 + 2*WALLimitBytes + in.MetricsBoundBytes + in.RequestsMaxSizeMB*MiB + in.BodySpoolBytes
	need := b - in.SchildUsedBytes
	if need < 0 {
		need = 0
	}
	reserve := Reserve(in.FSTotalBytes)
	r := BudgetResult{BudgetBytes: b, NeedBytes: need, ReserveBytes: reserve, Verdict: BudgetOK}
	switch {
	case b > in.FSTotalBytes:
		r.Verdict = BudgetError
	case in.FSAvailBytes-need < reserve:
		r.Verdict = BudgetHint
	}
	return r
}

// Incident aggregation (D38): WAF and request-limit blocks of one client,
// one rule key and one UTC minute share one incident.
const MaxOpenAggregates = 65536

// Blocked is one blocked request as the aggregation sees it.
type Blocked struct {
	Client string
	Rules  []string // WAF rule ids that caused the block
	Limit  string   // request limit code (instead of rules)
	T      int64    // unix ms
	Draw   string   // fresh incident number drawn for this request
}

// RuleKey is the rule part of the aggregation key: "limit:<code>" for a
// request limit, else the sorted, de-duplicated rule ids joined with ",".
func RuleKey(rules []string, limit string) string {
	if limit != "" {
		return "limit:" + limit
	}
	s := append([]string(nil), rules...)
	sort.Strings(s)
	out := s[:0]
	for i, x := range s {
		if i == 0 || x != s[i-1] {
			out = append(out, x)
		}
	}
	return strings.Join(out, ",")
}

// Aggregated is one incident row.
type Aggregated struct {
	Incident string `json:"incident"`
	Client   string `json:"client"`
	RuleKey  string `json:"rule_key"`
	MinuteMS int64  `json:"minute_ms"`
	Count    int64  `json:"count"`
	FirstMS  int64  `json:"first_ms"`
	LastMS   int64  `json:"last_ms"`
}

// AggregateResult of Aggregate.
type AggregateResult struct {
	Numbers   []string     `json:"numbers"`
	Incidents []Aggregated `json:"incidents"`
}

// Aggregate assigns incident numbers to blocked requests in arrival order.
// minute = t floored to 60 s. A request of a later minute than any before
// closes every open aggregate. A request whose (client, rule key, minute)
// is open joins it: the block page shows that incident's number, count + 1,
// first and last seen widen. Otherwise the request gets its drawn number
// and a new incident, which is opened for later requests when its minute is
// the newest and fewer than maxOpen aggregates are open (else it stays a
// single-request incident: never dropped, only not aggregated).
func Aggregate(maxOpen int, reqs []Blocked) AggregateResult {
	type key struct{ client, rule string }
	open := map[key]int{}
	newest := int64(-1)
	res := AggregateResult{Numbers: []string{}, Incidents: []Aggregated{}}
	for _, r := range reqs {
		minute := r.T - r.T%60000
		if minute > newest {
			open = map[key]int{}
			newest = minute
		}
		k := key{r.Client, RuleKey(r.Rules, r.Limit)}
		if i, ok := open[k]; ok && minute == newest {
			a := &res.Incidents[i]
			a.Count++
			if r.T < a.FirstMS {
				a.FirstMS = r.T
			}
			if r.T > a.LastMS {
				a.LastMS = r.T
			}
			res.Numbers = append(res.Numbers, a.Incident)
			continue
		}
		res.Incidents = append(res.Incidents, Aggregated{Incident: r.Draw, Client: r.Client, RuleKey: k.rule, MinuteMS: minute, Count: 1, FirstMS: r.T, LastMS: r.T})
		res.Numbers = append(res.Numbers, r.Draw)
		if minute == newest && len(open) < maxOpen {
			open[k] = len(res.Incidents) - 1
		}
	}
	return res
}

// MVP-21 hint disk_fill_projection (D38).
const (
	ProjectionDays         = 7  // complete UTC days looked at
	ProjectionMinSamples   = 36 // a day counts with at least 6 h of 10-minute points
	ProjectionMinDays      = 4  // counted days needed
	ProjectionHintDays     = 14 // hint below this many days left (notice)
	ProjectionWarnDays     = 3  // warning below this many days left
	HintDiskFillProjection = "disk_fill_projection"
)

// Day is one UTC day of a mount.
type Day struct {
	MinUsedBytes int64
	Samples      int
}

// ProjectionResult of Projection.
type ProjectionResult struct {
	Hint            bool    `json:"hint"`
	Level           *string `json:"level"`
	DaysLeft        *int64  `json:"days_left"`
	RateBytesPerDay *int64  `json:"rate_bytes_per_day"`
}

// Projection decides disk_fill_projection for one mount from the daily
// minima of the last 7 complete UTC days (oldest first) and the current
// usage. Days with fewer than 36 samples do not count; with fewer than 4
// counted days there is no hint. Growth must be steady: at least two thirds
// of the steps between consecutive counted days rise (a one-off copy is one
// step). The rate is the Theil-Sen slope (lower median of the slopes of
// every pair of counted days, in bytes per day). With a positive rate,
// days_left = floor((total - used) / rate); hint when days_left < 14,
// warning when < 3, else notice.
func Projection(total, used int64, days []Day) ProjectionResult {
	none := ProjectionResult{}
	type pt struct{ d, m int64 }
	var pts []pt
	for i, d := range days {
		if d.Samples >= ProjectionMinSamples {
			pts = append(pts, pt{int64(i), d.MinUsedBytes})
		}
	}
	if len(pts) < ProjectionMinDays {
		return none
	}
	up := 0
	for i := 1; i < len(pts); i++ {
		if pts[i].m > pts[i-1].m {
			up++
		}
	}
	if up*3 < 2*(len(pts)-1) {
		return none
	}
	type frac struct{ num, den int64 }
	var sl []frac
	for i := 0; i < len(pts); i++ {
		for j := i + 1; j < len(pts); j++ {
			sl = append(sl, frac{pts[j].m - pts[i].m, pts[j].d - pts[i].d})
		}
	}
	sort.SliceStable(sl, func(a, b int) bool { return sl[a].num*sl[b].den < sl[b].num*sl[a].den })
	med := sl[(len(sl)-1)/2]
	if med.num <= 0 {
		return none
	}
	free := total - used
	if free < 0 {
		free = 0
	}
	left := free * med.den / med.num
	if left >= ProjectionHintDays {
		return none
	}
	rate := med.num / med.den
	level := "notice"
	if left < ProjectionWarnDays {
		level = "warning"
	}
	return ProjectionResult{Hint: true, Level: &level, DaysLeft: &left, RateBytesPerDay: &rate}
}

// Hint codes of D38 (HealthHintCode). store_cap_unreachable and
// storage_budget are server-only like store_near_cap (they never mark a
// website); disk_fill_projection reaches every website on the server like
// disk_full_soon.
const (
	HintStoreCapUnreachable = "store_cap_unreachable"
	HintStorageBudget       = "storage_budget"
)

// Warning code of `schild ingress validate` (D38): a Caddyfile log output
// `output file <path> { roll_disabled }` relies on an external logrotate
// rule that must use copytruncate (the embedded Caddy does not reopen the
// file). Printed as "<code>: <message>"; MessageKey names the UI text.
const (
	WarnLogRollDisabled       = "log_roll_disabled"
	WarnLogRollDisabledMsgKey = "ingress.warn.log_roll_disabled"
)

// RunVector parses and validates a storage-bounds vector input and returns
// the result of its op.
func RunVector(raw []byte) (any, error) {
	if len(raw) > MaxInputBytes {
		return nil, contract.Errf(contract.CodeOversize, "%d bytes > %d", len(raw), MaxInputBytes)
	}
	v, err := jsonx.ParseObject(raw)
	if err != nil {
		return nil, contract.Errf(contract.CodeMalformed, "%v", err)
	}
	if err := schema.Validate(Schema, v); err != nil {
		return nil, err
	}
	n := func(m map[string]any, k string) int64 {
		x, ok := m[k].(interface{ Int64() (int64, error) })
		if !ok {
			return 0
		}
		i, _ := x.Int64()
		return i
	}
	str := func(m map[string]any, k string) string { s, _ := m[k].(string); return s }
	switch v["op"] {
	case "check_due":
		return map[string]any{"due": CheckDue(n(v, "max_size_mb"), n(v, "written_bytes"), n(v, "elapsed_s"))}, nil
	case "cap_pass":
		in := CapInput{MaxSizeMB: n(v, "max_size_mb"), BaseBytes: n(v, "base_bytes"), WALBytes: n(v, "wal_bytes"), FloorRows: int(n(v, "floor_rows"))}
		seen := map[string]bool{}
		for _, x := range v["rows"].([]any) {
			m := x.(map[string]any)
			r := Row{ID: str(m, "id"), Kind: str(m, "kind"), Type: str(m, "type"), Outcome: str(m, "outcome"), Action: str(m, "action"), T: n(m, "t"), Bytes: n(m, "bytes")}
			r.Sampled, _ = m["sampled"].(bool)
			if seen[r.ID] {
				return nil, contract.Errf(contract.CodeSchema, "rows: id %q twice", r.ID)
			}
			seen[r.ID] = true
			in.Rows = append(in.Rows, r)
		}
		return CapPass(in), nil
	case "disk_budget":
		return Budget(BudgetInput{MaxSizeMB: n(v, "max_size_mb"), MetricsBoundBytes: n(v, "metrics_bound_bytes"), RequestsMaxSizeMB: n(v, "requests_max_size_mb"), BodySpoolBytes: n(v, "body_spool_bytes"),
			FSTotalBytes: n(v, "fs_total_bytes"), FSAvailBytes: n(v, "fs_avail_bytes"), SchildUsedBytes: n(v, "schild_used_bytes")}), nil
	case "incident_aggregate":
		var reqs []Blocked
		draws := map[string]bool{}
		for _, x := range v["requests"].([]any) {
			m := x.(map[string]any)
			b := Blocked{Client: str(m, "client"), Limit: str(m, "limit"), T: n(m, "t"), Draw: str(m, "draw")}
			if rs, ok := m["rules"].([]any); ok {
				for _, r := range rs {
					b.Rules = append(b.Rules, r.(string))
				}
			}
			if draws[b.Draw] {
				return nil, contract.Errf(contract.CodeSchema, "requests: draw %q twice", b.Draw)
			}
			draws[b.Draw] = true
			reqs = append(reqs, b)
		}
		return Aggregate(int(n(v, "max_open")), reqs), nil
	case "disk_projection":
		var days []Day
		for _, x := range v["days"].([]any) {
			m := x.(map[string]any)
			days = append(days, Day{MinUsedBytes: n(m, "min_used_bytes"), Samples: int(n(m, "samples"))})
		}
		return Projection(n(v, "total_bytes"), n(v, "used_bytes"), days), nil
	}
	return nil, contract.Errf(contract.CodeSchema, "unknown op")
}
