package reqring

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/deutschland-schild/schild/contract/bots"
	cm "github.com/deutschland-schild/schild/contract/monitoring"
	cr "github.com/deutschland-schild/schild/contract/requests"
	"github.com/deutschland-schild/schild/gateway/internal/pathtpl"
)

// ErrBusy: another query held the lock longer than maxWait (one at a time
// per gateway; 429).
var ErrBusy = errors.New("reqring: another request query is running")

// ErrInvalid is a bad parameter (400 invalid with the parameter's pointer).
type ErrInvalid struct{ Param, Msg string }

func (e *ErrInvalid) Error() string { return e.Param + ": " + e.Msg }

// BotNames maps catalogue bot ids to their compact numbers and back.
type BotNames interface {
	BotID(name string) (uint16, bool)
	BotName(id uint16) string
}

// SetBots sets the bot names used for the wire form (nil: bot ids "bot-<n>").
func (r *Ring) SetBots(b BotNames) { r.mu.Lock(); r.botNames = b; r.mu.Unlock() }

func (r *Ring) bots() BotNames {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.botNames
}

// wait takes the query lock, waiting for a running query: the list, the
// aggregates of the dashboard panels and the background scan of the
// false-positive hints queue up instead of failing; ErrBusy after maxWait.
func (r *Ring) wait(ctx context.Context) error {
	t := time.NewTimer(maxWait)
	defer t.Stop()
	select {
	case r.qsem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return ErrBusy
	}
}

func (r *Ring) unlock() { <-r.qsem }

// maxWait for the query lock.
const maxWait = 20 * time.Second

// Window reports the time the ring may answer: [now - keep_hours, now].
func (r *Ring) Window(now time.Time) (time.Time, time.Time) {
	return now.Add(-time.Duration(r.cfg.KeepHours) * time.Hour), now
}

// Covers reports whether [from, to) lies within keep_hours of now.
func (r *Ring) Covers(from, to, now time.Time) bool {
	lo, _ := r.Window(now)
	return !from.Before(lo.Add(-time.Minute)) && from.Before(to)
}

// Oldest is the time of the oldest record kept (zero when empty).
func (r *Ring) Oldest() time.Time {
	r.mu.Lock()
	defer r.mu.Unlock()
	var o int64
	for _, f := range r.files {
		if f.kind == kindSeg && f.count > 0 && (o == 0 || f.min < o) {
			o = f.min
		}
	}
	if o == 0 {
		return time.Time{}
	}
	return time.UnixMilli(o)
}

// coveredFrom is the start of the oldest segment kept (ms; 0 none): from
// then on a missing record was sampled out or dropped, not expired.
func (r *Ring) coveredFrom() int64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	var o int64
	for _, f := range r.files {
		if f.kind == kindSeg && (o == 0 || min(f.start, f.min) < o) {
			o = min(f.start, f.min)
		}
	}
	return o
}

// snapshot copies the infos of files of a kind overlapping [from, to] ms.
func (r *Ring) snapshot(kind byte, from, to int64) []fileInfo {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []fileInfo
	for _, f := range r.files {
		if f.kind != kind || f.gone {
			continue
		}
		mx := f.max
		if f.open {
			mx = 1<<62 - 1
		}
		mn := f.min
		if f.count == 0 {
			mn = f.start
		}
		// Records can be older than their segment's start (long requests
		// finish late), never newer than its max.
		if mx < from || mn > to {
			continue
		}
		out = append(out, *f)
	}
	return out
}

// load decodes the records of a file and calls fn with each in file order;
// fn returns false to stop. A file deleted meanwhile counts as empty.
func (r *Ring) load(fi *fileInfo, fn func(idx int, rec *Rec) bool) error {
	return r.loadAnchors(fi, fn, nil)
}

func (r *Ring) loadAnchors(fi *fileInfo, fn func(idx int, rec *Rec) bool, anchor func(ev [16]byte, visitor [8]byte, t int64)) error {
	frames, _, _, start, err := readFrames(fi.path)
	if err != nil && fi.raw && errors.Is(err, os.ErrNotExist) {
		// compressed meanwhile
		frames, _, _, start, err = readFrames(strings.TrimSuffix(fi.path, ".raw") + ".z")
	}
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var d dict
	var rec Rec
	stop := false
	_, err = walkFrames(frames, start, &d, frameVisitor{
		rec: func(idx int, p []byte) bool {
			if decodeRec(p, start, &d, &rec) != nil {
				return true
			}
			if !fn(idx, &rec) {
				stop = true
				return false
			}
			return true
		},
		anchor: func(ev [16]byte, vid uint64, t int64) {
			if anchor == nil {
				return
			}
			if v, ok := d.get(dictVisitor, vid); ok && len(v) == 8 {
				var vk [8]byte
				copy(vk[:], v)
				anchor(ev, vk, t)
			}
		},
	})
	_ = stop
	return err
}

// ---------------------------------------------------------------- filters

// Filter selects records (queryRequests parameters; zero values match all).
type Filter struct {
	Site        string
	Path        string
	Rule        string
	Outcome     int // -1 any
	StatusClass int // -1 any, else 1..5
	Country     string
	BotCategory int // -1 any
	Bot         int // -1 any, else the compact id
	Verif       int // -1 any, else 1..4
	Visitor     *[8]byte
	IP          netip.Addr // invalid: any
	UserAgent   string     // lower case; part of the value (D50)
}

// rawMatchesTemplate reports whether a real (redacted) path has the path
// template tpl (D63: the top lists show templates, the records real paths).
// The segment count is compared first, so most records skip the templating.
func rawMatchesTemplate(path, tpl string) bool {
	return strings.Count(path, "/") == strings.Count(tpl, "/") && pathtpl.Template(path) == tpl
}

// AnyFilter matches every record.
func AnyFilter() Filter {
	return Filter{Outcome: -1, StatusClass: -1, BotCategory: -1, Bot: -1, Verif: -1}
}

func (f *Filter) match(r *Rec) bool {
	if f.Site != "" && r.Site != f.Site {
		return false
	}
	if f.Path != "" && r.Path != f.Path && !(r.PathRaw && rawMatchesTemplate(r.Path, f.Path)) {
		return false
	}
	if f.Rule != "" {
		ok := false
		for i := uint8(0); i < r.NRules; i++ {
			ok = ok || r.Rules[i] == f.Rule
		}
		if !ok {
			return false
		}
	}
	if f.Outcome >= 0 && int(r.Outcome) != f.Outcome {
		return false
	}
	if f.StatusClass > 0 && int(r.Status/100) != f.StatusClass {
		return false
	}
	if f.Country != "" && countryOf(r) != f.Country {
		return false
	}
	if f.BotCategory >= 0 && int(r.BotCat) != f.BotCategory {
		return false
	}
	if f.Bot >= 0 && (!r.HasBot || int(r.Bot) != f.Bot) {
		return false
	}
	if f.Verif >= 0 && int(r.Verif) != f.Verif {
		return false
	}
	if f.Visitor != nil && r.Visitor != *f.Visitor {
		return false
	}
	if f.IP.IsValid() && r.IP != f.IP {
		return false
	}
	if f.UserAgent != "" && !strings.Contains(strings.ToLower(r.UA), f.UserAgent) {
		return false
	}
	return true
}

func countryOf(r *Rec) string {
	if r.Country[0] < 'A' || r.Country[0] > 'Z' || r.Country[1] < 'A' || r.Country[1] > 'Z' {
		return "ZZ"
	}
	return string(r.Country[:])
}

// ParseVisitor parses a v1- visitor key.
func ParseVisitor(s string) (*[8]byte, bool) {
	if !cr.ValidVisitorKey(s) {
		return nil, false
	}
	var v [8]byte
	if _, err := hex.Decode(v[:], []byte(s[3:])); err != nil {
		return nil, false
	}
	return &v, true
}

// ---------------------------------------------------------------- wire form

const wireTime = "2006-01-02T15:04:05.000Z"

// FormatMs renders a ms time as a Timestamp with milliseconds.
func FormatMs(ms int64) string { return time.UnixMilli(ms).UTC().Format(wireTime) }

// Wire turns a record into the RequestRecord of the API.
func (r *Ring) Wire(x *Rec) cr.Record {
	return wire(x, r.bots())
}

func wire(x *Rec, bn BotNames) cr.Record {
	out := cr.Record{T: FormatMs(x.T), Site: x.Site, Host: x.Host, Path: x.Path, PathKind: "template", Method: Methods[x.Method],
		Status: int(x.Status), Outcome: cr.Outcomes[x.Outcome], AnomalyScore: int(x.Score), Country: countryOf(x), ASN: x.ASN,
		NetClass: NetClasses[x.NetClass&15], Browser: pick(cm.BrowserFamilies, x.Browser), OS: pick(cm.OSFamilies, x.OS),
		Device: pick(cm.DeviceClasses, x.Device), BotCategory: pick(cm.BotCategories, x.BotCat), Referrer: x.Ref,
		DurationMS: durMS(x.Dur), BytesOut: x.BytesOut, PageView: x.PageView, Visitor: cr.VisitorPrefix + hex.EncodeToString(x.Visitor[:])}
	if x.IP.IsValid() {
		out.IP = x.IP.String()
	}
	out.UserAgent = x.UA
	if x.PathRaw {
		out.PathKind = "redacted"
	}
	if out.Host == "" {
		out.Host = "_"
	}
	if out.Referrer == "" {
		out.Referrer = cm.ReferrerDirect
	}
	if out.Status < 100 || out.Status > 599 {
		out.Status = 502
	}
	for i := uint8(0); i < x.NRules; i++ {
		out.Rules = append(out.Rules, x.Rules[i])
	}
	if x.HasEvent {
		out.EventID = formatUUID(x.EventID)
	}
	if x.HasBot {
		out.Bot = botName(bn, x.Bot)
		if x.Verif >= 1 && int(x.Verif) <= len(bots.Verifications) {
			out.Verification = bots.Verifications[x.Verif-1]
		}
	}
	return out
}

func botName(bn BotNames, id uint16) string {
	if bn != nil {
		if s := bn.BotName(id); s != "" {
			return s
		}
	}
	return "bot-" + strconv.Itoa(int(id))
}

func pick(list []string, i uint8) string {
	if int(i) < len(list) {
		return list[i]
	}
	return list[len(list)-1]
}

// durMS is the upper bound of a latency bucket (the overflow bucket
// reports the last finite bound).
func durMS(b uint8) float64 {
	i := int(b)
	if i >= cm.HistogramBuckets-1 {
		i = cm.HistogramBuckets - 2
	}
	return cm.BucketBound(i)
}

// ---------------------------------------------------------------- queryRequests

// QueryParams of queryRequests.
type QueryParams struct {
	From, To time.Time
	Filter   Filter
	Cursor   string
	Limit    int
	// MaxWindow and MaxScan: 6 h and 100000 for the dashboard, 1 h and
	// 10000 for the agent API.
	MaxWindow time.Duration
	MaxScan   int
}

type cursor struct {
	start int64
	idx   int
}

func parseCursor(s string) (cursor, bool) {
	a, b, ok := strings.Cut(s, ".")
	if !ok {
		return cursor{}, false
	}
	st, err1 := strconv.ParseInt(a, 36, 64)
	i, err2 := strconv.ParseInt(b, 36, 64)
	if err1 != nil || err2 != nil || st <= 0 || i < 0 {
		return cursor{}, false
	}
	return cursor{st, int(i)}, true
}

func (c cursor) String() string {
	return strconv.FormatInt(c.start, 36) + "." + strconv.FormatInt(int64(c.idx), 36)
}

// Query answers queryRequests: matching records newest first (by segment,
// then by order within it), at most MaxScan records read per call, then
// scan_capped with a cursor.
func (r *Ring) Query(ctx context.Context, p QueryParams, now time.Time) (cr.Page, error) {
	if p.MaxWindow <= 0 {
		p.MaxWindow = cr.MaxQueryWindow
	}
	if p.MaxScan <= 0 {
		p.MaxScan = cr.MaxScan
	}
	if p.Limit <= 0 {
		p.Limit = 50
	}
	if !p.From.Before(p.To) {
		return cr.Page{}, &ErrInvalid{"from", "from muss vor to liegen"}
	}
	if p.To.Sub(p.From) > p.MaxWindow {
		return cr.Page{}, &ErrInvalid{"from", fmt.Sprintf("höchstens %s auf einmal", hoursText(p.MaxWindow))}
	}
	if lo, _ := r.Window(now); p.From.Before(lo.Add(-time.Minute)) {
		return cr.Page{}, &ErrInvalid{"from", "nur die letzten " + hoursText(time.Duration(r.cfg.KeepHours)*time.Hour)}
	}
	var cur cursor
	if p.Cursor != "" {
		c, ok := parseCursor(p.Cursor)
		if !ok {
			return cr.Page{}, &ErrInvalid{"cursor", "unbekannter Cursor"}
		}
		cur = c
	}
	if err := r.wait(ctx); err != nil {
		return cr.Page{}, err
	}
	defer r.unlock()
	r.Flush()
	from, to := p.From.UnixMilli(), p.To.UnixMilli()
	files := r.snapshot(kindSeg, from, to)
	sort.Slice(files, func(i, j int) bool { return files[i].start > files[j].start })
	bn := r.bots()
	page := cr.Page{From: FormatMs(from), To: FormatMs(to), Items: []cr.Record{}, SampleRate: 1, KeepHours: r.cfg.KeepHours}
	if c := r.coveredFrom(); c > 0 {
		k := FormatMs(c)
		page.KeptFrom = &k
	}
	scanned := 0
	for fi := range files {
		f := &files[fi]
		if cur.start != 0 && f.start > cur.start {
			continue
		}
		if err := ctx.Err(); err != nil {
			return cr.Page{}, err
		}
		page.SampleRate = min(page.SampleRate, f.rate())
		// Decode the file, keep its records up to the cursor.
		var recs []Rec
		hi := -1
		if cur.start == f.start {
			hi = cur.idx
		}
		err := r.load(f, func(idx int, x *Rec) bool {
			if hi >= 0 && idx >= hi {
				return false
			}
			recs = append(recs, *x)
			return true
		})
		if err != nil {
			continue
		}
		lo := max(0, len(recs)-(p.MaxScan-scanned))
		for i := len(recs) - 1; i >= lo; i-- {
			x := &recs[i]
			scanned++
			if x.T < from || x.T >= to || !p.Filter.match(x) {
				continue
			}
			page.Items = append(page.Items, wire(x, bn))
			if len(page.Items) == p.Limit {
				if i > 0 || fi < len(files)-1 {
					c := cursor{f.start, i}.String()
					if i == 0 {
						c = cursor{nextStart(files, fi), 1 << 30}.String()
					}
					page.NextCursor = &c
				}
				page.Scanned = scanned
				return page, nil
			}
		}
		if lo > 0 {
			c := cursor{f.start, lo}.String()
			page.NextCursor, page.ScanCapped = &c, true
			break
		}
		cur = cursor{}
		if scanned >= p.MaxScan && fi < len(files)-1 {
			c := cursor{nextStart(files, fi), 1 << 30}.String()
			page.NextCursor, page.ScanCapped = &c, true
			break
		}
	}
	page.Scanned = scanned
	return page, nil
}

func nextStart(files []fileInfo, i int) int64 {
	if i+1 < len(files) {
		return files[i+1].start
	}
	return 1
}

func hoursText(d time.Duration) string {
	h := int(d / time.Hour)
	if h > 48 && h%24 == 0 {
		return strconv.Itoa(h/24) + " Tage"
	}
	if h == 1 {
		return "1 Stunde"
	}
	return strconv.Itoa(h) + " Stunden"
}

// ---------------------------------------------------------------- context

// Context answers getRequestContext for an event at t (the event's time):
// the requests of the same visitor from 5 min before to 5 min after it.
// The site strip and sites_affected are added by the caller.
func (r *Ring) Context(ctx context.Context, eventID string, t time.Time, now time.Time) (cr.Context, error) {
	ev, ok := parseUUID(eventID)
	if !ok {
		return cr.Context{}, &ErrInvalid{"event_id", "keine Ereignis-ID"}
	}
	if err := r.wait(ctx); err != nil {
		return cr.Context{}, err
	}
	defer r.unlock()
	r.Flush()
	bn := r.bots()
	w := cr.ContextWindow.Milliseconds()
	out := cr.Context{EventID: eventID, State: "expired", From: FormatMs(t.UnixMilli() - w), To: FormatMs(t.UnixMilli() + w),
		VisitorRequests: []cr.Record{}, SiteStrip: []cr.StripPoint{}}
	if t.Before(now.Add(-time.Duration(max(r.cfg.KeepHours, r.cfg.PinKeepHours)) * time.Hour)) {
		return out, nil
	}
	// 1. A pinned context: the anchor names the visitor.
	tm := t.UnixMilli()
	var anchorRec *Rec
	var visitor [8]byte
	pinned := false
	var anchorT int64
	for _, f := range r.snapshot(kindPin, tm-2*w, tm+2*w) {
		_ = r.loadAnchors(&f, func(int, *Rec) bool { return !pinned }, func(e [16]byte, v [8]byte, at int64) {
			if e == ev && !pinned {
				pinned, visitor, anchorT = true, v, at
			}
		})
		if pinned {
			break
		}
	}
	// 2. Else the record with the event id in the memory ring or the
	// segments around t.
	if !pinned {
		find := func(x *Rec) {
			if anchorRec == nil && x.HasEvent && x.EventID == ev {
				y := *x
				anchorRec = &y
			}
		}
		r.mem.scan(tm-time.Minute.Milliseconds(), tm+time.Minute.Milliseconds(), find)
		if anchorRec == nil {
			for _, f := range r.snapshot(kindSeg, tm-time.Minute.Milliseconds(), tm+time.Minute.Milliseconds()) {
				_ = r.load(&f, func(_ int, x *Rec) bool { find(x); return anchorRec == nil })
				if anchorRec != nil {
					break
				}
			}
		}
		if anchorRec == nil {
			if o := r.coveredFrom(); o != 0 && tm >= o {
				out.State = "sampled" // left out by sampling or lost to a full writer
			}
			return out, nil
		}
		visitor, anchorT = anchorRec.Visitor, anchorRec.T
	}
	from, to := anchorT-w, anchorT+w+1
	out.From, out.To = FormatMs(anchorT-w), FormatMs(anchorT+w)
	var recs []Rec
	collect := func(x *Rec) {
		if x.Visitor == visitor && x.T >= from && x.T < to {
			recs = append(recs, *x)
		}
	}
	state := "complete"
	switch {
	case pinned:
		for _, f := range r.snapshot(kindPin, from-w, to+w) {
			_ = r.load(&f, func(_ int, x *Rec) bool { collect(x); return true })
		}
	case r.mem.oldest() != 0 && r.mem.oldest() <= from:
		r.mem.scan(from, to, collect)
	default:
		for _, f := range r.snapshot(kindSeg, from, to) {
			if f.level > 0 {
				state = "sampled"
			}
			_ = r.load(&f, func(_ int, x *Rec) bool { collect(x); return true })
		}
	}
	sort.SliceStable(recs, func(i, j int) bool { return recs[i].T < recs[j].T })
	recs = dedupe(recs)
	out.State = state
	sum := cr.VisitorSummary{}
	for i := range recs {
		x := &recs[i]
		if anchorRec == nil && x.HasEvent && x.EventID == ev {
			y := *x
			anchorRec = &y
		}
		sum.Requests++
		if x.PageView {
			sum.PageViews++
		}
		if x.Status/100 == 2 {
			sum.Status2xx++
		}
		if alert(x) {
			sum.Alerts++
		}
		if len(out.VisitorRequests) < cr.MaxContextRequests {
			out.VisitorRequests = append(out.VisitorRequests, wire(x, bn))
		} else {
			out.Truncated = true
		}
	}
	switch {
	case sum.Alerts == 0:
		sum.Pattern = "no_alert"
	case sum.Alerts == sum.Requests:
		sum.Pattern = "alert_only"
	default:
		sum.Pattern = "in_session"
	}
	if sum.Requests > 0 {
		out.VisitorSummary = &sum
	}
	if anchorRec != nil {
		a := wire(anchorRec, bn)
		out.Anchor = &a
	}
	return out, nil
}

// dedupe drops repeated records (two overlapping pins of one visitor).
func dedupe(recs []Rec) []Rec {
	if len(recs) < 2 {
		return recs
	}
	out := recs[:1]
	for i := 1; i < len(recs); i++ {
		p, x := &out[len(out)-1], &recs[i]
		if x.T == p.T && x.EventID == p.EventID && x.Path == p.Path && x.Status == p.Status && x.Outcome == p.Outcome && x.BytesOut == p.BytesOut {
			continue
		}
		out = append(out, *x)
	}
	return out
}
