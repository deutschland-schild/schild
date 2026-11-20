package reqring

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/contract/msg"
	cr "github.com/deutschland-schild/schild/contract/requests"
)

// clock is a settable test clock.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func newTestRing(t *testing.T, cfg Config) (*Ring, *clock) {
	t.Helper()
	c := &clock{t: time.Date(2026, 10, 29, 10, 0, 1, 0, time.UTC)}
	if cfg.StoragePath == "" {
		cfg.StoragePath = t.TempDir()
	}
	if cfg.Now == nil {
		cfg.Now = c.now
	}
	r, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return r, c
}

// step processes waiting entries and runs the housekeeping (not started).
func (r *Ring) step(now time.Time) {
	r.drain()
	r.housekeep(now)
}

func entry(c *clock, ip string, path string) Entry {
	a := netip.MustParseAddr(ip)
	return Entry{T: c.now().UnixMilli(), Client: a, Site: "example.org", Host: "example.org:443", RawPath: path + "/", Template: path,
		Referrer: "_direct", Status: 200, BytesOut: 1234, ASN: 64500, Country: [2]byte{'D', 'E'}, Method: 0, Outcome: OutPassed,
		Browser: 0, OS: 0, Device: 0, BotCat: 12, Dur: 20, PageView: true}
}

func TestVisitorKeyMatchesContract(t *testing.T) {
	r, c := newTestRing(t, Config{})
	k := bytes.Repeat([]byte{7}, 32)
	r.mac, r.keyDay = hmac.New(sha256.New, k), c.now().Unix()/86400
	for _, ip := range []string{"203.0.113.9", "2001:db8:1:2:3:4:5:6", "::ffff:198.51.100.1"} {
		a := netip.MustParseAddr(ip)
		v := r.visitorKey(a, c.now())
		want := cr.VisitorKey(k, a)
		got := cr.VisitorPrefix + fmt.Sprintf("%x", v[:])
		if got != want {
			t.Fatalf("%s: %s != %s", ip, got, want)
		}
	}
	// IPv6 /64 is one visitor.
	a, b := netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8::ffff:1")
	if r.visitorKey(a, c.now()) != r.visitorKey(b, c.now()) {
		t.Fatal("/64 not one visitor")
	}
	// The daily key changes at 00:00 UTC.
	v1 := r.visitorKey(a, c.now())
	v2 := r.visitorKey(a, c.now().Add(24*time.Hour))
	if v1 == v2 {
		t.Fatal("visitor key survived the day")
	}
}

func TestRoundTripAndQuery(t *testing.T) {
	r, c := newTestRing(t, Config{})
	ev := msg.NewID()
	e := entry(c, "203.0.113.9", "/login")
	e.EventID, e.Outcome, e.Score, e.Rules, e.NRules, e.Status, e.WBReason = ev, OutWouldBlock, 8, [3]string{"942100", "941100", ""}, 2, 302, WBReasonIndex("gateway_observe")
	r.Add(&e)
	c.add(time.Second)
	e2 := entry(c, "198.51.100.7", "/")
	e2.Bot, e2.Verif, e2.BotCat = 3, VerifMismatch, 0
	r.Add(&e2)
	r.Flush()
	now := c.now()
	p, err := r.Query(context.Background(), QueryParams{From: now.Add(-time.Hour), To: now.Add(time.Minute), Filter: AnyFilter()}, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Items) != 2 || p.SampleRate != 1 || p.Scanned != 2 {
		t.Fatalf("%+v", p)
	}
	b, a := p.Items[0], p.Items[1] // newest first
	if a.EventID != ev || a.Outcome != "would_block" || a.AnomalyScore != 8 || len(a.Rules) != 2 || a.Rules[0] != "942100" ||
		a.Host != "example.org" || a.Path != "/login" || a.PathKind != "template" || a.Status != 302 || a.Country != "DE" ||
		a.ASN != 64500 || a.Browser != "chrome" || a.BotCategory != "likely_browser" || !a.PageView || a.BytesOut != 1234 ||
		!cr.ValidVisitorKey(a.Visitor) || a.Bot != "" || a.Verification != "" {
		t.Fatalf("%+v", a)
	}
	if b.Bot != "bot-3" || b.Verification != "mismatch" || b.BotCategory != "search_engine" || b.Visitor == a.Visitor {
		t.Fatalf("%+v", b)
	}
	// Filters.
	f := AnyFilter()
	f.Rule = "941100"
	p, _ = r.Query(context.Background(), QueryParams{From: now.Add(-time.Hour), To: now.Add(time.Minute), Filter: f}, now)
	if len(p.Items) != 1 || p.Items[0].EventID != ev {
		t.Fatalf("rule filter: %+v", p)
	}
	vk, _ := ParseVisitor(b.Visitor)
	f = AnyFilter()
	f.Visitor = vk
	p, _ = r.Query(context.Background(), QueryParams{From: now.Add(-time.Hour), To: now.Add(time.Minute), Filter: f}, now)
	if len(p.Items) != 1 || p.Items[0].Visitor != b.Visitor {
		t.Fatalf("visitor filter: %+v", p)
	}
	// Window checks.
	if _, err := r.Query(context.Background(), QueryParams{From: now.Add(-7 * time.Hour), To: now, Filter: AnyFilter()}, now); err == nil {
		t.Fatal("7 h accepted")
	}
}

func TestQueryPagingAndScanCap(t *testing.T) {
	r, c := newTestRing(t, Config{})
	for i := 0; i < 300; i++ {
		e := entry(c, fmt.Sprintf("203.0.113.%d", i%200), fmt.Sprintf("/p/%d", i))
		e.Template = fmt.Sprintf("/p/%d", i)
		r.Add(&e)
		c.add(10 * time.Millisecond)
		if i == 150 {
			r.Flush()
			c.add(10 * time.Minute) // next segment
			r.step(c.now())
		}
	}
	r.Flush()
	now := c.now()
	seen := map[string]bool{}
	cur := ""
	for pages := 0; pages < 20; pages++ {
		p, err := r.Query(context.Background(), QueryParams{From: now.Add(-time.Hour), To: now.Add(time.Minute), Filter: AnyFilter(), Limit: 70, Cursor: cur}, now)
		if err != nil {
			t.Fatal(err)
		}
		for _, it := range p.Items {
			if seen[it.Path] {
				t.Fatalf("duplicate %s", it.Path)
			}
			seen[it.Path] = true
		}
		if p.NextCursor == nil {
			break
		}
		cur = *p.NextCursor
	}
	if len(seen) != 300 {
		t.Fatalf("paged %d of 300", len(seen))
	}
	p, err := r.Query(context.Background(), QueryParams{From: now.Add(-time.Hour), To: now.Add(time.Minute), Filter: AnyFilter(), Limit: 500, MaxScan: 100}, now)
	if err != nil || !p.ScanCapped || p.Scanned != 100 || len(p.Items) != 100 || p.NextCursor == nil {
		t.Fatalf("scan cap: %+v %v", p.Scanned, err)
	}
}

// One query at a time: the list waits for a running query instead of
// failing, and gives up with its context.
func TestOneQueryAtATime(t *testing.T) {
	r, c := newTestRing(t, Config{})
	now := c.now()
	p := QueryParams{From: now.Add(-time.Hour), To: now, Filter: AnyFilter()}
	r.qsem <- struct{}{}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := r.Query(ctx, p, now); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("held lock: %v", err)
	}
	time.AfterFunc(50*time.Millisecond, r.unlock)
	if _, err := r.Query(context.Background(), p, now); err != nil {
		t.Fatalf("after the running query: %v", err)
	}
}

// replayIPs are the addresses of the privacy test.
var replayIPs = []string{"203.0.113.9", "198.51.100.77", "192.0.2.200", "2001:db8:aaaa:bbbb:1:2:3:4", "2a01:4f8:c0c:1234::99"}

// TestNoAddressOnDisk replays requests and greps every ring file, raw and
// decompressed, for the addresses, their /24 and /64 networks in text and
// binary form: 0 hits (kill_if).
func TestNoAddressTextOnDisk(t *testing.T) {
	r, c := newTestRing(t, Config{RawPath: func(string) bool { return true }})
	for round := 0; round < 3; round++ {
		for i, ip := range replayIPs {
			e := entry(c, ip, "/search")
			e.RawPath = "/search/" + ip // a path that names the address is the visitor's own text; use a template here
			e.RawPath = "/search/x"
			e.EventID = msg.NewID()
			e.Pin = i == 0
			e.Outcome = OutBlockedWAF
			r.Add(&e)
			c.add(time.Second)
		}
		r.Flush()
		c.add(10 * time.Minute)
		r.step(c.now())
	}
	r.finish()
	r.drainClosing()
	var needles [][]byte
	for _, ip := range replayIPs {
		a := netip.MustParseAddr(ip)
		needles = append(needles, []byte(ip))
		if a.Is4() {
			p, _ := a.Prefix(24)
			needles = append(needles, []byte(p.String()), []byte(strings.TrimSuffix(p.Addr().String(), ".0")+"."))
		} else {
			p, _ := a.Prefix(64)
			needles = append(needles, []byte(p.String()), []byte(strings.TrimSuffix(p.Addr().String(), "::")))
		}
	}
	needles = append(needles, []byte("/24"), []byte("/64"))
	files, _ := filepath.Glob(filepath.Join(r.dir, "*"))
	if len(files) == 0 {
		t.Fatal("no ring files")
	}
	for _, f := range files {
		raw, _ := os.ReadFile(f)
		frames, _, _, _, err := readFrames(f)
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		for _, n := range needles {
			if bytes.Contains(raw, n) || bytes.Contains(frames, n) {
				t.Fatalf("%s contains %q", filepath.Base(f), n)
			}
		}
	}
}

// drainClosing compresses what the writer handed to the closer (tests
// without Start).
func (r *Ring) drainClosing() {
	for {
		select {
		case fi := <-r.closing:
			r.closeFile(fi)
		default:
			return
		}
	}
}

func TestRotationCompressionRetention(t *testing.T) {
	r, c := newTestRing(t, Config{KeepHours: 1})
	for i := 0; i < 8; i++ {
		e := entry(c, "203.0.113.9", "/")
		r.Add(&e)
		r.Flush()
		c.add(10 * time.Minute)
		r.step(c.now())
		r.drainClosing()
	}
	r.mu.Lock()
	n, zs := len(r.files), 0
	for _, f := range r.files {
		if !f.raw {
			zs++
		}
		if f.max < c.now().Add(-time.Hour).UnixMilli() {
			t.Errorf("file older than keep_hours kept: %s", f.path)
		}
	}
	r.mu.Unlock()
	if n == 0 || n > 7 || zs == 0 {
		t.Fatalf("files %d closed %d", n, zs)
	}
	got, _ := filepath.Glob(filepath.Join(r.dir, "*.z"))
	if len(got) != zs {
		t.Fatalf("disk %d index %d", len(got), zs)
	}
}

// TestCapAndConsistentSampling floods a small ring: it never exceeds its
// cap (by more than the open segment's write buffer), samples, and a
// sampled segment holds every request of the visitors it keeps.
func TestCapAndConsistentSampling(t *testing.T) {
	const capBytes = 600 << 10
	r, c := newTestRing(t, Config{KeepHours: 1, MaxBytes: capBytes})
	var maxSeen int64
	for seg := 0; seg < 10; seg++ {
		for i := 0; i < 6000; i++ {
			e := entry(c, fmt.Sprintf("10.%d.%d.%d", seg, i/250, i%250), fmt.Sprintf("/item/%d", i))
			e.Template = fmt.Sprintf("/item/%d", i%500)
			r.Add(&e)
			if i%1000 == 0 {
				r.drain()
				c.add(time.Second)
				r.housekeep(c.now())
				r.drainClosing()
				r.retain(c.now())
				r.mu.Lock()
				maxSeen = max(maxSeen, r.bytes)
				r.mu.Unlock()
			}
		}
		// Each visitor sends a second request in the same segment.
		for i := 0; i < 6000; i += 7 {
			e := entry(c, fmt.Sprintf("10.%d.%d.%d", seg, i/250, i%250), "/again")
			r.Add(&e)
		}
		r.drain()
		c.add(10 * time.Minute)
		r.step(c.now())
		r.drainClosing()
		r.retain(c.now())
		r.mu.Lock()
		maxSeen = max(maxSeen, r.bytes)
		r.mu.Unlock()
	}
	if maxSeen > capBytes+(64<<10) {
		t.Fatalf("ring reached %d bytes, cap %d", maxSeen, capBytes)
	}
	if UsedBytes(filepath.Dir(r.dir)) > capBytes {
		t.Fatalf("disk %d > cap", UsedBytes(filepath.Dir(r.dir)))
	}
	if r.Stats().Sampled == 0 {
		t.Fatal("no sampling above the cap")
	}
	// Consistency: in every sampled segment a visitor with "/again" also
	// has its first request.
	r.mu.Lock()
	files := append([]*fileInfo(nil), r.files...)
	r.mu.Unlock()
	checked := 0
	for _, f := range files {
		if f.level == 0 || f.kind != kindSeg {
			continue
		}
		first, again := map[[8]byte]bool{}, map[[8]byte]bool{}
		_ = r.load(f, func(_ int, x *Rec) bool {
			if x.Path == "/again" {
				again[x.Visitor] = true
			} else {
				first[x.Visitor] = true
			}
			return true
		})
		for v := range again {
			if !first[v] {
				t.Fatalf("segment %s keeps a visitor partly", f.path)
			}
			checked++
		}
	}
	if checked == 0 {
		t.Fatal("no sampled segment checked")
	}
}

func TestPinnedContext(t *testing.T) {
	r, c := newTestRing(t, Config{})
	r.level = maxLevel // sample almost everything away
	ip := "203.0.113.50"
	for _, p := range []string{"/", "/login", "/account"} {
		e := entry(c, ip, p)
		r.Add(&e)
		c.add(20 * time.Second)
	}
	ev := msg.NewID()
	e := entry(c, ip, "/account/edit")
	e.EventID, e.Pin, e.Outcome, e.Status = ev, true, OutBlockedWAF, 403
	r.Add(&e)
	evT := c.now()
	c.add(30 * time.Second)
	e = entry(c, ip, "/logout")
	r.Add(&e)
	other := entry(c, "198.51.100.1", "/")
	r.Add(&other)
	r.Flush()
	// Push the memory ring out of the window.
	r.mem.expire(c.now().Add(time.Hour).UnixMilli())
	ctx, err := r.Context(context.Background(), ev, evT, c.now())
	if err != nil {
		t.Fatal(err)
	}
	if ctx.State != "complete" || ctx.Anchor == nil || ctx.Anchor.EventID != ev || len(ctx.VisitorRequests) != 5 {
		t.Fatalf("%+v", ctx)
	}
	if ctx.VisitorSummary == nil || ctx.VisitorSummary.Pattern != "in_session" || ctx.VisitorSummary.Alerts != 1 || ctx.VisitorSummary.Requests != 5 {
		t.Fatalf("%+v", ctx.VisitorSummary)
	}
	if ctx.VisitorRequests[0].Path != "/" || ctx.VisitorRequests[4].Path != "/logout" {
		t.Fatalf("order %+v", ctx.VisitorRequests)
	}
	// An unknown event inside the ring: sampled (left out), outside: expired.
	c2, _ := r.Context(context.Background(), msg.NewID(), evT, c.now())
	if c2.State != "sampled" || c2.Anchor != nil {
		t.Fatalf("%+v", c2)
	}
	c3, _ := r.Context(context.Background(), msg.NewID(), evT.Add(-72*time.Hour), c.now())
	if c3.State != "expired" {
		t.Fatalf("%+v", c3)
	}
}

// TestPinnedContextSameMillisecond: a request of the visitor that finished in
// the millisecond of the alert is part of the pinned context, and the alert
// is in it once.
func TestPinnedContextSameMillisecond(t *testing.T) {
	r, c := newTestRing(t, Config{})
	r.level = maxLevel
	ip := "203.0.113.51"
	e := entry(c, ip, "/")
	r.Add(&e)
	c.add(time.Second)
	e = entry(c, ip, "/kontakt")
	r.Add(&e)
	ev := msg.NewID()
	e = entry(c, ip, "/kontakt/senden")
	e.EventID, e.Pin, e.Outcome, e.Status = ev, true, OutBlockedWAF, 403
	r.Add(&e)
	evT := c.now()
	r.Flush()
	r.mem.expire(c.now().Add(time.Hour).UnixMilli())
	ctx, err := r.Context(context.Background(), ev, evT, c.now())
	if err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, x := range ctx.VisitorRequests {
		paths = append(paths, x.Path)
	}
	if len(paths) != 3 || ctx.Anchor == nil || ctx.VisitorSummary == nil || ctx.VisitorSummary.Alerts != 1 {
		t.Fatalf("context: %v %+v", paths, ctx.VisitorSummary)
	}
}

// TestPinnedContextOutlivesTheRing: D51, the context of an incident stays
// after keep_hours, the ordinary segments do not, and privacy/export still
// finds it. PinKeepHours ends it.
func TestPinnedContextOutlivesTheRing(t *testing.T) {
	r, c := newTestRing(t, Config{KeepHours: 1, PinKeepHours: 24})
	ip := "203.0.113.51"
	ev := msg.NewID()
	e := entry(c, ip, "/account/edit")
	e.EventID, e.Pin, e.Outcome, e.Status = ev, true, OutBlockedWAF, 403
	r.Add(&e)
	evT := c.now()
	r.Flush()
	step := func(d time.Duration) {
		for range int(d / (10 * time.Minute)) {
			c.add(10 * time.Minute)
			r.step(c.now())
			r.drainClosing()
		}
	}
	step(3 * time.Hour)
	r.mu.Lock()
	for _, f := range r.files {
		if f.kind == kindSeg && f.max < c.now().Add(-time.Hour).UnixMilli() {
			t.Errorf("segment older than keep_hours kept: %s", f.path)
		}
	}
	r.mu.Unlock()
	got, err := r.Context(context.Background(), ev, evT, c.now())
	if err != nil || got.State != "complete" || got.Anchor == nil {
		t.Fatalf("%v %+v", err, got)
	}
	recs, err := r.ByIP(context.Background(), netip.MustParseAddr(ip), 100, c.now())
	if err != nil || len(recs) != 1 || recs[0].EventID != ev {
		t.Fatalf("%v %+v", err, recs)
	}
	if n, err := r.ForgetIP(context.Background(), netip.MustParseAddr(ip)); err != nil {
		t.Fatal(err)
	} else if recs, _ = r.ByIP(context.Background(), netip.MustParseAddr(ip), 100, c.now()); len(recs) != 0 {
		t.Fatalf("erased %d, still found %+v", n, recs)
	}
	step(22 * time.Hour)
	if got, _ = r.Context(context.Background(), ev, evT, c.now()); got.State != "expired" {
		t.Fatalf("pinned context past PinKeepHours: %+v", got)
	}
}

func TestPinsPerHourCapped(t *testing.T) {
	r, c := newTestRing(t, Config{})
	for i := 0; i < MaxPinsPerHour+30; i++ {
		e := entry(c, fmt.Sprintf("203.0.113.%d", i%250), "/x")
		e.EventID, e.Pin = msg.NewID(), true
		r.Add(&e)
		r.drain()
	}
	if got := r.Stats().Pinned; got != MaxPinsPerHour {
		t.Fatalf("pinned %d", got)
	}
}

func TestDropWhenFull(t *testing.T) {
	r, c := newTestRing(t, Config{})
	e := entry(c, "203.0.113.9", "/")
	for i := 0; i < ChanSize+10; i++ {
		r.Add(&e)
	}
	if r.Dropped() != 10 {
		t.Fatalf("dropped %d", r.Dropped())
	}
}

func TestAddDoesNotAllocate(t *testing.T) {
	r, c := newTestRing(t, Config{})
	e := entry(c, "203.0.113.9", "/")
	e.EventID = msg.NewID()
	n := testing.AllocsPerRun(1000, func() {
		r.Add(&e)
		select {
		case <-r.ch:
		default:
		}
	})
	if n != 0 {
		t.Fatalf("%v allocs", n)
	}
}

func TestRecoveryAfterCrash(t *testing.T) {
	dir := t.TempDir()
	r, c := newTestRing(t, Config{StoragePath: dir})
	for i := 0; i < 50; i++ {
		e := entry(c, "203.0.113.9", "/")
		r.Add(&e)
	}
	r.Flush()
	// Simulate a crash: a torn last frame and a stale temp file.
	raws, _ := filepath.Glob(filepath.Join(r.dir, "*.raw"))
	if len(raws) != 1 {
		t.Fatal(raws)
	}
	f, _ := os.OpenFile(raws[0], os.O_APPEND|os.O_WRONLY, 0)
	f.Write([]byte{frameRec, 40, 1, 2})
	f.Close()
	os.WriteFile(filepath.Join(r.dir, "seg-1.z.tmp"), []byte("x"), 0o600)
	r2, err := New(Config{StoragePath: dir, Now: c.now})
	if err != nil {
		t.Fatal(err)
	}
	defer r2.Close()
	if left, _ := filepath.Glob(filepath.Join(r2.dir, "*.tmp")); len(left) != 0 {
		t.Fatal("temp file kept")
	}
	now := c.now()
	p, err := r2.Query(context.Background(), QueryParams{From: now.Add(-time.Hour), To: now.Add(time.Minute), Filter: AnyFilter(), Limit: 500}, now)
	if err != nil || len(p.Items) != 50 {
		t.Fatalf("%d %v", len(p.Items), err)
	}
}

// A crash between writing seg-N.z and removing seg-N.raw leaves both
// files: the segment is indexed once, its records are read once.
func TestRecoveryRawAndZ(t *testing.T) {
	dir := t.TempDir()
	r, c := newTestRing(t, Config{StoragePath: dir})
	for i := 0; i < 50; i++ {
		e := entry(c, "203.0.113.9", "/")
		r.Add(&e)
	}
	r.Flush()
	raws, _ := filepath.Glob(filepath.Join(r.dir, "*.raw"))
	if len(raws) != 1 {
		t.Fatal(raws)
	}
	raw, err := os.ReadFile(raws[0])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := compressFile(raws[0]); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(raws[0], raw, 0o600); err != nil {
		t.Fatal(err)
	}
	r2, err := New(Config{StoragePath: dir, Now: c.now})
	if err != nil {
		t.Fatal(err)
	}
	defer r2.Close()
	if st := r2.Stats(); st.Files != 1 {
		t.Fatalf("%d files indexed, want 1", st.Files)
	}
	now := c.now()
	p, err := r2.Query(context.Background(), QueryParams{From: now.Add(-time.Hour), To: now.Add(time.Minute), Filter: AnyFilter(), Limit: 500}, now)
	if err != nil || len(p.Items) != 50 {
		t.Fatalf("%d %v", len(p.Items), err)
	}
}

func TestStartClose(t *testing.T) {
	r, c := newTestRing(t, Config{})
	r.Start(context.Background())
	e := entry(c, "203.0.113.9", "/")
	r.Add(&e)
	r.Flush()
	if r.Stats().Written != 1 {
		t.Fatal(r.Stats())
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if raws, _ := filepath.Glob(filepath.Join(r.dir, "*.raw")); len(raws) != 0 {
		t.Fatal("raw file after close", raws)
	}
}

func TestCutPathAndHost(t *testing.T) {
	if normHost("Example.ORG.:8443") != "example.org" || normHost("[2001:db8::1]:443") != "[2001:db8::1]" || normHost("a\x01b") != "" {
		t.Fatal("host")
	}
	long := strings.Repeat("ä", 400)
	if p := cutPath(long); len(p) > 512 || !strings.HasPrefix(long, p) {
		t.Fatal("cut")
	}
	if cutPath("/a\x00b") != "/ab" {
		t.Fatal("control")
	}
}

// TestLongKeepWindow (D66): 14 days of segments, the sample budget stays a
// 48 h share of the cap, and a page names the window and the oldest kept
// segment.
func TestLongKeepWindow(t *testing.T) {
	r, c := newTestRing(t, Config{KeepHours: 14 * 24, MaxBytes: 288 << 20})
	if b := r.slotBudget(); b != 1<<20 {
		t.Fatalf("slot budget %d, want 1 MiB", b)
	}
	if short, _ := newTestRing(t, Config{KeepHours: 12, MaxBytes: 72 << 20}); short.slotBudget() != 1<<20 {
		t.Fatalf("short ring budget %d", short.slotBudget())
	}
	start := c.now()
	e := entry(c, "203.0.113.9", "/")
	r.Add(&e)
	r.Flush()
	c.add(10 * 24 * time.Hour)
	e = entry(c, "203.0.113.9", "/")
	r.Add(&e)
	r.Flush()
	r.step(c.now())
	r.drainClosing()
	if !r.Covers(c.now().Add(-14*24*time.Hour), c.now(), c.now()) || r.Covers(c.now().Add(-15*24*time.Hour), c.now(), c.now()) {
		t.Fatal("window is not 14 days")
	}
	p, err := r.Query(context.Background(), QueryParams{From: c.now().Add(-time.Hour), To: c.now().Add(time.Minute), Filter: AnyFilter()}, c.now())
	if err != nil {
		t.Fatal(err)
	}
	if p.KeepHours != 14*24 || p.KeptFrom == nil || *p.KeptFrom > FormatMs(start.UnixMilli()) {
		t.Fatalf("page window %d %v", p.KeepHours, p.KeptFrom)
	}
	if _, err := r.Query(context.Background(), QueryParams{From: c.now().Add(-15 * 24 * time.Hour), To: c.now().Add(-15*24*time.Hour + time.Hour), Filter: AnyFilter()}, c.now()); err == nil || !strings.Contains(err.Error(), "14 Tage") {
		t.Fatalf("outside the window: %v", err)
	}
}
