package reqring

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"hash"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	cm "github.com/deutschland-schild/schild/contract/monitoring"
	cr "github.com/deutschland-schild/schild/contract/requests"
	"github.com/deutschland-schild/schild/gateway/internal/ratelog"
	"github.com/deutschland-schild/schild/gateway/internal/redact"
)

// Dir is the directory of the ring below storage.path.
const Dir = "requests"

// Bounds of the writer.
const (
	// ChanSize: entries waiting for the writer; a full channel drops.
	ChanSize = 16384
	// MaxPinsPerHour: incidents and alerts whose context is kept unsampled
	// (pinned) per hour; later ones in the same hour use the sampled ring.
	MaxPinsPerHour = 120
	// maxLevel: the lowest sample rate is 1/2^maxLevel.
	maxLevel = 12
	// tick of the writer: flush, rotation, retention, cap.
	tick = time.Second
)

// Config of the ring.
type Config struct {
	// StoragePath: the ring lives in StoragePath/requests.
	StoragePath string
	KeepHours   int
	// PinKeepHours bounds pinned context segments (D51); 0: KeepHours.
	PinKeepHours int
	MaxBytes     int64
	// RawPath reports whether records of a host keep the redacted real path
	// (the gateway: always, D63); nil: templates only (tests).
	RawPath func(host string) bool
	// Robots reports whether bot's robots.txt group of site disallows path
	// (observation only); nil: unknown.
	Robots func(site string, bot uint16, path string) bool
	Log    *slog.Logger
	Now    func() time.Time
	// MemBytes of the in-memory context ring (default ContextRingBytes).
	MemBytes int
}

// Ring is the request ring.
type Ring struct {
	// tee: see Tee.
	tee atomic.Pointer[teeBuf]
	// served: the state of the served log on disk (served.go).
	served  servedState
	cfg     Config
	dir     string
	ch      chan Entry
	dropped atomic.Int64
	written atomic.Int64
	sampled atomic.Int64 // records left out by sampling
	pinned  atomic.Int64
	logs    ratelog.Group

	mu    sync.Mutex
	files []*fileInfo // by start, oldest first
	bytes int64       // sum of file sizes

	// forgetMu serialises ForgetIP: two erasures rewriting the same
	// segment at once would each start from the old file, and the later
	// rename would bring back the address the earlier one erased.
	forgetMu sync.Mutex

	mem *memRing

	botNames BotNames

	// qsem: one query at a time per gateway.
	qsem chan struct{}
	// bdCache keeps the last breakdown scans (every dimension at once).
	bdMu    sync.Mutex
	bdCache []*bdEntry

	// writer state (writer goroutine only)
	seg          *segWriter
	pin          *segWriter
	level        uint8
	lastZ        int64   // compressed size of the last closed segment (at its level)
	lastLevel    uint8   // its level
	rawRatio     float64 // raw/compressed of the last close
	keyDay       int64
	mac          hash.Hash
	pins         map[[8]byte]pinState
	vkeys        map[netip.Prefix][8]byte
	lastSegStart int64
	lastPinStart int64
	pinHour      int64
	pinCount     int
	closing      chan *fileInfo
	wg           sync.WaitGroup
	cancel       context.CancelFunc
	done         chan struct{}
	started      atomic.Bool
	closeOnce    sync.Once
	flushReq     chan chan struct{}
	forgetReq    chan chan struct{}
	scratch      Rec
	uas          map[string]string
}

type pinState struct{ from, until int64 }

// New opens the ring directory: stale temp files are removed, raw files
// left by a crash are closed (compressed), closed files are indexed.
func New(cfg Config) (*Ring, error) {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.DiscardHandler)
	}
	if cfg.KeepHours <= 0 || cfg.KeepHours > cr.MaxKeepHours {
		cfg.KeepHours = cr.MaxKeepHours
	}
	if cfg.PinKeepHours <= 0 {
		cfg.PinKeepHours = cfg.KeepHours
	}
	if cfg.MaxBytes <= 0 {
		cfg.MaxBytes = cr.DefaultMaxSizeMB << 20
	}
	if cfg.MemBytes <= 0 {
		cfg.MemBytes = cr.ContextRingBytes
	}
	r := &Ring{cfg: cfg, dir: filepath.Join(cfg.StoragePath, Dir), ch: make(chan Entry, ChanSize), qsem: make(chan struct{}, 1), mem: newMemRing(cfg.MemBytes),
		pins: map[[8]byte]pinState{}, vkeys: map[netip.Prefix][8]byte{}, closing: make(chan *fileInfo, 64), done: make(chan struct{}), flushReq: make(chan chan struct{}), forgetReq: make(chan chan struct{}), rawRatio: 4, uas: map[string]string{}}
	if err := os.MkdirAll(r.dir, 0o700); err != nil {
		return nil, err
	}
	ents, err := os.ReadDir(r.dir)
	if err != nil {
		return nil, err
	}
	// indexed: a crash between writing seg-N.z and removing seg-N.raw
	// leaves both; compressing the raw file rewrites seg-N.z, which must
	// then not be indexed a second time (ReadDir lists .raw before .z).
	indexed := map[string]bool{}
	for _, e := range ents {
		name := e.Name()
		p := filepath.Join(r.dir, name)
		if strings.HasSuffix(name, ".tmp") {
			os.Remove(p)
			continue
		}
		_, _, raw, ok := parseName(name)
		if !ok || !e.Type().IsRegular() || indexed[p] {
			continue
		}
		var fi *fileInfo
		if raw {
			fi, err = compressFile(p)
		} else {
			fi, err = zInfo(p)
		}
		if err != nil {
			cfg.Log.Warn("request ring: unreadable segment removed", "file", name, "err", err)
			os.Remove(p)
			continue
		}
		indexed[fi.path] = true
		r.files = append(r.files, fi)
		r.bytes += fi.size
	}
	r.sortFiles()
	r.loadSeqIndex()
	for _, f := range r.files {
		if f.kind == kindSeg {
			r.lastSegStart = max(r.lastSegStart, f.start)
		} else {
			r.lastPinStart = max(r.lastPinStart, f.start)
		}
	}
	// The newest closed segment seeds the sampling level.
	for i := len(r.files) - 1; i >= 0; i-- {
		if f := r.files[i]; f.kind == kindSeg {
			r.lastZ, r.lastLevel, r.level = f.size, f.level, f.level
			break
		}
	}
	r.retain(cfg.Now())
	return r, nil
}

func (r *Ring) sortFiles() {
	sort.SliceStable(r.files, func(i, j int) bool { return r.files[i].start < r.files[j].start })
}

// Add hands one request to the writer; never blocks. A full channel drops
// the record and counts it (Stats.Dropped).
func (r *Ring) Add(e *Entry) {
	t := r.tee.Load()
	if t == nil {
		select {
		case r.ch <- *e:
		default:
			r.dropped.Add(1)
		}
		return
	}
	// A node of a group numbers what it serves: the number goes into the
	// served log and into the record on disk.
	x := *e
	x.Seq = t.add(e)
	select {
	case r.ch <- x:
	default:
		r.dropped.Add(1)
	}
}

// teeBuf is the served log: the requests this node served itself, each with
// a sequence number, for the other nodes of a group (MVP-27). They ask for
// what came after their cursor (Served), so a node that was away catches up
// from where it stopped, as far back as the log reaches.
//
// It is a ring of a fixed number of entries, made once and filled by value:
// Add hands its entry to nobody and stays free of allocations. The strings
// of an entry are memory the request owns; the log keeps them alive, so it
// is bounded by their bytes too.
type teeBuf struct {
	mu  sync.Mutex
	buf []Entry
	// head is the index of the oldest entry held, n how many are held.
	head, n int
	// next is the sequence number the next entry gets; the first is 1.
	next uint64
	// bytes of the strings the entries held reference, at most maxBytes.
	bytes, maxBytes int
}

// entryBytes is what an entry keeps alive beyond its own size.
func entryBytes(e *Entry) int {
	n := len(e.Site) + len(e.Host) + len(e.RawPath) + len(e.Template) + len(e.Referrer) + len(e.UA) + len(e.EventID)
	for i := range e.Rules {
		n += len(e.Rules[i])
	}
	return n
}

func (t *teeBuf) add(e *Entry) uint64 {
	sz := entryBytes(e)
	t.mu.Lock()
	for t.n > 0 && (t.n == len(t.buf) || t.bytes+sz > t.maxBytes) {
		old := &t.buf[t.head]
		t.bytes -= entryBytes(old)
		*old = Entry{}
		t.head = (t.head + 1) % len(t.buf)
		t.n--
	}
	seq := t.next
	slot := &t.buf[(t.head+t.n)%len(t.buf)]
	*slot = *e
	slot.Seq = seq
	t.n++
	t.bytes += sz
	t.next++
	t.mu.Unlock()
	return seq
}

// forgetServed takes the requests of an erased address out of the served
// log, so no node that asks later gets them.
func (r *Ring) forgetServed(ip netip.Addr) {
	t := r.tee.Load()
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	for i := 0; i < t.n; i++ {
		e := &t.buf[(t.head+i)%len(t.buf)]
		if e.Client.IsValid() && e.Client.Unmap().WithZone("") == ip {
			t.bytes -= entryBytes(e)
			*e = Entry{}
		}
	}
}

// Backlog is how many entries wait for the writer, and how many fit.
func (r *Ring) Backlog() (waiting, room int) { return len(r.ch), cap(r.ch) }

// AddForeign hands over a request another node of the group served: it is
// written like one of this node, and not told on.
func (r *Ring) AddForeign(e *Entry) {
	x := *e
	x.Seq = 0 // the number counts on the node that served it, not here
	select {
	case r.ch <- x:
	default:
		r.dropped.Add(1)
	}
}

// Start runs the writer and the closer until ctx ends or Close.
func (r *Ring) Start(ctx context.Context) {
	if !r.started.CompareAndSwap(false, true) {
		return
	}
	ctx, r.cancel = context.WithCancel(ctx)
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		for fi := range r.closing {
			r.closeFile(fi)
		}
	}()
	go r.run(ctx)
}

// Close stops the writer, closes the open segments and waits for the
// compression of every closed one.
func (r *Ring) Close() error {
	r.closeOnce.Do(r.close)
	return nil
}

func (r *Ring) close() {
	if r.started.Load() {
		r.cancel()
		<-r.done
		r.wg.Wait()
		return
	}
	r.drain()
	r.finish()
	close(r.closing)
	for fi := range r.closing {
		r.closeFile(fi)
	}
}

// Flush makes everything the writer has received readable (tests and
// queries of the open segment use the flushed bytes).
func (r *Ring) Flush() {
	if !r.started.Load() {
		r.drain()
		r.flushOpen()
		return
	}
	c := make(chan struct{})
	select {
	case r.flushReq <- c:
		<-c
	case <-r.done:
	}
}

func (r *Ring) run(ctx context.Context) {
	defer close(r.done)
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		select {
		case e := <-r.ch:
			r.handle(&e)
		case <-t.C:
			r.drain()
			r.housekeep(r.cfg.Now())
		case c := <-r.flushReq:
			r.drain()
			r.flushOpen()
			close(c)
		case c := <-r.forgetReq:
			r.drain()
			r.closeOpen()
			close(c)
		case <-ctx.Done():
			r.drain()
			r.finish()
			close(r.closing)
			return
		}
	}
}

// drain handles every waiting entry.
func (r *Ring) drain() {
	for {
		select {
		case e := <-r.ch:
			r.handle(&e)
		default:
			return
		}
	}
}

func (r *Ring) finish() {
	for _, s := range []**segWriter{&r.seg, &r.pin} {
		if *s != nil {
			r.closeSeg(*s)
			*s = nil
		}
	}
	r.saveServed()
}

// ---------------------------------------------------------------- writer

// visitorKey computes the daily visitor key of a client address (contract
// requests.VisitorKey: HMAC-SHA256 over the client key, IPv4 address or
// IPv6 /64, with the daily key; the first 8 bytes).
func (r *Ring) visitorKey(a netip.Addr, now time.Time) [8]byte {
	day := now.UTC().Unix() / 86400
	if r.mac == nil || day != r.keyDay {
		k := make([]byte, 32)
		if _, err := rand.Read(k); err != nil {
			panic(err)
		}
		r.mac, r.keyDay = hmac.New(sha256.New, k), day
		clear(k)
		clear(r.vkeys)
	}
	var out [8]byte
	if !a.IsValid() {
		return out
	}
	a = a.Unmap()
	p := netip.PrefixFrom(a, a.BitLen())
	if a.Is6() {
		p, _ = a.Prefix(64)
	}
	// The keys of recent clients are cached for the day (memory only, at
	// most maxVKeys; the cache starts over when full and at 00:00 UTC).
	if v, ok := r.vkeys[p]; ok {
		return v
	}
	defer func() {
		if len(r.vkeys) >= maxVKeys {
			clear(r.vkeys)
		}
		r.vkeys[p] = out
	}()
	var buf [96]byte
	b := append(buf[:0], visitorDomain...)
	b = p.AppendTo(b)
	r.mac.Reset()
	r.mac.Write(b)
	var sum [sha256.Size]byte
	copy(out[:], r.mac.Sum(sum[:0]))
	return out
}

// maxVKeys bounds the visitor key cache of the writer (about 4 MiB).
const maxVKeys = 1 << 16

// visitorDomain equals the HMAC domain of contract requests.VisitorKey.
const visitorDomain = "schild-visitor-v1\x00"

// keep reports whether a visitor is in the sample of a level.
func keep(v [8]byte, level uint8) bool {
	if level == 0 {
		return true
	}
	return binary.BigEndian.Uint64(v[:])>>(64-level) == 0
}

func (r *Ring) handle(e *Entry) {
	now := r.cfg.Now()
	rec := &r.scratch
	r.toRec(e, rec, now)
	r.mem.add(rec)
	r.pinWrite(e, rec, now)
	seg := r.segFor(rec.T, now)
	if seg == nil {
		return
	}
	if !keep(rec.Visitor, seg.info.level) {
		r.sampled.Add(1)
		return
	}
	if err := seg.write(rec); err != nil {
		r.logs.Warn(r.cfg.Log, "request ring: write failed", "err", err)
		return
	}
	r.written.Add(1)
	r.noteRec(seg, rec.T, rec.Seq)
}

func (r *Ring) noteRec(s *segWriter, t int64, seq uint64) {
	r.mu.Lock()
	fi := s.info
	if seq != 0 {
		if fi.seqMin == 0 || seq < fi.seqMin {
			fi.seqMin = seq
		}
		fi.seqMax = max(fi.seqMax, seq)
	}
	if fi.count == 0 || t < fi.min {
		fi.min = t
	}
	if t > fi.max {
		fi.max = t
	}
	fi.count++
	d := s.size - fi.size
	fi.size = s.size
	r.bytes += d
	r.mu.Unlock()
}

// toRec builds the record of an entry: visitor key instead of the address,
// normalised host, template or redacted path, robots.txt check.
func (r *Ring) toRec(e *Entry, rec *Rec, now time.Time) {
	*rec = Rec{T: e.T, Site: e.Site, Host: normHost(e.Host), Ref: e.Referrer, Rules: e.Rules, NRules: min(e.NRules, 3),
		PageView: e.PageView, Method: e.Method, Status: e.Status, Outcome: e.Outcome, WBReason: e.WBReason, Score: e.Score,
		Country: e.Country, ASN: e.ASN, NetClass: e.NetClass, UAClass: e.UAClass, Browser: e.Browser, OS: e.OS, Device: e.Device, BotCat: e.BotCat,
		Bot: e.Bot, Verif: e.Verif, HasBot: e.Bot != 0, Dur: e.Dur, BytesOut: e.BytesOut, Crawler: e.Crawler, Seq: e.Seq}
	if rec.Site == "" {
		rec.Site = "_any"
	}
	rec.Path = e.Template
	if r.cfg.RawPath != nil && e.RawPath != "" && r.cfg.RawPath(rec.Host) {
		rec.Path, rec.PathRaw = cutPath(redact.Path(e.RawPath)), true
	}
	rec.Path = cutPath(rec.Path)
	if rec.Path == "" {
		rec.Path = "/"
	}
	if id, ok := parseUUID(e.EventID); ok {
		rec.EventID, rec.HasEvent = id, true
	}
	if rec.HasBot && r.cfg.Robots != nil && e.RawPath != "" {
		rec.Disallowed = r.cfg.Robots(rec.Site, e.Bot, e.RawPath)
	}
	if int(rec.NetClass) >= len(NetClasses) {
		rec.NetClass = uint8(len(NetClasses) - 1)
	}
	if int(rec.Method) >= len(Methods) {
		rec.Method = uint8(len(Methods) - 1)
	}
	if int(rec.UAClass) >= len(cm.UAClasses) {
		rec.UAClass = uint8(len(cm.UAClasses) - 1)
	}
	if int(rec.BotCat) >= len(cm.BotCategories) {
		rec.BotCat = uint8(len(cm.BotCategories) - 2)
	}
	rec.Visitor = r.visitorKey(e.Client, now)
	rec.IP = e.Client.Unmap().WithZone("")
	rec.UA = r.userAgent(e.UA)
}

// userAgent cleans a User-Agent (length, control characters) once: there are few distinct ones, and this
// runs for every request (writer goroutine). The cache starts over when full.
func (r *Ring) userAgent(ua string) string {
	if ua == "" {
		return ""
	}
	if v, ok := r.uas[ua]; ok {
		return v
	}
	v := strings.Map(func(c rune) rune {
		if c < 0x20 || c == 0x7f {
			return -1
		}
		return c
	}, redact.UserAgent(ua))
	if len(r.uas) >= maxUAs {
		clear(r.uas)
	}
	r.uas[strings.Clone(ua)] = v
	return v
}

// maxUAs bounds the User-Agent cache of the writer (about 8 MiB at worst).
const maxUAs = 8192

// cutPath bounds a path at 512 bytes on a UTF-8 boundary and drops control
// characters (RequestRecord.path).
func cutPath(p string) string {
	if len(p) > 512 {
		p = p[:512]
		for len(p) > 0 && p[len(p)-1]&0xC0 == 0x80 {
			p = p[:len(p)-1]
		}
		if len(p) > 0 && p[len(p)-1] >= 0xC0 {
			p = p[:len(p)-1]
		}
	}
	for i := 0; i < len(p); i++ {
		if p[i] < 0x20 || p[i] == 0x7f {
			return strings.Map(func(c rune) rune {
				if c < 0x20 || c == 0x7f {
					return -1
				}
				return c
			}, p)
		}
	}
	return p
}

// normHost lower-cases a Host header and drops the port and a trailing
// dot; control characters make it empty.
func normHost(h string) string {
	if strings.HasPrefix(h, "[") {
		if i := strings.IndexByte(h, ']'); i > 0 {
			h = h[:i+1]
		}
	} else if i := strings.LastIndexByte(h, ':'); i >= 0 {
		h = h[:i]
	}
	h = strings.TrimSuffix(h, ".")
	if len(h) > 253 {
		h = h[:253]
	}
	for i := 0; i < len(h); i++ {
		c := h[i]
		if c < 0x20 || c == 0x7f || c >= 0x80 {
			return ""
		}
		if c >= 'A' && c <= 'Z' {
			return strings.ToLower(h)
		}
	}
	return h
}

// segFor returns the open segment for a record, rotating at the 10 min
// boundary of the writer's clock and when a segment outgrows its share of
// the cap or its dictionaries.
func (r *Ring) segFor(t int64, now time.Time) *segWriter {
	nowMs := now.UnixMilli()
	slot := nowMs - nowMs%cr.SegmentStep.Milliseconds()
	if r.seg != nil && (r.seg.info.start < slot || r.seg.full()) {
		r.rotate(false)
	}
	if r.seg != nil && r.seg.size > r.segRawLimit() {
		r.rotate(true)
	}
	if r.seg == nil {
		start := slot
		if start <= r.lastSegStart {
			start = r.lastSegStart + 1 // a segment cut early: the next one of the same 10 min
		}
		r.lastSegStart = start
		s, err := createSeg(r.dir, kindSeg, r.level, start)
		if err != nil {
			r.logs.Warn(r.cfg.Log, "request ring: cannot open a segment", "err", err)
			return nil
		}
		r.seg = s
		r.addFile(s.info)
	}
	return r.seg
}

func (r *Ring) addFile(fi *fileInfo) {
	r.mu.Lock()
	r.files = append(r.files, fi)
	r.bytes += fi.size
	r.sortFiles()
	r.mu.Unlock()
}

// slotBudget is the share of the cap of one 10 min segment: 48 h of
// segments fill the cap (D66). A longer keep_hours does not make it
// smaller: quiet days stay complete and the oldest go first above the cap;
// only a wave samples, so it cannot push out the history at once.
func (r *Ring) slotBudget() int64 {
	return r.cfg.MaxBytes / int64(min(r.cfg.KeepHours, cr.SampleBudgetHours)*6)
}

// segRawLimit: a raw segment larger than this is cut early and the next
// one samples harder (the compressed form is about rawRatio smaller).
func (r *Ring) segRawLimit() int64 {
	r.mu.Lock()
	ratio := r.rawRatio // written by the closer
	r.mu.Unlock()
	l := int64(float64(r.slotBudget()) * max(ratio, 1) * 1.5)
	return max(l, 64<<10)
}

// rotate closes the open segment. cut: it outgrew its budget, the next one
// keeps half the visitors.
func (r *Ring) rotate(cut bool) {
	s := r.seg
	r.seg = nil
	r.closeSeg(s)
	if cut && r.level < maxLevel {
		r.level++
	}
}

func (r *Ring) closeSeg(s *segWriter) {
	if err := s.close(); err != nil {
		r.logs.Warn(r.cfg.Log, "request ring: closing a segment failed", "err", err)
	}
	r.mu.Lock()
	s.info.open = false
	d := s.size - s.info.size
	s.info.size = s.size
	r.bytes += d
	r.mu.Unlock()
	r.served.dirty.Store(true) // its range of numbers goes into the index
	select {
	case r.closing <- s.info:
	default:
		r.closeFile(s.info) // the closer is behind: close here
	}
}

// closeFile compresses a closed raw segment (closer goroutine).
func (r *Ring) closeFile(fi *fileInfo) {
	r.mu.Lock()
	gone, path, rawSize := fi.gone, fi.path, fi.size
	r.mu.Unlock()
	if gone {
		return
	}
	nfi, err := compressFile(path)
	r.mu.Lock()
	defer r.mu.Unlock()
	if err != nil {
		r.logs.Warn(r.cfg.Log, "request ring: compressing a segment failed, removed", "err", err)
		os.Remove(path)
		r.dropFileLocked(fi)
		return
	}
	if fi.gone { // deleted by the cap while compressing
		os.Remove(nfi.path)
		return
	}
	r.bytes += nfi.size - fi.size
	fi.path, fi.size, fi.raw, fi.min, fi.max, fi.count = nfi.path, nfi.size, false, nfi.min, nfi.max, nfi.count
	if fi.kind == kindSeg && nfi.size > 0 {
		r.lastZ, r.lastLevel = nfi.size, fi.level
		r.rawRatio = float64(rawSize) / float64(nfi.size)
	}
}

func (r *Ring) dropFileLocked(fi *fileInfo) {
	for i, f := range r.files {
		if f == fi {
			r.files = append(r.files[:i], r.files[i+1:]...)
			r.bytes -= fi.size
			fi.gone = true
			return
		}
	}
}

func (r *Ring) flushOpen() {
	for _, s := range []*segWriter{r.seg, r.pin} {
		if s != nil {
			if err := s.flush(); err != nil {
				r.logs.Warn(r.cfg.Log, "request ring: flush failed", "err", err)
			}
		}
	}
}

// housekeep runs every second: flush, rotation of an idle segment, the
// sampling level, retention, the cap, expired pins and the memory ring.
func (r *Ring) housekeep(now time.Time) {
	r.flushOpen()
	nowMs := now.UnixMilli()
	slot := nowMs - nowMs%cr.SegmentStep.Milliseconds()
	if r.seg != nil && r.seg.info.start < slot {
		r.rotate(false)
		r.adjustLevel()
	}
	if r.pin != nil && r.pin.info.start < slot {
		r.closeSeg(r.pin)
		r.pin = nil
	}
	for v, p := range r.pins {
		if p.until < nowMs {
			delete(r.pins, v)
		}
	}
	r.mem.expire(nowMs - cr.ContextRingWindow.Milliseconds())
	r.retain(now)
	r.saveServed()
	r.logs.Flush()
}

// adjustLevel picks the sampling level of the next segment from the size
// of the last closed one: a segment may use its share of the cap
// (max_size_mb / (min(keep_hours, 48) x 6)); above it the next keeps half the
// visitors per step, below 40 % of it twice as many.
func (r *Ring) adjustLevel() {
	r.mu.Lock()
	z, lv := r.lastZ, r.lastLevel
	r.mu.Unlock()
	b := r.slotBudget()
	if z <= 0 || b <= 0 {
		return
	}
	full := float64(z) * float64(uint64(1)<<lv) // estimated size unsampled
	l := uint8(0)
	for l < maxLevel && full/float64(uint64(1)<<l) > float64(b)*0.8 {
		l++
	}
	switch {
	case l > r.level:
		r.level = l
	case l < r.level && float64(z) < float64(b)*0.4:
		r.level--
	}
}

// retain deletes segments older than keep_hours, pinned context segments
// older than PinKeepHours (D51) and, above max_size_mb, the oldest files
// first, pinned or not (D38). An open segment that alone exceeds the cap is
// cut.
func (r *Ring) retain(now time.Time) {
	cutoff := now.Add(-time.Duration(r.cfg.KeepHours) * time.Hour).UnixMilli()
	pinCutoff := now.Add(-time.Duration(r.cfg.PinKeepHours) * time.Hour).UnixMilli()
	r.mu.Lock()
	var del []string
	keepF := r.files[:0]
	for _, f := range r.files {
		cut := cutoff
		if f.kind == kindPin {
			cut = pinCutoff
		}
		if !f.open && f.max < cut && f.start < cut {
			del = append(del, f.path)
			r.bytes -= f.size
			f.gone = true
			r.served.left(f)
			continue
		}
		keepF = append(keepF, f)
	}
	r.files = keepF
	for r.bytes > r.cfg.MaxBytes {
		i := 0
		for i < len(r.files) && r.files[i].open {
			i++
		}
		if i == len(r.files) {
			break
		}
		f := r.files[i]
		del = append(del, f.path)
		r.bytes -= f.size
		f.gone = true
		r.served.left(f)
		r.files = append(r.files[:i], r.files[i+1:]...)
	}
	over := r.bytes > r.cfg.MaxBytes
	r.mu.Unlock()
	for _, p := range del {
		os.Remove(p)
		if strings.HasSuffix(p, ".raw") {
			os.Remove(strings.TrimSuffix(p, ".raw") + ".z") // compressed meanwhile
		}
	}
	if over && r.seg != nil {
		r.rotate(true)
	}
}

// ---------------------------------------------------------------- pins

// pinWrite keeps the context of an incident or alert unsampled: the
// visitor's requests of the last 5 min from the memory ring and every
// further request of the visitor for 5 min go into the pinned segment of
// the current 10 min, with an anchor for the event. At most MaxPinsPerHour
// per hour.
func (r *Ring) pinWrite(e *Entry, rec *Rec, now time.Time) {
	nowMs := now.UnixMilli()
	p, active := r.pins[rec.Visitor]
	active = active && rec.T <= p.until
	if e.Pin && rec.HasEvent {
		h := nowMs / 3600_000
		if h != r.pinHour {
			r.pinHour, r.pinCount = h, 0
		}
		if r.pinCount < MaxPinsPerHour && r.pinSeg(nowMs) != nil {
			r.pinCount++
			r.pinned.Add(1)
			from := rec.T - cr.ContextWindow.Milliseconds()
			if active && p.until > from {
				from = p.until + 1
			}
			if !active {
				p = pinState{from: from}
			}
			v := rec.Visitor
			if from <= rec.T {
				// Up to and including the millisecond of the alert: a request
				// of the visitor that finished in the same millisecond belongs
				// to the context too. The alert itself is in the memory ring
				// already and is written below.
				var hist []Rec
				r.mem.scan(from, rec.T+1, func(x *Rec) {
					if x.HasEvent && x.EventID == rec.EventID {
						return
					}
					if x.Visitor == v && len(hist) < cr.MaxContextRequests {
						y := *x
						hist = append(hist, y)
					}
				})
				for i := range hist {
					r.pinRec(&hist[i])
				}
			}
			r.pin.anchor(rec.EventID, v, rec.T)
			p.until = max(p.until, rec.T+cr.ContextWindow.Milliseconds())
			r.pins[v] = p
			active = true
		}
	}
	if active {
		r.pinRec(rec)
	}
}

func (r *Ring) pinSeg(nowMs int64) *segWriter {
	slot := nowMs - nowMs%cr.SegmentStep.Milliseconds()
	if r.pin != nil && (r.pin.info.start < slot || r.pin.full()) {
		r.closeSeg(r.pin)
		r.pin = nil
	}
	if r.pin == nil {
		start := slot
		if start <= r.lastPinStart {
			start = r.lastPinStart + 1
		}
		r.lastPinStart = start
		s, err := createSeg(r.dir, kindPin, 0, start)
		if err != nil {
			r.logs.Warn(r.cfg.Log, "request ring: cannot open a pinned segment", "err", err)
			return nil
		}
		r.pin = s
		r.addFile(s.info)
	}
	return r.pin
}

func (r *Ring) pinRec(rec *Rec) {
	if r.pin == nil {
		return
	}
	if err := r.pin.write(rec); err != nil {
		return
	}
	r.noteRec(r.pin, rec.T, rec.Seq)
}

// ---------------------------------------------------------------- stats

// Stats of the ring (settings page, Prometheus, tests).
type Stats struct {
	Files      int     `json:"files"`
	Bytes      int64   `json:"bytes"`
	MaxBytes   int64   `json:"max_bytes"`
	KeepHours  int     `json:"keep_hours"`
	Written    int64   `json:"written"`
	Dropped    int64   `json:"dropped"`
	Sampled    int64   `json:"sampled_out"`
	Pinned     int64   `json:"pinned"`
	SampleRate float64 `json:"sample_rate"`
	Oldest     int64   `json:"oldest_ms"`
	MemBytes   int     `json:"mem_bytes"`
}

// Stats returns the current figures.
func (r *Ring) Stats() Stats {
	r.mu.Lock()
	s := Stats{Files: len(r.files), Bytes: r.bytes, MaxBytes: r.cfg.MaxBytes, KeepHours: r.cfg.KeepHours, SampleRate: 1}
	for _, f := range r.files {
		if f.kind == kindSeg {
			if s.Oldest == 0 {
				s.Oldest = f.min
			}
			if f.open {
				s.SampleRate = f.rate()
			}
		}
	}
	r.mu.Unlock()
	s.Written, s.Dropped, s.Sampled, s.Pinned = r.written.Load(), r.dropped.Load(), r.sampled.Load(), r.pinned.Load()
	s.MemBytes = r.mem.bytes()
	return s
}

// Dropped is the number of records lost to a full writer channel.
func (r *Ring) Dropped() int64 { return r.dropped.Load() }

// UsedBytes sums the files of a ring directory (disk budget, D38).
func UsedBytes(storagePath string) int64 {
	ents, err := os.ReadDir(filepath.Join(storagePath, Dir))
	if err != nil {
		return 0
	}
	var n int64
	for _, e := range ents {
		if i, err := e.Info(); err == nil && i.Mode().IsRegular() {
			n += i.Size()
		}
	}
	return n
}
