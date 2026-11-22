package reqring

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	cr "github.com/deutschland-schild/schild/contract/requests"
)

// The served log on disk (MVP-27, D103). A node of a group numbers every
// request it serves itself (Entry.Seq). The newest are held in memory
// (teeBuf); all of them are in the segments, as long as the ring keeps
// those. Another node asks for what came after its cursor (Served) and so
// catches up on everything it missed, however long it was away and whether
// or not this node restarted meanwhile.
//
// Two small files in the ring directory keep what has to survive a start:
//
//	served.seq   "v1 <epoch> <next> <floor>": the name of this run of
//	             numbers, the next number, and the highest number in a
//	             segment that retention or the cap deleted
//	served.idx   "<file> <min> <max>" per closed segment: its range of
//	             numbers, so an answer opens only the files it needs

const (
	servedSeqFile = "served.seq"
	servedIdxFile = "served.idx"
	// servedJump is added to the stored number at a start: the file is
	// written once a second, and a number must never be handed out twice.
	servedJump = 1 << 20
)

type servedState struct {
	// file guards epoch, next and what was last written.
	file       sync.Mutex
	epoch      string
	next       uint64 // as read at New (0: no file)
	saved      uint64
	savedFloor uint64
	// floor: numbers up to it may be gone with a deleted segment.
	floor atomic.Uint64
	// dirty: the ranges of the closed files changed.
	dirty atomic.Bool
	// scan: one answer from disk at a time.
	scan sync.Mutex
}

// left notes that a file was deleted (under Ring.mu).
func (s *servedState) left(f *fileInfo) {
	if f.kind == kindSeg && f.seqMax > s.floor.Load() {
		s.floor.Store(f.seqMax)
	}
	s.dirty.Store(true)
}

func seqName(f *fileInfo) string { return fileName(f.kind, f.start, "") }

// loadSeqIndex reads served.seq and served.idx at New. A file the index
// does not name stays unknown and is read when an answer first needs it.
func (r *Ring) loadSeqIndex() {
	s := &r.served
	if b, err := os.ReadFile(filepath.Join(r.dir, servedSeqFile)); err == nil {
		f := strings.Fields(string(b))
		if len(f) == 4 && f[0] == "v1" && len(f[1]) == 32 {
			next, e1 := strconv.ParseUint(f[2], 10, 64)
			floor, e2 := strconv.ParseUint(f[3], 10, 64)
			if _, e3 := hex.DecodeString(f[1]); e1 == nil && e2 == nil && e3 == nil && next > 0 {
				s.epoch, s.next = f[1], next
				s.floor.Store(floor)
				s.savedFloor = floor
			}
		}
	}
	fh, err := os.Open(filepath.Join(r.dir, servedIdxFile))
	if err != nil {
		return
	}
	defer fh.Close()
	ranges := map[string][2]uint64{}
	sc := bufio.NewScanner(fh)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) != 3 {
			continue
		}
		mn, e1 := strconv.ParseUint(f[1], 10, 64)
		mx, e2 := strconv.ParseUint(f[2], 10, 64)
		if e1 == nil && e2 == nil && mn <= mx {
			ranges[f[0]] = [2]uint64{mn, mx}
		}
	}
	for _, f := range r.files {
		if rg, ok := ranges[seqName(f)]; ok {
			f.seqMin, f.seqMax, f.seqKnown = rg[0], rg[1], true
		}
	}
}

// Tee makes Add number every request of this node and keep a copy in the
// served log: the newest max entries whose strings fit maxBytes. A single
// gateway keeps none. The numbers go on where the last run stopped, with a
// jump, so none is handed out twice.
func (r *Ring) Tee(max, maxBytes int) {
	s := &r.served
	s.file.Lock()
	next := uint64(1)
	if s.epoch != "" {
		next = s.next + servedJump
	} else {
		var b [16]byte
		if _, err := rand.Read(b[:]); err != nil {
			panic(err)
		}
		s.epoch = hex.EncodeToString(b[:])
		// Segments that hold numbers without the file that counts them (it
		// was removed): go on above them.
		r.mu.Lock()
		for _, f := range r.files {
			if f.seqMax >= next {
				next = f.seqMax + servedJump
			}
		}
		r.mu.Unlock()
	}
	s.next = next
	s.file.Unlock()
	r.tee.Store(&teeBuf{buf: make([]Entry, max), maxBytes: maxBytes, next: next})
	r.saveServed()
}

// ServedEpoch names the run of numbers of the served log: it stays the
// same over restarts and changes only when the ring directory is new.
// Empty without a served log.
func (r *Ring) ServedEpoch() string {
	r.served.file.Lock()
	defer r.served.file.Unlock()
	if r.tee.Load() == nil {
		return ""
	}
	return r.served.epoch
}

// saveServed writes the next number and, when they changed, the ranges of
// the closed files (writer tick, Tee, close). Errors are logged and tried
// again with the next tick.
func (r *Ring) saveServed() {
	t := r.tee.Load()
	if t == nil {
		return
	}
	s := &r.served
	t.mu.Lock()
	next := t.next
	t.mu.Unlock()
	s.file.Lock()
	defer s.file.Unlock()
	if floor := s.floor.Load(); next != s.saved || floor != s.savedFloor {
		if err := writeSmall(filepath.Join(r.dir, servedSeqFile), fmt.Sprintf("v1 %s %d %d\n", s.epoch, next, floor)); err != nil {
			r.logs.Warn(r.cfg.Log, "request ring: cannot write the number of the served log", "err", err)
		} else {
			s.saved, s.savedFloor = next, floor
		}
	}
	if !s.dirty.Swap(false) {
		return
	}
	var b strings.Builder
	r.mu.Lock()
	for _, f := range r.files {
		if !f.open && f.seqKnown && !f.gone {
			fmt.Fprintf(&b, "%s %d %d\n", seqName(f), f.seqMin, f.seqMax)
		}
	}
	r.mu.Unlock()
	if err := writeSmall(filepath.Join(r.dir, servedIdxFile), b.String()); err != nil {
		s.dirty.Store(true)
		r.logs.Warn(r.cfg.Log, "request ring: cannot write the index of the served log", "err", err)
	}
}

// writeSmall replaces a small file through a temp file.
func writeSmall(path, text string) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(text), 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// Served returns the requests of this node after the number after, oldest
// first, at most limit entries and about maxBytes of strings. They come
// from the log in memory while it reaches back to after, else from the
// segments on disk. first is the lowest number that cannot have left with
// a deleted segment: a caller whose cursor lies below first-1 may have
// missed requests for good. next is the cursor for the following call.
// Numbers have holes (a start jumps ahead, a record can be sampled out,
// dropped or erased); a request of an erased address is never returned.
func (r *Ring) Served(after uint64, limit, maxBytes int) (rows []Entry, first, next uint64) {
	t := r.tee.Load()
	if t == nil {
		return nil, 0, after
	}
	first = r.served.floor.Load() + 1
	t.mu.Lock()
	memFirst, end := t.next-uint64(t.n), t.next
	t.mu.Unlock()
	if after >= end {
		// A cursor of another run of numbers (the caller compares epochs),
		// or nothing new.
		return nil, first, end - 1
	}
	if after+1 < memFirst {
		if rows = r.servedDisk(after, memFirst, limit, maxBytes); len(rows) > 0 {
			return rows, first, rows[len(rows)-1].Seq
		}
		// Nothing on disk in between (a jump, or all of it erased or lost):
		// go on with what memory holds.
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	memFirst = t.next - uint64(t.n)
	from := max(after+1, memFirst)
	size := 0
	next = from - 1
	for seq := from; seq < t.next && len(rows) < limit && size < maxBytes; seq++ {
		e := &t.buf[(t.head+int(seq-memFirst))%len(t.buf)]
		next = seq
		if !e.Client.IsValid() {
			continue // erased
		}
		rows = append(rows, *e)
		size += entryBytes(e) + 64
	}
	return rows, first, next
}

// servedDisk reads the requests with a number above after and below the
// bound from the segments, in the order of their numbers. Pinned segments
// are read too: they hold what sampling left out of the others; a request
// in both counts once.
func (r *Ring) servedDisk(after, below uint64, limit, maxBytes int) []Entry {
	s := &r.served
	s.scan.Lock()
	defer s.scan.Unlock()
	r.Flush()
	r.mu.Lock()
	files := append([]*fileInfo(nil), r.files...)
	r.mu.Unlock()
	var cand []Entry
	ceil := below // exclusive
	compact := func() {
		sort.Slice(cand, func(i, j int) bool { return cand[i].Seq < cand[j].Seq })
		out := cand[:0]
		for i := range cand {
			if i > 0 && cand[i].Seq == cand[i-1].Seq {
				continue
			}
			out = append(out, cand[i])
		}
		cand = out
		if len(cand) > limit {
			clear(cand[limit:])
			cand = cand[:limit]
			ceil = cand[limit-1].Seq + 1
		}
	}
	// Numbers rise with time, so the files are read oldest first. They are
	// not strictly ordered between neighbours (requests finish side by
	// side, a pinned segment repeats the minutes before it): after enough
	// rows were found, the files of the next two steps are still read.
	reached := int64(-1)
	margin := 2 * cr.SegmentStep.Milliseconds()
	for _, f := range files {
		r.mu.Lock()
		info := *f
		r.mu.Unlock()
		if info.gone {
			continue
		}
		if reached >= 0 && info.start > reached+margin {
			break
		}
		if !info.seqKnown {
			info.seqMin, info.seqMax = r.scanSeq(f)
		}
		if info.seqMax <= after || info.seqMin >= ceil {
			continue
		}
		_ = r.load(&info, func(_ int, x *Rec) bool {
			if x.Seq > after && x.Seq < ceil && x.IP.IsValid() {
				cand = append(cand, entryOf(x))
				if len(cand) >= 4*limit+64 {
					compact()
				}
			}
			return true
		})
		if reached < 0 && len(cand) >= limit {
			reached = info.start
		}
	}
	compact()
	size := 0
	for i := range cand {
		if size >= maxBytes {
			return cand[:i]
		}
		size += entryBytes(&cand[i]) + 64
	}
	return cand
}

// scanSeq reads a file once for the range of its numbers and keeps it.
func (r *Ring) scanSeq(f *fileInfo) (mn, mx uint64) {
	r.mu.Lock()
	info := *f
	r.mu.Unlock()
	if info.open {
		return info.seqMin, info.seqMax
	}
	if err := r.load(&info, func(_ int, x *Rec) bool {
		if x.Seq != 0 {
			if mn == 0 || x.Seq < mn {
				mn = x.Seq
			}
			mx = max(mx, x.Seq)
		}
		return true
	}); err != nil {
		return 0, 0 // unreadable now: asked again with the next answer
	}
	r.mu.Lock()
	if !f.seqKnown {
		f.seqMin, f.seqMax, f.seqKnown = mn, mx, true
	}
	r.mu.Unlock()
	r.served.dirty.Store(true)
	return mn, mx
}

// entryOf turns a record of this node back into the entry another node
// takes (AddForeign). The record holds the redacted path, not the template
// it was made from, and no pin: the node that takes it writes it as it
// would write its own.
func entryOf(x *Rec) Entry {
	e := Entry{T: x.T, Client: x.IP, Site: x.Site, Host: x.Host, Template: x.Path, Referrer: x.Ref, UA: x.UA, Rules: x.Rules, NRules: x.NRules,
		Score: x.Score, Status: x.Status, BytesOut: x.BytesOut, ASN: x.ASN, Country: x.Country, Method: x.Method, Outcome: x.Outcome, WBReason: x.WBReason,
		NetClass: x.NetClass, UAClass: x.UAClass, Browser: x.Browser, OS: x.OS, Device: x.Device, BotCat: x.BotCat, Verif: x.Verif, Bot: x.Bot,
		Dur: x.Dur, PageView: x.PageView, Crawler: x.Crawler, Seq: x.Seq}
	if e.Site == "_any" {
		e.Site = ""
	}
	if x.PathRaw {
		e.RawPath = x.Path
	}
	if x.HasEvent {
		e.EventID = formatUUID(x.EventID)
	}
	return e
}
