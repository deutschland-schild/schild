// Package queue is the durable, bounded priority queue between the lab's
// ingest and its scoring (concept 21 §5.0, MVP-03).
//
// Storage is an append-only segment log in its own directory: one writer
// goroutine owns every append and commits in groups, so concurrent Enqueue
// calls share one write and one fsync. Each record carries a CRC; a torn
// tail after a crash is cut off at startup. Processed items are recorded in
// a separate done-log (written by scoring, never on the ingest path), and a
// segment file is deleted once every item in it is done.
//
// Priorities: 0 new patterns, 1 repeats of known patterns, 2 sampled
// baseline. Admission is tiered so a full queue sheds the baseline first:
// baseline is admitted below 80 % of max_depth, repeats below 95 %, new
// patterns below 100 %. A full queue is answered at once, never by waiting.
//
// Replay/dedupe memory: accepted ids are kept in memory until they expire.
// After a restart the set is rebuilt from the queued items here and from the
// ids the scorer already processed (Remember, called by the lab at startup
// from its store) before ingest opens.
package queue

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"hash/fnv"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Priority of a queued message.
type Priority uint8

// Priorities, highest first.
const (
	NewPattern Priority = 0
	Repeat     Priority = 1
	Baseline   Priority = 2
	nPrio               = 3
)

// String names a priority like the dashboard API.
func (p Priority) String() string {
	return [...]string{"new_pattern", "repeat", "baseline"}[p]
}

// Errors returned to ingest.
var (
	ErrFull    = errors.New("queue: full")
	ErrBusy    = errors.New("queue: writer busy")
	ErrClosed  = errors.New("queue: closed")
	errCorrupt = errors.New("queue: corrupt record")
)

// Item is one queued message (a verified signal or feedback payload).
type Item struct {
	Seq        uint64
	Prio       Priority
	Kind       string // signal | feedback
	ID         string
	ReceivedMS int64
	Issuer     string
	KeyID      string
	Expires    int64 // unix s until which the id is remembered
	Payload    json.RawMessage
}

// Options of a queue.
type Options struct {
	// Path is the queue directory (created if missing).
	Path     string
	MaxDepth int64
	// MaxBatch bounds the items of one group commit (default 4096).
	MaxBatch int
	// Pending bounds queued write requests (default 4096); beyond it
	// EnqueueAdmitted fails fast with ErrBusy.
	Pending int
	// SegmentBytes rotates segment files (default 64 MiB).
	SegmentBytes int64
	// Sync selects the durability of a commit (default SyncOS).
	Sync SyncMode
	// NoSync is Sync = SyncNone (tests of the CPU path only).
	NoSync bool
}

// SyncMode is the durability of a group commit.
type SyncMode string

// Sync modes. SyncOS (default) is fsync(2): a committed item survives a
// crash of the lab process and of the operating system. SyncFull also
// flushes the drive's write cache where the OS separates the two (macOS
// F_FULLFSYNC), so it survives power loss there too; on Linux both are the
// same. SyncNone is for tests only.
const (
	SyncOS   SyncMode = "os"
	SyncFull SyncMode = "full"
	SyncNone SyncMode = "none"
)

func (q *Queue) sync(f *os.File) error {
	switch q.o.Sync {
	case SyncNone:
		return nil
	case SyncFull:
		return f.Sync()
	}
	return osSync(f)
}

type loc struct {
	seg  uint64
	off  int64
	size int32
	prio Priority
	recv int64
}

type segment struct {
	no    uint64
	f     *os.File
	size  int64
	live  int
	first uint64 // first seq in the file (0 = empty)
}

type writeReq struct {
	items []Item
	enc   [][]byte
	done  chan error
}

const shards = 64

type seenShard struct {
	mu sync.Mutex
	m  map[string]int64
}

// Queue is the durable priority queue.
type Queue struct {
	o       Options
	reqs    chan *writeReq
	depth   [nPrio]atomic.Int64
	pending atomic.Int64 // admitted items not yet committed
	seen    [shards]seenShard
	closed  atomic.Bool
	sendMu  sync.RWMutex
	stopped chan struct{}
	commits atomic.Uint64

	mu       sync.Mutex
	unread   [nPrio][]uint64 // FIFO of committed, unread seqs
	locs     map[uint64]loc  // committed, not done
	segs     map[uint64]*segment
	active   *segment
	nextSeq  uint64
	doneMu   sync.Mutex
	doneF    *os.File
	doneRecs int
}

var crcTable = crc32.MakeTable(crc32.Castagnoli)

// Open opens or creates the queue directory and starts the writer.
func Open(o Options) (*Queue, error) {
	if o.MaxDepth <= 0 {
		o.MaxDepth = 1_000_000
	}
	if o.MaxBatch <= 0 {
		o.MaxBatch = 4096
	}
	if o.Pending <= 0 {
		o.Pending = 4096
	}
	if o.SegmentBytes <= 0 {
		o.SegmentBytes = 64 << 20
	}
	switch {
	case o.NoSync:
		o.Sync = SyncNone
	case o.Sync == "":
		o.Sync = SyncOS
	case o.Sync != SyncOS && o.Sync != SyncFull && o.Sync != SyncNone:
		return nil, fmt.Errorf("queue: unknown sync mode %q", o.Sync)
	}
	if err := os.MkdirAll(o.Path, 0o700); err != nil {
		return nil, fmt.Errorf("queue: %w", err)
	}
	q := &Queue{o: o, reqs: make(chan *writeReq, o.Pending), stopped: make(chan struct{}), locs: map[uint64]loc{}, segs: map[uint64]*segment{}, nextSeq: 1}
	for i := range q.seen {
		q.seen[i].m = map[string]int64{}
	}
	if err := q.recover(); err != nil {
		q.closeFiles()
		return nil, fmt.Errorf("queue: recover %s: %w", o.Path, err)
	}
	go q.writer()
	return q, nil
}

func (q *Queue) segPath(no uint64) string {
	return filepath.Join(q.o.Path, fmt.Sprintf("seg-%016d.log", no))
}
func (q *Queue) donePath() string { return filepath.Join(q.o.Path, "done.log") }

// recover rebuilds the index from segments and the done-log.
func (q *Queue) recover() error {
	ents, err := os.ReadDir(q.o.Path)
	if err != nil {
		return err
	}
	var nos []uint64
	for _, e := range ents {
		if n, ok := strings.CutPrefix(e.Name(), "seg-"); ok {
			if v, err := strconv.ParseUint(strings.TrimSuffix(n, ".log"), 10, 64); err == nil {
				nos = append(nos, v)
			}
		}
	}
	sort.Slice(nos, func(i, j int) bool { return nos[i] < nos[j] })
	done := map[uint64]bool{}
	if b, err := os.ReadFile(q.donePath()); err == nil {
		for i := 0; i+8 <= len(b); i += 8 {
			done[binary.BigEndian.Uint64(b[i:])] = true
		}
	}
	now := time.Now().Unix()
	for i, no := range nos {
		f, err := os.OpenFile(q.segPath(no), os.O_RDWR, 0o600)
		if err != nil {
			return err
		}
		s := &segment{no: no, f: f}
		q.segs[no] = s
		var off int64
		rd := bufio.NewReaderSize(f, 1<<20)
		for {
			rec, n, err := readRecord(rd)
			if err != nil {
				// A torn or corrupt tail can only exist in the newest
				// segment (older ones were complete before rotation).
				if err != io.EOF && i == len(nos)-1 {
					if terr := f.Truncate(off); terr != nil {
						return terr
					}
				}
				break
			}
			var it Item
			if err := decodeRecord(rec, &it); err != nil {
				break
			}
			if it.Seq >= q.nextSeq {
				q.nextSeq = it.Seq + 1
			}
			if s.first == 0 {
				s.first = it.Seq
			}
			if !done[it.Seq] {
				q.locs[it.Seq] = loc{seg: no, off: off, size: int32(n), prio: it.Prio, recv: it.ReceivedMS}
				q.unread[it.Prio] = append(q.unread[it.Prio], it.Seq)
				q.depth[it.Prio].Add(1)
				s.live++
				if it.Expires > now {
					q.shard(it.ID).m[it.ID] = it.Expires
				}
			}
			off += int64(n)
		}
		s.size = off
	}
	for p := range q.unread {
		sort.Slice(q.unread[p], func(i, j int) bool { return q.unread[p][i] < q.unread[p][j] })
	}
	// Drop drained segments; the newest stays the active one.
	for _, no := range nos {
		if s := q.segs[no]; s.live == 0 && no != nos[len(nos)-1] {
			s.f.Close()
			os.Remove(q.segPath(no))
			delete(q.segs, no)
		}
	}
	if len(nos) > 0 {
		q.active = q.segs[nos[len(nos)-1]]
		if _, err := q.active.f.Seek(q.active.size, io.SeekStart); err != nil {
			return err
		}
	} else if err := q.rotate(); err != nil {
		return err
	}
	return q.compactDone()
}

// compactDone rewrites the done-log with the seqs of segments that still
// exist. Callers hold q.mu (or are in recover).
func (q *Queue) compactDone() error {
	// Done seqs below the first seq of the oldest remaining segment belong
	// to deleted files and can be forgotten; all others must be kept.
	minSeg := q.nextSeq
	for _, sg := range q.segs {
		if sg.first != 0 && sg.first < minSeg {
			minSeg = sg.first
		}
	}
	var keep []byte
	if b, err := os.ReadFile(q.donePath()); err == nil {
		for i := 0; i+8 <= len(b); i += 8 {
			if seq := binary.BigEndian.Uint64(b[i:]); seq >= minSeg {
				keep = append(keep, b[i:i+8]...)
			}
		}
	}
	tmp := q.donePath() + ".tmp"
	if err := os.WriteFile(tmp, keep, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, q.donePath()); err != nil {
		return err
	}
	if q.doneF != nil {
		q.doneF.Close()
	}
	f, err := os.OpenFile(q.donePath(), os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	q.doneF, q.doneRecs = f, len(keep)/8
	syncDir(q.o.Path)
	return nil
}

func (q *Queue) rotate() error {
	var no uint64 = 1
	for n := range q.segs {
		if n >= no {
			no = n + 1
		}
	}
	f, err := os.OpenFile(q.segPath(no), os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if q.active != nil && q.active.live == 0 {
		q.active.f.Close()
		os.Remove(q.segPath(q.active.no))
		delete(q.segs, q.active.no)
	}
	s := &segment{no: no, f: f}
	q.segs[no] = s
	q.active = s
	syncDir(q.o.Path)
	return nil
}

func syncDir(dir string) {
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync() // best effort; not supported on every platform
		d.Close()
	}
}

func (q *Queue) shard(id string) *seenShard {
	h := fnv.New32a()
	h.Write([]byte(id))
	return &q.seen[h.Sum32()%shards]
}

// Reserve marks id as taken until exp (unix s). It returns false when the id
// is already known (duplicate or replay within the window).
func (q *Queue) Reserve(id string, exp int64) bool {
	s := q.shard(id)
	now := time.Now().Unix()
	s.mu.Lock()
	defer s.mu.Unlock()
	if e, ok := s.m[id]; ok && e > now {
		return false
	}
	s.m[id] = exp
	return true
}

// Remember marks id as seen until exp (startup rebuild from the store).
func (q *Queue) Remember(id string, exp int64) {
	if exp <= time.Now().Unix() {
		return
	}
	s := q.shard(id)
	s.mu.Lock()
	if s.m[id] < exp {
		s.m[id] = exp
	}
	s.mu.Unlock()
}

// Release undoes a reservation whose message was not stored.
func (q *Queue) Release(id string) {
	s := q.shard(id)
	s.mu.Lock()
	delete(s.m, id)
	s.mu.Unlock()
}

// Seen reports whether id is remembered.
func (q *Queue) Seen(id string) bool {
	s := q.shard(id)
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.m[id]
	return ok && e > time.Now().Unix()
}

func (q *Queue) limit(p Priority) int64 {
	switch p {
	case Repeat:
		return q.o.MaxDepth * 95 / 100
	case Baseline:
		return q.o.MaxDepth * 80 / 100
	}
	return q.o.MaxDepth
}

func (q *Queue) total() int64 {
	var t int64
	for i := range q.depth {
		t += q.depth[i].Load()
	}
	return t
}

// Admit reports whether n items of priority p would fit now (no reservation).
func (q *Queue) Admit(p Priority, n int) bool {
	return q.pending.Load()+int64(n)+q.total() <= q.limit(p)
}

// TryAdmit reserves room for n items of priority p atomically; release
// unused room with Unadmit and hand admitted items to EnqueueAdmitted.
func (q *Queue) TryAdmit(p Priority, n int) bool {
	lim := q.limit(p)
	for {
		cur := q.pending.Load()
		if cur+int64(n)+q.total() > lim {
			return false
		}
		if q.pending.CompareAndSwap(cur, cur+int64(n)) {
			return true
		}
	}
}

// Unadmit releases room reserved with TryAdmit that was not used.
func (q *Queue) Unadmit(n int) { q.pending.Add(-int64(n)) }

// Full reports whether new patterns are refused.
func (q *Queue) Full() bool { return !q.Admit(NewPattern, 1) }

// MaxDepth returns the configured bound.
func (q *Queue) MaxDepth() int64 { return q.o.MaxDepth }

// Depth returns the depth per priority (committed, not done).
func (q *Queue) Depth() [nPrio]int64 {
	var d [nPrio]int64
	for i := range d {
		d[i] = q.depth[i].Load()
	}
	return d
}

// Commits returns the number of group commits so far.
func (q *Queue) Commits() uint64 { return q.commits.Load() }

// Enqueue stores items durably without admission control. The returned
// channel receives the commit result.
func (q *Queue) Enqueue(items []Item) (<-chan error, error) {
	q.pending.Add(int64(len(items)))
	done, err := q.EnqueueAdmitted(items)
	if err != nil {
		q.pending.Add(-int64(len(items)))
	}
	return done, err
}

// EnqueueAdmitted is Enqueue for items whose room was reserved with
// TryAdmit. It fails fast with ErrBusy when the writer backlog is full; on
// error the reservation is still held (call Unadmit). Items are encoded here,
// in the caller's goroutine, to keep the writer short.
func (q *Queue) EnqueueAdmitted(items []Item) (<-chan error, error) {
	q.sendMu.RLock()
	defer q.sendMu.RUnlock()
	if q.closed.Load() {
		return nil, ErrClosed
	}
	r := &writeReq{items: items, enc: make([][]byte, len(items)), done: make(chan error, 1)}
	for i := range items {
		r.enc[i] = encodeItem(&items[i])
	}
	select {
	case q.reqs <- r:
		return r.done, nil
	default:
		return nil, ErrBusy
	}
}

func (q *Queue) writer() {
	defer close(q.stopped)
	var buf []byte
	for r := range q.reqs {
		batch := []*writeReq{r}
		n := len(r.items)
	drain:
		for n < q.o.MaxBatch {
			select {
			case r2, ok := <-q.reqs:
				if !ok {
					break drain
				}
				batch = append(batch, r2)
				n += len(r2.items)
			default:
				break drain
			}
		}
		err := q.append(batch, &buf)
		q.commits.Add(1)
		for _, r := range batch {
			q.pending.Add(-int64(len(r.items)))
			if err != nil {
				for _, it := range r.items {
					q.Release(it.ID)
				}
			}
			r.done <- err
		}
	}
}

// append writes one group commit: all records, one fsync, then the index.
func (q *Queue) append(batch []*writeReq, bufp *[]byte) error {
	q.mu.Lock()
	if q.active.size >= q.o.SegmentBytes {
		if err := q.rotate(); err != nil {
			q.mu.Unlock()
			return err
		}
	}
	seg := q.active
	seq := q.nextSeq
	q.mu.Unlock()

	buf := (*bufp)[:0]
	type pend struct {
		seq  uint64
		off  int64
		size int
		prio Priority
		recv int64
	}
	ps := make([]pend, 0, 64)
	for _, r := range batch {
		for i := range r.items {
			it := &r.items[i]
			it.Seq = seq
			start := len(buf)
			buf = appendRecord(buf, it.Prio, seq, r.enc[i])
			ps = append(ps, pend{seq: seq, off: seg.size + int64(start), size: len(buf) - start, prio: it.Prio, recv: it.ReceivedMS})
			seq++
		}
	}
	*bufp = buf
	if _, err := seg.f.Write(buf); err != nil {
		_ = seg.f.Truncate(seg.size)
		_, _ = seg.f.Seek(seg.size, io.SeekStart)
		return err
	}
	if err := q.sync(seg.f); err != nil {
		return err
	}
	q.mu.Lock()
	if seg.first == 0 && len(ps) > 0 {
		seg.first = ps[0].seq
	}
	seg.size += int64(len(buf))
	q.nextSeq = seq
	for _, p := range ps {
		q.locs[p.seq] = loc{seg: seg.no, off: p.off, size: int32(p.size), prio: p.prio, recv: p.recv}
		q.unread[p.prio] = append(q.unread[p.prio], p.seq)
		seg.live++
		q.depth[p.prio].Add(1)
	}
	q.mu.Unlock()
	return nil
}

// Read returns up to max unread items in priority order. Call Done after
// processing them; until then they stay queued (and come back after a
// restart).
func (q *Queue) Read(max int) ([]Item, error) {
	type want struct {
		seq uint64
		l   loc
		f   *os.File
	}
	q.mu.Lock()
	var ws []want
	for p := 0; p < nPrio && len(ws) < max; p++ {
		k := min(len(q.unread[p]), max-len(ws))
		for _, seq := range q.unread[p][:k] {
			l := q.locs[seq]
			ws = append(ws, want{seq: seq, l: l, f: q.segs[l.seg].f})
		}
		q.unread[p] = q.unread[p][k:]
	}
	q.mu.Unlock()
	out := make([]Item, 0, len(ws))
	for _, w := range ws {
		b := make([]byte, w.l.size)
		var it Item
		if _, err := w.f.ReadAt(b, w.l.off); err != nil {
			it = Item{Kind: "corrupt"}
		} else if rec, _, err := readRecord(bufio.NewReader(bytes.NewReader(b))); err != nil || decodeRecord(rec, &it) != nil {
			it = Item{Kind: "corrupt"}
		}
		it.Seq, it.Prio = w.seq, w.l.prio
		out = append(out, it)
	}
	return out, nil
}

// Done records items as processed (one fsync of the done-log) and deletes
// segment files that hold nothing pending any more.
func (q *Queue) Done(items []Item) error {
	if len(items) == 0 {
		return nil
	}
	if q.closed.Load() {
		return ErrClosed
	}
	b := make([]byte, 0, 8*len(items))
	for _, it := range items {
		b = binary.BigEndian.AppendUint64(b, it.Seq)
	}
	q.doneMu.Lock()
	_, err := q.doneF.Write(b)
	if err == nil {
		err = q.sync(q.doneF)
	}
	q.doneRecs += len(items)
	q.doneMu.Unlock()
	if err != nil {
		return err
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	for _, it := range items {
		l, ok := q.locs[it.Seq]
		if !ok {
			continue
		}
		delete(q.locs, it.Seq)
		q.depth[l.prio].Add(-1)
		if s := q.segs[l.seg]; s != nil {
			s.live--
			if s.live == 0 && s != q.active {
				s.f.Close()
				os.Remove(q.segPath(s.no))
				delete(q.segs, s.no)
			}
		}
	}
	return nil
}

// Oldest returns the age of the oldest unread item.
func (q *Queue) Oldest(now time.Time) time.Duration {
	q.mu.Lock()
	defer q.mu.Unlock()
	var oldest int64
	for p := range q.unread {
		if len(q.unread[p]) > 0 {
			if l := q.locs[q.unread[p][0]]; oldest == 0 || l.recv < oldest {
				oldest = l.recv
			}
		}
	}
	if oldest == 0 {
		return 0
	}
	return now.Sub(time.UnixMilli(oldest))
}

// GC forgets expired ids and compacts the done-log when it grew large.
func (q *Queue) GC(now time.Time) int {
	n := 0
	t := now.Unix()
	for i := range q.seen {
		s := &q.seen[i]
		s.mu.Lock()
		for id, e := range s.m {
			if e <= t {
				delete(s.m, id)
				n++
			}
		}
		s.mu.Unlock()
	}
	q.mu.Lock()
	q.doneMu.Lock()
	if q.doneRecs > 1_000_000 && !q.closed.Load() {
		_ = q.compactDone()
	}
	q.doneMu.Unlock()
	q.mu.Unlock()
	return n
}

// SeenSize returns the number of remembered ids.
func (q *Queue) SeenSize() int {
	n := 0
	for i := range q.seen {
		q.seen[i].mu.Lock()
		n += len(q.seen[i].m)
		q.seen[i].mu.Unlock()
	}
	return n
}

// Close stops the writer and closes the files.
func (q *Queue) Close() error {
	q.sendMu.Lock()
	if q.closed.Swap(true) {
		q.sendMu.Unlock()
		return nil
	}
	close(q.reqs)
	q.sendMu.Unlock()
	<-q.stopped
	q.closeFiles()
	return nil
}

func (q *Queue) closeFiles() {
	q.mu.Lock()
	defer q.mu.Unlock()
	for _, s := range q.segs {
		s.f.Close()
	}
	q.doneMu.Lock()
	if q.doneF != nil {
		q.doneF.Close()
	}
	q.doneMu.Unlock()
}

// --- records ------------------------------------------------------------------

// Record: u32 body length | u32 crc32c(body) | body.
// Body: u8 version (1) | u8 priority | u64 seq | item.
func appendRecord(b []byte, p Priority, seq uint64, item []byte) []byte {
	b = binary.BigEndian.AppendUint32(b, uint32(10+len(item)))
	crcAt := len(b)
	b = append(b, 0, 0, 0, 0)
	start := len(b)
	b = append(b, 1, byte(p))
	b = binary.BigEndian.AppendUint64(b, seq)
	b = append(b, item...)
	binary.BigEndian.PutUint32(b[crcAt:], crc32.Checksum(b[start:], crcTable))
	return b
}

const maxRecord = 1 << 20

func readRecord(r *bufio.Reader) ([]byte, int, error) {
	var hdr [8]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		if err == io.ErrUnexpectedEOF {
			return nil, 0, errCorrupt
		}
		return nil, 0, err
	}
	n := binary.BigEndian.Uint32(hdr[:4])
	if n < 10 || n > maxRecord {
		return nil, 0, errCorrupt
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, 0, errCorrupt
	}
	if crc32.Checksum(body, crcTable) != binary.BigEndian.Uint32(hdr[4:]) {
		return nil, 0, errCorrupt
	}
	return body, int(n) + 8, nil
}

func decodeRecord(body []byte, it *Item) error {
	if len(body) < 10 || body[0] != 1 || body[1] >= nPrio {
		return errCorrupt
	}
	it.Prio = Priority(body[1])
	it.Seq = binary.BigEndian.Uint64(body[2:])
	return decodeItem(body[10:], it)
}

func encodeItem(it *Item) []byte {
	b := make([]byte, 0, 32+len(it.Kind)+len(it.ID)+len(it.Issuer)+len(it.KeyID)+len(it.Payload))
	b = binary.BigEndian.AppendUint64(b, uint64(it.ReceivedMS))
	b = binary.BigEndian.AppendUint64(b, uint64(it.Expires))
	for _, f := range []string{it.Kind, it.ID, it.Issuer, it.KeyID} {
		b = binary.AppendUvarint(b, uint64(len(f)))
		b = append(b, f...)
	}
	b = binary.AppendUvarint(b, uint64(len(it.Payload)))
	return append(b, it.Payload...)
}

func decodeItem(b []byte, it *Item) error {
	if len(b) < 16 {
		return errCorrupt
	}
	it.ReceivedMS = int64(binary.BigEndian.Uint64(b))
	it.Expires = int64(binary.BigEndian.Uint64(b[8:]))
	b = b[16:]
	var fs [5][]byte
	for i := range fs {
		l, n := binary.Uvarint(b)
		if n <= 0 || uint64(len(b)-n) < l {
			return errCorrupt
		}
		fs[i] = b[n : n+int(l)]
		b = b[n+int(l):]
	}
	it.Kind, it.ID, it.Issuer, it.KeyID = string(fs[0]), string(fs[1]), string(fs[2]), string(fs[3])
	it.Payload = append(json.RawMessage(nil), fs[4]...)
	return nil
}
