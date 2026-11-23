package reqring

import (
	"bufio"
	"bytes"
	"compress/flate"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Segment files below <storage.path>/requests:
//
//	seg-<start ms>.raw   open segment: header + frames, append-only
//	seg-<start ms>.z     closed segment: header + flate(frames)
//	pin-<start ms>.raw   open pinned context segment (same format)
//	pin-<start ms>.z     closed pinned context segment
//	*.tmp                a close in progress (removed at start)
//
// Each segment has its own dictionaries (site, host, path, referrer, rule,
// visitor key) as frames before their first use, so a segment decodes on
// its own and retention deletes whole files.

const (
	magicRaw  = "SRQ1"
	magicZ    = "SRQZ"
	version   = 1
	rawHeader = 4 + 1 + 1 + 1 + 8
	zHeader   = rawHeader + 8 + 8 + 4
	kindSeg   = 0
	kindPin   = 1
)

// fileInfo describes one segment file. Fields change under Ring.mu.
type fileInfo struct {
	path  string
	kind  byte
	level uint8 // sampling level: the segment keeps visitors with a key below 2^(64-level)
	start int64 // ms
	min   int64 // ms of the oldest record (start until the first record)
	max   int64 // ms of the newest record
	count int
	size  int64
	open  bool // written by the writer (raw)
	raw   bool // the file is in raw form (open, or closed and not compressed yet)
	gone  bool // deleted
	// seqMin, seqMax: the range of Rec.Seq in the file (0, 0: none of this
	// node's own requests). seqKnown is false for a file of an earlier run
	// that the index of ranges does not name; it is read once then.
	seqMin, seqMax uint64
	seqKnown       bool
}

func (f *fileInfo) rate() float64 { return 1 / float64(uint64(1)<<f.level) }

func fileName(kind byte, start int64, ext string) string {
	p := "seg-"
	if kind == kindPin {
		p = "pin-"
	}
	return p + strconv.FormatInt(start, 10) + ext
}

// parseName returns kind, start and whether the file is raw.
func parseName(name string) (kind byte, start int64, raw, ok bool) {
	switch {
	case strings.HasPrefix(name, "seg-"):
		kind = kindSeg
	case strings.HasPrefix(name, "pin-"):
		kind = kindPin
	default:
		return 0, 0, false, false
	}
	rest := name[4:]
	switch {
	case strings.HasSuffix(rest, ".raw"):
		raw, rest = true, strings.TrimSuffix(rest, ".raw")
	case strings.HasSuffix(rest, ".z"):
		rest = strings.TrimSuffix(rest, ".z")
	default:
		return 0, 0, false, false
	}
	n, err := strconv.ParseInt(rest, 10, 64)
	if err != nil || n <= 0 {
		return 0, 0, false, false
	}
	return kind, n, raw, true
}

func putHeader(b []byte, magic string, kind byte, level uint8, start int64) []byte {
	b = append(b, magic...)
	b = append(b, version, kind, level)
	return binary.BigEndian.AppendUint64(b, uint64(start))
}

// segWriter appends to an open segment.
type segWriter struct {
	info *fileInfo
	f    *os.File
	w    *bufio.Writer
	ids  [nDict]map[string]uint32
	dsz  int // bytes of dictionary strings
	buf  []byte
	size int64
}

// Dictionary bounds of one segment: a segment whose dictionaries grow past
// them is closed early (a flood of distinct paths costs files, not memory).
const (
	maxDictEntries = 1 << 16
	maxDictBytes   = 8 << 20
)

func createSeg(dir string, kind byte, level uint8, start int64) (*segWriter, error) {
	p := filepath.Join(dir, fileName(kind, start, ".raw"))
	f, err := os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	s := &segWriter{info: &fileInfo{path: p, kind: kind, level: level, start: start, min: start, max: start, open: true, raw: true, seqKnown: true},
		f: f, w: bufio.NewWriterSize(f, 64<<10)}
	for i := range s.ids {
		s.ids[i] = map[string]uint32{}
	}
	h := putHeader(nil, magicRaw, kind, level, start)
	if _, err := s.w.Write(h); err != nil {
		f.Close()
		os.Remove(p)
		return nil, err
	}
	s.size = int64(len(h))
	s.info.size = s.size
	return s, nil
}

func (s *segWriter) full() bool {
	if s.dsz > maxDictBytes {
		return true
	}
	for _, m := range s.ids {
		if len(m) >= maxDictEntries {
			return true
		}
	}
	return false
}

// id returns the dictionary id of v, writing a dictionary frame first when
// v is new in this segment.
func (s *segWriter) id(kind int, v string) uint32 {
	if len(v) > maxStr {
		v = v[:maxStr]
	}
	m := s.ids[kind]
	if id, ok := m[v]; ok {
		return id
	}
	return s.add(kind, v)
}

// idBytes is id for a byte key (no conversion allocation on a hit).
func (s *segWriter) idBytes(kind int, v []byte) uint32 {
	if id, ok := s.ids[kind][string(v)]; ok {
		return id
	}
	return s.add(kind, string(v))
}

func (s *segWriter) add(kind int, v string) uint32 {
	m := s.ids[kind]
	id := uint32(len(m))
	m[strings.Clone(v)] = id
	s.dsz += len(v)
	s.buf = append(s.buf[:0], frameDict, byte(kind))
	s.buf = binary.AppendUvarint(s.buf, uint64(len(v)))
	s.buf = append(s.buf, v...)
	n, _ := s.w.Write(s.buf)
	s.size += int64(n)
	return id
}

// write appends one record.
func (s *segWriter) write(r *Rec) error {
	var ids recIDs
	ids.site = s.id(dictSite, r.Site)
	ids.host = s.id(dictHost, r.Host)
	ids.path = s.id(dictPath, r.Path)
	ids.ref = s.id(dictRef, r.Ref)
	ids.visitor = s.idBytes(dictVisitor, r.Visitor[:])
	for i := uint8(0); i < r.NRules && i < 3; i++ {
		ids.rules[i] = s.id(dictRule, r.Rules[i])
	}
	p := appendRec(s.buf[:0], r, s.info.start, &ids)
	var hdr [1 + binary.MaxVarintLen64]byte
	hdr[0] = frameRec
	hn := 1 + binary.PutUvarint(hdr[1:], uint64(len(p)))
	if _, err := s.w.Write(hdr[:hn]); err != nil {
		return err
	}
	if _, err := s.w.Write(p); err != nil {
		return err
	}
	s.buf = p
	s.size += int64(hn + len(p))
	return nil
}

// anchor writes a pin anchor (event id, visitor, time).
func (s *segWriter) anchor(ev [16]byte, visitor [8]byte, t int64) {
	vid := s.idBytes(dictVisitor, visitor[:])
	s.buf = append(s.buf[:0], frameAnchor)
	s.buf = append(s.buf, ev[:]...)
	s.buf = binary.AppendUvarint(s.buf, uint64(vid))
	s.buf = binary.AppendVarint(s.buf, t-s.info.start)
	n, _ := s.w.Write(s.buf)
	s.size += int64(n)
}

func (s *segWriter) flush() error { return s.w.Flush() }

func (s *segWriter) close() error {
	err := s.w.Flush()
	if e := s.f.Close(); err == nil {
		err = e
	}
	return err
}

// ---------------------------------------------------------------- reading

// frameVisitor is called per frame of a segment.
type frameVisitor struct {
	// rec gets the payload of record number idx; return false to stop.
	rec func(idx int, payload []byte) bool
	// anchor gets a pin anchor.
	anchor func(ev [16]byte, visitorID uint64, t int64)
}

// walkFrames decodes frames from b into d until the end or the first
// incomplete frame (a raw file can end in the middle of a frame). It
// returns the number of bytes of whole frames.
func walkFrames(b []byte, start int64, d *dict, v frameVisitor) (int, error) {
	off, idx := 0, 0
	for off < len(b) {
		t := b[off]
		switch t {
		case frameDict:
			if off+2 > len(b) {
				return off, nil
			}
			kind := int(b[off+1])
			n, k := binary.Uvarint(b[off+2:])
			if k <= 0 {
				return off, nil
			}
			end := off + 2 + k + int(n)
			if n > maxStr || end > len(b) {
				if n > maxStr {
					return off, errCorrupt
				}
				return off, nil
			}
			if kind >= nDict {
				return off, errCorrupt
			}
			if d != nil {
				d[kind] = append(d[kind], string(b[off+2+k:end]))
			}
			off = end
		case frameRec:
			n, k := binary.Uvarint(b[off+1:])
			if k <= 0 {
				return off, nil
			}
			end := off + 1 + k + int(n)
			if n > 1<<16 || end > len(b) {
				if n > 1<<16 {
					return off, errCorrupt
				}
				return off, nil
			}
			if v.rec != nil && !v.rec(idx, b[off+1+k:end]) {
				return end, nil
			}
			idx++
			off = end
		case frameAnchor:
			if off+17 > len(b) {
				return off, nil
			}
			var ev [16]byte
			copy(ev[:], b[off+1:off+17])
			rd := reader{b: b[off+17:]}
			vid := rd.uvarint()
			dt := rd.varint()
			if rd.err {
				return off, nil
			}
			if v.anchor != nil {
				v.anchor(ev, vid, start+dt)
			}
			off = len(b) - len(rd.b)
		default:
			return off, errCorrupt
		}
	}
	return off, nil
}

// readFrames returns the frame bytes of a segment file and its header.
func readFrames(path string) (frames []byte, kind byte, level uint8, start int64, err error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, 0, 0, 0, err
	}
	if len(raw) < rawHeader {
		return nil, 0, 0, 0, errCorrupt
	}
	kind, level = raw[5], raw[6]
	start = int64(binary.BigEndian.Uint64(raw[7:15]))
	switch string(raw[:4]) {
	case magicRaw:
		return raw[rawHeader:], kind, level, start, nil
	case magicZ:
		if len(raw) < zHeader {
			return nil, 0, 0, 0, errCorrupt
		}
		out, err := io.ReadAll(io.LimitReader(flate.NewReader(bytes.NewReader(raw[zHeader:])), maxFrameBytes))
		if err != nil {
			return nil, 0, 0, 0, fmt.Errorf("reqring: %s: %w", filepath.Base(path), err)
		}
		return out, kind, level, start, nil
	}
	return nil, 0, 0, 0, errCorrupt
}

// maxFrameBytes bounds a decompressed segment (a segment is cut long
// before; this only guards against a damaged file).
const maxFrameBytes = 1 << 30

// zInfo reads the header of a closed segment.
func zInfo(path string) (*fileInfo, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var h [zHeader]byte
	if _, err := io.ReadFull(f, h[:]); err != nil {
		return nil, errCorrupt
	}
	if string(h[:4]) != magicZ || h[4] != version {
		return nil, errCorrupt
	}
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	return &fileInfo{path: path, kind: h[5], level: h[6], start: int64(binary.BigEndian.Uint64(h[7:15])),
		min: int64(binary.BigEndian.Uint64(h[15:23])), max: int64(binary.BigEndian.Uint64(h[23:31])),
		count: int(binary.BigEndian.Uint32(h[31:35])), size: st.Size()}, nil
}

// compressFile turns a raw segment into a closed one (header with the time
// range and count, flate frames) next to it, removes the raw file and
// returns the new info. A raw file that ends in a partial frame (a crash)
// keeps its whole frames.
func compressFile(rawPath string) (*fileInfo, error) {
	frames, kind, level, start, err := readFrames(rawPath)
	if err != nil {
		return nil, err
	}
	mn, mx, count := int64(0), int64(0), 0
	n, werr := walkFrames(frames, start, nil, frameVisitor{rec: func(_ int, p []byte) bool {
		t, k := binary.Varint(p)
		if k > 0 {
			t += start
			if count == 0 || t < mn {
				mn = t
			}
			if t > mx {
				mx = t
			}
		}
		count++
		return true
	}})
	if werr != nil && n == 0 {
		return nil, werr
	}
	frames = frames[:n]
	if count == 0 {
		mn, mx = start, start
	}
	zPath := strings.TrimSuffix(rawPath, ".raw") + ".z"
	if err := writeZ(zPath, frames, kind, level, start, mn, mx, count); err != nil {
		return nil, err
	}
	os.Remove(rawPath)
	st, err := os.Stat(zPath)
	if err != nil {
		return nil, err
	}
	return &fileInfo{path: zPath, kind: kind, level: level, start: start, min: mn, max: mx, count: count, size: st.Size()}, nil
}

// writeZ writes a closed segment through a temp file: written, synced,
// then renamed over zPath, so a crash leaves the old file or the new one,
// never a torn one (the raw file is removed after this returns).
func writeZ(zPath string, frames []byte, kind byte, level uint8, start, mn, mx int64, count int) error {
	tmp := zPath + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	h := putHeader(nil, magicZ, kind, level, start)
	h = binary.BigEndian.AppendUint64(h, uint64(mn))
	h = binary.BigEndian.AppendUint64(h, uint64(mx))
	h = binary.BigEndian.AppendUint32(h, uint32(count))
	bw := bufio.NewWriterSize(f, 64<<10)
	_, err = bw.Write(h)
	if err == nil {
		var fw *flate.Writer
		fw, err = flate.NewWriter(bw, flate.DefaultCompression)
		if err == nil {
			if _, err = fw.Write(frames); err == nil {
				err = fw.Close()
			}
		}
	}
	if err == nil {
		err = bw.Flush()
	}
	if err == nil {
		err = f.Sync()
	}
	if e := f.Close(); err == nil {
		err = e
	}
	if err == nil {
		err = os.Rename(tmp, zPath)
	}
	if err != nil {
		os.Remove(tmp)
	}
	return err
}
