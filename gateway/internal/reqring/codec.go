package reqring

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net/netip"
)

// Rec is one decoded record. Strings of records decoded from a segment are
// shared with the segment's dictionary (no allocation per record).
type Rec struct {
	T          int64 // unix ms
	Site       string
	Host       string
	Path       string
	Ref        string
	Rules      [3]string
	NRules     uint8
	PathRaw    bool
	PageView   bool
	HasEvent   bool
	HasBot     bool
	Disallowed bool // a bot request to a path its robots.txt group disallows
	Crawler    bool // D57: the crawler policy alone decided the outcome
	Method     uint8
	Status     uint16
	Outcome    uint8
	WBReason   uint8
	Score      uint16
	EventID    [16]byte
	Country    [2]byte
	ASN        uint32
	NetClass   uint8
	UAClass    uint8 // index into cm.UAClasses
	Browser    uint8
	OS         uint8
	Device     uint8
	BotCat     uint8
	Bot        uint16
	Verif      uint8
	Dur        uint8
	BytesOut   uint32
	Visitor    [8]byte
	IP         netip.Addr // invalid: erased
	UA         string     // "": none sent, or erased
	// Seq: the number of a request this node served itself in a group
	// (Entry.Seq); 0 none, a request of another node, or erased.
	Seq  uint64
	tail int // offset of the trailer in the payload
}

// Frame types of a segment.
const (
	frameDict   = 1 // kind, uvarint len, bytes: the next id of that kind
	frameRec    = 2 // uvarint len, record payload
	frameAnchor = 3 // pin anchor: event id (16), visitor dict id, t ms (zigzag delta)
)

// Dictionary kinds of a segment.
const (
	dictSite = iota
	dictHost
	dictPath
	dictRef
	dictRule
	dictVisitor
	nDict
)

// Record flags.
const (
	flPathRaw = 1 << iota
	flPageView
	flEvent
	flBot
	flDisallowed
	flRulesShift = 5 // bits 5-6: number of rules
	flCrawler    = 1 << 7
)

var errCorrupt = errors.New("reqring: corrupt record")

// maxStr bounds a dictionary string (paths are cut at 512 bytes before).
const maxStr = 1024

// appendRec encodes the payload of a record. ids are the dictionary ids
// (site, host, path, referrer, visitor, rules...) for a segment file; with
// ids nil the strings and the visitor key are inline (memory ring).
func appendRec(b []byte, r *Rec, base int64, ids *recIDs) []byte {
	b = binary.AppendVarint(b, r.T-base)
	if ids != nil {
		b = binary.AppendUvarint(b, uint64(ids.site))
		b = binary.AppendUvarint(b, uint64(ids.host))
		b = binary.AppendUvarint(b, uint64(ids.path))
		b = binary.AppendUvarint(b, uint64(ids.ref))
		b = binary.AppendUvarint(b, uint64(ids.visitor))
	} else {
		b = appendStr(b, r.Site)
		b = appendStr(b, r.Host)
		b = appendStr(b, r.Path)
		b = appendStr(b, r.Ref)
		b = append(b, r.Visitor[:]...)
	}
	n := r.NRules
	if n > 3 {
		n = 3
	}
	f := byte(n) << flRulesShift
	if r.PathRaw {
		f |= flPathRaw
	}
	if r.PageView {
		f |= flPageView
	}
	if r.HasEvent {
		f |= flEvent
	}
	if r.HasBot {
		f |= flBot
	}
	if r.Disallowed {
		f |= flDisallowed
	}
	if r.Crawler {
		f |= flCrawler
	}
	b = append(b, f, r.Method)
	b = binary.AppendUvarint(b, uint64(r.Status))
	b = append(b, r.Outcome<<4|r.WBReason&15)
	b = binary.AppendUvarint(b, uint64(r.Score))
	for i := uint8(0); i < n; i++ {
		if ids != nil {
			b = binary.AppendUvarint(b, uint64(ids.rules[i]))
		} else {
			b = appendStr(b, r.Rules[i])
		}
	}
	if r.HasEvent {
		b = append(b, r.EventID[:]...)
	}
	b = append(b, r.Country[0], r.Country[1])
	b = binary.AppendUvarint(b, uint64(r.ASN))
	b = append(b, r.NetClass&15|r.UAClass<<4, r.Browser<<4|r.OS&15, r.Device<<4|r.BotCat&15)
	if r.HasBot {
		b = binary.AppendUvarint(b, uint64(r.Bot))
		b = append(b, r.Verif)
	}
	b = append(b, r.Dur)
	b = binary.AppendUvarint(b, uint64(r.BytesOut))
	// The trailer: address and user agent; all zero means erased (D49, D50).
	switch {
	case r.IP.Is4():
		a := r.IP.As4()
		b = append(append(b, 4), a[:]...)
	case r.IP.IsValid():
		a := r.IP.As16()
		b = append(append(b, 16), a[:]...)
	default:
		b = append(b, 0)
	}
	b = appendStr(b, r.UA)
	// Optional, after the trailer: a record without it is one of a single
	// gateway, of another node, or of a version before this field. An
	// erasure zeroes everything from the trailer on, this number too.
	if r.Seq != 0 {
		b = binary.AppendUvarint(b, r.Seq)
	}
	return b
}

type recIDs struct {
	site, host, path, ref, visitor uint32
	rules                          [3]uint32
}

func appendStr(b []byte, s string) []byte {
	if len(s) > maxStr {
		s = s[:maxStr]
	}
	b = binary.AppendUvarint(b, uint64(len(s)))
	return append(b, s...)
}

// reader decodes a payload.
type reader struct {
	b   []byte
	err bool
}

func (r *reader) uvarint() uint64 {
	v, n := binary.Uvarint(r.b)
	if n <= 0 {
		r.err = true
		r.b = nil
		return 0
	}
	r.b = r.b[n:]
	return v
}

func (r *reader) varint() int64 {
	v, n := binary.Varint(r.b)
	if n <= 0 {
		r.err = true
		r.b = nil
		return 0
	}
	r.b = r.b[n:]
	return v
}

func (r *reader) byte() byte {
	if len(r.b) < 1 {
		r.err = true
		return 0
	}
	c := r.b[0]
	r.b = r.b[1:]
	return c
}

func (r *reader) bytes(n int) []byte {
	if len(r.b) < n {
		r.err = true
		r.b = nil
		return nil
	}
	out := r.b[:n]
	r.b = r.b[n:]
	return out
}

// str reads an inline string; intern turns it into a string (the memory
// ring interns nothing and copies).
func (r *reader) str() string {
	n := r.uvarint()
	if n > maxStr {
		r.err = true
		return ""
	}
	return string(r.bytes(int(n)))
}

// dict resolves dictionary ids of a segment.
type dict [nDict][]string

func (d *dict) get(kind int, id uint64) (string, bool) {
	if id >= uint64(len(d[kind])) {
		return "", false
	}
	return d[kind][id], true
}

// decodeRec decodes a payload into r; d nil: inline strings.
func decodeRec(p []byte, base int64, d *dict, r *Rec) error {
	rd := reader{b: p}
	*r = Rec{}
	r.T = base + rd.varint()
	if d != nil {
		var ok [5]bool
		r.Site, ok[0] = d.get(dictSite, rd.uvarint())
		r.Host, ok[1] = d.get(dictHost, rd.uvarint())
		r.Path, ok[2] = d.get(dictPath, rd.uvarint())
		r.Ref, ok[3] = d.get(dictRef, rd.uvarint())
		var v string
		v, ok[4] = d.get(dictVisitor, rd.uvarint())
		if ok != [5]bool{true, true, true, true, true} || len(v) != 8 {
			return errCorrupt
		}
		copy(r.Visitor[:], v)
	} else {
		r.Site, r.Host, r.Path, r.Ref = rd.str(), rd.str(), rd.str(), rd.str()
		copy(r.Visitor[:], rd.bytes(8))
	}
	f := rd.byte()
	r.PathRaw, r.PageView, r.HasEvent, r.HasBot, r.Disallowed = f&flPathRaw != 0, f&flPageView != 0, f&flEvent != 0, f&flBot != 0, f&flDisallowed != 0
	r.NRules = f >> flRulesShift & 3
	r.Crawler = f&flCrawler != 0
	r.Method = rd.byte()
	r.Status = uint16(rd.uvarint())
	o := rd.byte()
	r.Outcome, r.WBReason = o>>4, o&15
	r.Score = uint16(rd.uvarint())
	for i := uint8(0); i < r.NRules; i++ {
		if d != nil {
			s, ok := d.get(dictRule, rd.uvarint())
			if !ok {
				return errCorrupt
			}
			r.Rules[i] = s
		} else {
			r.Rules[i] = rd.str()
		}
	}
	if r.HasEvent {
		copy(r.EventID[:], rd.bytes(16))
	}
	c := rd.bytes(2)
	if len(c) == 2 {
		r.Country = [2]byte{c[0], c[1]}
	}
	r.ASN = uint32(rd.uvarint())
	nc := rd.byte()
	r.NetClass, r.UAClass = nc&15, nc>>4
	bo := rd.byte()
	r.Browser, r.OS = bo>>4, bo&15
	db := rd.byte()
	r.Device, r.BotCat = db>>4, db&15
	if r.HasBot {
		r.Bot = uint16(rd.uvarint())
		r.Verif = rd.byte()
	}
	r.Dur = rd.byte()
	r.BytesOut = uint32(rd.uvarint())
	if rd.err || int(r.Outcome) > int(OutBlockedCrawler) || int(r.Method) >= len(Methods) || int(r.NetClass) >= len(NetClasses) {
		return errCorrupt
	}
	r.tail = len(p) - len(rd.b)
	switch n := rd.byte(); n {
	case 0:
	case 4, 16:
		r.IP, _ = netip.AddrFromSlice(rd.bytes(int(n)))
	default:
		return errCorrupt
	}
	r.UA = rd.str()
	if rd.err {
		return errCorrupt
	}
	if len(rd.b) > 0 {
		r.Seq = rd.uvarint()
		if rd.err {
			return errCorrupt
		}
	}
	return nil
}

// parseUUID turns a canonical UUID string into 16 bytes.
func parseUUID(s string) ([16]byte, bool) {
	var out [16]byte
	if len(s) != 36 || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return out, false
	}
	var buf [32]byte
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '-' {
			continue
		}
		buf[n] = s[i]
		n++
	}
	if _, err := hex.Decode(out[:], buf[:]); err != nil {
		return out, false
	}
	return out, true
}

// formatUUID is the canonical form of 16 bytes.
func formatUUID(b [16]byte) string {
	var buf [36]byte
	hex.Encode(buf[0:8], b[0:4])
	buf[8] = '-'
	hex.Encode(buf[9:13], b[4:6])
	buf[13] = '-'
	hex.Encode(buf[14:18], b[6:8])
	buf[18] = '-'
	hex.Encode(buf[19:23], b[8:10])
	buf[23] = '-'
	hex.Encode(buf[24:36], b[10:16])
	return string(buf[:])
}

// FormatUUIDBytes is the canonical form of an event id of a record.
func FormatUUIDBytes(b [16]byte) string { return formatUUID(b) }
