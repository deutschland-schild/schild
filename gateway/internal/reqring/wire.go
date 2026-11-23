package reqring

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

// The compact form in which the nodes of a group hand each other the
// requests they served (MVP-27, contracts/cluster.md section 9, encoding
// "b1"). As JSON an entry is about 600 bytes and costs a reflection walk on
// both sides; here it is about 60 bytes and a few appends.
//
//	block  = uvarint(count) entry*
//	entry  = flags(1) zigzag(T - T of the entry before) zigzag(Seq - Seq before)
//	         client(4 or 16) ref(Site) ref(Host) ref(Template) path ref(UA)
//	         [ref(Referrer)] [text(EventID)] nrules(1) ref(rule)*
//	         uvarint(Score) uvarint(Status) uvarint(BytesOut) uvarint(ASN) country(2)
//	         Method Outcome WBReason NetClass UAClass Browser OS Device BotCat Verif Dur (1 each)
//	         uvarint(Bot)
//	ref    = uvarint(id): 0 is followed by text and takes the next id (from 1), any
//	         other id is a text seen before in this block
//	text   = uvarint(len) bytes
//	path   = uvarint(0): the same as Template; else uvarint(len+1) bytes
//	flags  = 1 PageView, 2 Crawler, 4 Pin, 8 EventID follows, 16 Referrer follows, 32 client has 16 bytes
//
// What a member sends is input from outside: the decoder bounds the number
// of entries, every text and the texts it remembers, and never reads past
// the block.

const (
	wirePageView = 1 << iota
	wireCrawler
	wirePin
	wireEvent
	wireReferrer
	wireV6
)

// Bounds of a block the decoder takes.
const (
	// WireMaxText is the longest text of an entry.
	WireMaxText = 4096
	wireMaxDict = 1 << 16
)

// ErrWire is a block that is cut short or breaks a bound.
var ErrWire = errors.New("reqring: bad block of requests")

type wireDict struct {
	ids map[string]uint64
}

func (d *wireDict) put(dst []byte, s string) []byte {
	if id, ok := d.ids[s]; ok {
		return binary.AppendUvarint(dst, id)
	}
	if len(d.ids) < wireMaxDict-1 {
		d.ids[s] = uint64(len(d.ids) + 1)
	}
	dst = append(dst, 0)
	dst = binary.AppendUvarint(dst, uint64(len(s)))
	return append(dst, s...)
}

// AppendEntries appends rows as a block to dst. An entry without a valid
// address is left out (an erased one is never handed on).
func AppendEntries(dst []byte, rows []Entry) []byte {
	n := 0
	for i := range rows {
		if rows[i].Client.IsValid() {
			n++
		}
	}
	dst = binary.AppendUvarint(dst, uint64(n))
	d := wireDict{ids: make(map[string]uint64, 64)}
	var t int64
	var seq uint64
	for i := range rows {
		e := &rows[i]
		if !e.Client.IsValid() {
			continue
		}
		ip := e.Client.Unmap().WithZone("")
		var flags byte
		if e.PageView {
			flags |= wirePageView
		}
		if e.Crawler {
			flags |= wireCrawler
		}
		if e.Pin {
			flags |= wirePin
		}
		if e.EventID != "" {
			flags |= wireEvent
		}
		if e.Referrer != "" {
			flags |= wireReferrer
		}
		if !ip.Is4() {
			flags |= wireV6
		}
		dst = append(dst, flags)
		dst = binary.AppendVarint(dst, e.T-t)
		dst = binary.AppendVarint(dst, int64(e.Seq-seq))
		t, seq = e.T, e.Seq
		if ip.Is4() {
			a := ip.As4()
			dst = append(dst, a[:]...)
		} else {
			a := ip.As16()
			dst = append(dst, a[:]...)
		}
		dst = d.put(dst, e.Site)
		dst = d.put(dst, e.Host)
		dst = d.put(dst, e.Template)
		if e.RawPath == e.Template {
			dst = append(dst, 0)
		} else {
			dst = binary.AppendUvarint(dst, uint64(len(e.RawPath))+1)
			dst = append(dst, e.RawPath...)
		}
		dst = d.put(dst, e.UA)
		if flags&wireReferrer != 0 {
			dst = d.put(dst, e.Referrer)
		}
		if flags&wireEvent != 0 {
			dst = binary.AppendUvarint(dst, uint64(len(e.EventID)))
			dst = append(dst, e.EventID...)
		}
		nr := min(int(e.NRules), len(e.Rules))
		dst = append(dst, byte(nr))
		for j := 0; j < nr; j++ {
			dst = d.put(dst, e.Rules[j])
		}
		dst = binary.AppendUvarint(dst, uint64(e.Score))
		dst = binary.AppendUvarint(dst, uint64(e.Status))
		dst = binary.AppendUvarint(dst, uint64(e.BytesOut))
		dst = binary.AppendUvarint(dst, uint64(e.ASN))
		dst = append(dst, e.Country[0], e.Country[1], e.Method, e.Outcome, e.WBReason, e.NetClass, e.UAClass, e.Browser, e.OS, e.Device, e.BotCat, e.Verif, e.Dur)
		dst = binary.AppendUvarint(dst, uint64(e.Bot))
	}
	return dst
}

// wireReader reads a block. Texts are slices of one string made of the
// whole block, so an entry costs no allocation of its own.
type wireReader struct {
	s    string
	off  int
	dict []string
	bad  bool
}

func (r *wireReader) uvarint() uint64 {
	var x uint64
	var shift uint
	for i := 0; i < binary.MaxVarintLen64; i++ {
		if r.off >= len(r.s) {
			r.bad = true
			return 0
		}
		b := r.s[r.off]
		r.off++
		if b < 0x80 {
			if i == binary.MaxVarintLen64-1 && b > 1 {
				r.bad = true
				return 0
			}
			return x | uint64(b)<<shift
		}
		x |= uint64(b&0x7f) << shift
		shift += 7
	}
	r.bad = true
	return 0
}

func (r *wireReader) varint() int64 {
	ux := r.uvarint()
	x := int64(ux >> 1)
	if ux&1 != 0 {
		x = ^x
	}
	return x
}

func (r *wireReader) bytes(n int) string {
	if n < 0 || n > len(r.s)-r.off {
		r.bad = true
		return ""
	}
	s := r.s[r.off : r.off+n]
	r.off += n
	return s
}

func (r *wireReader) byte() byte {
	if r.off >= len(r.s) {
		r.bad = true
		return 0
	}
	b := r.s[r.off]
	r.off++
	return b
}

func (r *wireReader) text() string {
	n := r.uvarint()
	if n > WireMaxText {
		r.bad = true
		return ""
	}
	return r.bytes(int(n))
}

func (r *wireReader) ref() string {
	id := r.uvarint()
	if id == 0 {
		s := r.text()
		if len(r.dict) < wireMaxDict-1 {
			r.dict = append(r.dict, s)
		}
		return s
	}
	if id > uint64(len(r.dict)) {
		r.bad = true
		return ""
	}
	return r.dict[id-1]
}

// ReadEntries reads a block of at most max entries from b. It returns
// ErrWire for a block that is cut short, holds more entries, or breaks a
// bound; nothing of such a block is returned.
func ReadEntries(b []byte, max int) ([]Entry, error) {
	r := wireReader{s: string(b)}
	n := r.uvarint()
	// An entry is at least 30 bytes: a count the block cannot hold is a lie.
	if r.bad || n > uint64(max) || n > uint64(len(b)/30+1) {
		return nil, ErrWire
	}
	rows := make([]Entry, n)
	var t int64
	var seq uint64
	for i := range rows {
		e := &rows[i]
		flags := r.byte()
		t += r.varint()
		seq += uint64(r.varint())
		e.T, e.Seq = t, seq
		if flags&wireV6 != 0 {
			var a [16]byte
			copy(a[:], r.bytes(16))
			e.Client = netip.AddrFrom16(a)
		} else {
			var a [4]byte
			copy(a[:], r.bytes(4))
			e.Client = netip.AddrFrom4(a)
		}
		e.Site, e.Host, e.Template = r.ref(), r.ref(), r.ref()
		if pl := r.uvarint(); pl == 0 {
			e.RawPath = e.Template
		} else if pl-1 > WireMaxText {
			r.bad = true
		} else {
			e.RawPath = r.bytes(int(pl - 1))
		}
		e.UA = r.ref()
		if flags&wireReferrer != 0 {
			e.Referrer = r.ref()
		}
		if flags&wireEvent != 0 {
			e.EventID = r.text()
		}
		nr := int(r.byte())
		if nr > len(e.Rules) {
			r.bad = true
			nr = 0
		}
		e.NRules = uint8(nr)
		for j := 0; j < nr; j++ {
			e.Rules[j] = r.ref()
		}
		score, status, out, asn := r.uvarint(), r.uvarint(), r.uvarint(), r.uvarint()
		if score > 0xffff || status > 0xffff || out > 0xffffffff || asn > 0xffffffff {
			r.bad = true
		}
		e.Score, e.Status, e.BytesOut, e.ASN = uint16(score), uint16(status), uint32(out), uint32(asn)
		fixed := r.bytes(13)
		if len(fixed) == 13 {
			e.Country = [2]byte{fixed[0], fixed[1]}
			e.Method, e.Outcome, e.WBReason, e.NetClass, e.UAClass = fixed[2], fixed[3], fixed[4], fixed[5], fixed[6]
			e.Browser, e.OS, e.Device, e.BotCat, e.Verif, e.Dur = fixed[7], fixed[8], fixed[9], fixed[10], fixed[11], fixed[12]
		}
		bot := r.uvarint()
		if bot > 0xffff {
			r.bad = true
		}
		e.Bot = uint16(bot)
		e.PageView, e.Crawler, e.Pin = flags&wirePageView != 0, flags&wireCrawler != 0, flags&wirePin != 0
		if r.bad {
			return nil, ErrWire
		}
	}
	if r.off != len(r.s) {
		return nil, ErrWire
	}
	return rows, nil
}
