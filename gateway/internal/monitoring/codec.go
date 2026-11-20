package monitoring

import (
	"bytes"
	"compress/flate"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"sort"
	"sync"

	cm "github.com/deutschland-schild/schild/contract/monitoring"
)

// Storage codec of metrics.db. A bucket is stored as two blobs:
//
//   - core: the MetricBucket without top lists, a compact binary encoding,
//     compressed with compress/flate;
//   - top: one section per dimension (dimension index, length, flate of
//     the binary entries), so a breakdown decompresses only its dimension.
//
// The JSON of layout 1 cost 0.13 ms (core) to 0.6 ms (with top lists) per
// bucket to decode: 1000 points took 0.6-1.0 s, a 14-day breakdown 2 s
// (MVP-21 measurement finding 7). The wire format (MetricBucket JSON) does
// not change; TestCodecCoversEveryField fails when the contract adds a field
// this codec does not know yet.
//
// Per-website top lists are top sections of their own (dimension index |
// 0x80, then the website id), so a breakdown of one website still
// decompresses only its dimension. The gap_kind of a bucket is one byte
// after partial (0 none, 1 restart, 2 lost).
//
// Only blobs of codecVersion and topVersion are read (D74: no older
// formats); any other blob reads as errCodec and its bucket is skipped.
// A change of the encoding raises the version.

const (
	codecVersion = 7
	topVersion   = 2
)

// siteSection marks a top section of one website.
const siteSection = 0x80

var errCodec = errors.New("metrics.db: bad bucket encoding")

// ---------------------------------------------------------------- writer

type wbuf struct{ b []byte }

func (w *wbuf) byte1(v byte)  { w.b = append(w.b, v) }
func (w *wbuf) uv(v uint64)   { w.b = binary.AppendUvarint(w.b, v) }
func (w *wbuf) iv(v int64)    { w.b = binary.AppendVarint(w.b, v) }
func (w *wbuf) f64(v float64) { w.b = binary.LittleEndian.AppendUint64(w.b, math.Float64bits(v)) }
func (w *wbuf) str(s string)  { w.uv(uint64(len(s))); w.b = append(w.b, s...) }
func (w *wbuf) bool1(v bool) {
	if v {
		w.byte1(1)
	} else {
		w.byte1(0)
	}
}
func (w *wbuf) bytes() []byte { return w.b }
func (w *wbuf) reset()        { w.b = w.b[:0] }
func (w *wbuf) traffic(t *cm.TrafficCounters) {
	for _, p := range trafficSlots(t) {
		w.iv(*p)
	}
}

// ---------------------------------------------------------------- reader

type rbuf struct {
	b   []byte
	bad bool
	// intern shares the strings that repeat across buckets (metric ids,
	// histogram keys, object names) within one read.
	intern map[string]string
}

func (r *rbuf) byte1() byte {
	if len(r.b) < 1 {
		r.bad = true
		return 0
	}
	v := r.b[0]
	r.b = r.b[1:]
	return v
}

func (r *rbuf) uv() uint64 {
	v, n := binary.Uvarint(r.b)
	if n <= 0 {
		r.bad = true
		r.b = nil
		return 0
	}
	r.b = r.b[n:]
	return v
}

func (r *rbuf) iv() int64 {
	v, n := binary.Varint(r.b)
	if n <= 0 {
		r.bad = true
		r.b = nil
		return 0
	}
	r.b = r.b[n:]
	return v
}

func (r *rbuf) f64() float64 {
	if len(r.b) < 8 {
		r.bad = true
		r.b = nil
		return 0
	}
	v := math.Float64frombits(binary.LittleEndian.Uint64(r.b))
	r.b = r.b[8:]
	return v
}

func (r *rbuf) str() string {
	n := r.uv()
	if n > uint64(len(r.b)) {
		r.bad = true
		r.b = nil
		return ""
	}
	raw := r.b[:n]
	r.b = r.b[n:]
	return string(raw)
}

// istr reads a string that repeats across buckets.
func (r *rbuf) istr() string {
	n := r.uv()
	if n > uint64(len(r.b)) {
		r.bad = true
		r.b = nil
		return ""
	}
	raw := r.b[:n]
	r.b = r.b[n:]
	if r.intern == nil {
		return string(raw)
	}
	if s, ok := r.intern[string(raw)]; ok {
		return s
	}
	s := string(raw)
	if len(r.intern) < 4096 {
		r.intern[s] = s
	}
	return s
}

// count reads a length prefix and bounds it by the bytes left (each item
// takes at least one byte). Callers allocate n items of their in-memory
// size, so a corrupt blob can still cost up to a few hundred times its
// length (an inflated blob is at most 8 MiB, inflate).
func (r *rbuf) count() int {
	n := r.uv()
	if n > uint64(len(r.b)) {
		r.bad = true
		r.b = nil
		return 0
	}
	return int(n)
}

func (r *rbuf) traffic(t *cm.TrafficCounters) {
	for _, p := range trafficSlots(t) {
		*p = r.iv()
	}
}

// trafficSlots lists every counter of TrafficCounters in a fixed order.
// Appending is fine; reordering breaks stored buckets.
func trafficSlots(t *cm.TrafficCounters) [30]*int64 {
	return [30]*int64{&t.Requests, &t.Forwarded, &t.Stopped, &t.BlockedWAF, &t.BlockedBehaviour, &t.RateLimited, &t.RejectedLimit,
		&t.Challenged, &t.FailClosed, &t.FailClosedBy.WAFTimeout, &t.FailClosedBy.WAFBusy, &t.FailClosedBy.NotReady, &t.FailClosedBy.Panic,
		&t.WouldBlock, &t.WouldRateLimit, &t.PageViews, &t.Detections, &t.Status.S1xx, &t.Status.S2xx, &t.Status.S3xx, &t.Status.S4xx,
		&t.Status.S5xx, &t.UpstreamErrors, &t.UpstreamTimeouts, &t.BytesIn, &t.BytesOut,
		&t.WaitingPageShown, &t.Rechecked, &t.FailClosedBy.BodyBusy, &t.BlockedCrawler}
}

// ---------------------------------------------------------------- flate

// flateLevel keeps blob sizes and encode cost where they were before the
// compress/flate encoder of Go 1.27: BestSpeed there grows the top lists of a
// heavy bucket by 19%, level 5 matches the old BestSpeed in size at about the
// same cost per blob. Any level reads back with the same decoder, so blobs
// already stored stay valid.
const flateLevel = 5

var (
	flateWriters = sync.Pool{New: func() any { w, _ := flate.NewWriter(io.Discard, flateLevel); return w }}
	flateReaders = sync.Pool{New: func() any { return flate.NewReader(bytes.NewReader(nil)) }}
)

func deflate(raw []byte) []byte {
	var out bytes.Buffer
	w := flateWriters.Get().(*flate.Writer)
	w.Reset(&out)
	_, _ = w.Write(raw)
	_ = w.Close()
	flateWriters.Put(w)
	return out.Bytes()
}

// inflate decompresses into dst (reused); at most 8 MiB.
func inflate(dst *bytes.Buffer, blob []byte) error {
	r := flateReaders.Get().(io.ReadCloser)
	defer flateReaders.Put(r)
	if err := r.(flate.Resetter).Reset(bytes.NewReader(blob), nil); err != nil {
		return err
	}
	dst.Reset()
	_, err := dst.ReadFrom(io.LimitReader(r, 8<<20))
	return err
}

// ---------------------------------------------------------------- core

func encodeHist(w *wbuf, h *cm.LatencyHistogram) {
	w.str(h.Scheme)
	w.bool1(h.Counts != nil)
	keys := sortedKeys(h.Counts)
	w.uv(uint64(len(keys)))
	for _, k := range keys {
		w.str(k)
		w.iv(h.Counts[k])
	}
}

func decodeHist(r *rbuf) cm.LatencyHistogram {
	h := cm.LatencyHistogram{Scheme: r.istr()}
	hasMap := r.byte1() == 1
	n := r.count()
	if hasMap {
		h.Counts = make(map[string]int64, n)
	}
	for i := 0; i < n && !r.bad; i++ {
		k := r.istr()
		v := r.iv()
		if hasMap {
			h.Counts[k] = v
		}
	}
	return h
}

func encodeValues(w *wbuf, v *cm.MetricValues) {
	flags := byte(0)
	if v.Counters != nil {
		flags |= 1
	}
	if v.Gauges != nil {
		flags |= 2
	}
	w.byte1(flags)
	keys := sortedKeys(v.Counters)
	w.uv(uint64(len(keys)))
	for _, k := range keys {
		w.str(k)
		w.f64(v.Counters[k])
	}
	keys = sortedKeys(v.Gauges)
	w.uv(uint64(len(keys)))
	for _, k := range keys {
		g := v.Gauges[k]
		w.str(k)
		w.f64(g.Avg)
		w.f64(g.Min)
		w.f64(g.Max)
	}
}

func decodeValues(r *rbuf) cm.MetricValues {
	var v cm.MetricValues
	flags := r.byte1()
	n := r.count()
	if flags&1 != 0 {
		v.Counters = make(map[string]float64, n)
	}
	for i := 0; i < n && !r.bad; i++ {
		k := r.istr()
		x := r.f64()
		if v.Counters != nil {
			v.Counters[k] = x
		}
	}
	n = r.count()
	if flags&2 != 0 {
		v.Gauges = make(map[string]cm.GaugeStats, n)
	}
	for i := 0; i < n && !r.bad; i++ {
		k := r.istr()
		g := cm.GaugeStats{Avg: r.f64(), Min: r.f64(), Max: r.f64()}
		if v.Gauges != nil {
			v.Gauges[k] = g
		}
	}
	return v
}

func encodeClients(w *wbuf, c *cm.BucketClients) {
	cl := byte(0)
	if c.Unique != nil {
		cl |= 1
	}
	if c.New != nil {
		cl |= 2
	}
	if c.UniqueDay != nil {
		cl |= 4
	}
	if c.Bots != nil {
		cl |= 8
	}
	w.byte1(cl)
	for _, p := range []*int64{c.Unique, c.New, c.UniqueDay, c.Bots} {
		if p != nil {
			w.iv(*p)
		}
	}
}

func decodeClients(r *rbuf) cm.BucketClients {
	var c cm.BucketClients
	cl := r.byte1()
	for i, p := range []**int64{&c.Unique, &c.New, &c.UniqueDay, &c.Bots} {
		if cl&(1<<i) != 0 {
			v := r.iv()
			*p = &v
		}
	}
	return c
}

// encodeCore encodes every field of the bucket but the top lists.
func encodeCore(b *cm.MetricBucket) []byte {
	var w wbuf
	w.byte1(codecVersion)
	w.str(b.T)
	w.str(string(b.Resolution))
	w.iv(int64(b.StepS))
	w.bool1(b.Partial)
	w.byte1(gapKindCode(b.GapKind))
	w.traffic(&b.Traffic)
	encodeHist(&w, &b.Latency.Total)
	encodeHist(&w, &b.Latency.Overhead)
	encodeHist(&w, &b.Latency.Upstream)
	encodeClients(&w, &b.Clients)
	if b.Sites == nil {
		w.byte1(0)
	} else {
		w.byte1(1)
		w.uv(uint64(len(b.Sites)))
		for i := range b.Sites {
			s := &b.Sites[i]
			w.str(s.Site)
			w.traffic(&s.Traffic)
			fl := byte(0)
			if s.Latency != nil {
				fl |= 1
			}
			if s.Clients != nil {
				fl |= 2
			}
			w.byte1(fl)
			if s.Latency != nil {
				encodeHist(&w, &s.Latency.Total)
				encodeHist(&w, &s.Latency.Overhead)
				encodeHist(&w, &s.Latency.Upstream)
			}
			if s.Clients != nil {
				encodeClients(&w, s.Clients)
			}
		}
	}
	encodeValues(&w, &b.Values)
	w.uv(uint64(len(b.Objects)))
	for i := range b.Objects {
		o := &b.Objects[i]
		w.str(o.Object)
		w.str(o.Kind)
		encodeValues(&w, &o.Values)
	}
	return deflate(w.bytes())
}

// gapKindCode and gapKindName map MetricBucket.gap_kind to its stored byte.
func gapKindCode(k string) byte {
	switch k {
	case cm.GapRestart:
		return 1
	case cm.GapLost:
		return 2
	}
	return 0
}

func gapKindName(c byte) string {
	switch c {
	case 1:
		return cm.GapRestart
	case 2:
		return cm.GapLost
	}
	return ""
}

// coreParts selects what decodeCore fills: the traffic counters only
// (breakdown totals) or everything.
type coreParts uint8

const (
	coreTraffic coreParts = iota
	coreAll
	// coreSites: the gateway's traffic counters and the websites (from
	// their parts, layout 3): the reads of one website.
	coreSites
)

func decodeCore(blob []byte, parts coreParts, scratch *bytes.Buffer, intern map[string]string) (*cm.MetricBucket, error) {
	if err := inflate(scratch, blob); err != nil {
		return nil, err
	}
	r := &rbuf{b: scratch.Bytes(), intern: intern}
	if r.byte1() != codecVersion {
		return nil, errCodec
	}
	b := &cm.MetricBucket{T: r.str(), Resolution: cm.Resolution(r.istr())}
	b.StepS = int(r.iv())
	b.Partial = r.byte1() == 1
	b.GapKind = gapKindName(r.byte1())
	r.traffic(&b.Traffic)
	if parts == coreTraffic || parts == coreSites {
		if r.bad {
			return nil, errCodec
		}
		if parts == coreSites {
			b.Sites = []cm.SiteTraffic{}
		}
		return b, nil
	}
	b.Latency.Total = decodeHist(r)
	b.Latency.Overhead = decodeHist(r)
	b.Latency.Upstream = decodeHist(r)
	b.Clients = decodeClients(r)
	if r.byte1() == 1 {
		n := r.count()
		b.Sites = make([]cm.SiteTraffic, n)
		for i := 0; i < n && !r.bad; i++ {
			s := &b.Sites[i]
			s.Site = r.istr()
			r.traffic(&s.Traffic)
			fl := r.byte1()
			if fl&1 != 0 {
				s.Latency = &cm.BucketLatency{Total: decodeHist(r), Overhead: decodeHist(r), Upstream: decodeHist(r)}
			}
			if fl&2 != 0 {
				c := decodeClients(r)
				s.Clients = &c
			}
		}
	}
	b.Values = decodeValues(r)
	if n := r.count(); n > 0 {
		b.Objects = make([]cm.ObjectValues, n)
		for i := 0; i < n && !r.bad; i++ {
			b.Objects[i].Object = r.istr()
			b.Objects[i].Kind = r.istr()
			b.Objects[i].Values = decodeValues(r)
		}
	}
	if r.bad {
		return nil, errCodec
	}
	return b, nil
}

// ---------------------------------------------------------------- top lists

// topDims are the lists of BucketTop by dimension name, in section order.
// Appending is fine; reordering breaks stored buckets.
var topDims = []string{"path", "asn", "country", "net_class", "ua_class", "method", "referrer", "browser", "os", "device", "bot_category", "rule"}

func topField(t *cm.BucketTop, dim string) *[]cm.TopEntry {
	switch dim {
	case "path":
		return &t.Path
	case "asn":
		return &t.ASN
	case "country":
		return &t.Country
	case "net_class":
		return &t.NetClass
	case "ua_class":
		return &t.UAClass
	case "method":
		return &t.Method
	case "referrer":
		return &t.Referrer
	case "browser":
		return &t.Browser
	case "os":
		return &t.OS
	case "device":
		return &t.Device
	case "bot_category":
		return &t.BotCategory
	case "rule":
		return &t.Rule
	}
	return nil
}

func encodeEntries(w *wbuf, es []cm.TopEntry) {
	w.uv(uint64(len(es)))
	for i := range es {
		e := &es[i]
		w.str(e.Key)
		w.str(e.Label)
		w.iv(e.Requests)
		w.iv(e.Stopped)
		w.iv(e.WouldBlock)
		w.iv(e.Detections)
		w.iv(e.Error)
	}
}

func decodeEntries(r *rbuf) []cm.TopEntry {
	n := r.count()
	if n == 0 {
		return nil
	}
	out := make([]cm.TopEntry, n)
	for i := 0; i < n && !r.bad; i++ {
		out[i] = cm.TopEntry{Key: r.str(), Label: r.str(), Requests: r.iv(), Stopped: r.iv(), WouldBlock: r.iv(), Detections: r.iv(), Error: r.iv()}
	}
	return out
}

// encodeTop writes one section per non-empty dimension: index, length of
// the compressed entries, the compressed entries; then the sections of the
// per-website lists (index | siteSection, website id, length, entries).
// nil for no top lists.
func encodeTop(t *cm.BucketTop, sites []cm.SiteTraffic) []byte {
	hasSite := false
	for i := range sites {
		hasSite = hasSite || sites[i].Top != nil
	}
	if t == nil && !hasSite {
		return nil
	}
	out := []byte{topVersion, 0}
	if t != nil {
		out[1] = 1 // the gateway-wide lists exist (maybe all empty)
	}
	var w wbuf
	section := func(i int, site string, es []cm.TopEntry) {
		if len(es) == 0 {
			return
		}
		w.reset()
		encodeEntries(&w, es)
		z := deflate(w.bytes())
		if site == "" {
			out = append(out, byte(i))
		} else {
			out = append(out, byte(i)|siteSection)
			out = binary.AppendUvarint(out, uint64(len(site)))
			out = append(out, site...)
		}
		out = binary.AppendUvarint(out, uint64(len(z)))
		out = append(out, z...)
	}
	if t != nil {
		for i, d := range topDims {
			section(i, "", *topField(t, d))
		}
	}
	for j := range sites {
		if st := sites[j].Top; st != nil {
			for i, d := range topDims {
				section(i, sites[j].Site, *topField(st, d))
			}
		}
	}
	return out
}

// topSel selects what decodeTop fills: dim "" = every dimension; site ""
// = the gateway-wide lists only, "*" = also every website's, else also
// that website's.
type topSel struct {
	dim, site string
}

// decodeTop decodes the selected sections of a top blob into b (b.Top and
// b.Sites[].Top; a website section whose website is not in b.Sites is
// skipped).
func decodeTop(b *cm.MetricBucket, blob []byte, sel topSel, scratch *bytes.Buffer) error {
	if len(blob) == 0 {
		return nil
	}
	r := &rbuf{b: blob[1:]}
	if blob[0] != topVersion {
		return errCodec
	}
	if r.byte1() == 1 {
		b.Top = &cm.BucketTop{}
	}
	for len(r.b) > 0 && !r.bad {
		i := int(r.byte1())
		site := ""
		if i&siteSection != 0 {
			i &^= siteSection
			site = r.str()
		}
		n := r.count()
		if r.bad {
			break
		}
		z := r.b[:n]
		r.b = r.b[n:]
		if i >= len(topDims) || sel.dim != "" && topDims[i] != sel.dim {
			continue
		}
		var dst *cm.BucketTop
		switch {
		case site == "":
			if b.Top == nil {
				b.Top = &cm.BucketTop{}
			}
			dst = b.Top
		case sel.site == "*" || sel.site == site:
			for j := range b.Sites {
				if b.Sites[j].Site == site {
					if b.Sites[j].Top == nil {
						b.Sites[j].Top = &cm.BucketTop{}
					}
					dst = b.Sites[j].Top
					break
				}
			}
		}
		if dst == nil {
			continue
		}
		if err := inflate(scratch, z); err != nil {
			return err
		}
		er := &rbuf{b: scratch.Bytes()}
		es := decodeEntries(er)
		if er.bad {
			return errCodec
		}
		*topField(dst, topDims[i]) = es
	}
	if r.bad {
		return errCodec
	}
	return nil
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
