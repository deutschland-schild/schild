package monitoring

import (
	"bytes"
	"encoding/binary"

	cm "github.com/deutschland-schild/schild/contract/monitoring"
)

// Storage layout 3 (D36 fix round 2, re-measurement B 3.4): a bucket is one
// row of its ring (the gateway core) plus part rows: one per gateway top
// list and one per website (its core and its top lists, each section
// compressed on its own). A gateway breakdown reads the core rows and one
// part per bucket, a website's breakdown, series or KPIs that website's
// part only. In layout 2 every read of one website or one dimension read
// the whole bucket (up to 200 KB with 32 websites): a 14-day breakdown of
// one website took about 1 s.
//
// A website part packs its sections into one blob of a few KiB, which
// SQLite stores with full overflow pages; parts of 1.5-4 KiB each (one per
// list) left a third of the pages empty.

// Part kinds: partSite is a website (owner = website id); partTop+i is the
// gateway's top list topDims[i] (owner "").
const (
	partSite = 0
	partTop  = 1
	// partSiteTotals (owner ""): requests, stopped and would_block of every
	// website of the bucket in one small blob, so the breakdown by=site
	// reads one row per bucket instead of every website's part (evening
	// measurement 2026-10-29 4.2: 1.3-1.5 s with 32 websites). Written for
	// the 1 min and 10 min rings (the breakdown never reads 10 s).
	partSiteTotals = 64
)

// part is one part row of a bucket.
type part struct {
	owner string
	kind  int
	z     []byte
}

// splitBucket returns the gateway core (the bucket without websites and top
// lists; a non-nil Sites stays non-nil), the top flag (non-nil when the
// gateway-wide lists exist) and the parts.
func splitBucket(b *cm.MetricBucket) (core, topFlag []byte, parts []part) {
	g := *b
	g.Top = nil
	if b.Sites != nil {
		g.Sites = []cm.SiteTraffic{}
	}
	core = encodeCore(&g)
	var w wbuf
	if b.Top != nil {
		topFlag = []byte{topVersion}
		for i, d := range topDims {
			if es := *topField(b.Top, d); len(es) > 0 {
				parts = append(parts, part{owner: "", kind: partTop + i, z: encodeSection(&w, es)})
			}
		}
	}
	for j := range b.Sites {
		parts = append(parts, part{owner: b.Sites[j].Site, kind: partSite, z: encodeSitePart(&w, &b.Sites[j], j)})
	}
	if b.Sites != nil && b.Resolution != cm.Res10s {
		parts = append(parts, part{owner: "", kind: partSiteTotals, z: encodeSiteTotals(&w, b.Sites)})
	}
	return core, topFlag, parts
}

// encodeSiteTotals: version, count, then per website its id, requests,
// stopped and would_block, flate compressed. An empty list is written too.
func encodeSiteTotals(w *wbuf, ss []cm.SiteTraffic) []byte {
	w.reset()
	w.byte1(codecVersion)
	w.uv(uint64(len(ss)))
	for i := range ss {
		w.str(ss[i].Site)
		w.iv(ss[i].Traffic.Requests)
		w.iv(ss[i].Traffic.Stopped)
		w.iv(ss[i].Traffic.WouldBlock)
	}
	return deflate(w.bytes())
}

// decodeSiteTotals returns the websites of a totals row (the counters
// requests, stopped and would_block only); only "" or "*" keeps every
// website, else that one.
func decodeSiteTotals(z []byte, only string, scratch *bytes.Buffer, intern map[string]string) ([]cm.SiteTraffic, error) {
	if err := inflate(scratch, z); err != nil {
		return nil, err
	}
	r := &rbuf{b: scratch.Bytes(), intern: intern}
	if r.byte1() != codecVersion {
		return nil, errCodec
	}
	n := r.count()
	out := make([]cm.SiteTraffic, 0, n)
	for i := 0; i < n && !r.bad; i++ {
		s := cm.SiteTraffic{Site: r.istr()}
		s.Traffic.Requests, s.Traffic.Stopped, s.Traffic.WouldBlock = r.iv(), r.iv(), r.iv()
		if only == "" || only == "*" || only == s.Site {
			out = append(out, s)
		}
	}
	if r.bad {
		return nil, errCodec
	}
	return out, nil
}

func encodeSection(w *wbuf, es []cm.TopEntry) []byte {
	w.reset()
	encodeEntries(w, es)
	return deflate(w.bytes())
}

func decodeSection(z []byte, scratch *bytes.Buffer) ([]cm.TopEntry, error) {
	if len(z) == 0 {
		return nil, nil
	}
	if err := inflate(scratch, z); err != nil {
		return nil, err
	}
	r := &rbuf{b: scratch.Bytes()}
	es := decodeEntries(r)
	if r.bad {
		return nil, errCodec
	}
	return es, nil
}

// encodeSitePart: version, position in the bucket, length and flate of the
// core (traffic, latency, clients), a top flag (1: the website has top
// lists), then per non-empty list its dimension index, length and flate.
func encodeSitePart(w *wbuf, s *cm.SiteTraffic, ord int) []byte {
	w.reset()
	w.byte1(codecVersion)
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
		encodeHist(w, &s.Latency.Total)
		encodeHist(w, &s.Latency.Overhead)
		encodeHist(w, &s.Latency.Upstream)
	}
	if s.Clients != nil {
		encodeClients(w, s.Clients)
	}
	core := deflate(w.bytes())
	out := []byte{codecVersion}
	out = binary.AppendUvarint(out, uint64(ord))
	out = binary.AppendUvarint(out, uint64(len(core)))
	out = append(out, core...)
	if s.Top == nil {
		return append(out, 0)
	}
	out = append(out, 1)
	for i, d := range topDims {
		es := *topField(s.Top, d)
		if len(es) == 0 {
			continue
		}
		z := encodeSection(w, es)
		out = append(out, byte(i))
		out = binary.AppendUvarint(out, uint64(len(z)))
		out = append(out, z...)
	}
	return out
}

// decodeSitePart decodes a website part: always its position and, with
// core, its counters, latency and clients; with top, the lists of dim (""
// every list).
func decodeSitePart(z []byte, site string, core, top bool, dim string, scratch *bytes.Buffer, intern map[string]string) (cm.SiteTraffic, int, error) {
	s := cm.SiteTraffic{Site: site}
	r := &rbuf{b: z}
	if r.byte1() != codecVersion {
		return s, 0, errCodec
	}
	ord := int(r.uv())
	n := r.count()
	if r.bad {
		return s, 0, errCodec
	}
	cz := r.b[:n]
	r.b = r.b[n:]
	if core {
		if err := inflate(scratch, cz); err != nil {
			return s, 0, err
		}
		cr := &rbuf{b: scratch.Bytes(), intern: intern}
		if cr.byte1() != codecVersion {
			return s, 0, errCodec
		}
		cr.traffic(&s.Traffic)
		fl := cr.byte1()
		if fl&1 != 0 {
			s.Latency = &cm.BucketLatency{Total: decodeHist(cr), Overhead: decodeHist(cr), Upstream: decodeHist(cr)}
		}
		if fl&2 != 0 {
			c := decodeClients(cr)
			s.Clients = &c
		}
		if cr.bad {
			return s, 0, errCodec
		}
	}
	if r.byte1() != 1 || !top {
		return s, ord, nil
	}
	s.Top = &cm.BucketTop{}
	for len(r.b) > 0 && !r.bad {
		i := int(r.byte1())
		n := r.count()
		if r.bad {
			break
		}
		sz := r.b[:n]
		r.b = r.b[n:]
		if i >= len(topDims) || dim != "" && topDims[i] != dim {
			continue
		}
		es, err := decodeSection(sz, scratch)
		if err != nil {
			return s, 0, err
		}
		*topField(s.Top, topDims[i]) = es
	}
	if r.bad {
		return s, 0, errCodec
	}
	return s, ord, nil
}
