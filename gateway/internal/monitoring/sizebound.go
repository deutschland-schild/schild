package monitoring

import (
	cm "github.com/deutschland-schild/schild/contract/monitoring"
	"github.com/deutschland-schild/schild/contract/websites"
)

// Worst-case stored bucket sizes (bytes: the ring row plus its part rows
// with 16 bytes and the owner per part for the row header) of the three
// rings for the gateway and per tracked website. Measured (D36 fix round
// 2) with the adversarial input of the D36 re-measurement (B 3.4,
// testlab/measure/monitoring/d36n): three 64-character path segments the path template
// keeps, 63-character referrer labels, random AS names, every list full,
// and a host with 17 mounts, 17 devices and 16 interfaces with long names
// (the sampler keeps at most 16 mounts and 16 interfaces); top list keys
// and labels cut at MaxTopKeyBytes (64). Measured / bound:
//
//	gateway  10 s 5 215 / 6 KiB   1 min 17 558 / 20 KiB   10 min 19 469 / 22 KiB
//	website  10 s   160 / 192 B   1 min    310 / 384 B    10 min  4 225 / 5 KiB
//
// The per-website part of the 10 s and 1 min rows is counters, histograms
// and estimates; the 10 min part adds the website's top lists
// (cm.SiteTopK). TestMetricsSizeBound checks the plain-host worst case
// against these numbers.
const (
	rowGateway10s = 6 << 10
	rowGateway1m  = 20 << 10
	rowGateway10m = 22 << 10
	rowSite10s    = 192
	rowSite1m     = 384
	rowSite10m    = 5 << 10
	// gatewayOverhead and siteOverhead: SQLite pages, page fill and
	// indexes, in percent of the bucket bytes (see MetricsBoundBytes).
	gatewayOverhead = 140
	siteOverhead    = 115
)

// RowBound10s, RowBound1m and RowBound10m are the largest row of each ring
// with w tracked websites.
func RowBound10s(w int64) int64 { return rowGateway10s + w*rowSite10s }
func RowBound1m(w int64) int64  { return rowGateway1m + w*rowSite1m }
func RowBound10m(w int64) int64 { return rowGateway10m + w*rowSite10m }

// MetricsBoundBytes is the documented bound of metrics.db for the given
// rings and w tracked websites (at most websites.MaxTracked, plus _other):
//
//	gateway  = slots10s*6 KiB + slots1m*20 KiB + slots10m*22 KiB
//	websites = w * (slots10s*192 B + slots1m*384 B + slots10m*5 KiB)
//	bound    = gateway*1.40 + websites*1.15
//
// The factors are SQLite's pages, page fill and indexes, measured with
// every slot holding the worst-case bucket: the gateway rows (small rows
// of the ring tables) 1.40, the website parts (a few KiB each, full
// overflow pages) 1.15. The file stops growing once every slot was
// written; traffic and key cardinality do not change it beyond this.
func MetricsBoundBytes(rings []cm.Ring, w int64) int64 {
	w = min(max(w, 0), websites.MaxTracked+1) // tracked websites plus _other
	var gw, site int64
	for _, r := range rings {
		n := int64(r.Slots())
		switch r.Resolution {
		case cm.Res10s:
			gw, site = gw+n*rowGateway10s, site+n*rowSite10s
		case cm.Res1m:
			gw, site = gw+n*rowGateway1m, site+n*rowSite1m
		default:
			gw, site = gw+n*rowGateway10m, site+n*rowSite10m
		}
	}
	return gw*gatewayOverhead/100 + w*site*siteOverhead/100
}
