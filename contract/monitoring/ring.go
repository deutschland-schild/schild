package monitoring

import (
	"errors"
	"fmt"
	"math"
	"strings"
	"time"
)

// Resolution of a ring.
type Resolution string

const (
	Res10s Resolution = "10s"
	Res1m  Resolution = "1m"
	Res10m Resolution = "10m"
)

// Ring is one fixed-size table of buckets: slot = (unix / step) mod slots.
type Ring struct {
	Resolution Resolution
	Step       time.Duration
	Keep       time.Duration
}

// Slots is the number of rows of the ring (fixed; the file never grows
// beyond them).
func (r Ring) Slots() int64 { return int64(r.Keep / r.Step) }

// Start returns the start of the bucket that contains t.
func (r Ring) Start(t time.Time) time.Time {
	s := int64(r.Step / time.Second)
	return time.Unix(t.Unix()/s*s, 0).UTC()
}

// Slot returns the row of the bucket that contains t.
func (r Ring) Slot(t time.Time) int64 {
	n := t.Unix() / int64(r.Step/time.Second)
	return n % r.Slots()
}

// Oldest returns the start of the oldest bucket the ring can still hold at now.
func (r Ring) Oldest(now time.Time) time.Time {
	return r.Start(now).Add(-time.Duration(r.Slots()-1) * r.Step)
}

// SlotRanges returns the at most two contiguous, inclusive slot ranges that
// cover the buckets from..to (both bucket starts, from <= to, within the
// ring): the primary key ranges a range query reads.
func (r Ring) SlotRanges(from, to time.Time) [][2]int64 {
	n := (to.Unix()-from.Unix())/int64(r.Step/time.Second) + 1
	if n >= r.Slots() {
		return [][2]int64{{0, r.Slots() - 1}}
	}
	a, b := r.Slot(from), r.Slot(to)
	if a <= b {
		return [][2]int64{{a, b}}
	}
	return [][2]int64{{a, r.Slots() - 1}, {0, b}}
}

// Rings returns the three rings for the given keep values (schild.yaml
// monitoring.keep, defaults 6 h, 48 h, 14 d).
func Rings(tenSecondsHours, minuteHours, tenMinuteDays int) []Ring {
	return []Ring{
		{Res10s, 10 * time.Second, time.Duration(tenSecondsHours) * time.Hour},
		{Res1m, time.Minute, time.Duration(minuteHours) * time.Hour},
		{Res10m, 10 * time.Minute, time.Duration(tenMinuteDays) * 24 * time.Hour},
	}
}

// ErrTooManyPoints is the 400 too_many_points of queryMetricSeries.
var ErrTooManyPoints = errors.New("monitoring: more than 1000 points")

// Choose picks the ring of a series query. requested "" or "auto": the
// finest ring that still covers from at now and yields at most MaxPoints;
// else that ring, and ErrTooManyPoints when it yields more. It returns the
// ring, the aligned first bucket and the number of points.
func Choose(rings []Ring, requested string, from, to, now time.Time) (Ring, time.Time, int, error) {
	if !from.Before(to) {
		return Ring{}, time.Time{}, 0, errors.New("monitoring: from must be before to")
	}
	points := func(r Ring) (time.Time, int) {
		f := r.Start(from)
		last := r.Start(to.Add(-time.Nanosecond))
		return f, int(last.Sub(f)/r.Step) + 1
	}
	if requested != "" && requested != "auto" {
		for _, r := range rings {
			if string(r.Resolution) == requested {
				f, n := points(r)
				if n > MaxPoints {
					return r, f, n, ErrTooManyPoints
				}
				return r, f, n, nil
			}
		}
		return Ring{}, time.Time{}, 0, fmt.Errorf("monitoring: unknown resolution %q", requested)
	}
	for _, r := range rings {
		f, n := points(r)
		if n <= MaxPoints && !f.Before(r.Oldest(now)) {
			return r, f, n, nil
		}
	}
	// Nothing covers from: the coarsest ring; older steps are null.
	r := rings[len(rings)-1]
	f, n := points(r)
	if n > MaxPoints {
		return r, f, n, ErrTooManyPoints
	}
	return r, f, n, nil
}

// MergeFactors (v0.5, D36): numbers of coarsest-ring buckets merged into
// one point when an auto series over the coarsest ring would exceed
// MaxPoints (10 min ring: 10 min, 30 min, 1 h, 3 h, 6 h, 12 h, 1 d). So the
// default 14 days (2016 buckets) are drawn at 30 min, 90 days at 3 h.
var MergeFactors = []int{1, 3, 6, 18, 36, 72, 144}

// SeriesPlan is how a series query is answered.
type SeriesPlan struct {
	Ring   Ring
	First  time.Time // start of the first point (aligned to Step)
	Points int
	Merge  int           // ring buckets per point
	Step   time.Duration // Ring.Step * Merge
}

// Plan is Choose with merging (v0.5, D36): an auto query that the coarsest
// ring cannot answer within MaxPoints merges Merge consecutive buckets per
// point, with the smallest factor of MergeFactors that fits; points start
// at multiples of the merged step (Unix time). Merged points: counters
// summed (rate over the seconds of the buckets present), histograms
// summed, gauges avg of the bucket averages, min of the minima, max of the
// maxima, estimates the mean of the bucket values; a point is null only
// when none of its buckets is present. An explicit resolution never merges
// (ErrTooManyPoints as before).
func Plan(rings []Ring, requested string, from, to, now time.Time) (SeriesPlan, error) {
	r, f, n, err := Choose(rings, requested, from, to, now)
	if err == nil {
		return SeriesPlan{Ring: r, First: f, Points: n, Merge: 1, Step: r.Step}, nil
	}
	if !errors.Is(err, ErrTooManyPoints) || (requested != "" && requested != "auto") || r.Resolution != rings[len(rings)-1].Resolution {
		return SeriesPlan{Ring: r, First: f, Points: n, Merge: 1, Step: r.Step}, err
	}
	for _, k := range MergeFactors[1:] {
		step := r.Step * time.Duration(k)
		s := int64(step / time.Second)
		first := time.Unix(from.Unix()/s*s, 0).UTC()
		last := time.Unix(to.Add(-time.Nanosecond).Unix()/s*s, 0).UTC()
		pts := int(last.Sub(first)/step) + 1
		if pts <= MaxPoints {
			return SeriesPlan{Ring: r, First: first, Points: pts, Merge: k, Step: step}, nil
		}
	}
	return SeriesPlan{Ring: r, First: f, Points: n, Merge: 1, Step: r.Step}, ErrTooManyPoints
}

// Query is one parsed `metric` parameter.
type Query struct {
	Metric Metric
	Stat   Stat
}

// ParseQuery parses `<metric id>[:<stat>]` and checks the stat against the
// kind; the error text names the problem for the `invalid` problem detail.
func ParseQuery(s string) (Query, error) {
	id, st, hasStat := strings.Cut(s, ":")
	m, ok := Lookup(id)
	if !ok {
		return Query{}, fmt.Errorf("unknown metric %q", id)
	}
	allowed := m.Kind.Stats()
	if !hasStat {
		return Query{m, allowed[0]}, nil
	}
	for _, a := range allowed {
		if string(a) == st {
			return Query{m, a}, nil
		}
	}
	return Query{}, fmt.Errorf("stat %q not allowed for %s metric %s", st, m.Kind, id)
}

// Latency histogram scheme "exp1.25-0.05ms": bucket i (0..56) holds values up
// to 0.05 * 1.25^i ms, bucket 57 everything above.
const (
	HistogramScheme  = "exp1.25-0.05ms"
	HistogramBuckets = 58
	histBase         = 0.05
	histGrowth       = 1.25
)

// BucketBound returns the upper bound of bucket i in ms (+Inf for the last).
func BucketBound(i int) float64 {
	if i >= HistogramBuckets-1 {
		return math.Inf(1)
	}
	return histBase * math.Pow(histGrowth, float64(i))
}

// BucketOf returns the bucket of a duration in ms.
func BucketOf(ms float64) int {
	if ms <= histBase {
		return 0
	}
	i := int(math.Ceil(math.Log(ms/histBase)/math.Log(histGrowth) - 1e-9))
	if i > HistogramBuckets-1 {
		return HistogramBuckets - 1
	}
	return i
}

// Quantile returns the q-quantile (upper bucket bound, ms) of sparse counts
// by bucket index; ok is false without data. The overflow bucket reports
// the last finite bound.
func Quantile(counts map[int]int64, q float64) (float64, bool) {
	var total int64
	for _, n := range counts {
		total += n
	}
	if total == 0 {
		return 0, false
	}
	target := int64(math.Ceil(q * float64(total)))
	var cum int64
	for i := 0; i < HistogramBuckets; i++ {
		cum += counts[i]
		if cum >= target {
			if i == HistogramBuckets-1 {
				return BucketBound(HistogramBuckets - 2), true
			}
			return BucketBound(i), true
		}
	}
	return BucketBound(HistogramBuckets - 2), true
}
