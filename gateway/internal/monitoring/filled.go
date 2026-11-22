package monitoring

import (
	"sort"
	"time"

	cm "github.com/deutschland-schild/schild/contract/monitoring"
)

// readFilled reads the 10 min ring over [start, end] for the KPIs and
// totals. A finished 10 min bucket that is partial or missing while its
// minutes are still in the 1 min ring (48 h by default) is read from the
// 1 min ring instead (D36 fix round 2, re-measurement A 2.2 and D: after a
// hard kill the 10 min bucket in progress lost every request before the
// kill, -34 % "Angriffe gestoppt" over 6 h, while the 1 min ring lost at
// most the last minute). fine false reads the 10 min ring only (the 1 min
// ring has no per-website top lists). fn gets the stored 10 min buckets
// and, for a refilled one, its minute buckets one by one. cov gets every
// 10 min bucket in time order; a bucket built from minutes is partial
// unless all ten minutes are there and complete.
func (m NodeView) readFilled(start, end, now time.Time, parts readParts, fine bool, cov *coverage, fn func(t time.Time, b *cm.MetricBucket)) error {
	return m.fill(start, end, now, parts, fine, cov, false, func(t time.Time, b *cm.MetricBucket, _ float64) { fn(t, b) })
}

// readFilledMerged is readFilled for the breakdowns and series (evening
// measurement 2026-10-29 4.3: after a SIGKILL they read the damaged 10 min
// bucket, -51 %): a refilled bucket comes as one 10 min bucket merged from
// its minutes (mergeBucket: counters exact, top lists as space-saving
// summaries, estimates of distinct clients an upper bound), marked partial
// when a minute is missing or partial. span is the seconds the bucket
// covers (bucketSpan; for a refilled bucket the sum over its minutes).
func (m NodeView) readFilledMerged(start, end, now time.Time, parts readParts, fine bool, cov *coverage, fn func(t time.Time, b *cm.MetricBucket, span float64)) error {
	return m.fill(start, end, now, parts, fine, cov, true, fn)
}

func (m NodeView) fill(start, end, now time.Time, parts readParts, fine bool, cov *coverage, merge bool, fn func(t time.Time, b *cm.MetricBucket, span float64)) error {
	ring, ring1 := m.rings[2], m.rings[1]
	cov.step = ring.Step
	oldest1, cur := ring1.Oldest(now), ring.Start(now)
	byMinute := func(t time.Time) bool { return fine && !t.Before(oldest1) && t.Before(cur) }
	starts := m.store.startTimes(start, end.Add(ring.Step))
	type span struct {
		t       time.Time
		partial bool
		kind    string
	}
	var spans []span
	covered := func() {
		sort.Slice(spans, func(i, j int) bool { return spans[i].t.Before(spans[j].t) })
		for _, s := range spans {
			cov.add(s.t, s.partial, s.kind)
		}
	}
	seen := map[int64]bool{}
	var redo []time.Time
	err := m.readNodes(ring, start, end, parts, func(t time.Time, b *cm.MetricBucket) {
		seen[t.Unix()] = true
		if b.Partial && byMinute(t) {
			redo = append(redo, t)
			return
		}
		spans = append(spans, span{t, b.Partial, b.GapKind})
		fn(t, b, bucketSpan(t, ring.Step, b.Partial, starts))
	})
	if err != nil {
		return err
	}
	// Only buckets byMinute accepts can be refilled: the walk starts at
	// oldest1 (on the grid of start) and stops at cur, so a range reaching
	// far into the past or future costs no more than the 1 min ring.
	t := start
	for t.Before(oldest1) { // a Duration ends at about 292 years: jump in steps
		n := oldest1.Sub(t) / ring.Step
		if n == 0 {
			break
		}
		t = t.Add(n * ring.Step)
	}
	for ; fine && !t.After(end) && t.Before(cur); t = t.Add(ring.Step) {
		if !seen[t.Unix()] && byMinute(t) {
			redo = append(redo, t)
		}
	}
	if len(redo) == 0 {
		covered()
		return nil
	}
	// One read of the 1 min ring over the refilled buckets.
	sort.Slice(redo, func(i, j int) bool { return redo[i].Before(redo[j]) })
	type slot struct {
		minutes []*cm.MetricBucket
		span    float64
		partial bool
		kind    string
	}
	slots := make(map[int64]*slot, len(redo))
	for _, t := range redo {
		slots[t.Unix()] = &slot{}
	}
	err = m.readNodes(ring1, redo[0], redo[len(redo)-1].Add(ring.Step-ring1.Step), parts, func(t1 time.Time, b *cm.MetricBucket) {
		s := slots[ring.Start(t1).Unix()]
		if s == nil {
			return
		}
		s.partial = s.partial || b.Partial
		if b.Partial {
			s.kind = worseGap(s.kind, b.GapKind)
		}
		sp := bucketSpan(t1, ring1.Step, b.Partial, starts)
		s.span += sp
		if merge {
			s.minutes = append(s.minutes, b)
			return
		}
		s.minutes = append(s.minutes, nil) // counted only
		fn(t1, b, sp)
	})
	if err != nil {
		return err
	}
	perBucket := int(ring.Step / ring1.Step)
	for _, t := range redo {
		s := slots[t.Unix()]
		n := len(s.minutes)
		if n == 0 && !seen[t.Unix()] {
			continue
		}
		partial := s.partial || n < perBucket
		kind := s.kind
		if n < perBucket {
			kind = worseGap(kind, m.missingKind(t, t.Add(ring.Step)))
		}
		if !partial {
			kind = ""
		}
		spans = append(spans, span{t, partial, kind})
		if merge && n > 0 {
			fn(t, mergeMinutes(t, ring, s.minutes, partial, kind), s.span)
		}
	}
	covered()
	return nil
}

// mergeMinutes builds one bucket of ring starting at t from its minute
// buckets (oldest first): mergeBucket for counters, histograms, estimates,
// websites and top lists; server values averaged over all minutes at once.
func mergeMinutes(t time.Time, ring cm.Ring, minutes []*cm.MetricBucket, partial bool, kind string) *cm.MetricBucket {
	dst := minutes[0]
	var vals valuesAgg
	objs := map[string]*valuesAgg{}
	var order []string
	kinds := map[string]string{}
	for i, b := range minutes {
		vals.add(&b.Values)
		for j := range b.Objects {
			o := &b.Objects[j]
			key := o.Kind + "\x00" + o.Object
			a := objs[key]
			if a == nil {
				a = &valuesAgg{}
				objs[key] = a
				order = append(order, key)
				kinds[key] = o.Kind
			}
			a.add(&o.Values)
		}
		if i > 0 {
			mergeBucket(dst, b)
		}
	}
	dst.Values = vals.wire()
	dst.Objects = nil
	for _, k := range order {
		dst.Objects = append(dst.Objects, cm.ObjectValues{Object: k[len(kinds[k])+1:], Kind: kinds[k], Values: objs[k].wire()})
	}
	dst.T, dst.Resolution, dst.StepS, dst.Partial, dst.GapKind = ts(t), ring.Resolution, int(ring.Step.Seconds()), partial, kind
	return dst
}

// missingKind is the gap kind of minutes missing in [from, to): restart
// when a start in it (or just after it) followed an orderly shutdown and
// none a hard stop, else lost (no start: a skipped or failed write).
func (m *Monitor) missingKind(from, to time.Time) string {
	if bad, any := m.store.unorderlyStarts(from, to); any && !bad {
		return cm.GapRestart
	}
	return cm.GapLost
}
