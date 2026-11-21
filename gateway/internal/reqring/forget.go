package reqring

import (
	"context"
	"net/netip"
	"os"
	"sort"
	"strings"
	"time"

	cr "github.com/deutschland-schild/schild/contract/requests"
)

// ByIP returns the records of an address over the whole ring and the pinned
// context, newest first (privacy/export, D49, D51).
func (r *Ring) ByIP(ctx context.Context, ip netip.Addr, limit int, now time.Time) ([]cr.Record, error) {
	f := AnyFilter()
	f.IP = ip.Unmap().WithZone("")
	lo, _ := r.Window(now)
	p := QueryParams{From: lo, To: now.Add(time.Minute), Filter: f, Limit: min(limit, 500), MaxWindow: cr.MaxKeepHours*time.Hour + time.Hour}
	out := []cr.Record{}
	for {
		page, err := r.Query(ctx, p, now)
		if err != nil {
			return nil, err
		}
		out = append(out, page.Items...)
		if page.NextCursor == nil || len(out) >= limit {
			break
		}
		p.Cursor = *page.NextCursor
	}
	pinned, err := r.pinnedMatching(ctx, &f)
	if err != nil {
		return nil, err
	}
	type key struct {
		t, event, path, outcome string
		status                  int
		bytes                   uint32
	}
	seen := make(map[key]bool, len(out))
	for i := range out {
		x := &out[i]
		seen[key{x.T, x.EventID, x.Path, x.Outcome, x.Status, x.BytesOut}] = true
	}
	for _, x := range pinned {
		if k := (key{x.T, x.EventID, x.Path, x.Outcome, x.Status, x.BytesOut}); !seen[k] {
			seen[k] = true
			out = append(out, x)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].T > out[j].T })
	return out[:min(len(out), limit)], nil
}

// pinnedMatching reads the pinned context segments. They hold more than a
// query sees: sampled requests and anything older than keep_hours (D51).
func (r *Ring) pinnedMatching(ctx context.Context, f *Filter) ([]cr.Record, error) {
	if err := r.wait(ctx); err != nil {
		return nil, err
	}
	defer r.unlock()
	r.Flush()
	bn := r.bots()
	var out []cr.Record
	for _, fi := range r.snapshot(kindPin, 0, 1<<62-1) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		_ = r.load(&fi, func(_ int, x *Rec) bool {
			if f.match(x) {
				out = append(out, wire(x, bn))
			}
			return true
		})
	}
	return out, nil
}

// ForgetIP overwrites an address and its user agents in every segment and empties
// the memory ring (privacy/delete, D49, D50). The records stay with their visitor key. It returns how
// many it changed. Open segments are closed first, so only closed files change,
// and a query reads the old or the new file, never a mix.
func (r *Ring) ForgetIP(ctx context.Context, ip netip.Addr) (int, error) {
	r.forgetMu.Lock()
	defer r.forgetMu.Unlock()
	ip = ip.Unmap().WithZone("")
	r.forgetServed(ip)
	if r.started.Load() {
		c := make(chan struct{})
		select {
		case r.forgetReq <- c:
			<-c
		case <-r.done:
		}
	} else {
		r.drain()
		r.closeOpen()
	}
	r.mu.Lock()
	files := append([]*fileInfo(nil), r.files...)
	r.mu.Unlock()
	erased := 0
	for _, fi := range files {
		n, err := r.scrubFile(ctx, fi, ip)
		if err != nil {
			return erased, err
		}
		if fi.kind == kindSeg { // a pinned copy is the same request
			erased += n
		}
	}
	return erased, nil
}

// closeOpen closes the open segments, empties the memory ring and the
// visitor key cache, both keyed by or holding addresses (writer goroutine).
func (r *Ring) closeOpen() {
	for _, s := range []**segWriter{&r.seg, &r.pin} {
		if *s != nil {
			r.closeSeg(*s)
			*s = nil
		}
	}
	r.mem.clear()
	clear(r.vkeys)
}

// scrubFile waits for the closer, then rewrites a segment that holds ip.
func (r *Ring) scrubFile(ctx context.Context, fi *fileInfo, ip netip.Addr) (int, error) {
	for {
		r.mu.Lock()
		gone, raw, open := fi.gone, fi.raw, fi.open
		path, kind, level, start, mn, mx, count := fi.path, fi.kind, fi.level, fi.start, fi.min, fi.max, fi.count
		r.mu.Unlock()
		if gone || open {
			return 0, nil
		}
		if raw {
			select {
			case <-ctx.Done():
				return 0, ctx.Err()
			case <-r.done:
				return 0, nil // a closing ring compresses what is left at the next start
			case <-time.After(20 * time.Millisecond):
			}
			continue
		}
		frames, _, _, _, err := readFrames(path)
		if err != nil {
			if os.IsNotExist(err) {
				return 0, nil
			}
			return 0, err
		}
		n := 0
		var d dict
		var rec Rec
		if _, err := walkFrames(frames, start, &d, frameVisitor{rec: func(_ int, p []byte) bool {
			if decodeRec(p, start, &d, &rec) == nil && rec.IP == ip {
				clear(p[rec.tail:])
				n++
			}
			return true
		}}); err != nil {
			return 0, err
		}
		if n == 0 {
			return 0, nil
		}
		tmp := strings.TrimSuffix(path, ".z") + ".scrub.tmp"
		if err := writeZ(tmp, frames, kind, level, start, mn, mx, count); err != nil {
			return 0, err
		}
		r.mu.Lock()
		defer r.mu.Unlock()
		if fi.gone { // deleted by retention meanwhile
			os.Remove(tmp)
			return 0, nil
		}
		if err := os.Rename(tmp, path); err != nil {
			os.Remove(tmp)
			return 0, err
		}
		if st, err := os.Stat(path); err == nil {
			r.bytes += st.Size() - fi.size
			fi.size = st.Size()
		}
		return n, nil
	}
}
