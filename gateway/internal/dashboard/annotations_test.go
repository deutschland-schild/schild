package dashboard

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/contract/websites"
	"github.com/deutschland-schild/schild/gateway/internal/store"
)

// TestSitesAffectedOwnWindow (D36 fix round 1, finding B.4.4 d): an
// incident names the websites its client touched up to the incident, not
// the ones it attacked afterwards.
func TestSitesAffectedOwnWindow(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "schild.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	at := time.Now().UTC().Add(-time.Hour).Truncate(time.Millisecond)
	var rows []*store.EventRow
	for i, x := range []struct {
		site string
		d    time.Duration
	}{{"a.example", 0}, {"c.example", -time.Hour}, {"b.example", 30 * time.Second}, {"d.example", time.Millisecond}} {
		rows = append(rows, &store.EventRow{ID: fmt.Sprintf("e%d", i), Time: at.Add(x.d), Type: "schild.request.blocked.v1", IP: "203.0.113.7", Site: x.site, Body: []byte(`{}`)})
	}
	if err := st.InsertEvents(ctx, rows); err != nil {
		t.Fatal(err)
	}
	s := &Server{St: st}
	sa := s.SitesAffected(ctx, "203.0.113.7", "a.example", at)
	if sa == nil || sa.Count != 2 || len(sa.Sites) != 2 || sa.Sites[0] != "a.example" || sa.Sites[1] != "c.example" {
		t.Fatalf("%+v", sa)
	}
}

// TestAnnotationBudget (D36 fix round 1, finding B.4.4 b): an attack with
// many incidents never pushes restarts, configuration changes, gaps and
// waves out of the 200 markers; dense incidents become a few markers that
// count them.
func TestAnnotationBudget(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "schild.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	from := time.Now().UTC().Add(-24 * time.Hour).Truncate(time.Hour)
	to := from.Add(24 * time.Hour)
	// 2000 incidents in one hour, 5 more spread over the day.
	for i := 0; i < 2000; i++ {
		in := &store.Incident{Incident: fmt.Sprintf("S-%05d", i), EventID: fmt.Sprintf("e%d", i), Time: from.Add(10*time.Hour + time.Duration(i)*1500*time.Millisecond),
			IP: "203.0.113.9", Status: "blocked", Site: "shop.example"}
		if err := st.InsertIncident(ctx, in); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 5; i++ {
		in := &store.Incident{Incident: fmt.Sprintf("T-%d", i), EventID: fmt.Sprintf("t%d", i), Time: from.Add(time.Duration(4*i+1) * time.Hour),
			IP: "203.0.113.10", Status: "blocked", Site: "shop.example"}
		if err := st.InsertIncident(ctx, in); err != nil {
			t.Fatal(err)
		}
	}
	bins, err := st.IncidentBins(ctx, "shop.example", from, to, to.Sub(from)/annIncidentBudget)
	if err != nil {
		t.Fatal(err)
	}
	items := incidentAnnotations(bins)
	var total int64
	for _, b := range bins {
		total += b.N
	}
	if total != 2005 || len(bins) > annIncidentBudget {
		t.Fatalf("%d bins counting %d incidents", len(bins), total)
	}
	// Grouped markers carry the bin and the newest incident (contracts
	// v0.5, Annotation: t = bin start, until = bin end, ref = newest).
	grouped := 0
	for i, a := range items {
		b := bins[i]
		if b.N == 1 {
			if a.Count != 0 || a.Until != "" || a.Ref == "" || a.T != ts(b.Last) {
				t.Fatalf("single incident marker %+v", a)
			}
			continue
		}
		grouped++
		if a.Count != b.N || a.T != ts(b.Start) || a.Until != ts(b.End) || !b.Start.Before(b.End) || b.Last.Before(b.Start) || !b.Last.Before(b.End) {
			t.Fatalf("grouped marker %+v of bin %+v", a, b)
		}
		var newest string
		if err := st.DB().QueryRowContext(ctx, `SELECT incident FROM incidents WHERE site = ? AND time_ms >= ? AND time_ms < ? ORDER BY time_ms DESC LIMIT 1`,
			"shop.example", b.Start.UnixMilli(), b.End.UnixMilli()).Scan(&newest); err != nil || a.Ref != newest {
			t.Fatalf("grouped marker ref %q, newest %q (%v)", a.Ref, newest, err)
		}
	}
	if grouped == 0 {
		t.Fatal("no grouped marker")
	}
	for i := 0; i < 3; i++ {
		items = append(items, websites.Annotation{T: ts(from.Add(time.Duration(i) * time.Hour)), Kind: websites.AnnRestart},
			websites.Annotation{T: ts(from.Add(time.Duration(i)*time.Hour + time.Minute)), Kind: websites.AnnConfigChanged},
			websites.Annotation{T: ts(from.Add(time.Duration(i)*time.Hour + 2*time.Minute)), Kind: websites.AnnMonitoringGap})
	}
	// A flood of 300 incident markers (as before the bins) still leaves
	// every other kind in.
	for i := 0; i < 300; i++ {
		items = append(items, websites.Annotation{T: ts(from.Add(time.Duration(i) * time.Second)), Kind: websites.AnnIncident, Ref: fmt.Sprintf("X-%d", i)})
	}
	out, truncated := budgetAnnotations(items)
	if len(out) != websites.MaxAnnotations || !truncated {
		t.Fatalf("%d markers, truncated %v", len(out), truncated)
	}
	n := map[string]int{}
	for i, a := range out {
		n[a.Kind]++
		if i > 0 && out[i-1].T > a.T {
			t.Fatal("not sorted by time")
		}
	}
	if n[websites.AnnRestart] != 3 || n[websites.AnnConfigChanged] != 3 || n[websites.AnnMonitoringGap] != 3 {
		t.Fatalf("kinds %v", n)
	}
	// Without a flood nothing is cut.
	if out, truncated := budgetAnnotations(items[:len(bins)+9]); truncated || len(out) != len(bins)+9 {
		t.Fatalf("%d markers, truncated %v", len(out), truncated)
	}
}
