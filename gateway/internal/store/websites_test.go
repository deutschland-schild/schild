package store

import (
	"context"
	"strings"
	"testing"
	"time"
)

// TestSiteReadsUseTheirIndexes: the site filters of the event list, the
// alert feed and the incident list read an index on site (D36), never the
// whole table.
func TestSiteReadsUseTheirIndexes(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	now := time.Now().UTC()
	rows := []*EventRow{
		{ID: "e1", Time: now, Type: "schild.request.blocked.v1", IP: "203.0.113.5", Host: "shop.example", Rules: []string{"941100"}, Site: "shop.example", Body: []byte(`{}`)},
		{ID: "e2", Time: now, Type: "schild.request.evaluated.v1", IP: "203.0.113.5", Host: "verein.example", Outcome: "passed", Site: "verein.example", Body: []byte(`{}`)},
	}
	if err := s.InsertEvents(ctx, rows); err != nil {
		t.Fatal(err)
	}
	plan := func(q string, args ...any) string {
		r, err := s.db.Query("EXPLAIN QUERY PLAN "+q, args...)
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()
		var out []string
		for r.Next() {
			var id, parent, notused int
			var detail string
			_ = r.Scan(&id, &parent, &notused, &detail)
			out = append(out, detail)
		}
		return strings.Join(out, "; ")
	}
	if p := plan(`SELECT seq FROM events WHERE site = ? ORDER BY seq DESC LIMIT 50`, "shop.example"); !strings.Contains(p, "events_site") {
		t.Errorf("event list by site: %s", p)
	}
	if p := plan(`SELECT seq FROM events WHERE site = ? AND (type IN (?, ?, ?) OR (type = ? AND outcome = 'would_block')) AND time_ms >= ? ORDER BY time_ms DESC, seq DESC LIMIT 50`,
		"shop.example", "a", "b", "c", "d", 0); !strings.Contains(p, "events_site_time") {
		t.Errorf("alert feed: %s", p)
	}
	if p := plan(`SELECT incident FROM incidents WHERE time_ms >= ? AND time_ms < ? AND site = ? ORDER BY time_ms DESC LIMIT 50`, 0, 1, "shop.example"); !strings.Contains(p, "incidents_site") {
		t.Errorf("incidents by site: %s", p)
	}
	got, err := s.AlertEvents(ctx, AlertFilter{Site: "shop.example"}, 10)
	if err != nil || len(got) != 1 || got[0].ID != "e1" || got[0].Site != "shop.example" {
		t.Fatalf("alerts: %v %+v", err, got)
	}
	sites, n, err := s.SitesOfIP(ctx, "203.0.113.5", now.Add(-time.Hour), now.Add(time.Minute), 32)
	if err != nil || n != 2 || len(sites) != 2 {
		t.Fatalf("sites of ip: %v %d %v", err, n, sites)
	}
}
