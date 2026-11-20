package store

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// alertMix writes n events of one website: mostly passed requests, every
// 20th a WAF block, every 50th a would-block, every 200th a behaviour hit;
// two other websites get the same.
func alertMix(t testing.TB, s *Store, n int, base time.Time) {
	t.Helper()
	ctx := context.Background()
	countries := []string{"DE", "FR", "NL", "US"}
	nets := []string{"residential", "hosting", "mobile"}
	var batch []*EventRow
	for i := 0; i < n; i++ {
		for _, site := range []string{"shop.example", "blog.example", "app.example"} {
			e := &EventRow{ID: fmt.Sprintf("%s-%d", site, i), Time: base.Add(time.Duration(i) * time.Second), Type: "schild.request.evaluated.v1", Outcome: "passed",
				IP: fmt.Sprintf("198.51.%d.%d", i/250%250, i%250), Country: countries[i%len(countries)], ASN: uint32(3320 + i%7), Host: site, Site: site,
				Path: fmt.Sprintf("/p/%d", i%40), Body: []byte(fmt.Sprintf(`{"data":{"client":{"geo":{"net_class":%q}}}}`, nets[i%len(nets)]))}
			switch {
			case i%200 == 0:
				e.Type, e.Outcome = "schild.behaviour.triggered.v1", ""
				e.Body = []byte(fmt.Sprintf(`{"data":{"action":"block","scenario":"waf_repeat","client":{"geo":{"net_class":%q}}}}`, nets[i%len(nets)]))
			case i%50 == 0:
				e.Outcome, e.Rules = "would_block", []string{"942100", strconv.Itoa(930000 + i%30)}
			case i%20 == 0:
				e.Type, e.Outcome, e.Rules = "schild.request.blocked.v1", "blocked", []string{"941100", strconv.Itoa(930000 + i%30)}
			}
			batch = append(batch, e)
		}
		if len(batch) >= 3000 {
			if err := s.InsertEvents(ctx, batch); err != nil {
				t.Fatal(err)
			}
			batch = batch[:0]
		}
	}
	if err := s.InsertEvents(ctx, batch); err != nil {
		t.Fatal(err)
	}
}

func (s *Store) planOf(t testing.TB, q string, args []any) string {
	t.Helper()
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

// TestAlertFiltersUseAlertIndexes (D36 fix round 1, finding B.4.4 c): every
// filter of listAlerts reads an index that holds the alert events only, in
// time order, and returns what a scan would.
func TestAlertFiltersUseAlertIndexes(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	base := time.Now().UTC().Add(-48 * time.Hour).Truncate(time.Second)
	alertMix(t, s, 4000, base)
	asn := uint32(3322)
	cases := []struct {
		name  string
		f     AlertFilter
		index string
		match func(e *EventRow) bool
	}{
		{"none", AlertFilter{}, "events_alert", func(*EventRow) bool { return true }},
		{"country", AlertFilter{Country: "FR"}, "events_alert_country", func(e *EventRow) bool { return e.Country == "FR" }},
		{"asn", AlertFilter{ASN: &asn}, "events_alert_asn", func(e *EventRow) bool { return e.ASN == asn }},
		{"path", AlertFilter{Path: "/p/2"}, "events_alert_path", func(e *EventRow) bool { return strings.HasPrefix(e.Path, "/p/2") }},
		{"net_class", AlertFilter{NetClass: "hosting"}, "events_alert_net", func(e *EventRow) bool { return strings.Contains(string(e.Body), `"hosting"`) }},
		{"rule", AlertFilter{Rule: "930010"}, "r USING PRIMARY KEY", func(e *EventRow) bool {
			for _, r := range e.Rules {
				if r == "930010" {
					return true
				}
			}
			return false
		}},
		{"rare", AlertFilter{Rule: "999999"}, "r USING PRIMARY KEY", func(*EventRow) bool { return false }},
	}
	all, _, err := s.ListEvents(ctx, EventFilter{Site: "shop.example"}, 0, 100000)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.f.Site = "shop.example"
			tc.f.From, tc.f.To = base, base.Add(72*time.Hour)
			q, args := alertQuery(tc.f, 500)
			p := s.planOf(t, q, args)
			if !strings.Contains(p, tc.index) || strings.Contains(p, "SCAN events") {
				t.Errorf("plan %s, want index %s", p, tc.index)
			}
			got, err := s.AlertEvents(ctx, tc.f, 500)
			if err != nil {
				t.Fatal(err)
			}
			var want []string
			for _, e := range all {
				alert := e.Type == "schild.request.blocked.v1" || e.Type == "schild.behaviour.triggered.v1" || e.Outcome == "would_block"
				if alert && tc.match(e) {
					want = append(want, e.ID)
				}
			}
			if len(want) > 500 {
				want = want[:500]
			}
			if len(got) != len(want) {
				t.Fatalf("%d alerts, want %d", len(got), len(want))
			}
			for i := range got {
				if got[i].ID != want[i] {
					t.Fatalf("alert %d: %s, want %s", i, got[i].ID, want[i])
				}
			}
		})
	}
	// Deleting events removes their rules; a new store migrates nothing twice.
	if _, err := s.db.Exec(`DELETE FROM events WHERE site = 'shop.example'`); err != nil {
		t.Fatal(err)
	}
	var n int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM event_rules WHERE site = 'shop.example'`).Scan(&n)
	if n != 0 {
		t.Fatalf("%d rules left after delete", n)
	}
	if p := s.planOf(t, `SELECT seq FROM events WHERE site = ? AND time_ms >= ? AND time_ms <= ? AND `+waveCond+` ORDER BY time_ms, seq LIMIT 1`, []any{"shop.example", 0, 1}); !strings.Contains(p, "events_wave") {
		t.Errorf("waves: %s", p)
	}
}

// BenchmarkAlertsMillion: listAlerts filters on a million events
// (SCHILD_BENCH_MILLION=1; builds the database first).
func BenchmarkAlertsMillion(b *testing.B) {
	if os.Getenv("SCHILD_BENCH_MILLION") == "" {
		b.Skip("set SCHILD_BENCH_MILLION=1")
	}
	s, err := Open(b.TempDir() + "/schild.db")
	if err != nil {
		b.Fatal(err)
	}
	defer s.Close()
	base := time.Now().UTC().Add(-7 * 24 * time.Hour)
	alertMix(b, s, 340000, base)
	asn := uint32(1)
	for i, f := range []AlertFilter{{}, {Country: "ZZ"}, {Rule: "999999"}, {Path: "/nothing"}, {NetClass: "tor"}, {ASN: &asn}} {
		f.Site, f.From, f.To = "shop.example", base, time.Now()
		b.Run([]string{"none", "country", "rule", "path", "net_class", "asn"}[i], func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				if _, err := s.AlertEvents(context.Background(), f, 500); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
