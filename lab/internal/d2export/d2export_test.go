package d2export

import (
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/deutschland-schild/schild/lab/internal/scoring"
	"github.com/deutschland-schild/schild/lab/internal/store"
)

var t0 = time.Date(2026, 11, 9, 8, 0, 0, 0, time.UTC)

func put(t *testing.T, db *store.DB, seq uint64, at time.Time, keyID, issuer, actionSig string, score int) {
	t.Helper()
	payload, _ := json.Marshal(map[string]any{"schema": "schild.signal/0.3", "id": "s", "kind": "tip", "time_bucket": at.Truncate(10 * time.Minute).Format(time.RFC3339),
		"action_sig": actionSig, "request_sig": "r", "waf_rules": []int{942100}, "score": score, "category": "sqli"})
	rs := scoring.ReceivedSignal{ReceivedAt: at.Format(time.RFC3339), Issuer: issuer, KeyID: keyID, PatternID: scoring.PatternID(actionSig), Payload: payload}
	if err := db.Update(func(tx *bolt.Tx) error {
		return store.PutJSON(tx, store.Signals, store.Key(store.U64(uint64(at.UnixMilli())), store.U64(seq)), rs)
	}); err != nil {
		t.Fatal(err)
	}
}

func fixture(t *testing.T) *store.DB {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "store.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	// sqli/wp-login.php: shop first, blog 10 min later, docs 1 h later.
	put(t, db, 1, t0, "site-shop", "org-a", "sqli/wp-login.php", 80)
	put(t, db, 2, t0.Add(time.Minute), "site-shop", "org-a", "sqli/wp-login.php", 80)
	put(t, db, 3, t0.Add(10*time.Minute), "site-blog", "org-a", "sqli/wp-login.php", 60)
	put(t, db, 4, t0.Add(time.Hour), "site-docs", "org-b", "sqli/wp-login.php", 40)
	// lfi/.env: only one site.
	put(t, db, 5, t0.Add(2*time.Hour), "site-blog", "org-a", "lfi/.env", 90)
	// baseline sample (score below min_score) on a second site: ignored by default.
	put(t, db, 6, t0.Add(3*time.Hour), "site-shop", "org-a", "lfi/.env", 5)
	// outside the period
	put(t, db, 7, t0.Add(-48*time.Hour), "site-docs", "org-b", "lfi/.env", 90)
	return db
}

func TestBuild(t *testing.T) {
	db := fixture(t)
	ex, err := Build(db, Options{From: t0.Add(-time.Hour), To: t0.Add(24 * time.Hour), MinScore: 40, Lab: "lab-1"}, t0)
	if err != nil {
		t.Fatal(err)
	}
	if ex.Summary.Patterns != 2 || ex.Summary.PatternsMultiSite != 1 || ex.Summary.Sites != 3 || ex.Summary.ShareMultiSite != 0.5 {
		t.Fatalf("summary %+v", ex.Summary)
	}
	p := ex.Patterns[0]
	if p.ActionSig != "sqli/wp-login.php" || p.Signals != 4 || len(p.Sites) != 3 || p.Sites[0].Site != "site-shop" || p.Sites[0].Signals != 2 {
		t.Fatalf("pattern %+v", p)
	}
	if len(p.LagsS) != 2 || p.LagsS[0] != 600 || p.LagsS[1] != 3600 {
		t.Fatalf("lags %v", p.LagsS)
	}
	if ex.Summary.LagMedianS != 2100 {
		t.Fatalf("median %v", ex.Summary.LagMedianS)
	}
	// min_score 0 includes the baseline: lfi/.env now on two sites.
	ex, _ = Build(db, Options{From: t0.Add(-time.Hour), To: t0.Add(24 * time.Hour)}, t0)
	if ex.Summary.PatternsMultiSite != 2 {
		t.Fatalf("min_score 0: %+v", ex.Summary)
	}
	raw, _ := json.Marshal(ex)
	for _, bad := range []string{"203.0.113", "198.51.100", "192.0.2", "2001:db8", "\"ip\""} {
		if strings.Contains(string(raw), bad) {
			t.Fatalf("export contains %q", bad)
		}
	}
	if _, err := Build(db, Options{From: t0, To: t0}, t0); err == nil {
		t.Fatal("empty period accepted")
	}
}

func TestMerge(t *testing.T) {
	db := fixture(t)
	o := Options{From: t0.Add(-time.Hour), To: t0.Add(24 * time.Hour), MinScore: 40}
	a, _ := Build(db, Options{From: o.From, To: o.To, MinScore: 40, Lab: "lab-1"}, t0)
	// lab-2 got the blog signal earlier (the shop's arrived late there).
	raw, _ := json.Marshal(a)
	var b Export
	_ = json.Unmarshal(raw, &b)
	b.Labs = []string{"lab-2"}
	for i := range b.Patterns {
		for j := range b.Patterns[i].Sites {
			if b.Patterns[i].Sites[j].Site == "site-shop" {
				b.Patterns[i].Sites[j].FirstSeen = t0.Add(20 * time.Minute).Format("2006-01-02T15:04:05.000Z")
			}
		}
	}
	m, err := Merge([]*Export{a, &b})
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Labs) != 2 || m.Patterns[0].Sites[0].Site != "site-shop" || m.Patterns[0].LagsS[0] != 600 || m.Patterns[0].Signals != 4 {
		t.Fatalf("merge %+v", m.Patterns[0])
	}
	b.MinScore = 0
	if _, err := Merge([]*Export{a, &b}); err == nil {
		t.Fatal("different min_score merged")
	}
}

func TestHandler(t *testing.T) {
	db := fixture(t)
	h := Handler(db, "lab-1", func() int { return 40 })
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/export/d2?from=2026-11-09&to=2026-11-10", nil))
	if rec.Code != 200 {
		t.Fatal(rec.Code, rec.Body.String())
	}
	var ex Export
	if err := json.Unmarshal(rec.Body.Bytes(), &ex); err != nil {
		t.Fatal(err)
	}
	if ex.Summary.Patterns != 2 || ex.Labs[0] != "lab-1" || ex.MinScore != 40 {
		t.Fatalf("%+v", ex.Summary)
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/export/d2?from=nope", nil))
	if rec.Code != 400 {
		t.Fatal(rec.Code)
	}
}
