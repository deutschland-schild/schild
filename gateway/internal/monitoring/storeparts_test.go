package monitoring

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	cm "github.com/deutschland-schild/schild/contract/monitoring"
)

// heavySiteBucket is a heavy 10 min bucket with two websites (one with top
// lists).
func heavySiteBucket(start time.Time) cm.MetricBucket {
	b := heavyBucket(start, cm.Res10m, 600, 3)
	b.Sites = append(b.Sites, cm.SiteTraffic{Site: "shop", Traffic: cm.TrafficCounters{Requests: 3, Forwarded: 1, FailClosed: 2}})
	b.Sites = append(b.Sites, siteTraffic("verein.example", true))
	return b
}

// TestStoreLayout3RoundTrip: a bucket stored as ring row and parts reads
// back whole (readAll), and a read of one website and one dimension gets
// that website's numbers and list only.
func TestStoreLayout3RoundTrip(t *testing.T) {
	dir := t.TempDir()
	m, err := New(Config{StoragePath: dir}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	ring := m.rings[2]
	start := ring.Start(time.Now().Add(-time.Hour))
	b := heavySiteBucket(start)
	if err := m.store.put(ring, start, &b); err != nil {
		t.Fatal(err)
	}
	var got *cm.MetricBucket
	if err := m.store.read(ring, start, start, readAll, func(_ time.Time, x *cm.MetricBucket) { got = x }); err != nil || got == nil {
		t.Fatal(err)
	}
	want, _ := json.Marshal(b)
	have, _ := json.Marshal(got)
	if string(want) != string(have) {
		t.Fatalf("round trip differs:\n%s\n%s", want, have)
	}
	got = nil
	parts := readParts{core: coreSites, top: true, dim: "path", site: "verein.example", only: "verein.example"}
	if err := m.store.read(ring, start, start, parts, func(_ time.Time, x *cm.MetricBucket) { got = x }); err != nil || got == nil {
		t.Fatal(err)
	}
	if got.Top != nil || len(got.Sites) != 1 || got.Sites[0].Site != "verein.example" || got.Sites[0].Top == nil ||
		!reflect.DeepEqual(got.Sites[0].Top.Path, b.Sites[1].Top.Path) || got.Sites[0].Top.ASN != nil || got.Sites[0].Traffic != b.Sites[1].Traffic {
		t.Fatalf("one website, one list: %+v", got)
	}
	// Overwriting the slot replaces every part (no website of the old
	// bucket stays).
	b2 := heavyBucket(start, cm.Res10m, 600, 4)
	if err := m.store.put(ring, start, &b2); err != nil {
		t.Fatal(err)
	}
	var n int
	_ = m.store.db.QueryRow(`SELECT COUNT(*) FROM ring_10m_part WHERE owner != ''`).Scan(&n)
	if n != 0 {
		t.Fatalf("%d website parts left after the overwrite", n)
	}
}
