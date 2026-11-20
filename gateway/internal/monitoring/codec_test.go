package monitoring

import (
	"bytes"
	"compress/flate"
	"database/sql"
	"encoding/json"
	"fmt"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	cm "github.com/deutschland-schild/schild/contract/monitoring"
)

// jsonFlateSize is the size of a bucket in storage layout 1 (flate of the
// JSON), to keep layout 2 from growing metrics.db.
func jsonFlateSize(t *testing.T, b *cm.MetricBucket) int {
	raw, _ := json.Marshal(b)
	var buf bytes.Buffer
	w, _ := flate.NewWriter(&buf, flate.BestSpeed)
	_, _ = w.Write(raw)
	_ = w.Close()
	return buf.Len()
}

func TestCodecRoundTrip(t *testing.T) {
	start := time.Unix(1_800_000_000, 0)
	for _, b := range []cm.MetricBucket{heavyBucket(start, cm.Res1m, 60, 7), heavyBucket(start, cm.Res10s, 10, 1),
		{T: ts(start), Resolution: cm.Res10m, StepS: 600, Partial: true, GapKind: cm.GapRestart, Sites: []cm.SiteTraffic{}, Latency: cm.BucketLatency{Total: cm.LatencyHistogram{Scheme: cm.HistogramScheme, Counts: map[string]int64{}}}}} {
		b.Sites = append(b.Sites, cm.SiteTraffic{Site: "shop", Traffic: cm.TrafficCounters{Requests: 3, Forwarded: 1, FailClosed: 2,
			FailClosedBy: cm.FailClosedBy{WAFBusy: 2}, WaitingPageShown: 1, Rechecked: 1}})
		b.Traffic.WaitingPageShown = 9      // codec version 4
		b.Traffic.Rechecked = 2             // codec version 5
		b.Traffic.FailClosedBy.BodyBusy = 3 // codec version 6
		b.Sites = append(b.Sites, siteTraffic("verein.example", b.Top != nil))
		day, bots := int64(4711), int64(23)
		b.Clients.UniqueDay, b.Clients.Bots = &day, &bots
		core, top := encodeCore(&b), encodeTop(b.Top, b.Sites)
		var scratch bytes.Buffer
		got, err := decodeCore(core, coreAll, &scratch, map[string]string{})
		if err != nil {
			t.Fatal(err)
		}
		if err = decodeTop(got, top, topSel{site: "*"}, &scratch); err != nil {
			t.Fatal(err)
		}
		want, _ := json.Marshal(b)
		have, _ := json.Marshal(got)
		if !bytes.Equal(want, have) {
			t.Fatalf("round trip differs:\n%s\n%s", want, have)
		}
		if old := jsonFlateSize(t, &b); len(core)+len(top) > old {
			t.Errorf("%s bucket: layout 2 %d bytes > layout 1 %d bytes", b.Resolution, len(core)+len(top), old)
		} else {
			t.Logf("%s bucket: layout 2 %d bytes, layout 1 %d bytes", b.Resolution, len(core)+len(top), old)
		}
		// One dimension and the counters only.
		tc, err := decodeCore(core, coreTraffic, &scratch, nil)
		if err != nil || tc.Traffic != b.Traffic {
			t.Fatalf("traffic only: %v %+v", err, tc)
		}
		if b.Top != nil {
			one, _ := decodeCore(core, coreAll, &scratch, nil)
			err := decodeTop(one, top, topSel{dim: "asn"}, &scratch)
			if err != nil || !reflect.DeepEqual(one.Top.ASN, b.Top.ASN) || one.Top.Path != nil || one.Sites[1].Top != nil {
				t.Fatalf("asn only: %v", err)
			}
			// One website's list of one dimension.
			one, _ = decodeCore(core, coreAll, &scratch, nil)
			err = decodeTop(one, top, topSel{dim: "path", site: "verein.example"}, &scratch)
			if err != nil || one.Sites[1].Top == nil || !reflect.DeepEqual(one.Sites[1].Top.Path, b.Sites[1].Top.Path) || one.Sites[1].Top.ASN != nil || one.Top.ASN != nil {
				t.Fatalf("site path only: %v", err)
			}
		}
	}
}

// A corrupt blob is an error, never a panic or a large allocation.
func TestCodecCorrupt(t *testing.T) {
	b := heavyBucket(time.Unix(1_800_000_000, 0), cm.Res1m, 60, 1)
	core, top := encodeCore(&b), encodeTop(b.Top, b.Sites)
	var scratch bytes.Buffer
	for _, blob := range [][]byte{nil, {1}, core[:len(core)/2], deflate([]byte{codecVersion, 200, 200, 200, 200, 200, 1}), deflate([]byte{9})} {
		if _, err := decodeCore(blob, coreAll, &scratch, nil); err == nil {
			t.Errorf("corrupt core %x accepted", blob)
		}
	}
	for _, blob := range [][]byte{{9}, top[:len(top)/2], {topVersion, 1, 0, 0xff, 0xff, 0xff, 0x0f}} {
		if err := decodeTop(&cm.MetricBucket{}, blob, topSel{site: "*"}, &scratch); err == nil {
			t.Errorf("corrupt top %x accepted", blob)
		}
	}
}

// The codec must know every field of the stored wire types: when the
// contract adds one, this test fails until codec.go encodes it.
func TestCodecCoversEveryField(t *testing.T) {
	for typ, n := range map[reflect.Type]int{
		reflect.TypeOf(cm.MetricBucket{}): 12, reflect.TypeOf(cm.TrafficCounters{}): 22, reflect.TypeOf(cm.FailClosedBy{}): 5,
		reflect.TypeOf(cm.StatusClasses{}): 5, reflect.TypeOf(cm.BucketLatency{}): 3, reflect.TypeOf(cm.LatencyHistogram{}): 2,
		reflect.TypeOf(cm.BucketClients{}): 4, reflect.TypeOf(cm.SiteTraffic{}): 5, reflect.TypeOf(cm.MetricValues{}): 2,
		reflect.TypeOf(cm.GaugeStats{}): 3, reflect.TypeOf(cm.ObjectValues{}): 3, reflect.TypeOf(cm.TopEntry{}): 7,
		reflect.TypeOf(cm.BucketTop{}): len(topDims),
	} {
		if typ.NumField() != n {
			t.Errorf("%s has %d fields, the metrics.db codec knows %d: extend codec.go", typ, typ.NumField(), n)
		}
	}
}

// A metrics.db of layout 1 (one JSON column) starts its rings over.
func TestStoreLayoutUpgrade(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "metrics.db")
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE meta (k TEXT PRIMARY KEY, v TEXT NOT NULL) WITHOUT ROWID;
CREATE TABLE ring_1m (slot INTEGER PRIMARY KEY, t INTEGER NOT NULL, bucket BLOB NOT NULL) WITHOUT ROWID;
INSERT INTO meta VALUES ('ring_1m', '2880'); INSERT INTO ring_1m VALUES (1, 60, x'00');`); err != nil {
		t.Fatal(err)
	}
	db.Close()
	m, err := New(Config{StoragePath: dir}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	end := time.Now().UTC().Truncate(time.Minute)
	b := heavyBucket(end.Add(-time.Minute), cm.Res1m, 60, 1)
	if err := m.store.put(m.rings[1], end.Add(-time.Minute), &b); err != nil {
		t.Fatal(err)
	}
	page, err := m.Buckets("1m", end.Add(-time.Hour), "", 100, end)
	if err != nil || len(page.Items) != 1 || page.Items[0].Top == nil || len(page.Items[0].Top.Path) != cm.TopK {
		t.Fatalf("%v %+v", err, page)
	}
}

// siteTraffic is a website of a heavy bucket: latency, estimates and (with
// top) per-website lists of SiteTopK entries.
func siteTraffic(site string, top bool) cm.SiteTraffic {
	h := cm.LatencyHistogram{Scheme: cm.HistogramScheme, Counts: map[string]int64{"12": 40, "20": 3}}
	u, n, d, bt := int64(80), int64(7), int64(310), int64(12)
	st := cm.SiteTraffic{Site: site, Traffic: cm.TrafficCounters{Requests: 43, Forwarded: 40, Stopped: 3, BlockedWAF: 3, Detections: 3},
		Latency: &cm.BucketLatency{Total: h, Overhead: h, Upstream: h}, Clients: &cm.BucketClients{Unique: &u, New: &n, UniqueDay: &d, Bots: &bt}}
	if top {
		list := func(prefix string, k int) []cm.TopEntry {
			out := make([]cm.TopEntry, k)
			for i := range out {
				out[i] = cm.TopEntry{Key: fmt.Sprintf("%s%d", prefix, i), Requests: int64(100 - i), Stopped: 1, Error: int64(i)}
			}
			return out
		}
		st.Top = &cm.BucketTop{Path: list("/s/", cm.SiteTopK), ASN: list("6450", cm.SiteTopK), Country: list("D", cm.SiteTopK), Referrer: list("r", 4),
			Rule: list("9421", 3), NetClass: list("n", 2), Method: list("GET", 1)}
	}
	return st
}
