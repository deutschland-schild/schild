package monitoring

import (
	"fmt"
	"math/rand/v2"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/contract/config"
	cm "github.com/deutschland-schild/schild/contract/monitoring"
	"github.com/deutschland-schild/schild/contract/websites"
	"github.com/deutschland-schild/schild/gateway/internal/sites"
)

func sizeSites(t *testing.T, n int) *sites.Registry {
	t.Helper()
	var blocks []websites.Block
	for i := 0; i < n; i++ {
		blocks = append(blocks, websites.Block{Addresses: []string{fmt.Sprintf("app%d.example.org", i)}, Schild: true})
	}
	v := sites.NewView(websites.Input{Mode: websites.ModeIngress, Blocks: blocks})
	if v.Err != nil {
		t.Fatal(v.Err)
	}
	return sites.NewRegistry(v)
}

func randWord(r *rand.Rand, n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[r.IntN(len(letters))]
	}
	return string(b)
}

// worstCaseRows fills one bucket of every ring with the worst case of the
// MVP-21/D36 measurement (B.4.6): random 500-character paths, referrers
// and AS names, every list full, all countries, many rules, for n
// websites; it returns the stored row sizes (core + top) per ring.
func worstCaseRows(t *testing.T, n int) (r10s, r1m, r10m int64) {
	t.Helper()
	dir := t.TempDir()
	base := time.Now().UTC().Truncate(10 * time.Minute).Add(-time.Hour)
	m, err := New(Config{StoragePath: dir, Keep: config.MonitoringKeep{TenSecondsHours: 6, MinuteHours: 48, TenMinuteDays: 14},
		Sampler: SamplerConfig{Root: fixtureRoot(t), Linux: true, Host: true, Started: base, Version: "test"}, Sites: sizeSites(t, max(n, 1))}, base)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	rng := rand.New(rand.NewPCG(1, uint64(n)))
	hosts := make([]string, max(n, 1))
	for i := range hosts {
		hosts[i] = fmt.Sprintf("app%d.example.org", i)
	}
	if n == 0 {
		hosts = []string{"other.example.net"} // resolves to no website
	}
	for s := 1; s <= 600; s++ {
		m.flushWrites()
		if s%5 == 0 {
			m.Sample(base.Add(time.Duration(s) * time.Second))
		}
		for _, h := range hosts {
			for j := 0; j < 3; j++ {
				// Three 64-letter segments: the path template keeps them
				// (D36 re-measurement B 3.4; one long segment became /{slug}).
				p := "/" + randWord(rng, 64) + "/" + randWord(rng, 64) + "/" + randWord(rng, 64)
				r := newReq(p, chromeUA, "https://"+randWord(rng, 63)+".example/"+randWord(rng, 430))
				r.Host = h
				c := string(rune('A'+rng.IntN(26))) + string(rune('A'+rng.IntN(26)))
				rules := []string{fmt.Sprint(900000 + rng.IntN(60000)), fmt.Sprint(900000 + rng.IntN(60000))}
				m.Record(&Req{R: r, Class: BlockedWAF, Detection: true, Rules: rules, Status: 403, Timed: true, Total: time.Duration(rng.IntN(5000)) * time.Millisecond,
					Client: netip.AddrFrom4([4]byte{10, byte(rng.IntN(256)), byte(rng.IntN(256)), byte(rng.IntN(256))}), Country: c,
					ASN: uint32(64512 + rng.IntN(1000)), ASOrg: randWord(rng, 500), NetClass: "hosting"})
			}
		}
		m.Tick(base.Add(time.Duration(s) * time.Second))
	}
	m.flushWrites()
	// A bucket: its ring row plus its part rows (owner and 16 bytes of row
	// header each).
	bucketBytes := `length(m.core) + COALESCE(length(m.top), 0) + COALESCE((SELECT SUM(length(p.z) + length(p.owner) + 16) FROM %[1]s_part p WHERE p.slot = m.slot), 0)`
	q := func(tbl string) (slot, size int64) {
		if err := m.store.db.QueryRow(fmt.Sprintf(`SELECT m.slot, `+bucketBytes+` AS n FROM %[1]s m ORDER BY n DESC LIMIT 1`, tbl)).Scan(&slot, &size); err != nil {
			t.Fatal(err)
		}
		return slot, size
	}
	_, r10s = q("ring_10s")
	_, r1m = q("ring_1m")
	_, r10m = q("ring_10m")
	if n == 32 && !raceEnabled {
		// Copy the largest bucket of each ring into every slot and check
		// the file against MetricsBoundBytes (SQLite pages, overflow and
		// indexes included). It writes about 400 MiB through SQLite in
		// one goroutine: under the race detector (pure-Go SQLite fully
		// instrumented) that alone exceeds the test timeout and proves
		// nothing about races, so the plain test run covers it.
		for _, r := range m.rings {
			tbl := tableOf(r.Resolution)
			slot, _ := q(tbl)
			step := int64(r.Step / time.Second)
			end := base.Unix() / step * step
			tx, err := m.store.db.Begin()
			if err != nil {
				t.Fatal(err)
			}
			for k := int64(1); k < r.Slots(); k++ {
				tt := end - k*step
				s := (tt / step) % r.Slots()
				if s == slot {
					continue
				}
				if _, err := tx.Exec(`INSERT OR REPLACE INTO `+tbl+` (slot, t, core, top) SELECT ?, ?, core, top FROM `+tbl+` WHERE slot = ?`, s, tt, slot); err != nil {
					t.Fatal(err)
				}
				if _, err := tx.Exec(`DELETE FROM `+tbl+`_part WHERE slot = ?`, s); err != nil {
					t.Fatal(err)
				}
				if _, err := tx.Exec(`INSERT INTO `+tbl+`_part (owner, kind, slot, t, z) SELECT owner, kind, ?, ?, z FROM `+tbl+`_part WHERE slot = ?`, s, tt, slot); err != nil {
					t.Fatal(err)
				}
			}
			if err := tx.Commit(); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := m.store.db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
			t.Fatal(err)
		}
		st, err := os.Stat(dir + "/metrics.db")
		if err != nil {
			t.Fatal(err)
		}
		bound := MetricsBoundBytes(m.rings, 32)
		if os.Getenv("SCHILD_PRINT_SIZES") != "" {
			t.Logf("every slot written with the largest bucket: file %.1f MiB, bound %.1f MiB", float64(st.Size())/(1<<20), float64(bound)/(1<<20))
		}
		if st.Size() > bound {
			t.Errorf("file %d bytes is over the bound %d", st.Size(), bound)
		}
	}
	return r10s, r1m, r10m
}

// TestMetricsSizeBound: the stored rows of the worst case stay within the
// per-row sizes of MetricsBoundBytes for 1 and 32 websites, and every top
// list key is at most MaxTopKeyBytes long.
func TestMetricsSizeBound(t *testing.T) {
	if testing.Short() {
		t.Skip("fills a bucket of every ring")
	}
	for _, n := range []int{0, 1, 32} {
		a, b, c := worstCaseRows(t, n)
		if os.Getenv("SCHILD_PRINT_SIZES") != "" {
			t.Logf("websites %d: row bytes 10 s %d, 1 min %d, 10 min %d", n, a, b, c)
		}
		w := int64(n)
		if a > RowBound10s(w) || b > RowBound1m(w) || c > RowBound10m(w) {
			t.Errorf("websites %d: rows %d/%d/%d exceed the bound %d/%d/%d", n, a, b, c, RowBound10s(w), RowBound1m(w), RowBound10m(w))
		}
	}
	rings := cm.Rings(config.DefaultKeepTenSecondsHours, config.DefaultKeepMinuteHours, config.DefaultKeepTenMinuteDays)
	if os.Getenv("SCHILD_PRINT_SIZES") != "" {
		for _, n := range []int64{0, 1, 4, 32} {
			t.Logf("bound with %d websites: %.1f MiB", n, float64(MetricsBoundBytes(rings, n))/(1<<20))
		}
	}
}

func TestTopKeysAreCut(t *testing.T) {
	tt := newTopTable(4)
	long := "/" + randWord(rand.New(rand.NewPCG(1, 2)), 600)
	tt.add(long, randWord(rand.New(rand.NewPCG(3, 4)), 300), 1, 0, 0, 0, 0)
	tt.add(long[:200]+"other", "", 1, 0, 0, 0, 0) // same first bytes: same key
	es := tt.top(4, false)
	if len(es) != 1 || len(es[0].Key) > MaxTopKeyBytes || len(es[0].Label) > MaxTopKeyBytes || es[0].Requests != 2 {
		t.Fatalf("%+v", es)
	}
	if es[0].Key[len(es[0].Key)-len(TruncMarker):] != TruncMarker {
		t.Fatalf("no marker: %q", es[0].Key)
	}
	// A multi-byte character at the cut is never split.
	k := truncKey(string(make([]byte, 124)) + "äöü")
	if len(k) > MaxTopKeyBytes || k[len(k)-len(TruncMarker):] != TruncMarker {
		t.Fatalf("%q", k)
	}
	if n := testing.AllocsPerRun(100, func() { tt.add(long, "", 1, 0, 0, 0, 0) }); n != 0 {
		t.Fatalf("counting a known long key allocates %.0f times", n)
	}
}
