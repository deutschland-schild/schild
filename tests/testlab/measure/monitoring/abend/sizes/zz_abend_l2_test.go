//go:build d36measure

// Evening measurement 2026-10-29, item C, optional (TEST ONLY): a metrics.db
// written by layout 2 (commit 54a878a^) is converted at the first start of
// layout 3 (54a878a and later). Needs zz_abend_size_test.go next to it.
//
//	# in a copy of 54a878a^ gateway/internal/monitoring:
//	D36N_W=4 D36N_DIR=/tmp/l2 D36N_HOURS=3 go test -tags d36measure -run TestAbendL2Write -v ./internal/monitoring/
//	# in a copy of the commit under test:
//	D36N_W=4 D36N_DIR=/tmp/l2 go test -tags d36measure -run TestAbendL2Read -v ./internal/monitoring/
//	diff /tmp/l2/before.json /tmp/l2/after.json
package monitoring

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/contract/config"
	cm "github.com/deutschland-schild/schild/contract/monitoring"
)

func abendL2Dump(t *testing.T, m *Monitor, hosts []string, end time.Time, hours int) map[string]any {
	from := end.Add(-time.Duration(hours) * time.Hour)
	out := map[string]any{}
	for _, site := range []string{"", hosts[0]} {
		for _, by := range cm.Dimensions {
			b, err := m.Breakdown(by, from, end, site, nil, 20, end)
			if err != nil {
				t.Fatal(err)
			}
			out["breakdown "+by+" "+site] = b
		}
		metrics := series16
		if site != "" {
			metrics = d36nSiteSeries
		}
		for _, res := range []string{"1m", "10m"} {
			s, err := m.Series(SeriesQuery{Metrics: metrics, From: from, To: end, Resolution: res, Site: site}, end)
			if err != nil {
				t.Fatal(err)
			}
			out["series "+res+" "+site] = s
		}
		k, err := m.Kpis(site, from, end, nil, end)
		if err != nil {
			t.Fatal(err)
		}
		out["kpis "+site] = k
	}
	return out
}

func abendKeep() config.MonitoringKeep {
	return config.MonitoringKeep{TenSecondsHours: config.DefaultKeepTenSecondsHours, MinuteHours: config.DefaultKeepMinuteHours, TenMinuteDays: config.DefaultKeepTenMinuteDays}
}

func TestAbendL2Write(t *testing.T) {
	w, _ := strconv.Atoi(d36nEnv("D36N_W", "4"))
	hours, _ := strconv.Atoi(d36nEnv("D36N_HOURS", "3"))
	dir := os.Getenv("D36N_DIR")
	end := time.Now().UTC().Truncate(10 * time.Minute)
	r := d36nSimulate(t, dir, w, end.Add(-time.Duration(hours)*time.Hour), end, nil)
	d := abendL2Dump(t, r.m, r.hosts, end, hours)
	_ = r.m.Close()
	b, _ := json.MarshalIndent(d, "", " ")
	_ = os.WriteFile(filepath.Join(dir, "before.json"), b, 0o644)
	_ = os.WriteFile(filepath.Join(dir, "end.txt"), []byte(end.Format(time.RFC3339)+" "+strconv.Itoa(hours)), 0o644)
	fmt.Printf("ABENDL2 wrote layout-2 file end=%s hours=%d\n", end.Format(time.RFC3339), hours)
}

func TestAbendL2Read(t *testing.T) {
	w, _ := strconv.Atoi(d36nEnv("D36N_W", "4"))
	dir := os.Getenv("D36N_DIR")
	raw, err := os.ReadFile(filepath.Join(dir, "end.txt"))
	if err != nil {
		t.Fatal(err)
	}
	var es string
	var hours int
	fmt.Sscanf(string(raw), "%s %d", &es, &hours)
	end, _ := time.Parse(time.RFC3339, es)
	reg, hosts := d36nRegistry(t, w)
	t0 := time.Now()
	m, err := New(Config{StoragePath: dir, Keep: abendKeep(), Sampler: SamplerConfig{Root: fixtureRoot(t), Linux: true, Host: true, Started: end, Version: "test"}, Sites: reg}, end)
	if err != nil {
		t.Fatal(err)
	}
	open := time.Since(t0)
	defer m.Close()
	rows := m.store.db.QueryRow
	var meta string
	_ = rows(`SELECT group_concat(k||'='||v, ' ') FROM meta WHERE k LIKE 'ring%'`).Scan(&meta)
	var parts int64
	_ = rows(`SELECT (SELECT COUNT(*) FROM ring_10s_part)+(SELECT COUNT(*) FROM ring_1m_part)+(SELECT COUNT(*) FROM ring_10m_part)`).Scan(&parts)
	d := abendL2Dump(t, m, hosts, end, hours)
	b, _ := json.MarshalIndent(d, "", " ")
	_ = os.WriteFile(filepath.Join(dir, "after.json"), b, 0o644)
	fmt.Printf("ABENDL2 opened in %s meta: %s part_rows=%d\n", open.Round(time.Millisecond), meta, parts)
}
