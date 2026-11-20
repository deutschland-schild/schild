package diskbudget

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/config"
	"github.com/deutschland-schild/schild/contract/storage"
	"github.com/deutschland-schild/schild/gateway/internal/monitoring"
)

const (
	mib = int64(1) << 20
	gib = int64(1) << 30
)

func fakeFS(t *testing.T, total, avail int64) *[]string {
	t.Helper()
	var seen []string
	prev := statfsFn
	statfsFn = func(p string) (int64, int64, error) { seen = append(seen, p); return total, avail, nil }
	t.Cleanup(func() { statfsFn = prev })
	return &seen
}

func site(maxSizeMB int, monitoringOn, requestsOn bool) *config.Site {
	on, req := monitoringOn, requestsOn
	return &config.Site{Retention: config.Retention{MaxSizeMB: maxSizeMB},
		Monitoring: config.Monitoring{Enabled: &on, Requests: config.Requests{Enabled: &req, MaxSizeMB: 512}}}
}

func TestBudgetSum(t *testing.T) {
	in := Input(site(100, true, true), 1)
	if want := monitoring.MetricsBoundBytes(monitoring.RingsFor(config.MonitoringKeep{}), 1); in.MetricsBoundBytes != want || want == 0 {
		t.Errorf("metrics bound %d, want %d", in.MetricsBoundBytes, want)
	}
	if in.RequestsMaxSizeMB != 512 || in.MaxSizeMB != 100 {
		t.Errorf("%+v", in)
	}
	// Request ring off: 0. Monitoring off: both 0 (the ring needs monitoring).
	cfg := site(100, true, true)
	cfg.WAF.Body.MaxInFlightBytes = 4 << 30
	if in := Input(cfg, 1); in.BodySpoolBytes != 4<<30 {
		t.Fatalf("body temp space not in the budget: %d", in.BodySpoolBytes)
	}
	if in := Input(site(100, true, false), 1); in.RequestsMaxSizeMB != 0 || in.MetricsBoundBytes == 0 {
		t.Errorf("ring off: %+v", in)
	}
	if in := Input(site(100, false, true), 1); in.RequestsMaxSizeMB != 0 || in.MetricsBoundBytes != 0 {
		t.Errorf("monitoring off: %+v", in)
	}
	// budget = cap + cap/10 + 2 x 64 MiB + metrics bound + ring.
	r := storage.Budget(in)
	if want := 100*mib + 10*mib + 128*mib + in.MetricsBoundBytes + 512*mib; r.BudgetBytes != want {
		t.Errorf("budget %d, want %d", r.BudgetBytes, want)
	}
}

func TestBudgetRefusesOversizedCap(t *testing.T) {
	// The audit's example: max_size_mb 100000 on a 20 GB disk.
	fakeFS(t, 20_000_000_000, 15_000_000_000)
	f, err := Check(site(100000, true, true), t.TempDir(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if f.Verdict != storage.BudgetError {
		t.Fatalf("%+v", f)
	}
	var ce *contract.Error
	if err := f.Err(); !errors.As(err, &ce) || ce.Code != contract.CodeConfig || ce.Pointer != "/retention/max_size_mb" {
		t.Fatalf("err %v", err)
	}
}

func TestBudgetHintAndOK(t *testing.T) {
	dir := t.TempDir()
	// 300 MiB already used by the bounded files.
	for _, f := range []string{"schild.db", "metrics.db-wal"} {
		if err := os.WriteFile(filepath.Join(dir, f), make([]byte, 150*mib), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "other.log"), make([]byte, mib), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := UsedBytes(dir); got != 300*mib {
		t.Fatalf("used %d", got)
	}
	// 10 GB cap on a 20 GiB disk with 9 GiB available: the remaining
	// growth leaves less than the 1 GiB reserve.
	fakeFS(t, 20*gib, 9*gib)
	f, err := Check(site(10000, true, true), dir, 1)
	if err != nil || f.Verdict != storage.BudgetHint || f.Err() != nil {
		t.Fatalf("%+v %v", f, err)
	}
	h := f.Hint()
	if !h.Active || h.Path != dir || h.Threshold != float64(gib) || h.Value != float64(9*gib-f.NeedBytes) || f.NeedBytes != f.BudgetBytes-300*mib {
		t.Errorf("hint %+v figures %+v", h, f)
	}
	// Default cap on the same disk: ok.
	f, _ = Check(site(100, true, true), dir, 1)
	if f.Verdict != storage.BudgetOK || f.Hint().Active || f.Err() != nil {
		t.Errorf("%+v", f)
	}
}

// D38 amendment 2026-10-29: the reserve is capped at 20 GiB. On a 2 TiB
// disk 5 % would be about 102 GiB; with 50 GiB available and a default
// budget the hint stays off, and its threshold is 20 GiB once it is on.
func TestBudgetReserveCappedOnLargeDisk(t *testing.T) {
	if storage.Reserve(2<<40) != 20*gib || storage.Reserve(20*gib) != gib || storage.Reserve(100*gib) != 5*gib {
		t.Fatalf("reserve: %d %d %d", storage.Reserve(2<<40), storage.Reserve(20*gib), storage.Reserve(100*gib))
	}
	dir := t.TempDir()
	fakeFS(t, 2<<40, 50*gib)
	f, err := Check(site(100, true, true), dir, 1)
	if err != nil || f.Verdict != storage.BudgetOK || f.ReserveBytes != 20*gib || f.Hint().Active {
		t.Fatalf("50 GiB available on 2 TiB: %+v %v", f, err)
	}
	fakeFS(t, 2<<40, 20*gib+f.NeedBytes/2)
	f, err = Check(site(100, true, true), dir, 1)
	if h := f.Hint(); err != nil || f.Verdict != storage.BudgetHint || !h.Active || h.Threshold != float64(20*gib) {
		t.Fatalf("just over the reserve: %+v %+v %v", f, h, err)
	}
}

func TestBudgetBeforeFirstStart(t *testing.T) {
	// storage.path does not exist yet: the file system of its parent.
	base := t.TempDir()
	seen := fakeFS(t, 100*gib, 50*gib)
	f, err := Check(site(100, true, true), filepath.Join(base, "a", "b"), 0)
	if err != nil || f.Verdict != storage.BudgetOK || f.UsedBytes != 0 {
		t.Fatalf("%+v %v", f, err)
	}
	if len(*seen) != 1 || (*seen)[0] != base {
		t.Errorf("statfs of %v, want %s", *seen, base)
	}
}

func TestStatfsReal(t *testing.T) {
	total, avail, err := statfs(t.TempDir())
	if err != nil || total <= 0 || avail < 0 || avail > total {
		t.Errorf("total %d avail %d err %v", total, avail, err)
	}
}
