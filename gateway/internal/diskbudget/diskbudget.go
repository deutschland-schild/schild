// Package diskbudget is the disk budget of D38 (contracts/storage-bounds.md
// section 2): the sum of every bound schild keeps on storage.path, compared
// with the file system of storage.path and with what the bounded files use
// now. `schild preflight` and `schild run` refuse to start when the budget
// exceeds the file system (contract code config, /retention/max_size_mb);
// the running gateway raises the hint storage_budget when filling the
// bounds would eat the reserve.
package diskbudget

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/config"
	"github.com/deutschland-schild/schild/contract/storage"
	"github.com/deutschland-schild/schild/gateway/internal/monitoring"
	"github.com/deutschland-schild/schild/gateway/internal/reqring"
)

// Pointer is the JSON pointer of the refusal.
const Pointer = "/retention/max_size_mb"

// BoundedFiles are the files below storage.path whose bounds make up the
// budget (the event store and the metric rings with their WALs). The MVP-22
// request ring segments (storage.path/requests, reqring.Dir) count too.
var BoundedFiles = []string{"schild.db", "schild.db-wal", "metrics.db", "metrics.db-wal"}

// Figures is one budget check.
type Figures struct {
	Path              string `json:"path"`
	TotalBytes        int64  `json:"total_bytes"`
	AvailBytes        int64  `json:"avail_bytes"`
	UsedBytes         int64  `json:"used_bytes"`
	MetricsBoundBytes int64  `json:"metrics_bound_bytes"`
	RequestsMaxSizeMB int64  `json:"requests_max_size_mb"`
	BodySpoolBytes    int64  `json:"body_spool_bytes"`
	storage.BudgetResult
}

// Input returns the budget input of cfg without the file system figures:
// the metrics.db bound for the configured rings and websites (0 with
// monitoring off), the request ring cap (0 with the ring off) and the temp
// space of bodies (D41).
func Input(cfg *config.Site, websites int) storage.BudgetInput {
	in := storage.BudgetInput{MaxSizeMB: int64(cfg.Retention.MaxSizeMB), BodySpoolBytes: cfg.WAF.Body.MaxInFlightBytes}
	if cfg.Monitoring.On() {
		in.MetricsBoundBytes = monitoring.MetricsBoundBytes(monitoring.RingsFor(cfg.Monitoring.Keep), int64(websites))
	}
	if cfg.Monitoring.RequestsOn() {
		in.RequestsMaxSizeMB = int64(cfg.Monitoring.Requests.MaxSizeMB)
	}
	return in
}

// UsedBytes sums the sizes of the bounded files in dir (missing files count 0).
func UsedBytes(dir string) int64 {
	var n int64
	for _, f := range BoundedFiles {
		if st, err := os.Stat(filepath.Join(dir, f)); err == nil && st.Mode().IsRegular() {
			n += st.Size()
		}
	}
	return n + reqring.UsedBytes(dir)
}

// Check measures the file system of dataDir (or, before the first start,
// its nearest existing parent) and decides the budget.
func Check(cfg *config.Site, dataDir string, websites int) (Figures, error) {
	total, avail, err := fsOf(dataDir)
	if err != nil {
		return Figures{Path: dataDir}, err
	}
	in := Input(cfg, websites)
	in.FSTotalBytes, in.FSAvailBytes = total, avail
	in.SchildUsedBytes = UsedBytes(dataDir)
	return Figures{Path: dataDir, TotalBytes: total, AvailBytes: avail, UsedBytes: in.SchildUsedBytes,
		MetricsBoundBytes: in.MetricsBoundBytes, RequestsMaxSizeMB: in.RequestsMaxSizeMB, BodySpoolBytes: in.BodySpoolBytes, BudgetResult: storage.Budget(in)}, nil
}

// Err is the refusal: nil unless the budget exceeds the file system.
func (f Figures) Err() error {
	if f.Verdict != storage.BudgetError {
		return nil
	}
	return contract.Errf(contract.CodeConfig, "storage budget %s (retention.max_size_mb + 10 %% + 2 x 64 MiB WAL + metrics.db bound %s + request ring %d MiB + body temp space %s) exceeds the file system of %s (%s): lower retention.max_size_mb, monitoring.requests.max_size_mb or waf.body.max_in_flight_bytes",
		MiB(f.BudgetBytes), MiB(f.MetricsBoundBytes), f.RequestsMaxSizeMB, MiB(f.BodySpoolBytes), f.Path, MiB(f.TotalBytes)).WithPointer(Pointer)
}

// Hint is the storage_budget hint of these figures: value = what would stay
// available once the bounds filled, threshold = the reserve.
func (f Figures) Hint() monitoring.StorageBudget {
	return monitoring.StorageBudget{Active: f.Verdict == storage.BudgetHint, Path: f.Path,
		Value: float64(f.AvailBytes - f.NeedBytes), Threshold: float64(f.ReserveBytes)}
}

// MiB formats bytes as MiB with one decimal.
func MiB(b int64) string { return fmt.Sprintf("%.1f MiB", float64(b)/(1<<20)) }

// statfsFn is replaced in tests.
var statfsFn = statfs

// fsOf returns total = f_blocks * f_frsize and available = f_bavail *
// f_frsize of the file system that holds p or its nearest existing parent.
func fsOf(p string) (total, avail int64, err error) {
	p = filepath.Clean(p)
	for {
		if _, serr := os.Stat(p); serr == nil {
			return statfsFn(p)
		} else if !errors.Is(serr, os.ErrNotExist) {
			return 0, 0, serr
		}
		parent := filepath.Dir(p)
		if parent == p {
			return 0, 0, fmt.Errorf("storage budget: no existing directory above %s", p)
		}
		p = parent
	}
}
