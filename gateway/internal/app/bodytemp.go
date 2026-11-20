package app

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/deutschland-schild/schild/contract/bodylimit"
	"github.com/deutschland-schild/schild/gateway/internal/memlimit"
)

// spoolScanEvery is how often the temp files of bodies are measured
// (contracts/body-limits.md section 6: never on a request path).
const spoolScanEvery = 10 * time.Second

// BodyTempDir is the temp space of request bodies under the data directory.
func BodyTempDir(dataDir string) string { return filepath.Join(dataDir, bodylimit.TempDir) }

// PrepareBodyTemp creates the temp space of bodies, removes what an earlier
// process left there and points TMPDIR at it (contracts/storage-bounds.md
// section 8). The content is visitor data, so nothing else may keep it.
//
// TMPDIR must be set before the first WAF instance: Coraza takes the place of
// its body buffers from os.TempDir when a WAF is built and ignores SecTmpDir,
// and it asks os.TempDir again for every multipart file.
func PrepareBodyTemp(dataDir string) (removed int, err error) {
	dir := BodyTempDir(dataDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return 0, fmt.Errorf("body temp space: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return 0, fmt.Errorf("body temp space: %w", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, fmt.Errorf("body temp space: %w", err)
	}
	for _, e := range entries {
		if !e.Type().IsRegular() || !isBodyTemp(e.Name()) {
			continue
		}
		if err := os.Remove(filepath.Join(dir, e.Name())); err != nil {
			return removed, fmt.Errorf("body temp space: %w", err)
		}
		removed++
	}
	if err := os.Setenv("TMPDIR", dir); err != nil {
		return removed, fmt.Errorf("body temp space: %w", err)
	}
	return removed, nil
}

func isBodyTemp(name string) bool {
	for _, p := range bodylimit.TempFilePrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// spoolBytes sums the sizes of the temp files of bodies in dir.
func spoolBytes(dir string) int64 {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	var n int64
	for _, e := range entries {
		if !isBodyTemp(e.Name()) {
			continue
		}
		if st, err := e.Info(); err == nil && st.Mode().IsRegular() {
			n += st.Size()
		}
	}
	return n
}

// spoolLoop keeps schild_body_spool_bytes current.
func (a *App) spoolLoop(ctx context.Context) {
	dir := BodyTempDir(a.dataDir)
	scan := func() { a.Metrics.BodySpoolBytes.Set(float64(spoolBytes(dir))) }
	scan()
	every(ctx, spoolScanEvery, scan)
}

// bodyMemory is the memory max_in_flight is derived from: the container limit
// or the machine, or GOMEMLIMIT when the operator set it (0: unknown).
func bodyMemory(m memlimit.Result) int64 {
	if m.Source == memlimit.SourceEnv {
		return m.Limit
	}
	return m.Total
}
