package hostcheck

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/deutschland-schild/schild/contract"
	hc "github.com/deutschland-schild/schild/contract/hostcheck"
	"github.com/deutschland-schild/schild/contract/jsonx"
	"github.com/deutschland-schild/schild/contract/verify"
)

// DefaultReportDir is host_check.report_dir's default.
const DefaultReportDir = "/var/lib/schild/host-check"

// reportFileRe matches <started_at>-<report_id>.json (host-check.md 1).
var reportFileRe = regexp.MustCompile(`^20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\.json$`)

// FileName returns the file name of a report.
func FileName(r *hc.Report) string { return r.Run.StartedAt + "-" + r.ReportID + ".json" }

// WriteReport writes a marshalled report atomically (temp file, fsync,
// rename) with mode 0640 into dir and keeps the newest keep reports. It
// writes nothing outside dir.
func WriteReport(dir string, r *hc.Report, body []byte, keep int) (string, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", err
	}
	name := FileName(r)
	if !reportFileRe.MatchString(name) {
		return "", fmt.Errorf("hostcheck: bad report file name %q", name)
	}
	f, err := os.CreateTemp(dir, ".tmp-report-*")
	if err != nil {
		return "", err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err := f.Chmod(0o640); err != nil {
		f.Close()
		return "", err
	}
	if _, err := f.Write(body); err != nil {
		f.Close()
		return "", err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	final := filepath.Join(dir, name)
	if err := os.Rename(tmp, final); err != nil {
		return "", err
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		d.Close()
	}
	if keep > 0 {
		if err := Prune(dir, keep); err != nil {
			return final, err
		}
	}
	return final, nil
}

// List returns the report files in dir, newest first. Other files are
// ignored.
func List(dir string) ([]string, error) {
	es, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range es {
		if e.Type().IsRegular() && reportFileRe.MatchString(e.Name()) {
			out = append(out, e.Name())
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(out)))
	return out, nil
}

// Prune deletes all but the newest keep reports (and stale temp files).
func Prune(dir string, keep int) error {
	names, err := List(dir)
	if err != nil {
		return err
	}
	var errs []error
	if len(names) > keep {
		for _, n := range names[keep:] {
			if err := os.Remove(filepath.Join(dir, n)); err != nil && !errors.Is(err, os.ErrNotExist) {
				errs = append(errs, err)
			}
		}
	}
	es, _ := os.ReadDir(dir)
	for _, e := range es {
		if strings.HasPrefix(e.Name(), ".tmp-report-") {
			if info, err := e.Info(); err == nil && info.ModTime().Before(nowFunc().Add(-ageStaleTemp)) {
				_ = os.Remove(filepath.Join(dir, e.Name()))
			}
		}
	}
	return errors.Join(errs...)
}

// ReadReport reads and verifies one report file (size limit, forbidden
// content, schema). The raw bytes are returned unchanged.
func ReadReport(path string) ([]byte, *hc.Report, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, contract.MaxHostReportBytes+1))
	if err != nil {
		return nil, nil, err
	}
	r, err := ParseReport(b)
	return b, r, err
}

// Latest returns the newest valid kept report in dir, or nil (the
// previous report for growth per day in area logs).
func Latest(dir string) *hc.Report {
	names, err := List(dir)
	if err != nil {
		return nil
	}
	for i, n := range names {
		if i >= 3 {
			break
		}
		if _, r, err := ReadReport(filepath.Join(dir, n)); err == nil {
			return r
		}
	}
	return nil
}

// ParseReport verifies report bytes against the contract and decodes them.
func ParseReport(b []byte) (*hc.Report, error) {
	v, err := verify.Document(verify.DocHostReport, b, &verify.Context{})
	if err != nil {
		return nil, err
	}
	var r hc.Report
	if err := jsonx.Decode(v, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

const ageStaleTemp = 10 * time.Minute

var nowFunc = time.Now
