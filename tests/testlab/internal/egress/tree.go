package egress

import (
	"bytes"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
)

// TreeReport is the result of scanning stored data (for example every file a
// lab wrote: queue, public log, bundles, SQLite databases) for canary values.
type TreeReport struct {
	Roots    []string  `json:"roots"`
	Files    int       `json:"files"`
	Bytes    int64     `json:"bytes"`
	Canaries int       `json:"canaries"`
	Findings []Finding `json:"findings"`
}

// OK reports whether no canary was found.
func (r TreeReport) OK() bool { return len(r.Findings) == 0 }

// treeChunk is the read size; overlap keeps canaries that straddle two reads.
const treeChunk = 1 << 20

// ScanTree walks every regular file below the roots and reports each canary
// found in a file's raw bytes. It reads files as they are on disk (SQLite
// pages, NDJSON, JSON), so a canary that a lab stored in any form shows up.
// Symlinks are not followed. Unreadable files are findings too: a scan that
// skipped data would prove nothing.
func ScanTree(roots, canaries []string) (TreeReport, error) {
	rep := TreeReport{Roots: roots}
	var needles [][]byte
	maxLen := 0
	for _, c := range canaries {
		if c == "" {
			continue
		}
		needles = append(needles, []byte(c))
		maxLen = max(maxLen, len(c))
	}
	rep.Canaries = len(needles)
	for _, root := range roots {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				rep.Findings = append(rep.Findings, Finding{Kind: "unreadable", Detail: err.Error(), Location: path})
				return nil
			}
			if !d.Type().IsRegular() {
				return nil
			}
			n, hits, err := scanFile(path, needles, maxLen)
			rep.Files++
			rep.Bytes += n
			if err != nil {
				rep.Findings = append(rep.Findings, Finding{Kind: "unreadable", Detail: err.Error(), Location: path})
			}
			for _, h := range hits {
				rep.Findings = append(rep.Findings, Finding{Kind: CanaryLeak, Detail: "canary value present: " + h, Location: path})
			}
			return nil
		})
		if err != nil {
			return rep, err
		}
	}
	sort.SliceStable(rep.Findings, func(i, j int) bool { return rep.Findings[i].Location < rep.Findings[j].Location })
	return rep, nil
}

func scanFile(path string, needles [][]byte, maxLen int) (int64, []string, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, nil, err
	}
	defer f.Close()
	found := map[string]bool{}
	buf := make([]byte, 0, treeChunk+maxLen)
	chunk := make([]byte, treeChunk)
	var total int64
	for {
		n, rerr := f.Read(chunk)
		total += int64(n)
		buf = append(buf, chunk[:n]...)
		for _, nd := range needles {
			if !found[string(nd)] && bytes.Contains(buf, nd) {
				found[string(nd)] = true
			}
		}
		// keep the tail so a canary split across two reads is still seen
		if keep := maxLen - 1; keep > 0 && len(buf) > keep {
			buf = append(buf[:0], buf[len(buf)-keep:]...)
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return total, sortedSet(found), rerr
		}
	}
	return total, sortedSet(found), nil
}

func sortedSet(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
