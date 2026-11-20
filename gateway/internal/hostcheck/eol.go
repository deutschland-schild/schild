package hostcheck

import (
	_ "embed"
	"encoding/json"
	"strings"
	"sync"
	"time"
)

// The bundled, dated EOL table (offline: the check never looks anything up).
//
//go:embed eol.json
var eolJSON []byte

// EOLTable is the parsed eol.json.
type EOLTable struct {
	Date     string     `json:"date"`
	Source   string     `json:"source"`
	OS       []OSEOL    `json:"os"`
	Software []CycleEOL `json:"software"`
}

// OSEOL is one distribution release.
type OSEOL struct {
	ID           string `json:"id"`
	Version      string `json:"version"`
	EOL          string `json:"eol"`
	Extended     string `json:"extended,omitempty"`
	ExtendedName string `json:"extended_name,omitempty"`
	Paid         bool   `json:"paid,omitempty"`
	Approx       bool   `json:"approx,omitempty"`
}

// CycleEOL is one release cycle of a runtime, database or app.
type CycleEOL struct {
	Name   string `json:"name"`
	Cycle  string `json:"cycle"`
	EOL    string `json:"eol"`
	Approx bool   `json:"approx,omitempty"`
}

var (
	tableOnce sync.Once
	table     *EOLTable
)

// Table returns the bundled EOL table.
func Table() *EOLTable {
	tableOnce.Do(func() {
		table = &EOLTable{}
		if err := json.Unmarshal(eolJSON, table); err != nil {
			panic("hostcheck: eol.json: " + err.Error())
		}
	})
	return table
}

// rhelLike are distributions that follow the RHEL major version.
var rhelLike = map[string]bool{"rhel": true, "rocky": true, "almalinux": true, "ol": true, "centos": true}

// LookupOS finds the release of a distribution. RHEL-like systems match by
// major version, Alpine by major.minor, others exactly.
func (t *EOLTable) LookupOS(id, versionID, prettyName string) *OSEOL {
	v := versionID
	if rhelLike[id] {
		v, _, _ = strings.Cut(versionID, ".")
		if id == "centos" && strings.Contains(strings.ToLower(prettyName), "stream") {
			id = "centos-stream"
		}
	}
	if id == "alpine" {
		parts := strings.Split(versionID, ".")
		if len(parts) >= 2 {
			v = parts[0] + "." + parts[1]
		}
	}
	for i := range t.OS {
		if t.OS[i].ID == id && t.OS[i].Version == v {
			return &t.OS[i]
		}
	}
	return nil
}

// LookupCycle finds the EOL date of name at cycle ("" when unknown).
func (t *EOLTable) LookupCycle(name, cycle string) string {
	for _, c := range t.Software {
		if c.Name == name && c.Cycle == cycle {
			return c.EOL
		}
	}
	return ""
}

func parseDate(s string) time.Time {
	d, _ := time.Parse("2006-01-02", s)
	return d
}

// past reports whether the date s (YYYY-MM-DD) lies before now.
func past(s string, now time.Time) bool {
	return s != "" && parseDate(s).Before(now)
}
