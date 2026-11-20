package caddymod

import (
	"encoding/json"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	hc "github.com/deutschland-schild/schild/contract/hostcheck"
	"github.com/deutschland-schild/schild/contract/storage"
)

// Log outputs with roll_disabled (D38, contracts/storage-bounds.md
// section 6). Caddy's `output file <path> { roll_disabled }` leaves the
// rotation to logrotate. The embedded Caddy never reopens the file, so a
// rule that moves it (the logrotate default "create") makes Caddy write
// into the rotated file forever. The rule needs copytruncate.

// LogrotateRotate and LogrotateMaxSizeMB are the numbers of the suggested
// rule (14 days, at most 200 MB per file before the daily run).
const (
	LogrotateRotate    = 14
	LogrotateMaxSizeMB = 200
)

// LogRollDisabled returns the file names of every log writer of the adapted
// Caddy config that writes to a file with rolling disabled, sorted and
// without duplicates.
func LogRollDisabled(cfgJSON []byte) []string {
	var cfg struct {
		Logging struct {
			Logs map[string]struct {
				Writer struct {
					Output   string `json:"output"`
					Filename string `json:"filename"`
					Roll     *bool  `json:"roll"`
				} `json:"writer"`
			} `json:"logs"`
		} `json:"logging"`
	}
	if json.Unmarshal(cfgJSON, &cfg) != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, l := range cfg.Logging.Logs {
		w := l.Writer
		if w.Output != "file" || w.Roll == nil || *w.Roll || w.Filename == "" || seen[w.Filename] {
			continue
		}
		seen[w.Filename] = true
		out = append(out, w.Filename)
	}
	sort.Strings(out)
	return out
}

// LogRollWarning is the validator warning for one such output, printed as
// "<code>: <message>" (storage.WarnLogRollDisabled).
func LogRollWarning(path string) string {
	return storage.WarnLogRollDisabled + ": output file " + path +
		" uses roll_disabled; the embedded Caddy does not reopen it, so the logrotate rule needs copytruncate (schild check: logs.logrotate_config)"
}

var slugUnsafe = regexp.MustCompile(`[^a-z0-9]+`)

// LogrotateSuggestion renders the logrotate rule for path from the host
// check template of logs.logrotate_config (contract/hostcheck), so the
// suggestion is exactly what the server check proposes as fix_config.
func LogrotateSuggestion(path string) hc.FixConfig {
	base := strings.TrimSuffix(strings.ToLower(filepath.Base(path)), ".log")
	slug := strings.Trim(slugUnsafe.ReplaceAllString("caddy-"+base, "-"), "-")
	if len(slug) > 48 {
		slug = strings.TrimRight(slug[:48], "-")
	}
	t := hc.FixTemplates["logs.logrotate_config"][0]
	return hc.RenderFix(t, map[string]string{
		"slug":        slug,
		"file":        path,
		"rotate":      strconv.Itoa(LogrotateRotate),
		"max_size_mb": strconv.Itoa(LogrotateMaxSizeMB),
	})
}
