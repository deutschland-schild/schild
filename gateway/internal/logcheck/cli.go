package logcheck

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// LimitsLoader reads the limits from a schild.yaml.
type LimitsLoader func(path string) (Limits, error)

const usageText = `schild logcheck - which requests would schild's hard limits reject (also in observe mode)?

Usage:
  schild logcheck [flags] [SITE=]FILE ...     (no FILE or "-": read stdin)

FILE may be gzip-compressed (*.gz). SITE names the site in the report; default:
the file name without .log/.gz (or the logged host with -by-host).

Flags:
`

// Main runs the logcheck command.
func Main(args []string, stdin io.Reader, stdout, stderr io.Writer, load LimitsLoader) error {
	fs := flag.NewFlagSet("logcheck", flag.ContinueOnError)
	fs.SetOutput(stderr)
	format := fs.String("format", "auto", "log format: "+strings.Join(Formats, ", "))
	cfgPath := fs.String("config", "", "schild.yaml to read waf.request_body_limit_bytes and waf.eval_timeout_ms from (default: $SCHILD_CONFIG or /etc/schild/schild.yaml if present, else the client defaults)")
	bodyLimit := fs.Int64("body-limit", 0, "override waf.request_body_limit_bytes")
	evalTimeout := fs.Int("eval-timeout-ms", 0, "override waf.eval_timeout_ms")
	siteName := fs.String("site", "", "site name for stdin and files without SITE=")
	byHost := fs.Bool("by-host", false, "group by the logged Host (Caddy, nginx-json with host) instead of by file")
	asJSON := fs.Bool("json", false, "JSON output")
	showIPs := fs.Bool("show-ips", false, "include client IPs in the examples (local use only, never share the output)")
	examples := fs.Int("examples", 5, "example paths per check")
	fs.Usage = func() {
		fmt.Fprint(stderr, usageText)
		fs.PrintDefaults()
	}
	// Flags may follow the files (schild logcheck shop.log -json).
	var inputs []string
	for {
		if err := fs.Parse(args); err != nil {
			return err
		}
		if fs.NArg() == 0 {
			break
		}
		inputs = append(inputs, fs.Arg(0))
		args = fs.Args()[1:]
	}
	lim := DefaultLimits()
	path := *cfgPath
	explicit := path != ""
	if path == "" {
		path = os.Getenv("SCHILD_CONFIG")
		explicit = path != ""
	}
	if path == "" {
		if _, err := os.Stat("/etc/schild/schild.yaml"); err == nil {
			path = "/etc/schild/schild.yaml"
		}
	}
	if path != "" && load != nil {
		l, err := load(path)
		switch {
		case err == nil:
			lim = l
			lim.Source = path
		case explicit:
			return fmt.Errorf("logcheck: %w", err)
		default:
			fmt.Fprintf(stderr, "logcheck: %s not usable (%v), using the client defaults\n", path, err)
		}
	}
	if *bodyLimit > 0 {
		lim.BodyBytes, lim.Source = *bodyLimit, lim.Source+" + -body-limit"
	}
	if *evalTimeout > 0 {
		lim.EvalTimeoutMS, lim.Source = *evalTimeout, lim.Source+" + -eval-timeout-ms"
	}
	if lim.BodyBytes > MaxBodyLimit {
		return fmt.Errorf("logcheck: body limit %d above the schema maximum %d", lim.BodyBytes, MaxBodyLimit)
	}
	if _, err := Parse("x", *format); err != nil && strings.HasPrefix(err.Error(), "unknown format") {
		return fmt.Errorf("logcheck: %w", err)
	}
	an := New(Options{Limits: lim, ShowIPs: *showIPs, Examples: *examples})
	if len(inputs) == 0 {
		inputs = []string{"-"}
	}
	for _, in := range inputs {
		name, file, ok := strings.Cut(in, "=")
		if !ok {
			name, file = "", in
		}
		if name == "" {
			name = *siteName
		}
		if name == "" {
			if file == "-" {
				name = "stdin"
			} else {
				name = strings.TrimSuffix(strings.TrimSuffix(filepath.Base(file), ".gz"), ".log")
			}
		}
		if err := readInput(an, name, file, *format, *byHost, stdin); err != nil {
			return err
		}
	}
	rep := an.Report(time.Now())
	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(rep)
	}
	return WriteText(stdout, rep)
}

func readInput(an *Analyzer, site, file, format string, byHost bool, stdin io.Reader) error {
	r := stdin
	if file != "-" {
		f, err := os.Open(file)
		if err != nil {
			return fmt.Errorf("logcheck: %w", err)
		}
		defer f.Close()
		r = f
	}
	br := bufio.NewReaderSize(r, 64<<10)
	if magic, err := br.Peek(2); err == nil && magic[0] == 0x1f && magic[1] == 0x8b {
		zr, err := gzip.NewReader(br)
		if err != nil {
			return fmt.Errorf("logcheck: %s: %w", file, err)
		}
		defer zr.Close()
		br = bufio.NewReaderSize(zr, 64<<10)
	}
	sc := bufio.NewScanner(br)
	// Long query strings are the point of this tool: allow lines up to 16 MiB.
	sc.Buffer(make([]byte, 0, 256<<10), 16<<20)
	for sc.Scan() {
		line := sc.Text()
		name := site
		if byHost {
			if rec, err := Parse(line, format); err == nil && rec.Host != "" {
				name = strings.ToLower(rec.Host)
			}
		}
		if err := an.Line(name, format, line); err != nil && !errors.Is(err, ErrSkip) {
			continue
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("logcheck: %s: %w", file, err)
	}
	return nil
}
