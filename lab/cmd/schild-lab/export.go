package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/deutschland-schild/schild/contract/config"
	"github.com/deutschland-schild/schild/lab/internal/d2export"
	"github.com/deutschland-schild/schild/lab/internal/store"
)

// exportCmd: schild-lab export d2 | d2-merge (D2, runbook 13.2).
//
//	schild-lab export d2 [-config lab.yaml] [-from DAY] [-to DAY] [-min-score N] [-url URL | -data DIR] [-out FILE]
//	schild-lab export d2-merge [-out FILE] FILE ...
//
// Without -data the export is fetched from the running lab's local metrics
// listener (GET /export/d2; the store file is locked while the lab runs).
// -data reads a stopped lab's data directory or a restored backup.
func exportCmd(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("export: d2 or d2-merge")
	}
	switch args[0] {
	case "d2":
		return exportD2(args[1:], stdout, stderr)
	case "d2-merge":
		return exportD2Merge(args[1:], stdout, stderr)
	}
	return fmt.Errorf("export: unknown export %q (d2, d2-merge)", args[0])
}

func writeExport(ex *d2export.Export, out string, stdout, stderr io.Writer) error {
	w := stdout
	if out != "" && out != "-" {
		f, err := os.OpenFile(out, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		defer f.Close()
		w = f
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(ex); err != nil {
		return err
	}
	s := ex.Summary
	fmt.Fprintf(stderr, "d2 %s..%s labs %v: %d sites, %d patterns, %d on 2+ sites (%.1f %%), lag median %.0f s (p25 %.0f, p75 %.0f, n=%d)\n",
		ex.From, ex.To, ex.Labs, s.Sites, s.Patterns, s.PatternsMultiSite, s.ShareMultiSite*100, s.LagMedianS, s.LagP25S, s.LagP75S, s.Lags)
	return nil
}

func exportD2(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("export d2", flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := fs.String("config", "", "lab.yaml path (default $SCHILD_LAB_CONFIG or /etc/schild-lab/lab.yaml)")
	from := fs.String("from", "", "start day (UTC, inclusive; default to - 7 days)")
	to := fs.String("to", "", "end day (UTC, exclusive; default now)")
	minScore := fs.Int("min-score", -1, "only signals with score >= N (default: scoring.min_score of lab.yaml)")
	rawURL := fs.String("url", "", "metrics listener of the running lab (default http://<listen.metrics>)")
	data := fs.String("data", "", "read this data directory directly (lab stopped, or a restored backup)")
	out := fs.String("out", "", "write the JSON here (default stdout)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.LoadLab(*path)
	if err != nil {
		return err
	}
	ms := *minScore
	if ms < 0 {
		ms = 40
		if cfg.Scoring.MinScore != nil {
			ms = *cfg.Scoring.MinScore
		}
	}
	if *data != "" {
		now := time.Now().UTC()
		o := d2export.Options{To: now, MinScore: ms, Lab: cfg.Identity.Lab}
		if *to != "" {
			if o.To, err = d2export.ParseDay(*to); err != nil {
				return err
			}
		}
		o.From = o.To.Add(-7 * 24 * time.Hour)
		if *from != "" {
			if o.From, err = d2export.ParseDay(*from); err != nil {
				return err
			}
		}
		db, err := store.Open(filepath.Join(*data, "store.db"))
		if err != nil {
			return fmt.Errorf("%w (is the lab still running? then leave out -data)", err)
		}
		defer db.Close()
		ex, err := d2export.Build(db, o, now)
		if err != nil {
			return err
		}
		return writeExport(ex, *out, stdout, stderr)
	}
	base := *rawURL
	if base == "" {
		host := cfg.Listen.Metrics
		if strings.HasPrefix(host, "0.0.0.0:") || strings.HasPrefix(host, ":") {
			host = "127.0.0.1:" + host[strings.LastIndex(host, ":")+1:]
		}
		base = "http://" + host
	}
	q := url.Values{}
	if *from != "" {
		q.Set("from", *from)
	}
	if *to != "" {
		q.Set("to", *to)
	}
	q.Set("min_score", strconv.Itoa(ms))
	c := &http.Client{Timeout: 60 * time.Second}
	resp, err := c.Get(strings.TrimRight(base, "/") + "/export/d2?" + q.Encode())
	if err != nil {
		return fmt.Errorf("%w (lab not running? use -data DIR)", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 256<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("export d2: %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	var ex d2export.Export
	if err := json.Unmarshal(body, &ex); err != nil {
		return err
	}
	return writeExport(&ex, *out, stdout, stderr)
}

func exportD2Merge(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("export d2-merge", flag.ContinueOnError)
	fs.SetOutput(stderr)
	out := fs.String("out", "", "write the JSON here (default stdout)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() == 0 {
		return errors.New("export d2-merge: FILE ... (exports of schild-lab export d2)")
	}
	var exs []*d2export.Export
	for _, p := range fs.Args() {
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		var ex d2export.Export
		if err := json.Unmarshal(b, &ex); err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
		exs = append(exs, &ex)
	}
	m, err := d2export.Merge(exs)
	if err != nil {
		return err
	}
	return writeExport(m, *out, stdout, stderr)
}
