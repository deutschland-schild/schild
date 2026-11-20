// Command hostreport-check validates host report files written by
// `schild check` (MVP-11) independently of the code that wrote them: every
// file must pass the contract (schild.host_report/0.1: forbidden fields and
// content first, then the schema), must not carry any secret canary of the
// test lab, and is listed with its basic facts. Exit 1 on any problem, 2 on
// usage errors.
//
//	hostreport-check [-json] FILE|DIR ...
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/deutschland-schild/schild/contract/hostcheck"
	"github.com/deutschland-schild/schild/contract/verify"
	"github.com/deutschland-schild/schild/testlab/internal/hostcanary"
)

type result struct {
	File       string `json:"file"`
	OK         bool   `json:"ok"`
	Error      string `json:"error,omitempty"`
	Hostname   string `json:"hostname,omitempty"`
	Role       string `json:"role,omitempty"`
	AsRoot     bool   `json:"as_root"`
	Findings   int    `json:"findings"`
	Unreadable int    `json:"unreadable"`
	Inventory  int    `json:"inventory"`
	Bytes      int    `json:"bytes"`
}

func main() {
	jsonOut := flag.Bool("json", false, "print results as JSON")
	flag.Parse()
	if flag.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "usage: hostreport-check [-json] FILE|DIR ...")
		os.Exit(2)
	}
	var files []string
	for _, a := range flag.Args() {
		st, err := os.Stat(a)
		if err != nil {
			fmt.Fprintln(os.Stderr, "hostreport-check:", err)
			os.Exit(2)
		}
		if !st.IsDir() {
			files = append(files, a)
			continue
		}
		m, _ := filepath.Glob(filepath.Join(a, "*.json"))
		files = append(files, m...)
	}
	ok := len(files) > 0
	var res []result
	for _, f := range files {
		r := check(f)
		ok = ok && r.OK
		res = append(res, r)
	}
	if *jsonOut {
		b, _ := json.MarshalIndent(map[string]any{"ok": ok, "files": res}, "", "  ")
		fmt.Println(string(b))
	} else {
		for _, r := range res {
			mark := "OK  "
			if !r.OK {
				mark = "FAIL"
			}
			fmt.Printf("%s %s host=%s role=%s as_root=%v findings=%d unreadable=%d inventory=%d %s\n",
				mark, r.File, r.Hostname, r.Role, r.AsRoot, r.Findings, r.Unreadable, r.Inventory, r.Error)
		}
		if len(files) == 0 {
			fmt.Println("hostreport-check: no report files")
		}
	}
	if !ok {
		os.Exit(1)
	}
}

func check(path string) result {
	r := result{File: path}
	raw, err := os.ReadFile(path)
	if err != nil {
		r.Error = err.Error()
		return r
	}
	r.Bytes = len(raw)
	for _, s := range hostcanary.Secrets() {
		if bytes.Contains(raw, []byte(s)) {
			r.Error = "SECRET LEAK: carries the secret canary " + s
			return r
		}
	}
	if _, err := verify.Document(verify.DocHostReport, raw, &verify.Context{Now: time.Now()}); err != nil {
		r.Error = "contract: " + err.Error()
		return r
	}
	var rep hostcheck.Report
	if err := json.Unmarshal(raw, &rep); err != nil {
		r.Error = err.Error()
		return r
	}
	r.Hostname, r.Role, r.AsRoot, r.Findings, r.Inventory = rep.Host.Hostname, rep.Host.Role, rep.Run.AsRoot, len(rep.Findings), len(rep.Inventory)
	for _, f := range rep.Findings {
		if f.Status == "unreadable" {
			r.Unreadable++
		}
	}
	// host-check.md: file name <started_at>-<report_id>.json
	if !strings.HasSuffix(filepath.Base(path), rep.ReportID+".json") {
		r.Error = "file name does not end in <report_id>.json"
		return r
	}
	r.OK = true
	return r
}
