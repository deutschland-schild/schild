// Command egress-check verifies that nothing forbidden left a schild server.
// It reads the client's transparency log (schild.signal.sent.v1 events) and
// scans every outgoing payload for canary values, IP-address-like tokens and
// fields outside the signal positive list. Any finding exits non-zero.
//
// This is the "signal log cross-check" path of T19; it needs no TLS keys and
// no pcap, so it runs in CI. D72: the first gateway version sends no signals
// and writes no transparency log, so the log mode has no gateway input today;
// it stays for the signal contract (lab later). -scan-dirs is in use.
//
// -scan-dirs (MVP-11) additionally walks stored data, for example every lab's
// data volume, and fails on any canary value in any file (host report
// canaries: a host report must never reach a lab). With -scan-dirs and no
// -log, the transparency log is not read.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/deutschland-schild/schild/testlab/internal/egress"
)

func main() {
	var (
		logPath  = flag.String("log", "", "NDJSON transparency log (default: stdin)")
		canaries = flag.String("canaries", "", "comma-separated canary values")
		ips      = flag.String("forbidden-ips", "", "comma-separated forbidden source IPs")
		jsonOut  = flag.Bool("json", false, "print the full report as JSON")
		scanDirs = flag.String("scan-dirs", "", "comma-separated directories to scan for -canaries (every file, raw bytes)")
	)
	flag.Parse()

	if *scanDirs != "" {
		if len(split(*canaries)) == 0 {
			fmt.Fprintln(os.Stderr, "egress-check: -scan-dirs needs -canaries")
			os.Exit(2)
		}
		tree, err := egress.ScanTree(split(*scanDirs), split(*canaries))
		if err != nil {
			fmt.Fprintf(os.Stderr, "egress-check: %v\n", err)
			os.Exit(2)
		}
		if *jsonOut {
			b, _ := json.MarshalIndent(tree, "", "  ")
			fmt.Println(string(b))
		} else {
			fmt.Printf("egress-check: scanned %d files (%d bytes) in %d dirs for %d canaries: %d findings\n",
				tree.Files, tree.Bytes, len(tree.Roots), tree.Canaries, len(tree.Findings))
			for _, f := range tree.Findings {
				fmt.Printf("  FINDING %s: %s (%s)\n", f.Kind, f.Detail, f.Location)
			}
		}
		if !tree.OK() || tree.Files == 0 {
			if tree.Files == 0 {
				fmt.Fprintln(os.Stderr, "egress-check: no files scanned (wrong mount?)")
			}
			os.Exit(1)
		}
		if *logPath == "" {
			return
		}
	}

	in := os.Stdin
	if *logPath != "" {
		f, err := os.Open(*logPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "egress-check: %v\n", err)
			os.Exit(2)
		}
		defer f.Close()
		in = f
	}

	ck := egress.New(split(*canaries), split(*ips))
	rep, err := ck.CheckLog(in)
	if err != nil {
		fmt.Fprintf(os.Stderr, "egress-check: %v\n", err)
		os.Exit(2)
	}

	if *jsonOut {
		b, _ := json.MarshalIndent(rep, "", "  ")
		fmt.Println(string(b))
	} else {
		fmt.Printf("egress-check: signals=%d canary=%d ip=%d field=%d\n",
			rep.Signals, rep.CanaryFindings, rep.IPFindings, rep.FieldFindings)
		for _, f := range rep.Findings {
			fmt.Printf("  FINDING %s: %s (%s)\n", f.Kind, f.Detail, f.Location)
		}
	}
	if !rep.OK() {
		os.Exit(1)
	}
}

func split(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
