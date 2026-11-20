// Command traffic is the test-lab traffic generator. It builds a deterministic
// plan for a scenario (make traffic SCENARIO=T01 SEED=42) and either prints the
// labelled request counts (--count, the reproducibility check) or sends the
// requests to the test lab, attaching the secret ground-truth label header to
// every one. It targets only the test lab's own containers.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/deutschland-schild/schild/testlab/internal/label"
	"github.com/deutschland-schild/schild/testlab/traffic/internal/ftwcorpus"
	"github.com/deutschland-schild/schild/testlab/traffic/internal/plan"
	"github.com/deutschland-schild/schild/testlab/traffic/internal/req"
	"github.com/deutschland-schild/schild/testlab/traffic/internal/sources"
)

func main() {
	var (
		scenario    = flag.String("scenario", "T01", "scenario id: "+strings.Join(plan.Scenarios, ","))
		seed        = flag.Int64("seed", 42, "seed")
		n           = flag.Int("n", 0, "request count (0 = scenario default)")
		profile     = flag.String("profile", "t0", "t0|t1 (selects the inet source ranges)")
		targetsFile = flag.String("targets", "", "JSON file of targets ([]req.Target); default: $TRAFFIC_TARGETS or a dev default")
		count       = flag.Bool("count", false, "print labelled counts and exit (no requests sent)")
		planOut     = flag.String("plan-out", "", "write the full plan as JSON to this path")
		canaryOut   = flag.String("canary-out", "", "write planted canary markers (one per line) to this path")
		rps         = flag.Float64("rps", 50, "max requests per second when sending")
		timeout     = flag.Duration("timeout", 10*time.Second, "per-request timeout")
		resultsOut  = flag.String("results-out", "", "write a results/<spec>.json reproducibility result to this directory and exit")
		spec        = flag.String("spec", "MVP-06", "spec id for -results-out")
		emitLabel   = flag.Bool("emit-label", false, "print one signed label header value and exit (for external attack tools)")
		elClass     = flag.String("label-class", "malicious", "class for -emit-label")
		elSource    = flag.String("label-source", "external", "source for -emit-label")
		elScenario  = flag.String("label-scenario", "T02", "scenario for -emit-label")
		elTechnique = flag.String("label-technique", "", "technique for -emit-label")
		ftwRender   = flag.String("ftw-render", "", "go-ftw corpus dir to copy with a signed label on every request (see traffic/compose/ftw)")
		ftwOut      = flag.String("ftw-out", "", "output dir for -ftw-render")
	)
	flag.Parse()

	if *ftwRender != "" {
		if *ftwOut == "" {
			fatal("-ftw-render needs -ftw-out")
		}
		n, err := ftwcorpus.Render(*ftwRender, *ftwOut, []byte(os.Getenv(label.EnvSecret)), *elScenario)
		if err != nil {
			fatal("ftw-render: %v", err)
		}
		fmt.Printf("ftw-render: %d labelled requests -> %s\n", n, *ftwOut)
		return
	}

	if *emitLabel {
		secret := []byte(os.Getenv(label.EnvSecret))
		if len(secret) == 0 {
			fatal("missing %s", label.EnvSecret)
		}
		cls := label.Class(*elClass)
		hdr, err := label.Sign(secret, label.Label{
			Class: cls, Scenario: *elScenario, Source: *elSource,
			Technique: *elTechnique, ExpectBlock: label.ExpectedOutcome(cls),
		})
		if err != nil {
			fatal("emit-label: %v", err)
		}
		fmt.Println(hdr)
		return
	}

	targets, err := loadTargets(*targetsFile)
	if err != nil {
		fatal("targets: %v", err)
	}
	siteNames := make([]string, len(targets))
	for i, t := range targets {
		siteNames[i] = t.Name
	}

	opt := plan.Options{N: *n}
	if *profile == "t1" {
		opt.V4Base, opt.V6Prefix = sources.T1Inet, sources.T1Inet6
	} else {
		opt.V4Base, opt.V6Prefix = sources.T0Inet, sources.T0Inet6
	}

	p, err := plan.Build(*scenario, *seed, siteNames, opt)
	if err != nil {
		fatal("%v", err)
	}

	if *resultsOut != "" {
		os.Exit(emitResults(*spec, *resultsOut, *scenario, *seed, *profile, siteNames, opt))
	}

	if *planOut != "" {
		writeJSONFile(*planOut, p)
	}
	if *canaryOut != "" {
		writeLines(*canaryOut, p.Canaries)
	}

	fmt.Printf("traffic: scenario=%s seed=%d requests=%d canaries=%d counts: %s\n",
		p.Scenario, p.Seed, len(p.Requests), len(p.Canaries), p.CountsString())

	if *count {
		return
	}

	secret := []byte(os.Getenv(label.EnvSecret))
	if len(secret) == 0 {
		fatal("missing %s", label.EnvSecret)
	}

	byName := map[string]req.Target{}
	for _, t := range targets {
		byName[t.Name] = t
	}
	send(p, byName, secret, *rps, *timeout)
}

func send(p plan.Plan, targets map[string]req.Target, secret []byte, rps float64, timeout time.Duration) {
	client := &http.Client{Timeout: timeout}
	interval := time.Duration(0)
	if rps > 0 {
		interval = time.Duration(float64(time.Second) / rps)
	}
	var sent, failed int
	for _, r := range p.Requests {
		t, ok := targets[r.Site]
		if !ok {
			failed++
			continue
		}
		if err := sendOne(client, t, r, secret); err != nil {
			failed++
		} else {
			sent++
		}
		if interval > 0 {
			time.Sleep(interval)
		}
	}
	fmt.Printf("traffic: sent=%d failed=%d\n", sent, failed)
}

func sendOne(client *http.Client, t req.Target, r req.Request, secret []byte) error {
	url := strings.TrimRight(t.BaseURL, "/") + r.Path
	if r.Query != "" {
		url += "?" + r.Query
	}
	var body io.Reader
	if len(r.Body) > 0 {
		body = bytes.NewReader(r.Body)
	}
	ctx, cancel := context.WithTimeout(context.Background(), client.Timeout)
	defer cancel()
	httpReq, err := http.NewRequestWithContext(ctx, r.Method, url, body)
	if err != nil {
		return err
	}
	host := t.Host
	if host != "" {
		httpReq.Host = host
	}
	for k, v := range r.Headers {
		httpReq.Header.Set(k, v)
	}
	if r.SrcIP != "" {
		// Recorded for ground truth / botnet simulation. Real per-request
		// source addresses need the container to own the /22 (compose); the
		// header documents the intended source regardless.
		httpReq.Header.Set("X-Test-Source", r.SrcIP)
	}
	hdr, err := label.Sign(secret, r.Label)
	if err != nil {
		return err
	}
	httpReq.Header.Set(label.HeaderName, hdr)
	resp, err := client.Do(httpReq)
	if err != nil {
		return err
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return nil
}

func loadTargets(path string) ([]req.Target, error) {
	data := ""
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		data = string(b)
	} else if env := os.Getenv("TRAFFIC_TARGETS"); env != "" {
		data = env
	}
	if data == "" {
		// Dev default: one local edge for every logical site name.
		base := "http://localhost:8080"
		if b := os.Getenv("TRAFFIC_BASE_URL"); b != "" {
			base = b
		}
		var ts []req.Target
		for _, name := range []string{"wp", "dvwa", "juice", "api"} {
			ts = append(ts, req.Target{Name: name, BaseURL: base, Host: name + ".example", Mode: "observe"})
		}
		return ts, nil
	}
	var ts []req.Target
	if err := json.Unmarshal([]byte(data), &ts); err != nil {
		return nil, err
	}
	if len(ts) == 0 {
		return nil, fmt.Errorf("no targets")
	}
	return ts, nil
}

func writeJSONFile(path string, v any) {
	b, _ := json.MarshalIndent(v, "", "  ")
	if err := os.WriteFile(path, b, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "traffic: write %s: %v\n", path, err)
	}
}

func writeLines(path string, lines []string) {
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "traffic: write %s: %v\n", path, err)
	}
}

func fatal(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "traffic: "+format+"\n", a...)
	os.Exit(1)
}
