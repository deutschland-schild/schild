package main

// MVP-11 agent smoke: `smoke agents <phase> [flags]`.
//
// The phases run inside the stack (like the main smoke) and are called one by
// one by testlab/scripts/agent-smoke.sh, which does the Docker side in
// between (running `schild-agent enrol` in the app VM containers, cutting the
// app VM off the network, ...). Every phase appends its step results as JSON
// lines to <state>/steps.ndjson; the last phase (`report`) folds them into
// results/runs/smoke-<profile>/agents.json.
//
// A step is "pass", "fail" or "pending" (the gateway or the agent binary does
// not support MVP-11 yet; the integrate agent enables the steps by building a
// schild that does). Only "fail" fails the run, unless -require is set.
//
// Phases:
//
//	probe          dashboard API (/hosts) and agent listener (TLS, pinned) answer
//	enrol-code     create a one-time enrolment code (dashboard), check the pin
//	enrol-confirm  find the pending agent, refuse a wrong fingerprint, confirm
//	wait-report    a host's report arrives after -after; app VM: planted findings
//	expect-host    the host has (or, with -absent, has not) a report / rejection
//	revoke         revoke an agent in the dashboard
//	forged         deliveries signed with the TEST ONLY agent keys: accepted,
//	               replayed, expired, wrong gateway, impersonation, unknown key,
//	               revoked key, forbidden content, oversize, malformed
//	traffic        legit traffic while the agent listener is flooded: unchanged
//	canaries       host report canaries: present at the gateway (positive
//	               control), absent from everything the labs stored or received;
//	               secret canaries absent everywhere
//	report         fold steps.ndjson into agents.json; exit 1 on a failed step

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/dsse"
	"github.com/deutschland-schild/schild/contract/hostcheck"
	"github.com/deutschland-schild/schild/contract/jsonx"
	"github.com/deutschland-schild/schild/contract/testkeys"
	"github.com/deutschland-schild/schild/contract/verify"
	"github.com/deutschland-schild/schild/testlab/internal/egress"
	"github.com/deutschland-schild/schild/testlab/internal/hostcanary"
	"github.com/deutschland-schild/schild/testlab/internal/label"
)

// Step status values.
const (
	stPass    = "pass"
	stFail    = "fail"
	stPending = "pending"
	stSkipped = "skipped" // opt-in step not run; never a failure
)

// exitUnsupported tells the shell that the gateway does not support MVP-11 yet.
const exitUnsupported = 3

type agentStep struct {
	Name     string  `json:"name"`
	Status   string  `json:"status"`
	Seconds  float64 `json:"seconds"`
	Detail   string  `json:"detail"`
	Evidence any     `json:"evidence,omitempty"`
}

type agentEnv struct {
	dashboard   string
	agentURL    string
	pinFile     string
	gatewayName string
	stripper    string
	state       string
	api         *apiClient
	agentHC     *http.Client
	pin         string
}

func agentsMain(args []string) int {
	log.SetFlags(0)
	if len(args) == 0 {
		log.Print("usage: smoke agents probe|enrol-code|enrol-confirm|wait-report|expect-host|revoke|retire|forged|traffic|canaries|report [flags]")
		return 2
	}
	phase, args := args[0], args[1:]
	fs := flag.NewFlagSet("agents "+phase, flag.ContinueOnError)
	e := &agentEnv{}
	fs.StringVar(&e.dashboard, "dashboard", "http://schild-api:8788", "client dashboard of the gateway")
	fs.StringVar(&e.agentURL, "agent-url", "https://schild-api:8790", "agent listener of the gateway")
	fs.StringVar(&e.pinFile, "pin-file", "/run/agent-tls/pin", "sha256:<hex> of the gateway's agent certificate (DER)")
	fs.StringVar(&e.gatewayName, "gateway-name", "site-api", "the gateway's node_name")
	fs.StringVar(&e.stripper, "stripper", "http://stripper-api:8080", "label stripper in front of the gateway")
	fs.StringVar(&e.state, "state", "/results/runs/smoke-t1/agents", "state directory (steps.ndjson, phase outputs)")
	label_ := fs.String("label", "", "enrol-code: label for the new agent")
	name := fs.String("name", "", "step name (enrol-code, enrol-confirm, wait-report, expect-host)")
	hostname := fs.String("hostname", "", "agent / host name")
	fingerprint := fs.String("fingerprint", "", "enrol-confirm: fingerprint the agent printed (sha256:<hex>)")
	after := fs.String("after", "", "wait-report, expect-host: RFC 3339 time the report / rejection must be newer than")
	timeout := fs.Duration("timeout", 3*time.Minute, "wait-report: how long to wait")
	planted := fs.Bool("planted", false, "wait-report: also check the findings planted on the app VM")
	absent := fs.Bool("absent", false, "expect-host: the host must not exist")
	rejected := fs.String("rejected", "", "expect-host: last_rejected.code must be this")
	status := fs.String("status", "", "expect-host: agent status must be this")
	silent := fs.Bool("silent", false, "expect-host: the host must show as not reporting, baseline protection unchanged")
	labDirs := fs.String("lab-dirs", "", "canaries: comma-separated lab data dirs")
	gwDirs := fs.String("gateway-dirs", "", "canaries: comma-separated gateway data dirs (secret canaries only)")
	n := fs.Int("n", 120, "traffic: legit requests per phase")
	out := fs.String("out", "/results/runs/smoke-t1/agents.json", "report: output file")
	require := fs.Bool("require", false, "report: pending steps count as failures")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if err := os.MkdirAll(e.state, 0o755); err != nil {
		log.Printf("agents: %v", err)
		return 2
	}
	if phase == "report" {
		return e.report(*out, *require)
	}
	if err := e.init(); err != nil {
		e.record(agentStep{Name: "agents: " + phase, Status: stFail, Detail: err.Error()})
		return 1
	}
	var steps []agentStep
	switch phase {
	case "probe":
		st := e.probe()
		e.record(st)
		if st.Status != stPass {
			return exitUnsupported
		}
		return 0
	case "enrol-code":
		steps = []agentStep{e.enrolCode(*name, *label_)}
	case "enrol-confirm":
		steps = []agentStep{e.enrolConfirm(*name, *hostname, *fingerprint)}
	case "wait-report":
		steps = e.waitReport(*name, *hostname, *after, *timeout, *planted)
	case "expect-host":
		steps = []agentStep{e.expectHost(*name, *hostname, *after, *absent, *rejected, *status, *silent)}
	case "revoke":
		steps = []agentStep{e.revoke(*name, *hostname)}
	case "retire":
		return e.retire(*hostname)
	case "forged":
		steps = []agentStep{e.forged()}
	case "traffic":
		steps = []agentStep{e.traffic(*n)}
	case "canaries":
		steps = e.canaries(splitList(*labDirs), splitList(*gwDirs))
	default:
		log.Printf("agents: unknown phase %q", phase)
		return 2
	}
	code := 0
	for _, st := range steps {
		e.record(st)
		if st.Status == stFail {
			code = 1
		}
	}
	return code
}

func (e *agentEnv) init() error {
	pw := os.Getenv("SMOKE_PASSWORD")
	if pw == "" {
		return errors.New("SMOKE_PASSWORD is not set")
	}
	e.api = newAPI("schild-api", e.dashboard)
	if err := e.api.loginClient(os.Getenv("SMOKE_SETUP_CODE_API"), pw); err != nil {
		return err
	}
	b, err := os.ReadFile(e.pinFile)
	if err != nil {
		return fmt.Errorf("pin: %w", err)
	}
	e.pin = strings.TrimSpace(string(b))
	want, err := hex.DecodeString(strings.TrimPrefix(e.pin, "sha256:"))
	if err != nil || len(want) != sha256.Size {
		return fmt.Errorf("pin %q: want sha256:<64 hex>", e.pin)
	}
	// The agent pins the gateway certificate (host-check.md section 3): no
	// CA, no hostname, only the sha256 of the DER certificate.
	e.agentHC = &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true, // replaced by the pin check below
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 {
				return errors.New("no certificate")
			}
			got := sha256.Sum256(raw[0])
			if !bytes.Equal(got[:], want) {
				return fmt.Errorf("certificate sha256:%x does not match the pin", got)
			}
			return nil
		},
	}}}
	return nil
}

func (e *agentEnv) record(st agentStep) {
	mark := strings.ToUpper(st.Status)
	log.Printf("%-7s %-72s %6.1fs  %s", mark, st.Name, st.Seconds, st.Detail)
	b, _ := json.Marshal(st)
	f, err := os.OpenFile(filepath.Join(e.state, "steps.ndjson"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		log.Printf("agents: record: %v", err)
		return
	}
	defer f.Close()
	_, _ = f.Write(append(b, '\n'))
}

func timed(name string, fn func() (string, any, error)) agentStep {
	t0 := time.Now()
	detail, ev, err := fn()
	st := agentStep{Name: name, Status: stPass, Seconds: round(time.Since(t0).Seconds()), Detail: detail, Evidence: ev}
	var pe pendingError
	switch {
	case errors.As(err, &pe):
		st.Status, st.Detail = stPending, pe.reason
	case err != nil:
		st.Status, st.Detail = stFail, err.Error()
	}
	return st
}

type pendingError struct{ reason string }

func (p pendingError) Error() string { return "pending: " + p.reason }

// unsupported turns "this gateway has no MVP-11 API" into pending.
func unsupported(err error) error {
	var ae *apiError
	if errors.As(err, &ae) && (ae.Status == 404 || ae.Status == 405 || ae.Status == 501) {
		return pendingError{fmt.Sprintf("gateway answers HTTP %d (MVP-11 API not built yet)", ae.Status)}
	}
	return err
}

// ---- dashboard API types (contracts/api/client-dashboard.openapi.yaml 0.3.0)

type hostSummary struct {
	ID           string         `json:"id"`
	Hostname     string         `json:"hostname"`
	Role         string         `json:"role"`
	AgentID      *string        `json:"agent_id"`
	Status       string         `json:"status"`
	Silent       bool           `json:"silent"`
	LastReportAt *string        `json:"last_report_at"`
	ReceivedAt   *string        `json:"received_at"`
	Counts       map[string]int `json:"counts"`
	Unreadable   int            `json:"unreadable"`
}

type hostDetail struct {
	Host         hostSummary       `json:"host"`
	Report       *hostcheck.Report `json:"report"`
	History      []json.RawMessage `json:"history"`
	LastRejected *struct {
		At     string `json:"at"`
		Code   string `json:"code"`
		Detail string `json:"detail"`
	} `json:"last_rejected"`
}

type agentInfo struct {
	ID          string  `json:"id"`
	Hostname    string  `json:"hostname"`
	Label       *string `json:"label"`
	KeyID       string  `json:"keyid"`
	Fingerprint string  `json:"fingerprint"`
	Status      string  `json:"status"`
	Source      string  `json:"source"`
	CreatedAt   string  `json:"created_at"`
}

type enrolment struct {
	Code        string `json:"code"`
	ExpiresAt   string `json:"expires_at"`
	GatewayURL  string `json:"gateway_url"`
	GatewayName string `json:"gateway_name"`
	GatewayPin  string `json:"gateway_pin"`
	Command     string `json:"command"`
}

func (e *agentEnv) hosts() ([]hostSummary, error) {
	var page struct {
		Items []hostSummary `json:"items"`
	}
	_, err := e.api.do("GET", "/hosts?limit=200", nil, &page)
	return page.Items, err
}

// hostByName returns the host of that name. When a re-run of the smoke on
// the same lab enrolled the name again (earlier agents retired), it is the
// host of the newest agent.
func (e *agentEnv) hostByName(name string) (*hostSummary, error) {
	hs, err := e.hosts()
	if err != nil {
		return nil, err
	}
	var match []*hostSummary
	for i := range hs {
		if hs[i].Hostname == name {
			match = append(match, &hs[i])
		}
	}
	if len(match) <= 1 {
		if len(match) == 0 {
			return nil, nil
		}
		return match[0], nil
	}
	newest, err := e.newestAgent(name, "")
	if err != nil {
		return nil, err
	}
	for _, h := range match {
		if newest != nil && h.AgentID != nil && *h.AgentID == newest.ID {
			return h, nil
		}
	}
	return match[len(match)-1], nil
}

// newestAgent is the most recently created agent of that host name (with
// status, if set), or nil.
func (e *agentEnv) newestAgent(hostname, status string) (*agentInfo, error) {
	as, err := e.agents()
	if err != nil {
		return nil, err
	}
	var best *agentInfo
	for i := range as {
		a := &as[i]
		if a.Hostname != hostname || (status != "" && a.Status != status) {
			continue
		}
		if best == nil || a.CreatedAt >= best.CreatedAt {
			best = a
		}
	}
	return best, nil
}

// retire makes a re-run of the smoke on the same lab possible: every
// enrolled agent of the host name is revoked (the VM gets a fresh key and
// a new enrolment). No step is recorded; it prints what it did.
func (e *agentEnv) retire(hostname string) int {
	as, err := e.agents()
	if err != nil {
		log.Printf("agents retire %s: %v", hostname, err)
		return 1
	}
	n := 0
	for _, a := range as {
		if a.Hostname != hostname || a.Status != "enrolled" {
			continue
		}
		var ag agentInfo
		if _, err := e.api.do("POST", "/agents/"+a.ID+"/revoke", map[string]any{"note": "smoke re-run: earlier enrolment retired"}, &ag); err != nil {
			log.Printf("agents retire %s: revoke %s: %v", hostname, a.ID, err)
			return 1
		}
		n++
	}
	log.Printf("agents retire %s: %d earlier enrolment(s) revoked", hostname, n)
	return 0
}

func (e *agentEnv) host(id string) (*hostDetail, []byte, error) {
	var raw json.RawMessage
	if _, err := e.api.do("GET", "/hosts/"+id, nil, &raw); err != nil {
		return nil, nil, err
	}
	var d hostDetail
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil, raw, err
	}
	return &d, raw, nil
}

func (e *agentEnv) agents() ([]agentInfo, error) {
	var page struct {
		Items []agentInfo `json:"items"`
	}
	_, err := e.api.do("GET", "/agents?limit=200", nil, &page)
	return page.Items, err
}

// ---- phases

func (e *agentEnv) probe() agentStep {
	return timed("gateway supports MVP-11 (dashboard /hosts, agent listener with pinned TLS)", func() (string, any, error) {
		if _, err := e.hosts(); err != nil {
			return "", nil, unsupported(err)
		}
		// Any HTTP answer will do: it proves the TLS handshake with the pinned
		// certificate (GET on the report endpoint is not a delivery).
		resp, err := e.agentHC.Get(e.agentURL + "/v0/agent/report")
		if err != nil {
			return "", nil, pendingError{"agent listener " + e.agentURL + ": " + err.Error()}
		}
		resp.Body.Close()
		return "dashboard /hosts answers; agent listener presents the pinned certificate", map[string]any{"get_report_endpoint": resp.StatusCode}, nil
	})
}

func (e *agentEnv) enrolCode(name, lbl string) agentStep {
	return timed(name, func() (string, any, error) {
		var en enrolment
		body := map[string]any{}
		if lbl != "" {
			body["label"] = lbl
		}
		// Without the password the dashboard refuses (403 forbidden).
		if _, err := e.api.do("POST", "/agents/enrolments", body, nil, 403); err != nil {
			return "", nil, unsupported(fmt.Errorf("enrolment code without the password: %w", err))
		}
		if _, err := e.api.do("POST", "/agents/enrolments", body, &en, 201); err != nil {
			return "", nil, unsupported(err)
		}
		if en.GatewayName != e.gatewayName || !strings.Contains(en.Command, "--gateway-name "+e.gatewayName+" ") {
			return "", nil, fmt.Errorf("enrolment names gateway %q (command %q), want node_name %s", en.GatewayName, en.Command, e.gatewayName)
		}
		if en.GatewayPin != e.pin {
			return "", nil, fmt.Errorf("enrolment shows pin %s, the gateway's agent certificate is %s", en.GatewayPin, e.pin)
		}
		if !strings.Contains(en.Command, en.Code) || !strings.Contains(en.Command, en.GatewayPin) {
			return "", nil, fmt.Errorf("command %q does not carry code and pin", en.Command)
		}
		b, _ := json.Marshal(en)
		if err := os.WriteFile(filepath.Join(e.state, "enrolment-"+lbl+".json"), b, 0o644); err != nil {
			return "", nil, err
		}
		// The shell reads the code from this file (one line, nothing else).
		if err := os.WriteFile(filepath.Join(e.state, "code-"+lbl), []byte(en.Code+"\n"), 0o644); err != nil {
			return "", nil, err
		}
		return "one-time code created only with the password; command carries code, gateway name and the right pin", map[string]any{"expires_at": en.ExpiresAt, "gateway_url": en.GatewayURL}, nil
	})
}

func (e *agentEnv) enrolConfirm(name, hostname, fp string) agentStep {
	return timed(name, func() (string, any, error) {
		var pending *agentInfo
		err := eventually(context.Background(), 30*time.Second, time.Second, "pending agent "+hostname, func() (bool, error) {
			a, err := e.newestAgent(hostname, "pending")
			if err != nil {
				return false, unsupported(err)
			}
			pending = a
			return a != nil, nil
		})
		if err != nil {
			return "", nil, err
		}
		if fp != "" && pending.Fingerprint != fp {
			return "", nil, fmt.Errorf("dashboard shows fingerprint %s, the agent printed %s", pending.Fingerprint, fp)
		}
		// A wrong fingerprint must be refused (409 fingerprint_mismatch).
		wrong := "sha256:" + strings.Repeat("0", 64)
		var prob map[string]any
		code, err := e.api.do("POST", "/agents/"+pending.ID+"/confirm", map[string]any{"fingerprint": wrong}, &prob, 409)
		if err != nil {
			return "", nil, fmt.Errorf("confirm with a wrong fingerprint: %w", err)
		}
		var ag agentInfo
		if _, err := e.api.do("POST", "/agents/"+pending.ID+"/confirm", map[string]any{"fingerprint": pending.Fingerprint}, &ag); err != nil {
			return "", nil, err
		}
		if ag.Status != "enrolled" {
			return "", nil, fmt.Errorf("after confirm: status %q", ag.Status)
		}
		return "pending agent found, wrong fingerprint refused (409), confirmed", map[string]any{"agent_id": ag.ID, "keyid": ag.KeyID, "fingerprint": ag.Fingerprint, "wrong_fingerprint_status": code, "problem": prob["code"]}, nil
	})
}

func newer(ts *string, after string) bool {
	if ts == nil {
		return false
	}
	if after == "" {
		return true
	}
	t, err1 := time.Parse(time.RFC3339, *ts)
	a, err2 := time.Parse(time.RFC3339, after)
	return err1 == nil && err2 == nil && !t.Before(a)
}

func (e *agentEnv) waitReport(name, hostname, after string, timeout time.Duration, planted bool) []agentStep {
	var d *hostDetail
	var raw []byte
	first := timed(name, func() (string, any, error) {
		var h *hostSummary
		err := eventually(context.Background(), timeout, 2*time.Second, "report of "+hostname, func() (bool, error) {
			var err error
			if h, err = e.hostByName(hostname); err != nil {
				return false, unsupported(err)
			}
			if h == nil {
				return false, nil
			}
			ts := h.ReceivedAt
			if ts == nil {
				ts = h.LastReportAt
			}
			return newer(ts, after), nil
		})
		if err != nil {
			return "", nil, err
		}
		if d, raw, err = e.host(h.ID); err != nil {
			return "", nil, err
		}
		if d.Report == nil {
			return "", nil, errors.New("host listed but getHost has no report")
		}
		var stored struct {
			Report json.RawMessage `json:"report"`
		}
		if err := json.Unmarshal(raw, &stored); err != nil {
			return "", nil, err
		}
		if _, err := verify.Document(verify.DocHostReport, stored.Report, &verify.Context{Now: time.Now()}); err != nil {
			return "", nil, fmt.Errorf("stored report does not pass the contract: %w", err)
		}
		if d.Report.Host.Hostname != hostname || d.Report.Host.Role != "agent" {
			return "", nil, fmt.Errorf("report host %q role %q", d.Report.Host.Hostname, d.Report.Host.Role)
		}
		for _, s := range hostcanary.Secrets() {
			if bytes.Contains(raw, []byte(s)) {
				return "", nil, fmt.Errorf("SECRET LEAK: the stored report carries the secret canary %s", s)
			}
		}
		var ov map[string]any
		_, _ = e.api.do("GET", "/overview", nil, &ov)
		return fmt.Sprintf("report visible in the dashboard API (%d findings, %d inventory items, %d kept)", len(d.Report.Findings), len(d.Report.Inventory), len(d.History)),
			map[string]any{"host_id": h.ID, "status": h.Status, "counts": h.Counts, "unreadable": h.Unreadable, "received_at": h.ReceivedAt, "overview_servers": ov["servers"]}, nil
	})
	steps := []agentStep{first}
	if !planted {
		return steps
	}
	if first.Status != stPass {
		steps = append(steps, agentStep{Name: "app VM findings as planted", Status: first.Status, Detail: "no report: " + first.Detail})
		return steps
	}
	steps = append(steps, timed("app VM findings as planted (password SSH, public MariaDB, PHP 8.1, pending canary update)", func() (string, any, error) {
		return checkPlanted(d.Report)
	}))
	return steps
}

// checkPlanted compares a report with what the app VM image plants
// (testlab/dockerfiles/app-vm). Only clear-cut facts: each must be found.
func checkPlanted(r *hostcheck.Report) (string, any, error) {
	has := func(id, subject string, ok func(f hostcheck.Finding) bool) bool {
		for _, f := range r.Findings {
			if f.ID == id && (subject == "" || strings.Contains(strings.ToLower(f.Subject), subject)) && f.Status == "finding" && (ok == nil || ok(f)) {
				return true
			}
		}
		return false
	}
	want := map[string]bool{
		"ssh.password_authentication": has("ssh.password_authentication", "", nil),
		"ssh.permit_root_login":       has("ssh.permit_root_login", "", nil),
		"ports.public_service tcp/3306": has("ports.public_service", "tcp/3306", func(f hostcheck.Finding) bool {
			return f.Evidence.Port == 3306
		}),
		"software.runtime_eol php": has("software.runtime_eol", "php", nil),
		"updates.* lists " + hostcanary.Package: has("updates.pending", "", func(f hostcheck.Finding) bool {
			return slices.Contains(f.Evidence.Packages, hostcanary.Package) || f.Evidence.Package == hostcanary.Package
		}) || has("updates.security_pending", "", func(f hostcheck.Finding) bool {
			return slices.Contains(f.Evidence.Packages, hostcanary.Package) || f.Evidence.Package == hostcanary.Package
		}),
		"firewall.active (none active)": has("firewall.active", "", nil) || hasUnreadable(r, "firewall.active"),
	}
	php := ""
	for _, it := range r.Inventory {
		if it.Kind == "runtime" && strings.EqualFold(it.Name, "php") {
			php = it.Version
		}
	}
	want["inventory runtime php 8.1"] = strings.HasPrefix(php, "8.1")
	// php-fpm listens on loopback only: never a public-service finding.
	want["no finding for loopback tcp/9000"] = !has("ports.public_service", "tcp/9000", nil)
	var missing []string
	for k, ok := range want {
		if !ok {
			missing = append(missing, k)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		return "", want, fmt.Errorf("not found in the report: %s", strings.Join(missing, "; "))
	}
	return fmt.Sprintf("%d planted facts found", len(want)), want, nil
}

func hasUnreadable(r *hostcheck.Report, id string) bool {
	for _, f := range r.Findings {
		if f.ID == id && f.Status == "unreadable" {
			return true
		}
	}
	return false
}

func (e *agentEnv) expectHost(name, hostname, after string, absent bool, rejected, status string, silent bool) agentStep {
	return timed(name, func() (string, any, error) {
		h, err := e.hostByName(hostname)
		if err != nil {
			return "", nil, unsupported(err)
		}
		ev := map[string]any{}
		if absent {
			if h != nil {
				return "", nil, fmt.Errorf("host %s is listed (status %s): a report of an unenrolled agent was accepted", hostname, h.Status)
			}
			as, err := e.agents()
			if err != nil {
				return "", nil, err
			}
			for _, a := range as {
				if a.Hostname == hostname {
					return "", nil, fmt.Errorf("agent %s is listed with status %s", hostname, a.Status)
				}
			}
			return "no host and no agent " + hostname + " at the gateway", nil, nil
		}
		if h == nil {
			return "", nil, fmt.Errorf("host %s not listed", hostname)
		}
		d, _, err := e.host(h.ID)
		if err != nil {
			return "", nil, err
		}
		ev["history"] = len(d.History)
		if silent {
			var ov struct {
				Baseline struct {
					State string `json:"state"`
				} `json:"baseline"`
			}
			_, _ = e.api.do("GET", "/overview", nil, &ov)
			ev["silent"], ev["baseline"] = h.Silent, ov.Baseline.State
			if !h.Silent || ov.Baseline.State != "active" {
				return "", ev, fmt.Errorf("silent %v (want true), baseline %q (want active)", h.Silent, ov.Baseline.State)
			}
		}
		if rejected != "" {
			if d.LastRejected == nil || d.LastRejected.Code != rejected || !newer(&d.LastRejected.At, after) {
				return "", ev, fmt.Errorf("last_rejected %+v, want code %s after %s", d.LastRejected, rejected, after)
			}
			ev["last_rejected"] = d.LastRejected
		}
		if status != "" {
			a, err := e.newestAgent(hostname, "")
			if err != nil {
				return "", nil, err
			}
			got := ""
			if a != nil {
				got = a.Status
			}
			if got != status {
				return "", ev, fmt.Errorf("agent %s status %q, want %q", hostname, got, status)
			}
			ev["agent_status"] = got
		}
		return "host state as expected", ev, nil
	})
}

func (e *agentEnv) revoke(name, hostname string) agentStep {
	return timed(name, func() (string, any, error) {
		as, err := e.agents()
		if err != nil {
			return "", nil, unsupported(err)
		}
		for _, a := range as {
			if a.Hostname == hostname && a.Status == "enrolled" {
				var ag agentInfo
				if _, err := e.api.do("POST", "/agents/"+a.ID+"/revoke", map[string]any{"note": "smoke: revoked on purpose"}, &ag); err != nil {
					return "", nil, err
				}
				if ag.Status != "revoked" {
					return "", nil, fmt.Errorf("after revoke: status %q", ag.Status)
				}
				return "agent revoked in the dashboard", map[string]any{"agent_id": a.ID, "keyid": a.KeyID}, nil
			}
		}
		return "", nil, fmt.Errorf("no enrolled agent %s", hostname)
	})
}

// ---- signed deliveries with the TEST ONLY agent keys

// Hostnames of the config-enrolled test keys (config/t1/api/schild.yaml).
const (
	forgedHostA = "smoke-agent-a" // test-agent-a: enrolled by explicit public key
	forgedHostC = "old-app"       // test-agent-c: revoked: true
)

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func uuid4() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b)
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

func smokeHostReport(hostname, keyid string, now time.Time) map[string]any {
	return map[string]any{
		"schema":    hostcheck.SchemaReport,
		"report_id": uuid4(),
		"host": map[string]any{"hostname": hostname, "role": "agent", "agent_key_id": keyid, "os": map[string]any{
			"id": "debian", "version_id": "13", "name": "Debian GNU/Linux 13 (trixie)", "kernel": "6.12.0-testlab", "arch": "aarch64", "eol": nil}},
		"run": map[string]any{"started_at": now.Add(-10 * time.Second).UTC().Format(time.RFC3339), "duration_ms": 1200,
			"schild_version": "smoke", "eol_table": "2026-10-01", "as_root": false},
		"findings": []any{map[string]any{"id": "ssh.port", "area": "ssh", "severity": "info", "status": "ok",
			"title": "SSH läuft auf Port 22", "explanation": "Testbericht des Smoke-Tests.", "fix_command": nil,
			"evidence": map[string]any{"source": "sshd_t", "setting": "port", "value": "22"}}},
		"inventory": []any{},
	}
}

type delivery struct {
	Name     string `json:"name"`
	Want     string `json:"want"`
	HTTP     int    `json:"http"`
	Status   string `json:"status"`
	Error    string `json:"error,omitempty"`
	OK       bool   `json:"ok"`
	Note     string `json:"note,omitempty"`
	BodySize int    `json:"body_bytes"`
}

func (e *agentEnv) signReport(key string, mutate func(p, r map[string]any)) []byte {
	s := testkeys.Signer(key)
	now := time.Now().UTC()
	host := forgedHostA
	if key == "agent-c" {
		host = forgedHostC
	} else if key == "agent-b" {
		host = "smoke-unknown"
	}
	r := smokeHostReport(host, s.KeyID(), now)
	p := map[string]any{"schema": hostcheck.SchemaAgentReport, "gateway": e.gatewayName, "issued_at": now.Format(time.RFC3339), "nonce": randHex(16), "report": r}
	if mutate != nil {
		mutate(p, r)
	}
	payload, err := jsonx.Marshal(p)
	if err != nil {
		panic(err)
	}
	env, err := dsse.Sign(contract.KindAgentReport.PayloadType(), payload, s)
	if err != nil {
		panic(err)
	}
	raw, err := env.Marshal()
	if err != nil {
		panic(err)
	}
	return raw
}

// post sends one delivery and validates the answer against the ack contract
// (an ack has no field that could carry an instruction).
func (e *agentEnv) post(body []byte) (int, *hostcheck.Ack, error) {
	resp, err := e.agentHC.Post(e.agentURL+"/v0/agent/report", "application/json", bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	v, err := verify.Document(verify.DocAgentAck, raw, &verify.Context{Now: time.Now()})
	if err != nil {
		return resp.StatusCode, nil, fmt.Errorf("answer is not a valid agent ack: %w: %s", err, trunc(string(raw), 200))
	}
	var ack hostcheck.Ack
	if err := jsonx.Decode(v, &ack); err != nil {
		return resp.StatusCode, nil, err
	}
	return resp.StatusCode, &ack, nil
}

func (e *agentEnv) forged() agentStep {
	return timed("signed deliveries: accepted once; replay, expired, wrong gateway, impersonation, unknown, revoked, forbidden content, oversize, malformed refused", func() (string, any, error) {
		if _, err := e.hosts(); err != nil {
			return "", nil, unsupported(err)
		}
		// Report ids in the host's history. Compared by id, not by length:
		// the history is capped by keep_reports (30), which a re-run of the
		// smoke on the same lab reaches.
		histOf := func() map[string]int {
			ids := map[string]int{}
			h, err := e.hostByName(forgedHostA)
			if err != nil || h == nil {
				return ids
			}
			var d struct {
				History []struct {
					ReportID string `json:"report_id"`
				} `json:"history"`
			}
			if _, err := e.api.do("GET", "/hosts/"+h.ID, nil, &d); err != nil {
				return nil
			}
			for _, r := range d.History {
				ids[r.ReportID]++
			}
			return ids
		}
		histBefore := histOf()
		valid := e.signReport("agent-a", nil)
		cases := []struct {
			name, want string
			body       []byte
		}{
			{"valid report, test-agent-a (enrolled by public key)", "accepted", valid},
			{"same envelope again (replay)", "replay", valid},
			{"issued 6 minutes ago", "expired", e.signReport("agent-a", func(p, _ map[string]any) {
				p["issued_at"] = time.Now().UTC().Add(-6 * time.Minute).Format(time.RFC3339)
			})},
			{"issued 5 minutes in the future", "clock_skew", e.signReport("agent-a", func(p, _ map[string]any) {
				p["issued_at"] = time.Now().UTC().Add(5 * time.Minute).Format(time.RFC3339)
			})},
			{"addressed to another gateway", "channel", e.signReport("agent-a", func(p, _ map[string]any) { p["gateway"] = "other-gateway" })},
			{"report claims another agent's key id", "signature", e.signReport("agent-a", func(_, r map[string]any) {
				r["host"].(map[string]any)["agent_key_id"] = "test-agent-c"
			})},
			{"unknown key test-agent-b (never enrolled)", "signature", e.signReport("agent-b", nil)},
			{"revoked key test-agent-c (schild.yaml revoked: true)", "revoked", e.signReport("agent-c", nil)},
			{"environment dump in a finding", "forbidden_content", e.signReport("agent-a", func(_, r map[string]any) {
				f := r["findings"].([]any)[0].(map[string]any)
				f["explanation"] = "PATH=/usr/bin HOME=/root SHELL=/bin/sh"
			})},
			{"field named environment", "forbidden_field", e.signReport("agent-a", func(_, r map[string]any) {
				r["host"].(map[string]any)["environment"] = map[string]any{"LANG": "C"}
			})},
			{"envelope over 768 KiB", "oversize", append(append([]byte(`{"payloadType":"x","payload":"`), bytes.Repeat([]byte("A"), 800<<10)...), []byte(`","signatures":[]}`)...)},
			{"not JSON", "malformed", []byte("{")},
		}
		var res []delivery
		var bad []string
		for _, c := range cases {
			code, ack, err := e.post(c.body)
			d := delivery{Name: c.name, Want: c.want, HTTP: code, BodySize: len(c.body)}
			if err != nil {
				d.Error = err.Error()
			} else {
				d.Status = ack.Status
				if ack.Error != nil {
					d.Error = *ack.Error
				}
			}
			switch c.want {
			case "accepted":
				d.OK = err == nil && code == 200 && ack.Status == "accepted"
			case "replay":
				// host-check.md: a repeated nonce is answered with ack
				// `duplicate` (HTTP 200, nothing stored twice) or rejected
				// with `replay`. Both are fine; a second stored report is not
				// (checked below via the history).
				d.OK = err == nil && ((code == 200 && ack.Status == "duplicate") || (ack.Status == "rejected" && d.Error == "replay"))
				if d.OK {
					d.Note = "answered " + ack.Status
				}
			default:
				d.OK = err == nil && ack.Status == "rejected" && d.Error == c.want && slices.Contains([]int{400, 401, 403, 409, 413}, code)
			}
			if !d.OK {
				bad = append(bad, fmt.Sprintf("%s: want %s, got HTTP %d %s %s", c.name, c.want, code, d.Status, d.Error))
			}
			res = append(res, d)
		}
		// Exactly one new report of smoke-agent-a stored, once, despite the
		// replay.
		hist := histOf()
		var added []string
		for id, n := range hist {
			if histBefore[id] == 0 {
				added = append(added, fmt.Sprintf("%s x%d", id, n))
			}
		}
		if hist == nil || histBefore == nil || len(added) != 1 || !strings.HasSuffix(added[0], " x1") {
			bad = append(bad, fmt.Sprintf("host %s: new reports in the history %v, want exactly one, stored once (the replay must not be stored)", forgedHostA, added))
		}
		if h2, _ := e.hostByName("smoke-unknown"); h2 != nil {
			bad = append(bad, "host smoke-unknown (unknown key) is listed")
		}
		if len(bad) > 0 {
			return "", res, errors.New(strings.Join(bad, "; "))
		}
		return fmt.Sprintf("%d deliveries answered as the contract says; replay not stored", len(res)), res, nil
	})
}

// ---- traffic is unaffected by agent trouble

func (e *agentEnv) traffic(n int) agentStep {
	return timed("traffic unaffected while the agent listener is flooded (junk, oversize, unknown keys)", func() (string, any, error) {
		secret := os.Getenv(label.EnvSecret)
		if secret == "" {
			return "", nil, errors.New("SCHILD_LABEL_SECRET is not set")
		}
		g := &trafficGen{secret: []byte(secret), hc: &http.Client{Timeout: 30 * time.Second}}
		grund := func() string {
			var ov struct {
				Baseline struct {
					State string `json:"state"`
				} `json:"baseline"`
			}
			_, _ = e.api.do("GET", "/overview", nil, &ov)
			return ov.Baseline.State
		}
		run := func() ([]int, []float64, error) {
			specs := legitSpecs(7)
			for len(specs) < n {
				specs = append(specs, legitSpecs(len(specs))...)
			}
			specs = specs[:n]
			var codes []int
			var lat []float64
			for i := range specs {
				t0 := time.Now()
				s, err := g.send("api", e.stripper, specs[i:i+1], func(int) string { return legitIP(i) })
				if err != nil {
					return codes, lat, err
				}
				lat = append(lat, time.Since(t0).Seconds()*1000)
				codes = append(codes, s[0].Status)
			}
			return codes, lat, nil
		}
		before := grund()
		baseCodes, baseLat, err := run()
		if err != nil {
			return "", nil, err
		}
		stop := make(chan struct{})
		var wg sync.WaitGroup
		var flood, floodErr int
		var mu sync.Mutex
		junk := [][]byte{[]byte("{"), bytes.Repeat([]byte("A"), 1<<20), e.signReport("agent-b", nil), e.signReport("agent-c", nil)}
		for w := 0; w < 4; w++ {
			wg.Add(1)
			go func(w int) {
				defer wg.Done()
				for i := 0; ; i++ {
					select {
					case <-stop:
						return
					default:
					}
					_, _, err := e.post(junk[(w+i)%len(junk)])
					mu.Lock()
					flood++
					if err != nil {
						floodErr++
					}
					mu.Unlock()
				}
			}(w)
		}
		floodCodes, floodLat, err := run()
		close(stop)
		wg.Wait()
		if err != nil {
			return "", nil, err
		}
		after := grund()
		ev := map[string]any{"requests": n, "flood_deliveries": flood, "flood_non_ack_answers": floodErr,
			"p95_ms_baseline": pct(baseLat, 95), "p95_ms_flood": pct(floodLat, 95), "baseline_before": before, "baseline_after": after}
		var bad []string
		for i := range floodCodes {
			if floodCodes[i] >= 500 || floodCodes[i] != baseCodes[i] {
				bad = append(bad, fmt.Sprintf("request %d: %d under flood, %d before", i, floodCodes[i], baseCodes[i]))
			}
		}
		if before != "active" || after != before {
			bad = append(bad, fmt.Sprintf("baseline %q before, %q after", before, after))
		}
		if len(bad) > 0 {
			return "", ev, fmt.Errorf("%s", strings.Join(bad[:min(len(bad), 5)], "; "))
		}
		return fmt.Sprintf("%d legit requests answered the same under flood (%d junk deliveries); baseline %s", n, flood, after), ev, nil
	})
}

func pct(xs []float64, p int) float64 {
	if len(xs) == 0 {
		return 0
	}
	s := slices.Clone(xs)
	sort.Float64s(s)
	return round(s[min(len(s)-1, len(s)*p/100)])
}

// ---- canaries

func (e *agentEnv) canaries(labDirs, gwDirs []string) []agentStep {
	positive := timed("host report canaries reached the gateway (positive control), secrets did not", func() (string, any, error) {
		h, err := e.hostByName(hostcanary.Hostname)
		if err != nil {
			return "", nil, unsupported(err)
		}
		if h == nil {
			return "", nil, fmt.Errorf("no host %s at the gateway: the absence check below would prove nothing", hostcanary.Hostname)
		}
		_, raw, err := e.host(h.ID)
		if err != nil {
			return "", nil, err
		}
		var missing, leaked []string
		for _, c := range hostcanary.Local() {
			if !bytes.Contains(raw, []byte(c)) {
				missing = append(missing, c)
			}
		}
		for _, c := range hostcanary.Secrets() {
			if bytes.Contains(raw, []byte(c)) {
				leaked = append(leaked, c)
			}
		}
		if len(leaked) > 0 {
			return "", nil, fmt.Errorf("SECRET LEAK in the stored report: %v", leaked)
		}
		if len(missing) > 0 {
			return "", nil, fmt.Errorf("canaries not in the app VM's report at the gateway: %v (positive control failed)", missing)
		}
		return "hostname and package canary in the gateway's report; no secret canary", nil, nil
	})
	steps := []agentStep{positive}
	steps = append(steps, timed("host report canaries absent from everything the labs stored (D72: the gateway sends them nothing)", func() (string, any, error) {
		if len(labDirs) == 0 {
			return "", nil, errors.New("no -lab-dirs")
		}
		rep, err := egress.ScanTree(labDirs, hostcanary.All())
		if err != nil {
			return "", nil, err
		}
		if !rep.OK() || rep.Files == 0 {
			return "", rep, fmt.Errorf("%d files scanned, findings: %v", rep.Files, rep.Findings)
		}
		return fmt.Sprintf("%d files (%d bytes) of %d labs' data: no canary", rep.Files, rep.Bytes, len(labDirs)), rep, nil
	}))
	if len(gwDirs) > 0 {
		steps = append(steps, timed("secret canaries absent from the gateway's stored data", func() (string, any, error) {
			rep, err := egress.ScanTree(gwDirs, hostcanary.Secrets())
			if err != nil {
				return "", nil, err
			}
			if !rep.OK() || rep.Files == 0 {
				return "", rep, fmt.Errorf("%d files scanned, findings: %v", rep.Files, rep.Findings)
			}
			return fmt.Sprintf("%d files (%d bytes): no secret canary", rep.Files, rep.Bytes), rep, nil
		}))
	}
	if positive.Status == stPending {
		for i := 1; i < len(steps); i++ {
			if steps[i].Status == stPass {
				steps[i].Detail += " (no host reports yet: vacuous until the gateway supports MVP-11)"
				steps[i].Status = stPending
			}
		}
	}
	return steps
}

// ---- report

func (e *agentEnv) report(out string, require bool) int {
	b, err := os.ReadFile(filepath.Join(e.state, "steps.ndjson"))
	if err != nil {
		log.Printf("agents report: %v", err)
		return 1
	}
	var steps []agentStep
	counts := map[string]int{}
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if line == "" {
			continue
		}
		var st agentStep
		if err := json.Unmarshal([]byte(line), &st); err != nil {
			st = agentStep{Name: "unparsable step line", Status: stFail, Detail: trunc(line, 200)}
		}
		steps = append(steps, st)
		counts[st.Status]++
	}
	ok := counts[stFail] == 0 && (!require || counts[stPending] == 0) && len(steps) > 0
	rep := map[string]any{"spec": "MVP-11", "finished": time.Now().UTC().Format(time.RFC3339), "ok": ok, "require": require,
		"pass": counts[stPass], "fail": counts[stFail], "pending": counts[stPending], "skipped": counts[stSkipped], "steps": steps}
	j, _ := json.MarshalIndent(rep, "", "  ")
	_ = os.MkdirAll(filepath.Dir(out), 0o755)
	if err := os.WriteFile(out, append(j, '\n'), 0o644); err != nil {
		log.Printf("agents report: %v", err)
		return 1
	}
	log.Printf("agents: %d pass, %d fail, %d pending, %d skipped -> %s", counts[stPass], counts[stFail], counts[stPending], counts[stSkipped], out)
	if !ok {
		return 1
	}
	return 0
}
