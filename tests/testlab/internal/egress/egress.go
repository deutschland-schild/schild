// Package egress is the independent check that nothing forbidden leaves a
// schild server. It does not reuse the contract's own signal validator (the
// thing under test); it is a second, simpler implementation so a bug in the
// client cannot hide behind the same bug in the checker.
//
// It reads the client's transparency log (schild.signal.sent.v1 events, which
// record exactly what was sent) and/or the lab's ingest log, and checks every
// outgoing payload against three rules:
//
//  1. no canary value from the test lab appears anywhere in the envelope;
//  2. no IP-address-like string appears anywhere in the envelope (decision:
//     no visitor IP ever leaves the server, in any form);
//  3. no field outside the positive list appears in the signal payload.
//
// Any hit is a finding. A single finding fails the egress check.
package egress

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"regexp"
	"sort"
	"strings"
)

// Kind labels a finding.
type Kind string

const (
	CanaryLeak       Kind = "canary_leak"
	IPLeak           Kind = "ip_leak"
	ForbiddenField   Kind = "forbidden_field"
	MalformedSignal  Kind = "malformed_signal"
	UnexpectedSchema Kind = "unexpected_schema"
)

// Finding is one violation.
type Finding struct {
	Kind     Kind   `json:"kind"`
	Detail   string `json:"detail"`
	Location string `json:"location"` // e.g. envelope sha or line number
}

// Report is the result of a check.
type Report struct {
	Signals        int       `json:"signals"`
	CanaryFindings int       `json:"canary_findings"`
	IPFindings     int       `json:"ip_findings"`
	FieldFindings  int       `json:"field_findings"`
	Findings       []Finding `json:"findings"`
}

// OK reports whether the check passed (no findings).
func (r Report) OK() bool { return len(r.Findings) == 0 }

// PositiveList is the set of field names that may leave the server (E4),
// per payload kind and nesting level ("" = top level). Anything else is a
// forbidden field. It mirrors contracts/signal.schema.json (schild.signal/0.3)
// and contracts/feedback.schema.json (schild.feedback/0.2) but is maintained
// independently on purpose: a bug in the client must not hide behind the same
// bug in the checker.
var PositiveList = map[string]map[string]bool{
	"signal": {
		"schema": true, "id": true, "kind": true, "time_bucket": true, "action_sig": true,
		"request_sig": true, "waf_rules": true, "score": true, "category": true,
		"origin": true, "agent": true, "ja4": true,
	},
	"signal.origin": {"country": true, "asn": true, "net_class": true, "attribution": true, "protected": true},
	"signal.agent":  {"family": true, "major": true, "bot": true},
	"feedback": {
		"schema": true, "id": true, "time_bucket": true, "rule_id": true, "bundle_version": true,
		"verdict": true, "decided_by": true, "local_action": true, "match_shape": true,
	},
	"feedback.match_shape": {"location": true, "content_type": true, "len_bucket": true},
}

// ipLike finds address-like tokens: IPv4 dotted quads and colon-separated hex
// groups. Candidates are confirmed by looksLikeRealIP (an IPv6 candidate must
// parse as an address, so "18:30:00" in a timestamp is not one).
var ipLike = regexp.MustCompile(
	`\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b` +
		`|(?:[0-9a-fA-F]{0,4}:){2,}[0-9a-fA-F]{0,4}(?:\.[0-9]{1,3}){0,3}`)

// Checker holds the canary values and extra forbidden IP strings to look for.
type Checker struct {
	canaries    []string
	forbiddenIP []string
}

// New builds a checker. canaries are the unique markers the test lab planted;
// forbiddenIP are specific source IPs that must never appear.
func New(canaries, forbiddenIP []string) *Checker {
	c := &Checker{}
	for _, s := range canaries {
		if s = strings.TrimSpace(s); s != "" {
			c.canaries = append(c.canaries, s)
		}
	}
	for _, s := range forbiddenIP {
		if s = strings.TrimSpace(s); s != "" {
			c.forbiddenIP = append(c.forbiddenIP, s)
		}
	}
	return c
}

// signalEvent is the subset of schild.signal.sent.v1 the checker reads.
type signalEvent struct {
	Type string `json:"type"`
	Data struct {
		Kind           string          `json:"kind"`
		Lab            string          `json:"lab"`
		EnvelopeSHA256 string          `json:"envelope_sha256"`
		Result         string          `json:"result"`
		Payload        json.RawMessage `json:"payload"`
	} `json:"data"`
}

// CheckLog scans a transparency log (NDJSON of CloudEvents) and returns a
// report. Lines that are not schild.signal.sent.v1 events are ignored.
func (c *Checker) CheckLog(r io.Reader) (Report, error) {
	var rep Report
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	line := 0
	for sc.Scan() {
		line++
		b := strings.TrimSpace(sc.Text())
		if b == "" {
			continue
		}
		var ev signalEvent
		if err := json.Unmarshal([]byte(b), &ev); err != nil {
			continue // not our event
		}
		if ev.Type != "schild.signal.sent.v1" {
			continue
		}
		rep.Signals++
		loc := ev.Data.EnvelopeSHA256
		if loc == "" {
			loc = fmt.Sprintf("line %d", line)
		}
		c.scanPayload(&rep, b, ev.Data.Payload, loc)
	}
	return rep, sc.Err()
}

// CheckPayload scans one raw signal payload (used by tests and the lab ingest
// cross-check, which has payloads without the event wrapper).
func (c *Checker) CheckPayload(payload []byte, loc string) Report {
	var rep Report
	rep.Signals = 1
	c.scanPayload(&rep, string(payload), payload, loc)
	return rep
}

func (c *Checker) scanPayload(rep *Report, wholeLine string, payload []byte, loc string) {
	// 1. canary scan over the whole serialized line (envelope + payload).
	for _, canary := range c.canaries {
		if strings.Contains(wholeLine, canary) {
			rep.add(Finding{CanaryLeak, "canary value present: " + canary, loc})
		}
	}
	// 2. IP scan over the payload only (the envelope's signatures are base64
	// and would false-positive; the payload is where leaks would hide).
	if len(payload) > 0 {
		for _, m := range ipLike.FindAllString(string(payload), -1) {
			if looksLikeRealIP(m) {
				rep.add(Finding{IPLeak, "address-like token in payload: " + m, loc})
			}
		}
		for _, ip := range c.forbiddenIP {
			if strings.Contains(string(payload), ip) {
				rep.add(Finding{IPLeak, "forbidden source IP in payload: " + ip, loc})
			}
		}
		// 3. positive-list check over the payload object (top level and the
		// nested objects the contract allows).
		var obj map[string]any
		if err := json.Unmarshal(payload, &obj); err == nil {
			kind := "signal"
			if s, _ := obj["schema"].(string); strings.HasPrefix(s, "schild.feedback/") {
				kind = "feedback"
			}
			for _, k := range sortedKeys(obj) {
				if !PositiveList[kind][k] {
					rep.add(Finding{ForbiddenField, "field outside positive list: " + k, loc})
					continue
				}
				if sub, ok := obj[k].(map[string]any); ok {
					allowed := PositiveList[kind+"."+k]
					for _, sk := range sortedKeys(sub) {
						if !allowed[sk] {
							rep.add(Finding{ForbiddenField, "field outside positive list: " + k + "." + sk, loc})
						}
					}
				}
			}
		}
	}
}

func (r *Report) add(f Finding) {
	r.Findings = append(r.Findings, f)
	switch f.Kind {
	case CanaryLeak:
		r.CanaryFindings++
	case IPLeak:
		r.IPFindings++
	case ForbiddenField:
		r.FieldFindings++
	}
}

// looksLikeRealIP filters out obvious non-addresses the regex may catch, such
// as version strings "1.2.3" (only three octets would not match the IPv4 case
// anyway) and single hex groups. It keeps the check broad but not absurd.
func looksLikeRealIP(s string) bool {
	if !strings.Contains(s, ":") {
		return strings.Count(s, ".") == 3
	}
	// IPv6 (also with an embedded IPv4 tail): must parse as an address, or
	// use the "::" shorthand with at least one hex group. "18:30:00" from a
	// timestamp does neither.
	t := strings.Trim(s, ":")
	if net.ParseIP(s) != nil || (strings.Contains(s, "::") && t != "") {
		return true
	}
	return strings.Count(s, ":") >= 7
}

func sortedKeys(m map[string]any) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}
