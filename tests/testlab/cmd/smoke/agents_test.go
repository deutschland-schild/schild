package main

import (
	"strings"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/hostcheck"
	"github.com/deutschland-schild/schild/contract/testkeys"
	"github.com/deutschland-schild/schild/contract/verify"
	"github.com/deutschland-schild/schild/testlab/internal/hostcanary"
)

// TestForgedDeliveriesMatchContract checks the smoke's own expectations
// offline: every delivery the forged phase sends must get exactly the code
// the contract verifier gives it, with the gateway's trust (agent-a enrolled,
// agent-c revoked, agent-b unknown). Otherwise a failing live step could be
// the smoke's fault instead of the gateway's.
func TestForgedDeliveriesMatchContract(t *testing.T) {
	e := &agentEnv{gatewayName: "site-api"}
	seen := map[string]bool{}
	ctx := func() *verify.Context {
		return &verify.Context{
			Now:     time.Now().UTC(),
			Trust:   testkeys.TrustStore("agent-a", "agent-c", "site-a", "lab-a"),
			Revoked: func(k string) bool { return k == "test-agent-c" },
			Gateway: "site-api",
			Seen:    func(n string) bool { return seen[n] },
		}
	}
	valid := e.signReport("agent-a", nil)
	if _, err := verify.Signed(contract.KindAgentReport, valid, ctx()); err != nil {
		t.Fatalf("valid report rejected: %v", err)
	}
	// remember the nonce like a gateway does, then the same bytes are a replay
	for n := range nonces(t, valid) {
		seen[n] = true
	}
	cases := map[string][]byte{
		"replay": valid,
		"expired": e.signReport("agent-a", func(p, _ map[string]any) {
			p["issued_at"] = time.Now().UTC().Add(-6 * time.Minute).Format(time.RFC3339)
		}),
		"clock_skew": e.signReport("agent-a", func(p, _ map[string]any) { p["issued_at"] = time.Now().UTC().Add(5 * time.Minute).Format(time.RFC3339) }),
		"channel":    e.signReport("agent-a", func(p, _ map[string]any) { p["gateway"] = "other-gateway" }),
		"signature":  e.signReport("agent-b", nil),
		"revoked":    e.signReport("agent-c", nil),
		"forbidden_content": e.signReport("agent-a", func(_, r map[string]any) {
			r["findings"].([]any)[0].(map[string]any)["explanation"] = "PATH=/usr/bin HOME=/root SHELL=/bin/sh"
		}),
		"forbidden_field": e.signReport("agent-a", func(_, r map[string]any) { r["host"].(map[string]any)["environment"] = map[string]any{"LANG": "C"} }),
		"malformed":       []byte("{"),
	}
	cases["signature/impersonation"] = e.signReport("agent-a", func(_, r map[string]any) { r["host"].(map[string]any)["agent_key_id"] = "test-agent-c" })
	for want, raw := range cases {
		_, err := verify.Signed(contract.KindAgentReport, raw, ctx())
		code := string(contract.CodeOf(err))
		w := want
		if w == "signature/impersonation" {
			w = "signature"
		}
		if code != w {
			t.Errorf("%s: verifier says %q (%v)", want, code, err)
		}
	}
}

func nonces(t *testing.T, raw []byte) map[string]bool {
	t.Helper()
	res, err := verify.Signed(contract.KindAgentReport, raw, &verify.Context{Now: time.Now().UTC(), Trust: testkeys.TrustStore("agent-a")})
	if err != nil {
		t.Fatal(err)
	}
	a, ok := res.Value.(*hostcheck.AgentReport)
	if !ok {
		t.Fatalf("value %T", res.Value)
	}
	return map[string]bool{a.Nonce: true}
}

func TestCheckPlanted(t *testing.T) {
	f := func(id, subject string, ev hostcheck.Evidence) hostcheck.Finding {
		return hostcheck.Finding{ID: id, Subject: subject, Status: "finding", Evidence: ev}
	}
	r := &hostcheck.Report{
		Findings: []hostcheck.Finding{
			f("ssh.password_authentication", "", hostcheck.Evidence{}),
			f("ssh.permit_root_login", "", hostcheck.Evidence{}),
			f("ports.public_service", "tcp/3306", hostcheck.Evidence{Port: 3306}),
			f("software.runtime_eol", "php", hostcheck.Evidence{}),
			f("updates.security_pending", "", hostcheck.Evidence{Packages: []string{"curl", hostcanary.Package}}),
			{ID: "firewall.active", Status: "unreadable"},
		},
		Inventory: []hostcheck.InventoryItem{{Kind: "runtime", Name: "php", Version: "8.1.34"}},
	}
	if _, _, err := checkPlanted(r); err != nil {
		t.Fatalf("complete report: %v", err)
	}
	r.Findings = append(r.Findings, f("ports.public_service", "tcp/9000", hostcheck.Evidence{Port: 9000}))
	r.Findings[0].Status = "ok"
	_, _, err := checkPlanted(r)
	if err == nil || !strings.Contains(err.Error(), "ssh.password_authentication") || !strings.Contains(err.Error(), "loopback tcp/9000") {
		t.Fatalf("want both misses reported, got %v", err)
	}
}
