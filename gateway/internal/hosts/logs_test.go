//go:build !release

package hosts

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/contract"
	hc "github.com/deutschland-schild/schild/contract/hostcheck"
	"github.com/deutschland-schild/schild/contract/testkeys"
)

// TestIngestFixConfig (v0.5, D38): an agent report whose logs findings
// carry a fix_config rendered from the gateway templates is accepted and
// stored as sent; any other fix_config (another template, an added line, a
// path outside the roots) is rejected with schema and nothing is stored.
func TestIngestFixConfig(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	g := newGW(t, "gw-1", now, 30, "")
	id := g.enrolKey(t, "agent-a", "enrolled")
	a := testkeys.Signer("agent-a")
	pt := contract.KindAgentReport.PayloadType()

	rule := func(file string) string {
		return file + " {\n  daily\n  rotate 7\n  maxsize 500M\n  missingok\n  notifempty\n  compress\n  delaycompress\n  copytruncate\n}\n"
	}
	logsFinding := func(fc *hc.FixConfig) hc.Finding {
		sz := int64(6 << 30)
		return hc.Finding{ID: "logs.large_file", Area: "logs", Subject: "/var/log/app/big.log", Severity: "medium", Status: hc.StatusFinding,
			Title: "Große Logdatei ohne Rotation", Explanation: "/var/log/app/big.log ist 6,0 GB groß. Keine logrotate-Regel erfasst die Datei.",
			FixConfig: fc, Evidence: hc.Evidence{Source: "stat", Path: "/var/log/app/big.log", SizeBytes: &sz}}
	}
	cases := []struct {
		name string
		fc   *hc.FixConfig
		want string
	}{
		{"template rendering", &hc.FixConfig{Path: "/etc/logrotate.d/schild-app-big", Content: rule("/var/log/app/big.log")}, "accepted"},
		{"added line", &hc.FixConfig{Path: "/etc/logrotate.d/schild-app-big", Content: rule("/var/log/app/big.log") + "/etc/shadow { copytruncate }\n"}, "rejected:schema"},
		{"vendor file", &hc.FixConfig{Path: "/etc/logrotate.d/rsyslog", Content: rule("/var/log/app/big.log")}, "rejected:schema"},
		{"outside the roots", &hc.FixConfig{Path: "/etc/logrotate.d/schild-passwd", Content: rule("/etc/passwd")}, "rejected:schema"},
		{"other id's template", &hc.FixConfig{Path: "/etc/docker/daemon.json", Content: `{"log-driver": "local", "log-opts": {"max-size": "10m", "max-file": "5"}}` + "\n"}, "rejected:schema"},
	}
	accepted := 0
	for i, tc := range cases {
		p := reviewReport(t, now, a.KeyID(), "gw-1", nonceN(100+i))
		p.Report.Findings = append(p.Report.Findings, logsFinding(tc.fc))
		code, got := serve(t, g, "/v0/agent/report", fmt.Sprintf("10.66.2.%d", i+1), signAs(t, pt, p, a))
		if got != tc.want {
			t.Errorf("%s: got %s (HTTP %d), want %s", tc.name, got, code, tc.want)
		}
		if got == "accepted" {
			accepted++
		}
	}
	if h := historyLen(t, g, id); h != accepted {
		t.Fatalf("%d reports stored, want %d", h, accepted)
	}
	d, err := g.Host(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(d.Report)
	var r hc.Report
	if err := json.Unmarshal(b, &r); err != nil {
		t.Fatal(err)
	}
	var found bool
	for i, f := range r.Findings {
		if f.ID != "logs.large_file" || f.Subject != "/var/log/app/big.log" {
			continue
		}
		found = true
		if f.FixConfig == nil || f.FixConfig.Path != "/etc/logrotate.d/schild-app-big" {
			t.Errorf("fix_config not stored: %+v", f.FixConfig)
		}
		an := d.Annotations[i]
		if an.Title == nil || *an.Title != "Große Logdatei ohne Rotation" {
			t.Errorf("annotation %+v", an)
		}
	}
	if !found {
		t.Fatal("logs finding missing in the stored report")
	}
}
