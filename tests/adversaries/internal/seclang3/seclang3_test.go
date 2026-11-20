package seclang3

import (
	"testing"

	"github.com/deutschland-schild/schild/contract/seclang"
)

// forbidden rules: seclang3 must flag each, and the reference validator must
// reject each. If the reference accepted one, that is a validator bypass.
var forbidden = []struct {
	name string
	text string
	max  string
}{
	{"ctl", `SecRule ARGS "@detectSQLi" "id:7700001,phase:2,deny,severity:CRITICAL,msg:'x',ctl:ruleEngine=Off"`, "block"},
	{"allow", `SecRule REQUEST_URI "@beginsWith /admin" "id:7700002,phase:1,allow,severity:NOTICE,msg:'x'"`, "block"},
	{"nolog", `SecRule ARGS "@detectXSS" "id:7700003,phase:2,deny,severity:CRITICAL,msg:'x',nolog"`, "block"},
	{"setvar-bad", `SecRule ARGS "@detectSQLi" "id:7700004,phase:2,deny,severity:CRITICAL,msg:'x',setvar:tx.anomaly_score=0"`, "block"},
	{"logdata-macro", `SecRule ARGS "@detectSQLi" "id:7700005,phase:2,deny,severity:CRITICAL,msg:'x',logdata:'%{ARGS.password}'"`, "block"},
	{"msg-macro", `SecRule ARGS "@detectSQLi" "id:7700006,phase:2,deny,severity:CRITICAL,msg:'%{REQUEST_HEADERS.Cookie}'"`, "block"},
	{"op-macro", `SecRule REQUEST_URI "@streq %{REMOTE_ADDR}" "id:7700007,phase:1,deny,severity:CRITICAL,msg:'x'"`, "block"},
	{"remote-addr", `SecRule REMOTE_ADDR "@rx ^203\.0\.113\." "id:7700008,phase:1,deny,severity:CRITICAL,msg:'x'"`, "block"},
	{"server-name", `SecRule SERVER_NAME "@streq shop.example" "id:7700009,phase:1,deny,severity:CRITICAL,msg:'x'"`, "block"},
	{"geo", `SecRule GEO:COUNTRY_CODE "@streq RU" "id:7700010,phase:1,deny,severity:CRITICAL,msg:'x'"`, "block"},
	{"tx", `SecRule TX:score "@gt 1" "id:7700011,phase:2,deny,severity:CRITICAL,msg:'x'"`, "block"},
	{"host-header", `SecRule REQUEST_HEADERS:Host "@streq shop.example" "id:7700012,phase:1,deny,severity:CRITICAL,msg:'x'"`, "block"},
	{"xff-header", `SecRule REQUEST_HEADERS:X-Forwarded-For "@contains 192.0.2.1" "id:7700013,phase:1,deny,severity:CRITICAL,msg:'x'"`, "block"},
	{"all-headers", `SecRule REQUEST_HEADERS "@contains shop.example" "id:7700014,phase:1,deny,severity:CRITICAL,msg:'x'"`, "block"},
	{"ipmatch", `SecRule REQUEST_URI "@ipMatch 198.51.100.0/24" "id:7700015,phase:1,deny,severity:CRITICAL,msg:'x'"`, "block"},
	{"geolookup", `SecRule REQUEST_URI "@geoLookup" "id:7700016,phase:1,deny,severity:CRITICAL,msg:'x'"`, "block"},
	{"unconditional", `SecRule REQUEST_URI "@unconditionalMatch" "id:7700017,phase:1,deny,severity:CRITICAL,msg:'x'"`, "block"},
	{"catch-all-dotstar", `SecRule REQUEST_URI "@rx .*" "id:7700018,phase:1,deny,severity:CRITICAL,msg:'x'"`, "block"},
	{"catch-all-caret", `SecRule REQUEST_URI "@rx ^" "id:7700019,phase:1,deny,severity:CRITICAL,msg:'x'"`, "block"},
	{"catch-all-optional", `SecRule ARGS "@rx a?" "id:7700020,phase:2,deny,severity:CRITICAL,msg:'x'"`, "block"},
	{"secaction", `SecAction "id:7700021,phase:1,pass,severity:NOTICE,msg:'x'"`, "observe"},
	{"include", `Include /etc/passwd`, "block"},
	{"exec", `SecRule ARGS "@rx foo" "id:7700022,phase:2,deny,severity:CRITICAL,msg:'x',exec:/bin/sh"`, "block"},
}

func TestForbiddenFlaggedAndRejected(t *testing.T) {
	for _, f := range forbidden {
		findings := Check(f.text)
		if len(findings) == 0 {
			t.Errorf("%s: seclang3 did not flag a forbidden construct: %q", f.name, f.text)
		}
		if _, err := seclang.Validate(f.text, seclang.Options{MaxAction: f.max}); err == nil {
			t.Errorf("BYPASS %s: reference validator ACCEPTED a forbidden rule: %q", f.name, f.text)
		}
	}
}

// Known-good rules: seclang3 must not flag them (soundness: no false
// forbidden-construct claims that would create false bypass reports).
var good = []string{
	`SecRule ARGS "@detectSQLi" "id:7700001,phase:2,deny,status:403,severity:CRITICAL,msg:'sqli',t:none,t:urlDecodeUni,setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}"`,
	`SecRule REQUEST_FILENAME "@rx \.(php|phtml|phar)$" "id:7700002,phase:1,block,severity:ERROR,msg:'php upload'"`,
	`SecRule REQUEST_HEADERS:User-Agent "@pm sqlmap nikto nuclei" "id:7700003,phase:1,pass,log,severity:NOTICE,msg:'scanner ua'"`,
	`SecRule REQUEST_COOKIES|!REQUEST_COOKIES:wp_settings|ARGS "@detectXSS" "id:7700004,phase:2,block,severity:2,msg:'xss',tag:'xss'"`,
}

func TestGoodNotFlagged(t *testing.T) {
	for _, g := range good {
		if fs := Check(g); len(fs) != 0 {
			t.Errorf("seclang3 falsely flagged a valid rule %q: %+v", g, fs)
		}
		if _, err := seclang.Validate(g, seclang.Options{MaxAction: "observe"}); err != nil {
			// not fatal for this test, but surfaces a mismatch
			t.Logf("note: reference rejected the known-good sample under observe: %v", err)
		}
	}
}
