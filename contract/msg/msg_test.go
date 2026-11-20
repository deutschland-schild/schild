package msg

import (
	"regexp"
	"testing"
	"time"
)

func TestRequestSigCanonical(t *testing.T) {
	a := RequestSig(RequestShape{Method: "post", PathTemplate: "/wp-login.php", ParamNames: []string{"pwd", "log", "log"}, ContentType: "Application/X-WWW-Form-Urlencoded", RuleIDs: []int{949110, 930120}})
	b := RequestSig(RequestShape{Method: "POST", PathTemplate: "/wp-login.php", ParamNames: []string{"log", "pwd"}, ContentType: "application/x-www-form-urlencoded", RuleIDs: []int{930120, 949110, 930120}})
	if a != b {
		t.Fatal("order, case or duplicates change request_sig")
	}
	// Fixed value: changing the canonical form is a contract change.
	if b != "sha256:1ce928e7e35ea61e1a1e634babf6bc3a4da2ecd301152aa3ada4169905dbc08e" {
		t.Fatalf("request_sig changed: %s", b)
	}
	c := RequestSig(RequestShape{Method: "POST", PathTemplate: "/xmlrpc.php"})
	if c == b || !regexp.MustCompile(`^sha256:[0-9a-f]{64}$`).MatchString(c) {
		t.Fatal("request_sig")
	}
}

func TestTimeBucket(t *testing.T) {
	ts := time.Date(2026, 10, 26, 11, 58, 59, 0, time.FixedZone("CET", 3600))
	if got := TimeBucket(ts, 5); got != "2026-10-26T10:55:00Z" {
		t.Fatal(got)
	}
	if got := TimeBucket(ts, 15); got != "2026-10-26T10:45:00Z" {
		t.Fatal(got)
	}
	if got := TimeBucket(ts, 7); got != "2026-10-26T10:55:00Z" {
		t.Fatal("invalid size falls back to 5:", got)
	}
}

func TestParseTimeStrict(t *testing.T) {
	if got, err := ParseTime("2026-10-26T12:00:59Z"); err != nil || !got.Equal(time.Date(2026, 10, 26, 12, 0, 59, 0, time.UTC)) {
		t.Fatalf("valid: %v %v", got, err)
	}
	// time.Parse accepts a fractional second the layout does not name.
	for _, s := range []string{"2026-10-26T12:00:00.5Z", "2026-10-26T12:00:00,5Z", "2026-10-26T12:00:00.000000000Z",
		"2026-10-26T12:00:00", "2026-10-26 12:00:00Z", "2026-02-30T12:00:00Z", "2026-10-26T12:00:00+00:00"} {
		if _, err := ParseTime(s); err == nil {
			t.Errorf("%q accepted", s)
		}
	}
}

func TestIDsAndBuckets(t *testing.T) {
	re := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	for i := 0; i < 100; i++ {
		if id := NewID(); !re.MatchString(id) {
			t.Fatal(id)
		}
	}
	if !re.MatchString(NilID) {
		t.Fatal("NilID must match the uuid pattern")
	}
	for n, want := range map[int]string{0: "0-16", 16: "16-64", 255: "64-256", 1023: "256-1k", 4095: "1k-4k", 16383: "4k-16k", 1 << 20: "16k+"} {
		if LenBucket(n) != want {
			t.Errorf("LenBucket(%d)", n)
		}
	}
}

func TestEvidenceLevel(t *testing.T) {
	cases := []struct {
		class string
		e     Evidence
		want  string
	}{
		{"virtual_patch", Evidence{ReproducedOperators: 2, HumanApprovalOrgs: 2}, "block"},
		{"virtual_patch", Evidence{ReproducedOperators: 2, HumanApprovalOrgs: 1}, "challenge"},
		{"heuristic", Evidence{ReproducedOperators: 3, HumanApprovalOrgs: 3}, "challenge"},
		{"behavioral", Evidence{SensorOperators: 2}, "challenge"},
		{"behavioral", Evidence{SensorOperators: 1}, "observe"},
		{"behavioral", Evidence{TipIssuers: 3, MaxIssuerShare: 0.34}, "observe"},
		{"behavioral", Evidence{TipIssuers: 3, MaxIssuerShare: 0.35}, ""},
		{"behavioral", Evidence{TipIssuers: 2}, ""},
	}
	for _, c := range cases {
		if got := EvidenceLevel(c.class, c.e); got != c.want {
			t.Errorf("%s %+v: got %q want %q", c.class, c.e, got, c.want)
		}
	}
	if MaxActionRank("block") <= MaxActionRank("challenge") || MaxActionRank("x") != 0 {
		t.Fatal("rank")
	}
}

func TestWithdrawalApplies(t *testing.T) {
	all := Withdrawal{Scope: "all", UpToVersion: 42}
	if !all.Applies(42, "x") || all.Applies(43, "x") {
		t.Fatal("scope all")
	}
	one := Withdrawal{Scope: "rules", RuleIDs: []string{"schild-2026-0412"}, UpToVersion: 42}
	if !one.Applies(10, "schild-2026-0412") || one.Applies(10, "schild-2026-0413") {
		t.Fatal("scope rules")
	}
}

func TestForbiddenFieldSpellings(t *testing.T) {
	for _, k := range []string{"ip", "IP", "client_ip", "Client-IP", "clientIp", "client.ip", "X-Forwarded-For", "xForwardedFor", "REFERER", "key_id", "keyId"} {
		if !IsForbiddenField(k) {
			t.Errorf("%q not forbidden", k)
		}
	}
	for _, k := range []string{"origin", "location", "time_bucket", "request_sig", "match_shape", "ıp", "zip"} {
		if IsForbiddenField(k) {
			t.Errorf("%q wrongly forbidden", k)
		}
	}
}
