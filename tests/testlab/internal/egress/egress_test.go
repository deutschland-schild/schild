package egress

import (
	"strings"
	"testing"
)

// A real schild.signal/0.3 payload as the client sends it (positive list only).
const cleanLine = `{"type":"schild.signal.sent.v1","data":{"kind":"signal","envelope_sha256":"aa","result":"accepted","payload":{"schema":"schild.signal/0.3","id":"0f8f3c3e-6c1e-4d55-9d38-1c2b8f2a7a10","kind":"tip","time_bucket":"2026-10-26T18:30:00Z","action_sig":"sqli/api","request_sig":"sha256:6f1ed002ab5595859014ebf0951522d9bdcf2b3c1c8d3c8f1a5b6c7d8e9f0a1b","waf_rules":[942100,949110],"score":45,"category":"sqli","origin":{"country":"NL","asn":64500,"net_class":"hosting","attribution":"trusted_proxy","protected":false},"agent":{"family":"python-requests","major":2,"bot":true}}}}`

func TestCleanLogHasNoFindings(t *testing.T) {
	ck := New([]string{"CANARY-DEADBEEF"}, nil)
	rep, err := ck.CheckLog(strings.NewReader(cleanLine + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK() || rep.Signals != 1 {
		t.Fatalf("clean log flagged: %+v", rep)
	}
}

func TestCanaryLeakDetected(t *testing.T) {
	leak := `{"type":"schild.signal.sent.v1","data":{"kind":"signal","envelope_sha256":"bb","result":"accepted","payload":{"schema":"schild.signal/1","category":"sqli","note":"CANARY-DEADBEEF"}}}`
	ck := New([]string{"CANARY-DEADBEEF"}, nil)
	rep, _ := ck.CheckLog(strings.NewReader(leak + "\n"))
	if rep.CanaryFindings == 0 {
		t.Fatalf("canary leak not detected: %+v", rep)
	}
}

func TestIPLeakDetected(t *testing.T) {
	leak := `{"type":"schild.signal.sent.v1","data":{"payload":{"schema":"schild.signal/1","agent":"203.0.113.9"}}}`
	ck := New(nil, nil)
	rep := ck.CheckPayload([]byte(`{"schema":"schild.signal/1","agent":"203.0.113.9"}`), "t")
	if rep.IPFindings == 0 {
		t.Fatalf("ipv4 leak not detected: %+v", rep)
	}
	_ = leak
	rep6 := ck.CheckPayload([]byte(`{"schema":"schild.signal/1","agent":"2001:db8::1"}`), "t")
	if rep6.IPFindings == 0 {
		t.Fatalf("ipv6 leak not detected: %+v", rep6)
	}
}

func TestForbiddenFieldDetected(t *testing.T) {
	ck := New(nil, nil)
	rep := ck.CheckPayload([]byte(`{"schema":"schild.signal/1","client_ip":"x","category":"xss"}`), "t")
	if rep.FieldFindings == 0 {
		t.Fatalf("forbidden field not detected: %+v", rep)
	}
}

func TestPositiveListPasses(t *testing.T) {
	ck := New(nil, nil)
	rep := ck.CheckPayload([]byte(`{"schema":"schild.signal/0.3","id":"x","kind":"tip","time_bucket":"2026-10-26T18:35:00Z","category":"sqli","waf_rules":[942100],"score":5,"origin":{"country":"DE","asn":64496,"attribution":"tcp_peer"},"agent":{"family":"firefox","major":131,"bot":false}}`), "t")
	if !rep.OK() {
		t.Fatalf("positive-list payload flagged: %+v", rep)
	}
	fb := ck.CheckPayload([]byte(`{"schema":"schild.feedback/0.2","id":"x","time_bucket":"2026-10-26T18:35:00Z","rule_id":"schild-2026-0001","verdict":"false_positive","match_shape":{"location":"ARGS:q"}}`), "t")
	if !fb.OK() {
		t.Fatalf("feedback payload flagged: %+v", fb)
	}
}

func TestFieldsOutsideTheSignalContract(t *testing.T) {
	ck := New(nil, nil)
	for _, p := range []string{
		`{"schema":"schild.signal/0.3","site":"a.example"}`,
		`{"schema":"schild.signal/0.3","count":3}`,
		`{"schema":"schild.signal/0.3","origin":{"country":"DE","city":"Berlin"}}`,
		`{"schema":"schild.signal/0.3","agent":{"family":"curl","ua":"curl/8.0"}}`,
		`{"schema":"schild.feedback/0.2","match_shape":{"location":"ARGS:q","value":"x"}}`,
	} {
		if rep := ck.CheckPayload([]byte(p), "t"); rep.FieldFindings == 0 {
			t.Errorf("field outside the contract not detected: %s", p)
		}
	}
}

func TestTimestampsAreNotAddresses(t *testing.T) {
	ck := New(nil, nil)
	rep := ck.CheckPayload([]byte(`{"schema":"schild.signal/0.3","time_bucket":"2026-10-26T18:30:00Z"}`), "t")
	if rep.IPFindings != 0 {
		t.Fatalf("timestamp flagged as address: %+v", rep)
	}
	for _, leak := range []string{"::ffff:203.0.113.9", "fe80::1", "2001:db8:0:0:0:0:0:17"} {
		if r := ck.CheckPayload([]byte(`{"schema":"schild.signal/0.3","category":"`+leak+`"}`), "t"); r.IPFindings == 0 {
			t.Errorf("ipv6 leak %s not detected", leak)
		}
	}
}

func TestForbiddenIPString(t *testing.T) {
	ck := New(nil, []string{"10.66.20.5"})
	rep := ck.CheckPayload([]byte(`{"schema":"schild.signal/1","note":"10.66.20.5"}`), "t")
	if rep.IPFindings == 0 {
		t.Fatalf("forbidden source IP not detected: %+v", rep)
	}
}
