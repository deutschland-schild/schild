package waf

import (
	"strings"
	"testing"
)

func TestMultiContentTypeJSONStructureChecked(t *testing.T) {
	inst := crs(t)
	deep := strings.Repeat("[", 20) + "1" + strings.Repeat("]", 20)
	lim := Limits{Body: 1 << 20, JSONDepth: 10}

	for _, tc := range []struct {
		name   string
		values []string
		body   string
		want   error
	}{
		{"deep json second header", []string{"text/plain", "application/json"}, deep, ErrJSONTooDeep},
		{"deep +json second header", []string{"text/plain", "application/problem+json; charset=utf-8"}, deep, ErrJSONTooDeep},
		{"malformed json second header", []string{"text/plain", "application/json"}, `{"a":`, ErrBodyUnparseable},
		{"valid json second header", []string{"text/plain", "application/json"}, `{"ok":true}`, nil},
		{"invalid utf8 form second header", []string{"text/plain", "application/x-www-form-urlencoded"}, "a=%ff", nil},
		// Prefix matches of rules 200001 and 200006 that Go parses as no media type.
		{"deep json, junk after the subtype", []string{"application/json x"}, deep, ErrJSONTooDeep},
		{"deep +json, junk after the subtype", []string{"application/vnd.api+json x"}, deep, ErrJSONTooDeep},
		{"malformed +json, longer subtype", []string{"application/a+json-seq"}, `{"a":`, ErrBodyUnparseable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := parseRequest(tc.values, tc.body)
			tx, _ := inst.NewTransaction()
			defer tx.Close()
			ProcessHeaders(tx, r, "192.0.2.1", 40000)
			_, _, err := ReadBodyInfo(tx, r, lim)
			if err != tc.want {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

func TestPlusXMLActivatesXMLProcessor(t *testing.T) {
	const xmlRule = 1002
	inst, err := Build(Config{
		CRS:              true,
		ParanoiaLevel:    1,
		AnomalyThreshold: 5,
		BodyLimit:        1 << 20,
		LocalRules:       `SecRule REQBODY_PROCESSOR "@streq XML" "id:1002,phase:2,pass,log,msg:'xml parser'"`,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, ct := range []string{
		"application/xml",
		"application/soap+xml",
		"application/vnd.bank+xml; charset=utf-8",
	} {
		t.Run(ct, func(t *testing.T) {
			r := parseRequest([]string{ct}, `<root><x>1</x></root>`)
			tx, _ := inst.NewTransaction()
			defer tx.Close()
			ProcessHeaders(tx, r, "192.0.2.1", 40000)
			if _, _, err := tx.ReadRequestBodyFrom(r.Body); err != nil {
				t.Fatal(err)
			}
			if _, err := tx.ProcessRequestBody(); err != nil {
				t.Fatal(err)
			}
			a := inst.Analyze(tx.MatchedRules())
			var matched bool
			for _, m := range a.Matches {
				if m.ID == xmlRule {
					matched = true
				}
			}
			if !matched {
				t.Fatalf("Content-Type %q did not activate XML request body processor", ct)
			}
		})
	}
}
