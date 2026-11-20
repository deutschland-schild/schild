package waitingpage

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/deutschland-schild/schild/contract/schema"
)

// TestRetryBounds: every draw gives 5..8 s and every value is reachable.
func TestRetryBounds(t *testing.T) {
	seen := map[int]bool{}
	for _, d := range []uint32{0, 1, 2, 3, 4, 1 << 31, 1<<32 - 1, 1<<32 - 2} {
		r := RetryAfter(d)
		if r < RetryMinS || r > RetryMaxS {
			t.Fatalf("draw %d: %d s", d, r)
		}
		seen[r] = true
	}
	if len(seen) != RetryJitterS+1 {
		t.Fatalf("values %v", seen)
	}
}

// TestOverloadReasons: the schema's reasons are the TrafficCounters
// fail_closed_by keys; only waf_busy and waf_timeout are overload.
func TestOverloadReasons(t *testing.T) {
	var doc struct {
		Properties struct {
			FailClosed struct {
				Enum []string `json:"enum"`
			} `json:"fail_closed"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(schema.Files()["waiting-page.schema.json"], &doc); err != nil {
		t.Fatal(err)
	}
	want := []string{ReasonWAFBusy, ReasonWAFTimeout, ReasonBodyBusy, ReasonNotReady, ReasonPanic}
	if strings.Join(doc.Properties.FailClosed.Enum, ",") != strings.Join(want, ",") {
		t.Fatalf("schema reasons %v", doc.Properties.FailClosed.Enum)
	}
	for _, r := range want {
		if Overload(r) != (r == ReasonWAFBusy || r == ReasonWAFTimeout || r == ReasonBodyBusy) {
			t.Errorf("Overload(%s)", r)
		}
	}
}

// TestCopy: both languages carry every text, the placeholders where the page
// needs them, and no incident number.
func TestCopy(t *testing.T) {
	for _, l := range []string{LangDE, LangEN} {
		c, ok := Texts[l]
		if !ok {
			t.Fatalf("no copy for %s", l)
		}
		for _, s := range []string{c.Title, c.Headline, c.Lead, c.LeadNoSite, c.NextReload, c.NextForm, c.Countdown, c.Footer} {
			if s == "" || strings.Contains(strings.ToLower(s), "vorfall") || strings.Contains(strings.ToLower(s), "incident") {
				t.Errorf("%s: %q", l, s)
			}
		}
		if !strings.Contains(c.Lead, "{site}") || strings.Contains(c.LeadNoSite, "{site}") || !strings.Contains(c.Countdown, "{n}") || !strings.Contains(c.Footer, "{time}") {
			t.Errorf("%s: placeholders", l)
		}
	}
	if Texts[LangDE].Headline != "Kurz Platz nehmen, bitte." {
		t.Error("headline chosen by the initiator")
	}
}

// TestDecideHEADAndPOST: spot checks next to the vectors.
func TestDecideHEADAndPOST(t *testing.T) {
	nav := Headers{SecFetchDest: "document", SecFetchMode: "navigate"}
	r := Decide(Input{Reason: ReasonWAFBusy, Enabled: true, Method: "POST", Headers: nav, Host: "a.example", Website: "a.example"})
	if r.Answer != AnswerWaitingPage || *r.Variant != VariantForm || r.Refresh != nil || !*r.Body {
		t.Fatalf("POST: %+v", r)
	}
	r = Decide(Input{Reason: ReasonWAFTimeout, Enabled: true, Method: "HEAD", Headers: nav, JitterDraw: 3})
	if r.Answer != AnswerWaitingPage || *r.Body || *r.Refresh != 8 || r.SiteName != nil {
		t.Fatalf("HEAD: %+v", r)
	}
	if r := Decide(Input{Reason: ReasonWAFBusy, Method: "GET", Headers: nav}); r.Answer != AnswerUnchanged {
		t.Fatalf("disabled: %+v", r)
	}
}
