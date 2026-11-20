package crowdsec

// Measured cost of a whole set (D43, contracts/crowdsec-hub.md section 6). The
// bounds of one rule and of a set hold for a hostile index that together
// stops the gate, so a candidate is also timed on a fixed probe set before it
// goes live. The timing is the gateway's; the verdict on the numbers is a pure
// function here, so the vectors can fix it. All times in one sample come from
// the same machine at the same moment, which is why a slow or busy machine
// does not refuse a normal set.
const (
	// CostMaxRatio: the time a candidate adds per probe request may be at most
	// this many times the time the image snapshot adds.
	CostMaxRatio = 4
	// CostFloorPercent: the snapshot counts as adding at least this share of
	// the baseline, so timer noise on a very fast machine, a tiny snapshot or
	// no snapshot at all do not make the bound collapse towards zero.
	CostFloorPercent = 200
	// CostRounds is the number of rounds of the probe set; the fastest time of
	// each probe counts, which is what stays when other work disturbs a round.
	CostRounds = 16
	// CostEarlyRounds: from this round on the measurement may end early with a
	// set more than twice over the bound.
	CostEarlyRounds = 4
	// CostBudgetS ends the measurement of a set too slow to finish its rounds.
	// A set that did not finish one round is refused.
	CostBudgetS = 15
)

// CostSample is one comparison: nanoseconds per probe request on an instance
// with no hub rules (baseline), with the image snapshot (reference, equal to
// the baseline without a snapshot) and with the candidate.
type CostSample struct {
	BaselineNS  int64 `json:"baseline_ns"`
	ReferenceNS int64 `json:"reference_ns"`
	CandidateNS int64 `json:"candidate_ns"`
	Rounds      int   `json:"rounds"` // finished rounds
}

// CostVerdict is the decision on a sample.
type CostVerdict struct {
	Outcome   string `json:"outcome"` // accepted | refused
	Code      string `json:"code,omitempty"`
	AddedNS   int64  `json:"added_ns"`   // what the candidate adds per request
	AllowedNS int64  `json:"allowed_ns"` // what it may add
}

// CheckSetCost decides on a measured sample.
func CheckSetCost(s CostSample) CostVerdict {
	added := max(s.CandidateNS-s.BaselineNS, 0)
	ref := max(s.ReferenceNS-s.BaselineNS, s.BaselineNS*CostFloorPercent/100)
	v := CostVerdict{Outcome: "accepted", AddedNS: added, AllowedNS: ref * CostMaxRatio}
	if s.Rounds < 1 || added > v.AllowedNS {
		v.Outcome, v.Code = "refused", RefuseCost
	}
	return v
}

// CostProbe is one request of the probe set.
type CostProbe struct {
	Method      string
	Target      string
	ContentType string
	Body        string
}

// CostProbeHeaders go with every probe, as a browser sends them.
var CostProbeHeaders = map[string]string{
	"Host":            "www.example.test",
	"User-Agent":      "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
	"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
	"Accept-Language": "de-DE,de;q=0.9,en;q=0.5",
	"Accept-Encoding": "gzip, deflate, br",
	"Referer":         "https://www.example.test/shop/angebote",
	"Cookie":          "session=2f1c9d7ab04e4d51; consent=essential; cart=3",
}

const multipartBoundary = "schild-cost-probe"

// CostProbes is the fixed probe set. Every zone a hub rule can read appears at
// least once; no value is an attack, because a match is not what is measured.
var CostProbes = []CostProbe{
	{Method: "GET", Target: "/"},
	{Method: "GET", Target: "/suche?q=blaue+schuhe&seite=2&sortierung=preis&utm_source=newsletter"},
	{Method: "GET", Target: "/wp-content/themes/shop/style.css?ver=6.4.2"},
	{Method: "POST", Target: "/kontakt", ContentType: "application/x-www-form-urlencoded",
		Body: "_token=8fKq2mXvZt&name=Erika+Mustermann&email=erika%40example.test&firma=Beispiel+GmbH&telefon=0301234567&betreff=Angebot&nachricht=Guten+Tag%2C+ich+habe+eine+Frage.&einwilligung=1"},
	{Method: "POST", Target: "/livewire/update", ContentType: "application/json",
		Body: `{"_token":"8fKq2mXvZt","components":[{"snapshot":"{\"data\":{\"search\":\"\",\"page\":1},\"memo\":{\"id\":\"a1b2c3\",\"name\":\"shop.product-list\",\"path\":\"shop\",\"method\":\"GET\",\"locale\":\"de\"}}","updates":{"search":"blaue schuhe"},"calls":[{"method":"gotoPage","params":[2],"metadata":{}}]}]}`},
	{Method: "POST", Target: "/konto/bild", ContentType: "multipart/form-data; boundary=" + multipartBoundary,
		Body: "--" + multipartBoundary + "\r\nContent-Disposition: form-data; name=\"_token\"\r\n\r\n8fKq2mXvZt\r\n--" + multipartBoundary +
			"\r\nContent-Disposition: form-data; name=\"datei\"; filename=\"foto.png\"\r\nContent-Type: image/png\r\n\r\nschild-probe-bytes\r\n--" + multipartBoundary + "--\r\n"},
}
