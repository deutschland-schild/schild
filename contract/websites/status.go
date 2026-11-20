package websites

// Status rules of a website (D36). Conservative and explainable: every
// status comes with the reasons that caused it, in a fixed order, so the
// dashboard can say why ("gestört: Schild antwortet mit 503", "bitte
// ansehen: web-1: Platte fast voll").

// Website status values (OpenAPI WebsiteStatus).
const (
	StatusOK        = "ok"        // UI: "läuft"
	StatusAttention = "attention" // UI: "bitte ansehen"
	StatusDisrupted = "disrupted" // UI: "gestört"
	StatusUnknown   = "unknown"   // UI: "keine Messwerte"
)

// Reason codes (OpenAPI WebsiteStatusReasonCode), in the order they are
// checked.
const (
	ReasonUnprotected         = "unprotected"          // unknown: schild sees none of its requests
	ReasonNoServer            = "no_server"            // unknown: no gateway serves it
	ReasonNotReady            = "not_ready"            // a gateway answers 503 (gate not ready)
	ReasonBaselineOff         = "baseline_off"         // a gateway runs without its WAF (fails closed)
	ReasonUnreachable         = "unreachable"          // MVP-20: a gateway does not answer the central dashboard
	ReasonFailClosed          = "fail_closed"          // >= 5 % of requests answered 503 by schild (and >= 10)
	ReasonUpstreamUnreachable = "upstream_unreachable" // >= 20 % of forwarded requests got no answer or a timeout from the app (and >= 10)
	ReasonErrors5xx           = "errors_5xx"           // >= 20 % of requests answered 5xx (and >= 10)
	ReasonSiteHint            = "site_hint"            // a hint of this website
	ReasonBaselineDegraded    = "baseline_degraded"    // a gateway's baseline protection is degraded
	ReasonServerHint          = "server_hint"          // a hint of a gateway it runs on
	ReasonMonitoringOff       = "monitoring_off"       // unknown: no counters
	ReasonUntracked           = "untracked"            // unknown: beyond the first 32 websites, counted in _other
	ReasonNoData              = "no_data"              // unknown: counters not available yet
)

// Thresholds over the 5-minute window (integers, so every implementation
// computes the same verdict).
const (
	WindowS          = 300
	MinCount         = 10 // at least this many affected requests
	FailClosedPerMil = 50 // 5 %
	UpstreamPerMil   = 200
	Errors5xxPerMil  = 200
)

// ServerOnlyHintCodes (D36 open items and D38, 2026-10-29) mark only the
// server (ServerStatus) and never reach its websites: they are about
// schild's own event store, which does not change how a website is
// served. Every other server-wide hint still marks every website on the
// server (disk_full_soon, disk_fill_projection, ...).
var ServerOnlyHintCodes = map[string]bool{"store_near_cap": true, "store_cap_unreachable": true, "storage_budget": true}

// Traffic of a website in the window.
type Traffic struct {
	Requests         int64 `json:"requests"`
	Forwarded        int64 `json:"forwarded"`
	FailClosed       int64 `json:"fail_closed"`
	UpstreamErrors   int64 `json:"upstream_errors"`
	UpstreamTimeouts int64 `json:"upstream_timeouts"`
	Status5xx        int64 `json:"status_5xx"`
}

// Hint is a HealthHint as the status rules see it.
type Hint struct {
	Code   string `json:"code"`
	Level  string `json:"level"`
	Object string `json:"object,omitempty"`
}

// Server is one gateway the website runs on.
type Server struct {
	Node     string `json:"node"`
	State    string `json:"state"`               // ok | not_ready | unreachable
	Baseline string `json:"baseline_protection"` // active | degraded | off
	Hints    []Hint `json:"hints"`
}

// StatusInput of Status.
type StatusInput struct {
	Protection string   `json:"protection"`
	Tracked    bool     `json:"tracked"`
	Monitoring bool     `json:"monitoring"`
	Traffic    *Traffic `json:"traffic,omitempty"`
	SiteHints  []Hint   `json:"site_hints,omitempty"`
	Servers    []Server `json:"servers"`
}

// Reason is one reason of a status.
type Reason struct {
	Code   string `json:"code"`
	Node   string `json:"node,omitempty"`
	Hint   string `json:"hint,omitempty"`
	Object string `json:"object,omitempty"`
}

// StatusResult of Status.
type StatusResult struct {
	Status  string   `json:"status"`
	Reasons []Reason `json:"reasons"`
}

func atLeast(n, total, perMil int64) bool {
	return n >= MinCount && n*1000 >= perMil*total
}

// Status applies the rules:
//
//  1. unprotected: unknown (unprotected); no gateway: unknown (no_server).
//  2. A gateway is down when its state is not ok or its baseline protection is off
//     (reason not_ready, unreachable or baseline_off). All gateways down:
//     disrupted; some: attention.
//  3. With numbers (monitoring on, tracked, traffic present): fail_closed
//     >= 5 %, upstream errors and timeouts >= 20 % of forwarded, 5xx >= 20 %,
//     each with at least 10 requests: disrupted.
//  4. Every website hint (site_hint), a degraded baseline protection on a gateway
//     that is up (baseline_degraded) and every hint of a gateway
//     (server_hint) except ServerOnlyHintCodes: attention.
//  5. Otherwise ok; without numbers unknown (monitoring_off, untracked or
//     no_data).
//
// Reasons: those that decide the status first (disrupted ones), then the
// attention ones, each group in the order above and servers in input order.
func Status(in StatusInput) StatusResult {
	if in.Protection == Unprotected {
		return StatusResult{StatusUnknown, []Reason{{Code: ReasonUnprotected}}}
	}
	if len(in.Servers) == 0 {
		return StatusResult{StatusUnknown, []Reason{{Code: ReasonNoServer}}}
	}
	var hard, soft []Reason
	var downs []Reason
	for _, s := range in.Servers {
		switch {
		case s.State != "ok":
			downs = append(downs, Reason{Code: s.State, Node: s.Node})
		case s.Baseline == "off":
			downs = append(downs, Reason{Code: ReasonBaselineOff, Node: s.Node})
		}
	}
	if len(downs) == len(in.Servers) {
		hard = append(hard, downs...)
	} else {
		soft = append(soft, downs...)
	}
	numbers := in.Monitoring && in.Tracked && in.Traffic != nil
	if numbers {
		t := in.Traffic
		if atLeast(t.FailClosed, t.Requests, FailClosedPerMil) {
			hard = append(hard, Reason{Code: ReasonFailClosed})
		}
		if atLeast(t.UpstreamErrors+t.UpstreamTimeouts, t.Forwarded, UpstreamPerMil) {
			hard = append(hard, Reason{Code: ReasonUpstreamUnreachable})
		}
		if atLeast(t.Status5xx, t.Requests, Errors5xxPerMil) {
			hard = append(hard, Reason{Code: ReasonErrors5xx})
		}
	}
	for _, h := range in.SiteHints {
		soft = append(soft, Reason{Code: ReasonSiteHint, Hint: h.Code, Object: h.Object})
	}
	for _, s := range in.Servers {
		if s.State == "ok" && s.Baseline == "degraded" {
			soft = append(soft, Reason{Code: ReasonBaselineDegraded, Node: s.Node})
		}
		for _, h := range s.Hints {
			if ServerOnlyHintCodes[h.Code] {
				continue
			}
			soft = append(soft, Reason{Code: ReasonServerHint, Node: s.Node, Hint: h.Code, Object: h.Object})
		}
	}
	switch {
	case len(hard) > 0:
		return StatusResult{StatusDisrupted, append(hard, soft...)}
	case len(soft) > 0:
		return StatusResult{StatusAttention, soft}
	case !in.Monitoring:
		return StatusResult{StatusUnknown, []Reason{{Code: ReasonMonitoringOff}}}
	case !in.Tracked:
		return StatusResult{StatusUnknown, []Reason{{Code: ReasonUntracked}}}
	case in.Traffic == nil:
		return StatusResult{StatusUnknown, []Reason{{Code: ReasonNoData}}}
	}
	return StatusResult{StatusOK, []Reason{}}
}

// ServerStatus is the status of one gateway in runs_on and on the Server
// page: disrupted when it is down (state not ok or baseline protection off),
// attention with a degraded baseline protection or any hint, else ok.
func ServerStatus(s Server) string {
	switch {
	case s.State != "ok" || s.Baseline == "off":
		return StatusDisrupted
	case s.Baseline == "degraded" || len(s.Hints) > 0:
		return StatusAttention
	}
	return StatusOK
}

// RunStatusVector parses and validates a website-status vector input and
// returns the status.
func RunStatusVector(raw []byte) (StatusResult, error) {
	v, err := parse(raw, SchemaStatus)
	if err != nil {
		return StatusResult{}, err
	}
	in := StatusInput{Protection: v["protection"].(string), Tracked: v["tracked"].(bool), Monitoring: v["monitoring"].(bool)}
	if t, ok := v["traffic"].(map[string]any); ok {
		n := func(k string) int64 {
			x, _ := t[k].(interface{ Int64() (int64, error) }).Int64()
			return x
		}
		in.Traffic = &Traffic{Requests: n("requests"), Forwarded: n("forwarded"), FailClosed: n("fail_closed"),
			UpstreamErrors: n("upstream_errors"), UpstreamTimeouts: n("upstream_timeouts"), Status5xx: n("status_5xx")}
	}
	in.SiteHints = hints(v["site_hints"])
	seen := map[string]bool{}
	for _, x := range arr(v["servers"]) {
		m := x.(map[string]any)
		s := Server{Node: m["node"].(string), State: m["state"].(string), Baseline: m["baseline_protection"].(string), Hints: hints(m["hints"])}
		if seen[s.Node] {
			return StatusResult{}, schemaErr("servers: node %q twice", s.Node)
		}
		seen[s.Node] = true
		in.Servers = append(in.Servers, s)
	}
	return Status(in), nil
}

func hints(v any) []Hint {
	var out []Hint
	for _, x := range arr(v) {
		m := x.(map[string]any)
		h := Hint{Code: m["code"].(string), Level: m["level"].(string)}
		if o, ok := m["object"].(string); ok {
			h.Object = o
		}
		out = append(out, h)
	}
	return out
}
