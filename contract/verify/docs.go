package verify

import (
	"encoding/json"
	"fmt"

	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/bodylimit"
	"github.com/deutschland-schild/schild/contract/hostcheck"
	"github.com/deutschland-schild/schild/contract/jsonx"
	"github.com/deutschland-schild/schild/contract/keys"
	"github.com/deutschland-schild/schild/contract/logtree"
	"github.com/deutschland-schild/schild/contract/msg"
	"github.com/deutschland-schild/schild/contract/peerauth"
	"github.com/deutschland-schild/schild/contract/schema"
)

// Doc names an unsigned contract document.
type Doc string

const (
	DocSubmission Doc = "submission"
	DocStream     Doc = "stream"
	DocEvent      Doc = "events"
	DocConfigSite Doc = "config/schild"
	DocConfigLab  Doc = "config/lab"
	DocResults    Doc = "results"
	// v0.1 (cosign.md)
	DocLogTree     Doc = "log-tree"
	DocPeerRequest Doc = "peer-request"
	// v0.3 (host-check.md)
	DocHostReport Doc = "host-report"
	DocAgentAck   Doc = "agent-ack"
)

// MaxBytes returns the size limit of a document kind.
func (d Doc) MaxBytes() int {
	switch d {
	case DocSubmission:
		return contract.MaxSubmissionBytes
	case DocStream:
		return contract.MaxStreamEventBytes
	case DocEvent:
		return contract.MaxLocalEventBytes
	case DocConfigSite, DocConfigLab:
		return contract.MaxConfigBytes
	case DocResults:
		return contract.MaxResultsBytes
	case DocLogTree:
		return contract.MaxLogTreeBytes
	case DocPeerRequest:
		return contract.MaxPeerRequestBytes
	case DocHostReport:
		return contract.MaxHostReportBytes
	case DocAgentAck:
		return contract.MaxAgentAckBytes
	}
	return 0
}

// Document checks size, strict JSON and schema of an unsigned document and
// runs its semantic checks. It returns the parsed value.
func Document(d Doc, raw []byte, ctx *Context) (map[string]any, error) {
	max := d.MaxBytes()
	if max == 0 {
		return nil, fmt.Errorf("verify: unknown document %q", d)
	}
	if len(raw) > max {
		return nil, contract.Errf(contract.CodeOversize, "%d bytes > %d", len(raw), max)
	}
	v, err := jsonx.ParseObject(raw)
	if err != nil {
		return nil, contract.Errf(contract.CodeMalformed, "%v", err)
	}
	if d == DocHostReport {
		// v0.3: secrets are rejected before the schema, so a secret in an
		// unknown field is still reported as such.
		if err := hostcheck.CheckForbidden(v); err != nil {
			return nil, err
		}
	}
	if err := schema.Validate(string(d), v); err != nil {
		return nil, err
	}
	switch d {
	case DocHostReport:
		return v, hostcheck.CheckReport(v)
	case DocStream:
		return v, checkStream(v, ctx)
	case DocConfigSite:
		return v, checkSiteConfig(v)
	case DocConfigLab:
		return v, checkLabConfig(v)
	case DocLogTree:
		return v, checkLogTree(v)
	case DocPeerRequest:
		return v, checkPeerRequest(v, ctx)
	case DocResults:
		s, _ := msg.ParseTime(v["started_at"].(string))
		f, err := msg.ParseTime(v["finished_at"].(string))
		if err != nil || f.Before(s) {
			return v, contract.Errf(contract.CodeSchema, "finished_at before started_at or invalid")
		}
	}
	return v, nil
}

// StreamKind maps a stream event type to the signed kind it carries.
func StreamKind(eventType string) contract.Kind {
	switch eventType {
	case "schild.dist.checkpoint.v1", "schild.dist.heartbeat.v1":
		return contract.KindCheckpoint
	case "schild.dist.bundle.v1":
		return contract.KindBundle
	case "schild.dist.withdrawal.v1":
		return contract.KindWithdrawal
	}
	return ""
}

func checkStream(v map[string]any, ctx *Context) error {
	typ, _ := v["type"].(string)
	field := "envelope"
	if typ == "schild.dist.heartbeat.v1" {
		field = "checkpoint"
	}
	env, ok := v[field].(map[string]any)
	if !ok {
		return nil // bundle by reference: verified after download
	}
	kind := StreamKind(typ)
	if pt, _ := env["payloadType"].(string); pt != kind.PayloadType() {
		return contract.Errf(contract.CodePayloadType, "%s carries %q", typ, pt)
	}
	c := *ctx
	c.SkipState = true
	_, err := SignedValue(kind, env, &c)
	return err
}

// maxOrder checks r[obj][lo] <= r[obj][hi] with schema defaults.
func maxOrder(r map[string]any, obj, lo, hi string, dlo, dhi float64) error {
	m, ok := r[obj].(map[string]any)
	if !ok {
		return nil
	}
	num := func(k string, d float64) float64 {
		switch x := m[k].(type) {
		case float64:
			return x
		case json.Number:
			f, _ := x.Float64()
			return f
		}
		return d
	}
	if num(lo, dlo) > num(hi, dhi) {
		return contract.Errf(contract.CodeConfig, "%s.%s above %s", obj, lo, hi)
	}
	return nil
}

func dupErr(what, id string) error {
	return contract.Errf(contract.CodeConfig, "duplicate %s %q", what, id)
}

func checkSiteConfig(v map[string]any) error {
	keyids := map[string]bool{}
	pubs := map[string]bool{}
	// v0.3: one public key, one identity.
	if hc, ok := v["host_check"].(map[string]any); ok {
		if ag, ok := hc["agents"].(map[string]any); ok {
			for _, k := range asList(ag["keys"]) {
				kid := k["keyid"].(string)
				if keyids[kid] {
					return dupErr("keyid", kid)
				}
				keyids[kid] = true
				pub := k["public_key"].(string)
				if pubs[pub] {
					return dupErr("public key", pub)
				}
				pubs[pub] = true
			}
		}
	}
	// v0.4 (MVP-17): explicit rate limit ids are unique. (MVP-18): response
	// durations within their maximum.
	if b, ok := v["behaviour"].(map[string]any); ok {
		if d, ok := b["distributed"].(map[string]any); ok {
			if r, ok := d["responses"].(map[string]any); ok {
				if err := maxOrder(r, "route_tighten", "minutes", "max_minutes", 20, 120); err != nil {
					return err
				}
				if err := maxOrder(r, "account_slowdown", "start_s", "max_s", 5, 60); err != nil {
					return err
				}
			}
		}
		lids := map[string]bool{}
		for _, l := range asList(b["rate_limits"]) {
			id, ok := l["id"].(string)
			if !ok {
				continue
			}
			if lids[id] {
				return dupErr("rate limit id", id)
			}
			lids[id] = true
		}
	}
	// v0.5 (D41): the body limits nest (defaults count).
	if w, ok := v["waf"].(map[string]any); ok {
		body, _ := w["body"].(map[string]any)
		num := func(m map[string]any, key string, d int64) int64 {
			switch x := m[key].(type) {
			case float64:
				return int64(x)
			case json.Number:
				n, _ := x.Int64()
				return n
			}
			return d
		}
		msg := bodylimit.CheckConfig(int(num(body, "max_per_client", bodylimit.DefaultMaxPerClient)), int(num(body, "max_per_network", bodylimit.DefaultMaxPerNetwork)),
			int(num(body, "max_in_flight", 0)), num(body, "max_in_flight_bytes", bodylimit.DefaultMaxInFlightBytes), num(w, "request_body_limit_bytes", 13107200),
			num(body, "max_waiting_bytes_per_client", bodylimit.DefaultMaxWaitingBytesPerClient), num(body, "max_waiting_bytes_per_network", bodylimit.DefaultMaxWaitingBytesPerNetwork), num(body, "max_waiting_bytes", 0))
		if msg != "" {
			return contract.Errf(contract.CodeConfig, "%s", msg)
		}
		q, _ := w["requests"].(map[string]any)
		msg = bodylimit.CheckRequests(int(num(q, "max_waiting_per_client", bodylimit.DefaultMaxWaitingPerClient)),
			int(num(q, "max_waiting_per_network", bodylimit.DefaultMaxWaitingPerNetwork)), int(num(q, "max_waiting", 0)))
		if msg != "" {
			return contract.Errf(contract.CodeConfig, "%s", msg)
		}
		n, _ := w["connections"].(map[string]any)
		msg = bodylimit.CheckConnections(int(num(n, "max_per_client", bodylimit.DefaultMaxConnsPerClient)),
			int(num(n, "max_per_network", bodylimit.DefaultMaxConnsPerNetwork)), int(num(n, "max_open", 0)))
		if msg != "" {
			return contract.Errf(contract.CodeConfig, "%s", msg)
		}
	}
	// v0.4 (MVP-21): a coarser monitoring resolution never covers less time.
	if m, ok := v["monitoring"].(map[string]any); ok {
		if k, ok := m["keep"].(map[string]any); ok {
			num := func(key string, d float64) float64 {
				switch x := k[key].(type) {
				case float64:
					return x
				case json.Number:
					f, _ := x.Float64()
					return f
				}
				return d
			}
			ten, minute, days := num("ten_seconds_hours", 6), num("minute_hours", 48), num("ten_minute_days", 14)
			if ten > minute || minute > days*24 {
				return contract.Errf(contract.CodeConfig, "monitoring.keep: ten_seconds_hours <= minute_hours <= ten_minute_days*24 required")
			}
		}
		// v0.5 (MVP-22): the request ring needs the monitoring counters.
		r, _ := m["requests"].(map[string]any)
		if on, _ := r["enabled"].(bool); on && m["enabled"] == false {
			return contract.Errf(contract.CodeConfig, "monitoring.requests.enabled needs monitoring.enabled")
		}
	}
	// v0.4 (MVP-21): the agent listener is never the dashboard or metrics
	// listener (defaults count).
	if a, ok := v["agent_api"].(map[string]any); ok {
		str := func(m map[string]any, k, d string) string {
			if x, ok := m[k].(string); ok {
				return x
			}
			return d
		}
		l, _ := v["listen"].(map[string]any)
		al := str(a, "listen", "127.0.0.1:8789")
		if al == str(l, "dashboard", "127.0.0.1:8788") || al == str(l, "metrics", "127.0.0.1:9101") {
			return contract.Errf(contract.CodeConfig, "agent_api.listen %s equals listen.dashboard or listen.metrics", al)
		}
	}
	return nil
}

func checkLabConfig(v map[string]any) error {
	issuers := map[string]bool{}
	for _, i := range asList(v["issuers"]) {
		id := i["id"].(string)
		if issuers[id] {
			return dupErr("issuer", id)
		}
		issuers[id] = true
	}
	keyids := map[string]bool{}
	pubs := map[string]bool{}
	for _, k := range asList(v["keys"]) {
		kid := k["keyid"].(string)
		if keyids[kid] {
			return dupErr("keyid", kid)
		}
		keyids[kid] = true
	}
	for _, c := range asList(v["clients"]) {
		kid := c["keyid"].(string)
		if keyids[kid] {
			return dupErr("keyid", kid)
		}
		keyids[kid] = true
		// The same site key under two issuers would count its tips twice.
		pub := c["public_key"].(string)
		if pubs[pub] {
			return dupErr("public key", pub)
		}
		pubs[pub] = true
		if iss := c["issuer"].(string); !issuers[iss] {
			return contract.Errf(contract.CodeConfig, "client %s names unknown issuer %q", kid, iss)
		}
	}
	self := v["identity"].(map[string]any)["lab"].(string)
	peers := map[string]bool{}
	for _, p := range asList(v["peers"]) {
		lab := p["lab"].(string)
		if lab == self {
			return contract.Errf(contract.CodeConfig, "lab %q lists itself as peer", lab)
		}
		if peers[lab] {
			return dupErr("peer", lab)
		}
		peers[lab] = true
		// One key under two peers would count for two operators.
		for _, k := range asList(p["keys"]) {
			pub := k["public_key"].(string)
			if pubs[pub] {
				return dupErr("public key", pub)
			}
			pubs[pub] = true
		}
	}
	return nil
}

func asList(v any) []map[string]any {
	a, _ := v.([]any)
	out := make([]map[string]any, 0, len(a))
	for _, x := range a {
		if m, ok := x.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

func checkLogTree(v map[string]any) error {
	var doc struct {
		Entries []logtree.Entry `json:"entries"`
		Head    struct {
			Size uint64 `json:"size"`
			Root string `json:"root"`
		} `json:"head"`
	}
	if err := jsonx.Decode(v, &doc); err != nil {
		return contract.Errf(contract.CodeSchema, "%v", err)
	}
	return logtree.Check(doc.Entries, doc.Head.Size, doc.Head.Root)
}

func checkPeerRequest(v map[string]any, ctx *Context) error {
	var doc struct {
		Method        string `json:"method"`
		Path          string `json:"path"`
		Target        string `json:"target"`
		BodySHA256    string `json:"body_sha256"`
		Authorization string `json:"authorization"`
	}
	if err := jsonx.Decode(v, &doc); err != nil {
		return contract.Errf(contract.CodeSchema, "%v", err)
	}
	trust := ctx.Trust
	if trust == nil {
		trust = keys.NewTrustStore()
	}
	_, err := peerauth.Verify(peerauth.Request{Method: doc.Method, Path: doc.Path, Target: doc.Target, BodySHA256: doc.BodySHA256, Header: doc.Authorization}, trust, ctx.Now)
	return err
}
