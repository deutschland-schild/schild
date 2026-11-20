package crowdsec

import (
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/jsonx"
	"github.com/deutschland-schild/schild/contract/schema"
)

// ConvertResult is the vector result of op convert.
type ConvertResult struct {
	Outcome string `json:"outcome"` // converted | skipped
	Code    string `json:"code,omitempty"`
	Rule    *Rule  `json:"rule,omitempty"`
}

// RunVector runs one crowdsec-hub input (crowdsec-hub.schema.json).
func RunVector(raw []byte) (any, error) {
	if len(raw) > MaxInputBytes {
		return nil, contract.Errf(contract.CodeOversize, "%d bytes > %d", len(raw), MaxInputBytes)
	}
	v, err := jsonx.ParseObject(raw)
	if err != nil {
		return nil, contract.Errf(contract.CodeMalformed, "%v", err)
	}
	if err := schema.Validate(Schema, v); err != nil {
		return nil, err
	}
	str := func(m map[string]any, k string) string { s, _ := m[k].(string); return s }
	flag := func(m map[string]any, k string) bool { b, _ := m[k].(bool); return b }
	num := func(m map[string]any, k string) int64 {
		x, ok := m[k].(interface{ Int64() (int64, error) })
		if !ok {
			return 0
		}
		i, _ := x.Int64()
		return i
	}
	switch v["op"] {
	case "convert":
		body := []byte(str(v, "content"))
		sum := sha256.Sum256(body)
		r, sk := Convert(str(v, "name"), str(v, "version"), hex.EncodeToString(sum[:]), body, str(v, "description"))
		if sk != nil {
			return ConvertResult{Outcome: "skipped", Code: sk.Code}, nil
		}
		return ConvertResult{Outcome: "converted", Rule: r}, nil
	case "update":
		lim := DefaultLimits
		if l, ok := v["limits"].(map[string]any); ok {
			if n := num(l, "index_bytes"); n > 0 {
				lim.IndexBytes = int(n)
			}
			if n := num(l, "rules"); n > 0 {
				lim.Rules = int(n)
			}
			if n := num(l, "set_bytes"); n > 0 {
				lim.SetBytes = int(n)
			}
			if n := num(l, "set_lines"); n > 0 {
				lim.SetLines = int(n)
			}
		}
		lim.ShrinkBase = int(num(v, "shrink_base"))
		var prev map[string]Known
		if p, ok := v["previous"].(map[string]any); ok {
			prev = make(map[string]Known, len(p))
			for n, x := range p {
				k := x.(map[string]any)
				prev[n] = Known{Digest: str(k, "digest"), FirstSeen: str(k, "first_seen"), ChangedAt: str(k, "changed_at")}
			}
		}
		return CheckIndex([]byte(str(v, "index")), prev, lim, str(v, "now")), nil
	case "set_cost":
		return CheckSetCost(CostSample{BaselineNS: num(v, "baseline_ns"), ReferenceNS: num(v, "reference_ns"), CandidateNS: num(v, "candidate_ns"), Rounds: int(num(v, "rounds"))}), nil
	case "select":
		cand := func(k string) Candidate {
			c, _ := v[k].(map[string]any)
			return Candidate{Present: flag(c, "present"), Valid: flag(c, "valid"), Commit: str(c, "commit"), Time: str(c, "time")}
		}
		now, err := time.Parse(time.RFC3339, str(v, "now"))
		if err != nil {
			return nil, contract.Errf(contract.CodeSchema, "now: %v", err)
		}
		return SelectSet(str(v, "state"), str(v, "pin"), cand("stored"), cand("image"), now), nil
	}
	return nil, contract.Errf(contract.CodeSchema, "unknown op %v", v["op"])
}
