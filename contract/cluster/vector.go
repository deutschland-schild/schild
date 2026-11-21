package cluster

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/jsonx"
	"github.com/deutschland-schild/schild/contract/schema"
)

// MaxVectorInput bounds the input of a cluster-record vector.
const MaxVectorInput = 4 << 20

// VectorInput is the input of the cluster-record vectors
// (contracts/cluster-record.schema.json): what a node holds of the member
// list, the record it is handed, and the record it holds of the same thing.
type VectorInput struct {
	Group   string    `json:"group"`
	Members []*Record `json:"members"`
	Record  *Record   `json:"record"`
	Held    *Record   `json:"held"`
}

// VectorResult is the expected result.
type VectorResult struct {
	// Taken: the record passes every check of cluster.md section 4.
	Taken bool `json:"taken"`
	// Reason names the first failing check: version, group, schema, clock,
	// origin, removed or signature; "" when taken.
	Reason string `json:"reason"`
	// Replaces: with a held record, whether the record becomes the state in
	// its place (section 3); null without one or when not taken.
	Replaces *bool `json:"replaces"`
}

// Reason is the name of a check error as the vectors carry it.
func Reason(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrVersion):
		return "version"
	case errors.Is(err, ErrGroup):
		return "group"
	case errors.Is(err, ErrClock):
		return "clock"
	case errors.Is(err, ErrOrigin):
		return "origin"
	case errors.Is(err, ErrRemoved):
		return "removed"
	case errors.Is(err, ErrSignature):
		return "signature"
	}
	return "schema"
}

// RunVector checks the input of a cluster-record vector at the clock now.
func RunVector(raw []byte, now time.Time) (any, error) {
	if len(raw) > MaxVectorInput {
		return nil, contract.Errf(contract.CodeOversize, "%d bytes > %d", len(raw), MaxVectorInput)
	}
	v, err := jsonx.ParseObject(raw)
	if err != nil {
		return nil, contract.Errf(contract.CodeMalformed, "%v", err)
	}
	if err := schema.Validate(schema.ClusterRecord, v); err != nil {
		return nil, err
	}
	var in VectorInput
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil, contract.Errf(contract.CodeSchema, "%v", err)
	}
	ro := NewRoster(in.Group)
	for _, m := range in.Members {
		if m.Class == ClassMembers && ro.Check(m, now) == nil {
			ro.Set(m)
		}
	}
	res := VectorResult{Reason: Reason(ro.Check(in.Record, now))}
	res.Taken = res.Reason == ""
	if res.Taken && in.Held != nil {
		w := Wins(in.Record, in.Held)
		res.Replaces = &w
	}
	return res, nil
}
