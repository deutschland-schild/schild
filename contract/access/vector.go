package access

import (
	"net/netip"

	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/jsonx"
	"github.com/deutschland-schild/schild/contract/schema"
)

// MaxInputBytes bounds one access-gate vector input.
const MaxInputBytes = 64 << 10

// RunVector runs one access-gate vector: schema, shape check, Decide.
func RunVector(raw []byte) (Result, error) {
	if len(raw) > MaxInputBytes {
		return Result{}, contract.Errf(contract.CodeOversize, "%d bytes > %d", len(raw), MaxInputBytes)
	}
	v, err := jsonx.ParseObject(raw)
	if err != nil {
		return Result{}, contract.Errf(contract.CodeMalformed, "%v", err)
	}
	if err := schema.Validate(schema.AccessGate, v); err != nil {
		return Result{}, err
	}
	var in struct {
		Protection  Protection `json:"protection"`
		Path        string     `json:"path"`
		ClientIP    string     `json:"client_ip"`
		Allowlisted bool       `json:"allowlisted"`
		Session     string     `json:"session"`
	}
	if err := jsonx.Decode(v, &in); err != nil {
		return Result{}, contract.Errf(contract.CodeSchema, "%v", err)
	}
	if err := in.Protection.CheckShape(); err != nil {
		return Result{}, contract.Errf(contract.CodeSchema, "%v", err)
	}
	d := Input{Protection: in.Protection, Path: in.Path, Allowlisted: in.Allowlisted, Session: in.Session}
	if in.ClientIP != "" {
		ip, err := netip.ParseAddr(in.ClientIP)
		if err != nil {
			return Result{}, contract.Errf(contract.CodeSchema, "client_ip: %v", err)
		}
		d.Client = ip
	}
	return Decide(d), nil
}
