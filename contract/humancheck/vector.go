package humancheck

import (
	"time"

	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/jsonx"
	"github.com/deutschland-schild/schild/contract/schema"
)

// MaxInputBytes bounds one human-check vector input.
const MaxInputBytes = 64 << 10

// RunVector runs one human-check golden vector: schema, shape check, Decide.
func RunVector(raw []byte, now time.Time) (Result, error) {
	if len(raw) > MaxInputBytes {
		return Result{}, contract.Errf(contract.CodeOversize, "%d bytes > %d", len(raw), MaxInputBytes)
	}
	v, err := jsonx.ParseObject(raw)
	if err != nil {
		return Result{}, contract.Errf(contract.CodeMalformed, "%v", err)
	}
	if err := schema.Validate(schema.HumanCheck, v); err != nil {
		return Result{}, err
	}
	var in struct {
		Policy             Policy `json:"policy"`
		Method             string `json:"method"`
		Path               string `json:"path"`
		Accept             string `json:"accept"`
		SecFetchMode       string `json:"sec_fetch_mode"`
		Allowlisted        bool   `json:"allowlisted"`
		GoodBot            bool   `json:"good_bot"`
		Clearance          string `json:"clearance"`
		SharedScenarioHit  bool   `json:"shared_scenario_hit"`
		AggressiveCrawlHit bool   `json:"aggressive_crawl_hit"`
		DistributedWave    bool   `json:"distributed_wave"`
	}
	if err := jsonx.Decode(v, &in); err != nil {
		return Result{}, contract.Errf(contract.CodeSchema, "%v", err)
	}
	if err := in.Policy.CheckShape(now); err != nil {
		return Result{}, contract.Errf(contract.CodeSchema, "%v", err)
	}
	return Decide(Input{
		Policy:             in.Policy,
		Method:             in.Method,
		Path:               in.Path,
		Accept:             in.Accept,
		SecFetchMode:       in.SecFetchMode,
		Allowlisted:        in.Allowlisted,
		GoodBot:            in.GoodBot,
		Clearance:          in.Clearance,
		SharedScenarioHit:  in.SharedScenarioHit,
		AggressiveCrawlHit: in.AggressiveCrawlHit,
		DistributedWave:    in.DistributedWave,
		Now:                now,
	}), nil
}
