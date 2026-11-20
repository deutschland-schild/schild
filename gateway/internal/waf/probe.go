package waf

import (
	"errors"
	"net/http"
	"time"
)

// ProbeHit is one place a rule matched in a sample request.
type ProbeHit struct {
	ID       int
	Variable string // e.g. ARGS_POST, REQUEST_FILENAME
	Key      string // e.g. json.components.0.updates.text, "" for a whole variable
}

// ErrProbeTimeout: the sample took longer than its budget.
var ErrProbeTimeout = errors.New("waf: sample evaluation timed out")

// probeClient is the documentation address a sample comes from (RFC 5737).
const probeClient = "192.0.2.10"

// Probe runs a sample request through phases 1 and 2 of the running rules and
// returns what matched (D55). Nothing reaches a backend, a counter or a log:
// the caller only reads the answer. A sample over the body limits returns its
// LimitError, as a real request would get it.
func (inst *Instance) Probe(r *http.Request, budget time.Duration) (a *Analysis, hits []ProbeHit, err error) {
	tx, c := inst.NewTransaction()
	timer := time.AfterFunc(budget, func() { c.Cancel() })
	defer func() {
		timer.Stop()
		if v := recover(); v != nil {
			if !IsCancelled(v) {
				panic(v)
			}
			a, hits, err = nil, nil, ErrProbeTimeout
		}
		c.Finish()
		_ = tx.Close()
	}()
	ProcessHeaders(tx, r, probeClient, 40000)
	if _, _, err := ReadBody(tx, r, DefaultLimits); err != nil {
		return nil, nil, err
	}
	_, _ = tx.ProcessRequestBody()
	mrs := tx.MatchedRules()
	for _, mr := range mrs {
		id := mr.Rule().ID()
		for _, md := range mr.MatchedDatas() {
			if md == nil || md.Variable() == 0 {
				continue
			}
			hits = append(hits, ProbeHit{ID: id, Variable: md.Variable().Name(), Key: md.Key()})
		}
	}
	return inst.Analyze(mrs), hits, nil
}
