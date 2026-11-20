package waf

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/deutschland-schild/schild/contract/crowdsec"
)

// maxCostPause bounds the pause between two rounds of a cost measurement.
const maxCostPause = 250 * time.Millisecond

// MeasureHubCost times the probe set of the contract on three instances
// without the CRS: no hub rules, the reference set and the candidate. Each
// instance runs every probe in every round, so all three see the same
// disturbance, and the fastest time of each probe counts. It runs on the
// calling goroutine, one request at a time, and pauses as long as a round took
// (at most maxCostPause), so it uses at most one core, part of the time, and
// holds no slot of the request path. The rounds end early at the deadline of
// budget; the sample says how many finished.
func MeasureHubCost(ctx context.Context, reference, candidate []HubRule, budget time.Duration) (crowdsec.CostSample, error) {
	var s crowdsec.CostSample
	sets := [][]HubRule{nil, reference, candidate}
	insts := make([]*Instance, len(sets))
	for i, rs := range sets {
		if i == 1 && len(rs) == 0 {
			insts[i] = insts[0] // no snapshot: the reference is the baseline
			continue
		}
		inst, err := Build(Config{Hub: rs})
		if err != nil {
			return s, err
		}
		defer inst.Close()
		insts[i] = inst
	}
	deadline := time.Now().Add(budget)
	best := make([][]time.Duration, len(insts))
	for i := range best {
		best[i] = make([]time.Duration, len(crowdsec.CostProbes))
	}
	for round := 0; round < crowdsec.CostRounds; round++ {
		start := time.Now()
		for i, inst := range insts {
			for p := range crowdsec.CostProbes {
				if err := ctx.Err(); err != nil {
					return s, err
				}
				if time.Now().After(deadline) {
					return costSample(round, best), nil
				}
				d, err := timeProbe(inst, &crowdsec.CostProbes[p])
				if err != nil {
					return s, err
				}
				if best[i][p] == 0 || d < best[i][p] {
					best[i][p] = d
				}
			}
		}
		if round+1 >= crowdsec.CostEarlyRounds {
			// The fastest times only fall with more rounds, but a set this far
			// over the bound will not come back: spare the machine.
			c := costSample(round+1, best)
			if v := crowdsec.CheckSetCost(c); v.AddedNS > 2*v.AllowedNS {
				return c, nil
			}
		}
		select {
		case <-ctx.Done():
			return s, ctx.Err()
		case <-time.After(min(time.Since(start), maxCostPause)):
		}
	}
	return costSample(crowdsec.CostRounds, best), nil
}

// costSample turns the fastest times of each instance into the mean time per
// probe request.
func costSample(rounds int, best [][]time.Duration) crowdsec.CostSample {
	mean := func(ds []time.Duration) int64 {
		var sum time.Duration
		for _, d := range ds {
			sum += d
		}
		return int64(sum) / int64(len(ds))
	}
	return crowdsec.CostSample{BaselineNS: mean(best[0]), ReferenceNS: mean(best[1]), CandidateNS: mean(best[2]), Rounds: rounds}
}

// timeProbe runs one probe through the phases of the request path.
func timeProbe(inst *Instance, p *crowdsec.CostProbe) (time.Duration, error) {
	r, err := http.NewRequest(p.Method, "http://www.example.test"+p.Target, strings.NewReader(p.Body))
	if err != nil {
		return 0, err
	}
	for k, v := range crowdsec.CostProbeHeaders {
		r.Header.Set(k, v)
	}
	r.Host = crowdsec.CostProbeHeaders["Host"]
	if p.ContentType != "" {
		r.Header.Set("Content-Type", p.ContentType)
	}
	r.RemoteAddr = "192.0.2.10:40000"
	tx, _ := inst.NewTransaction()
	defer func() { _ = tx.Close() }()
	start := time.Now()
	ProcessHeaders(tx, r, "192.0.2.10", 40000)
	if _, _, err := ReadBodyInfo(tx, r, Limits{}); err != nil {
		return 0, fmt.Errorf("waf: cost probe %s: %w", p.Target, err)
	}
	if _, err := tx.ProcessRequestBody(); err != nil {
		return 0, err
	}
	return time.Since(start), nil
}
