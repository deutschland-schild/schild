package rules

import "testing"

var (
	modes    = []string{ModeObserve, ModeAutoblock}
	states   = []string{StateOff, StateDetect, StateBlock}
	origins  = []string{OriginRelease, OriginUpdate, OriginOperator}
	allows   = []string{"", "no_block", "bypass_waf"}
	settling = []int64{0, 2000}
)

// every runs f over every input of Compute and Apply.
func every(f func(Input, Request, Rule, Action)) {
	for _, m := range modes {
		for _, st := range states {
			for _, o := range origins {
				for _, d := range []bool{false, true} {
					for _, su := range settling {
						in := Input{Mode: m, State: st, Origin: o, Disabled: d, SettlingUntil: su, Now: 1000}
						r := Compute(in)
						for _, al := range allows {
							for _, ex := range []bool{false, true} {
								for _, sm := range []string{"", ModeObserve} {
									q := Request{Allow: al, Excepted: ex, SiteMode: sm}
									f(in, q, r, Apply(r, q))
								}
							}
						}
					}
				}
			}
		}
	}
}

// Only state block, outside observe, of an active rule may block a request,
// and only a block counts as a hit.
func TestOnlyActiveBlockBlocks(t *testing.T) {
	every(func(in Input, q Request, r Rule, a Action) {
		if a.CountsAsHit != (a.Action == ActionBlock) {
			t.Errorf("%+v %+v: counts_as_hit without a block: %+v", in, q, a)
		}
		if a.Action == ActionBlock && (in.State != StateBlock || in.Mode == ModeObserve || r.Status != StatusActive || in.Disabled || q.Allow != "") {
			t.Errorf("%+v %+v: %+v blocks", in, q, a)
		}
	})
}

// Detect never blocks: a match shows as "Erkannt" (would_block, D90) and
// never counts as a hit.
func TestDetectNeverBlocks(t *testing.T) {
	every(func(in Input, q Request, r Rule, a Action) {
		if in.State == StateDetect && (a.CountsAsHit || a.Action != ActionWouldBlock && a.Action != ActionNone) {
			t.Errorf("%+v %+v: %+v", in, q, a)
		}
	})
}

// D89: an update blocks only after settling_s, never before.
func TestUpdateSettlesFirst(t *testing.T) {
	every(func(in Input, q Request, r Rule, a Action) {
		if in.Origin == OriginUpdate && in.Now < in.SettlingUntil && a.Action == ActionBlock {
			t.Errorf("%+v %+v: unsettled update blocks: %+v", in, q, a)
		}
	})
}

// An effect lower than block always says why, except off and a repository
// state that is itself lower.
func TestLimitedBy(t *testing.T) {
	every(func(in Input, _ Request, r Rule, _ Action) {
		switch r.Effect {
		case EffectDetect, EffectWouldBlock:
			if r.LimitedBy == "" {
				t.Errorf("%+v: %+v without limited_by", in, r)
			}
		default:
			if r.LimitedBy != "" {
				t.Errorf("%+v: %+v", in, r)
			}
		}
	})
}
