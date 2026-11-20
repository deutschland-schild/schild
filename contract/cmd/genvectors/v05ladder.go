//go:build !release

package main

import (
	"fmt"
	"time"

	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/vectors"
)

// genEventsV05Ladder: D29 amendment (initiator, 2026-10-29) - the block
// ladder depends on the client's net class: data-centre addresses (hosting)
// 15 min, 1 h, 24 h, 7 d; every other class 15 min, 1 h, 4 h, 24 h (cap).
func genEventsV05Ladder(g *gen) {
	const c = "events"
	ctx := vectors.Context{}
	block := func(netClass string, level, duration int) map[string]any {
		cl := reqData("x")["client"].(map[string]any)
		cl["geo"].(map[string]any)["net_class"] = netClass
		return cloudEvent("schild.behaviour.triggered.v1", fmt.Sprintf("ladder-%s-%d-%d", netClass, level, duration), map[string]any{
			"scenario": "path_probing", "scope": "client", "client": cl, "key_bits": 32, "host": "verein.example", "route": "/.env",
			"count": 40, "threshold": 30, "window_s": 60, "mode": "block", "action": "block", "would_action": "block",
			"level": level, "duration_s": duration, "until": ts(time.Duration(duration) * time.Second), "incident": "K7QM-4XWD"})
	}
	ok := func(name, desc, nc string, level, d int) {
		g.add(c, name, true, "", desc, ctx, mustJSON(block(nc, level, d)), block(nc, level, d))
	}
	bad := func(name, desc, nc string, level, d int) {
		g.add(c, name, false, contract.CodeSchema, desc, ctx, mustJSON(block(nc, level, d)), block(nc, level, d))
	}
	ok("ladder-hosting-2", "D29 amendment: data centre, level 2: 1 h.", "hosting", 2, 3600)
	ok("ladder-hosting-3", "D29 amendment: data centre, level 3: 24 h.", "hosting", 3, 86400)
	ok("ladder-hosting-4", "D29 amendment: data centre, repeat offender (level 4): 7 days (\"7 Tage, weil Rechenzentrum und wiederholt\"); kept across restarts.", "hosting", 4, 604800)
	ok("ladder-hosting-7", "D29 amendment: data centre, beyond the last step: stays at 7 days.", "hosting", 7, 604800)
	ok("ladder-residential-3", "D29 amendment: residential, level 3: 4 h (unchanged ladder).", "residential", 3, 14400)
	ok("ladder-residential-4", "D29 amendment: residential, level 4: 24 h cap.", "residential", 4, 86400)
	ok("ladder-unknown-5", "D29 amendment: unknown net class, level 5: 24 h cap.", "unknown", 5, 86400)
	bad("ladder-residential-7d", "D29 amendment: 7 days only for data-centre addresses.", "residential", 4, 604800)
	bad("ladder-vpn-7d", "D29 amendment: VPN and proxy addresses keep the 24 h cap (only hosting goes to 7 days).", "vpn", 4, 604800)
	bad("ladder-residential-wrong-step", "D29 amendment: residential level 3 is 4 h, not 24 h.", "residential", 3, 86400)
	bad("ladder-hosting-wrong-step", "D29 amendment: data-centre level 3 is 24 h, not 4 h.", "hosting", 3, 14400)
	bad("ladder-hosting-skip", "D29 amendment: a first block is 15 min, also for data-centre addresses.", "hosting", 1, 604800)
	bad("ladder-hosting-14d", "D29 amendment: at most 7 days.", "hosting", 5, 1209600)
	bad("ladder-free-duration", "D29 amendment: durations are ladder steps only.", "residential", 2, 7200)
}
