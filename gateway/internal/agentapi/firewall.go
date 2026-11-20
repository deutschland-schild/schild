package agentapi

import (
	"net/http"
	"sync"
	"time"
	"unicode"

	contractapi "github.com/deutschland-schild/schild/contract/agentapi"
	"github.com/deutschland-schild/schild/contract/firewall"
)

// FirewallDeps is the handoff of the blocks to the host's firewall (D87).
type FirewallDeps struct {
	// Blocks returns every block that runs now, as the firewall gets it.
	Blocks func() []firewall.Block
	// Poll is how often a waiting call looks for a change (default 1 s).
	Poll time.Duration
	// Wait bounds a call (default firewall.Wait).
	Wait time.Duration

	mu     sync.Mutex
	report firewall.Report
	// sent remembers the clients of the last answers by revision, so that a
	// report of what was applied names the clients the table holds.
	sent  map[string]map[string]bool
	order []string
}

// maxRevisions the gateway remembers for reports.
const maxRevisions = 8

// State returns the firewall's last report; ok false before its first call.
func (d *FirewallDeps) State() (firewall.Report, bool) {
	if d == nil {
		return firewall.Report{}, false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.report, !d.report.At.IsZero()
}

func (d *FirewallDeps) remember(rev string, blocks []firewall.Block) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.sent == nil {
		d.sent = map[string]map[string]bool{}
	}
	if _, ok := d.sent[rev]; ok {
		return
	}
	set := make(map[string]bool, len(blocks))
	for _, b := range blocks {
		set[b.Client] = true
	}
	d.sent[rev] = set
	d.order = append(d.order, rev)
	if len(d.order) > maxRevisions {
		delete(d.sent, d.order[0])
		d.order = d.order[1:]
	}
}

func (d *FirewallDeps) record(req firewall.SyncRequest, at time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	clients, ok := d.sent[req.Applied]
	d.report = firewall.Report{At: at, Applied: req.Applied, Held: req.Held, Table: req.Table, Version: req.Version, Error: req.Error, Clients: clients, Complete: ok}
}

func (d *FirewallDeps) answer() firewall.SyncResponse {
	blocks := d.Blocks()
	if blocks == nil {
		blocks = []firewall.Block{}
	}
	return firewall.SyncResponse{Revision: firewall.Revision(blocks), Blocks: blocks}
}

// syncFirewall answers `schild firewall run`: a long poll that returns the
// blocks that run as soon as they differ from what the firewall applied.
func (s *Server) syncFirewall(w http.ResponseWriter, r *http.Request) {
	ci, _ := r.Context().Value(ctxKey{}).(*callInfo)
	if ci == nil {
		Problem(w, http.StatusForbidden, "forbidden", "Not part of the agent API.")
		return
	}
	if !contractapi.AllowsWrite(ci.token.Scope, contractapi.OpSyncFirewall) {
		Problem(w, http.StatusForbidden, contractapi.CodeScopeRequired, "Only schild firewall run calls this, with a token of scope firewall:sync: schild token add --scope firewall:sync --expires 365d --label firewall")
		return
	}
	d := s.Firewall
	if d == nil || d.Blocks == nil {
		Problem(w, http.StatusNotFound, "not_found", "Address blocks are not available on this gateway.")
		return
	}
	var req firewall.SyncRequest
	if !readExceptionBody(w, r, &req) {
		return
	}
	if len(req.Applied) > 16 || req.Held < 0 || len(req.Table) > 64 || len(req.Version) > 128 || len([]rune(req.Error)) > 300 || hasControl(req.Error+req.Table+req.Version) {
		Problem(w, http.StatusBadRequest, "invalid", "applied (a revision), held, table, version and error in one line.")
		return
	}
	d.record(req, s.now())
	wait, poll := d.Wait, d.Poll
	if wait <= 0 {
		wait = firewall.Wait
	}
	if poll <= 0 {
		poll = time.Second
	}
	ans := d.answer()
	if ans.Revision == req.Applied {
		deadline := time.NewTimer(wait)
		defer deadline.Stop()
		tick := time.NewTicker(poll)
		defer tick.Stop()
	wait:
		for {
			select {
			case <-r.Context().Done():
				return
			case <-deadline.C:
				break wait
			case <-tick.C:
				if ans = d.answer(); ans.Revision != req.Applied {
					break wait
				}
			}
		}
	}
	d.remember(ans.Revision, ans.Blocks)
	ci.rows = len(ans.Blocks)
	writeJSON(w, ans)
}

func hasControl(s string) bool {
	for _, c := range s {
		if unicode.IsControl(c) {
			return true
		}
	}
	return false
}
