package agentapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"time"
	"unicode/utf8"

	contractapi "github.com/deutschland-schild/schild/contract/agentapi"
	"github.com/deutschland-schild/schild/contract/events"
	"github.com/deutschland-schild/schild/contract/msg"
	"github.com/deutschland-schild/schild/gateway/internal/behaviour"
	"github.com/deutschland-schild/schild/gateway/internal/eventlog"
	"github.com/deutschland-schild/schild/gateway/internal/store"
)

// Single blocks through the agent API (D42). An agent names an event, an
// incident or a client pseudonym; the address comes from what the gateway
// recorded, and neither the request nor the answer carries one. The decisions
// are contract: contractapi.CheckBlock and CheckLift. A block is in the engine
// before the answer returns, only its records are written in the background.

// liftFlushWait is the longest a lift waits for the row of its block.
const liftFlushWait = 2 * time.Second

// BlockDeps is what the block writes need from the gateway. nil on Server: the
// two operations answer 404.
type BlockDeps struct {
	Engine *behaviour.Engine
	// Mode is the gateway mode.
	Mode func() string
	// Own: on the allowlist, an address of this host or a trusted proxy.
	Own func(ip netip.Addr) bool
	// Released: an unblock exception of the operator runs for this client.
	Released func(ip netip.Addr) bool
	// NetClass of an address from the geo data ("" unknown).
	NetClass func(ip netip.Addr) string
	Emit     func(id, typ string, t time.Time, data any, idx eventlog.Index)
	Incident func(in *store.Incident)
	// FlushIncidents stores what Incident queued, until ctx ends.
	FlushIncidents func(ctx context.Context)

	mu     sync.Mutex
	writes map[string][]time.Time // token id -> changing calls in the window
}

// budget is the state of the limits of tok at now, with the window trimmed.
// Called with mu held.
func (d *BlockDeps) budget(tok string, perHour, maxBlocks int, now time.Time) contractapi.BlockBudget {
	if d.writes == nil {
		d.writes = map[string][]time.Time{}
	}
	w := d.writes[tok]
	cut := 0
	for cut < len(w) && now.Sub(w[cut]) >= contractapi.BlockBudgetWindowS*time.Second {
		cut++
	}
	w = w[cut:]
	d.writes[tok] = w
	b := contractapi.BlockBudget{WritesPerHour: perHour, WritesUsed: len(w), MaxBlocks: maxBlocks, Running: d.Engine.AgentBlocks()}
	if len(w) > 0 {
		b.OldestWriteAgeS = int(now.Sub(w[0]) / time.Second)
	}
	return b
}

func (d *BlockDeps) spend(tok string, now time.Time) { d.writes[tok] = append(d.writes[tok], now) }

// blockProblems holds the words of a refusal.
var blockProblems = map[string]string{
	"not_found":                    "Nothing of that name on this gateway. A visitor pseudonym of the request ring has no address behind it: use the event_id of the record.",
	"invalid":                      "The body needs target, duration_s of at least 60 and a reason.",
	contractapi.CodeTargetGone:     "The address is no longer stored, or the evidence is older than 7 days.",
	contractapi.CodeUnreliable:     "The address was not attributed by the TCP peer or a trusted proxy, so it could name a victim.",
	contractapi.CodePrivateAddress: "This is a private or special address.",
	contractapi.CodeOwnAddress:     "This address is on the allowlist, belongs to the gateway or is a trusted proxy.",
	contractapi.CodeSharedAddress:  "Many people share this address (cgnat, mobile, tor).",
	contractapi.CodeReleased:       "The operator released this client. An agent does not overrule that.",
	contractapi.CodeBlockBudget:    "This token used up its block writes for this hour.",
	contractapi.CodeBlockCap:       "The most agent blocks this gateway keeps are running.",
	contractapi.CodeNoRunningBlock: "This incident has no running block: a single request the WAF refused has nothing to lift.",
}

func refuseBlock(w http.ResponseWriter, v contractapi.BlockVerdict) {
	code := *v.Code
	if v.RetryAfter != nil {
		w.Header().Set("Retry-After", strconv.Itoa(*v.RetryAfter))
	}
	detail := blockProblems[code]
	switch code {
	case contractapi.CodeScopeRequired:
		detail = "This token may only read. Create one on the host: schild token add --scope blocks:write --expires 90d --label NAME"
	case contractapi.CodeDurationOver:
		detail = fmt.Sprintf("The longest block for this net class is %d seconds.", *v.MaxDurationS)
	}
	Problem(w, v.Status, code, detail)
}

// readBlockBody reads the JSON body of a block write into v.
func readBlockBody(w http.ResponseWriter, r *http.Request, v any) bool {
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mt != "application/json" {
		Problem(w, http.StatusBadRequest, "invalid", "Content-Type must be application/json.")
		return false
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, contractapi.MaxBlockBody+1))
	if err != nil || len(body) > contractapi.MaxBlockBody {
		Problem(w, http.StatusBadRequest, "invalid", "The body is limited to 1 KiB.")
		return false
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if dec.Decode(v) != nil {
		Problem(w, http.StatusBadRequest, "invalid", blockProblems["invalid"])
		return false
	}
	return true
}

// validReason: the text is free, its shape is not (OpenAPI pattern).
func validReason(s string) bool {
	if utf8.RuneCountInString(s) > contractapi.MaxReason {
		return false
	}
	for _, c := range s {
		if c < 0x20 || c == 0x7f {
			return false
		}
	}
	return true
}

// evidence is what the gateway recorded for a target.
type evidence struct {
	target  contractapi.BlockTarget
	ip      netip.Addr
	client  events.Client
	eventID string
	kind    string
}

// resolved reads the address of an event row into e.
func (s *Server) resolved(e *evidence, row *store.EventRow, ip string, at time.Time) {
	d := s.Blocks
	e.target.Exists = true
	e.eventID = row.ID
	addr, err := netip.ParseAddr(ip)
	if err != nil || s.now().Sub(at) > contractapi.BlockEvidenceWindow {
		e.target.Gone = true
		return
	}
	e.ip = addr.Unmap()
	var body struct {
		Data struct {
			Client events.Client `json:"client"`
		} `json:"data"`
	}
	if json.Unmarshal(row.Body, &body) == nil {
		e.client = body.Data.Client
		e.target.Attribution = e.client.Attribution
	}
	e.client.IP = e.ip.String()
	e.target.Address = e.ip.String()
	e.target.NetClass = e.client.Geo.NetClass
	if nc := d.NetClass(e.ip); nc != "" {
		e.target.NetClass = nc
	}
	e.target.Own = d.Own(e.ip)
	e.target.Released = d.Released(e.ip)
	if _, ok := d.Engine.ActiveBlock(e.ip); ok {
		e.target.Running = true
	}
}

// findTarget looks up the named target. A store error is an error; a name
// nothing stands behind leaves Exists false.
func (s *Server) findTarget(ctx context.Context, n contractapi.BlockTargetName) (*evidence, error) {
	e := &evidence{}
	switch {
	case n.EventID != "":
		e.kind = "event"
		row, err := s.St.GetEvent(ctx, n.EventID)
		if errors.Is(err, store.ErrNotFound) {
			return e, nil
		}
		if err != nil {
			return nil, err
		}
		s.resolved(e, row, row.IP, row.Time)
	case n.Incident != "":
		e.kind = "incident"
		in, err := s.St.GetIncident(ctx, n.Incident)
		if errors.Is(err, store.ErrNotFound) {
			return e, nil
		}
		if err != nil {
			return nil, err
		}
		row, err := s.St.GetEvent(ctx, in.EventID)
		if errors.Is(err, store.ErrNotFound) {
			row = &store.EventRow{ID: in.EventID}
		} else if err != nil {
			return nil, err
		}
		s.resolved(e, row, in.IP, in.Time)
	default:
		e.kind = "pseudonym"
		rows, err := s.St.RecentAddresses(ctx, contractapi.MaxScanRows)
		if err != nil {
			return nil, err
		}
		seen := map[string]bool{}
		for _, a := range rows {
			if seen[a.IP] {
				continue
			}
			seen[a.IP] = true
			if p, _ := s.client(a.IP); p != n.ClientPseudonym {
				continue
			}
			row, err := s.St.GetEvent(ctx, a.EventID)
			if err != nil {
				return nil, err
			}
			s.resolved(e, row, row.IP, row.Time)
			break
		}
	}
	return e, nil
}

func oneTarget(n contractapi.BlockTargetName) bool {
	c := 0
	for _, v := range []string{n.EventID, n.Incident, n.ClientPseudonym} {
		if v != "" {
			c++
		}
	}
	return c == 1
}

func (s *Server) createBlock(w http.ResponseWriter, r *http.Request) {
	ci, _ := r.Context().Value(ctxKey{}).(*callInfo)
	if ci == nil {
		Problem(w, http.StatusForbidden, "forbidden", "Not part of the agent API.")
		return
	}
	if !contractapi.AllowsWrite(ci.token.Scope, contractapi.OpCreateBlock) {
		refuseBlock(w, contractapi.CheckBlock(contractapi.BlockInput{Scope: ci.token.Scope}))
		return
	}
	if s.Blocks == nil {
		Problem(w, http.StatusNotFound, "not_found", "Blocks are not available on this gateway.")
		return
	}
	var req contractapi.BlockRequest
	if !readBlockBody(w, r, &req) {
		return
	}
	if !oneTarget(req.Target) || !validReason(req.Reason) {
		Problem(w, http.StatusBadRequest, "invalid", "Name exactly one target. The reason has at most 300 characters and no control characters.")
		return
	}
	ev, err := s.findTarget(r.Context(), req.Target)
	if err != nil {
		Problem(w, http.StatusInternalServerError, "internal", "The target could not be read.")
		return
	}
	d, c, tok := s.Blocks, s.cfg().AgentAPI, ci.token
	now := s.now()
	// One decision at a time: the budget and the cap count what the last one did.
	d.mu.Lock()
	defer d.mu.Unlock()
	if ev.ip.IsValid() {
		if _, ok := d.Engine.ActiveBlock(ev.ip); ok {
			ev.target.Running = true
		}
	}
	v := contractapi.CheckBlock(contractapi.BlockInput{Scope: tok.Scope, Mode: d.Mode(), DurationS: req.DurationS, Reason: req.Reason, Target: ev.target,
		Budget: d.budget(tok.ID, c.BlockWritesPerHour, c.MaxAgentBlocks, now)})
	if !v.Allowed {
		refuseBlock(w, v)
		return
	}
	pseudonym, network := s.client(ev.ip.String())
	res := contractapi.BlockResult{Effect: *v.Effect, Changed: v.Changed, ClientPseudonym: pseudonym, ClientNet: network, NetClass: netClassOf(ev.target.NetClass),
		DurationS: req.DurationS, Persisted: v.Persisted}
	if v.LimitedBy != nil {
		res.LimitedBy = *v.LimitedBy
	}
	if !v.CountsBudget { // a running block stands
		bi, _ := d.Engine.ActiveBlock(ev.ip)
		s.answerRunning(w, res, bi)
		return
	}
	dur := time.Duration(req.DurationS) * time.Second
	reason := contractapi.Sanitize(req.Reason, contractapi.MaxReason)
	id := msg.NewID()
	data := events.AgentBlockSet{Effect: *v.Effect, Client: ev.client, KeyBits: keyBits(ev.ip), DurationS: req.DurationS, TargetKind: ev.kind, EvidenceEventID: ev.eventID,
		TokenID: tok.ID, TokenLabel: tok.Label, Reason: reason}
	if v.Changed {
		res.Incident = d.Engine.NewIncident()
		bi, created := d.Engine.SetAgentBlock(behaviour.AgentBlock{IP: ev.ip, TokenID: tok.ID, NetClass: res.NetClass, Duration: dur, Incident: res.Incident, EventID: id, Time: now})
		if !created { // a scenario was faster
			res.Changed, res.Persisted, res.Incident = false, false, ""
			s.answerRunning(w, res, bi)
			return
		}
		until := ts(bi.Until)
		res.Until, data.Until, data.Persisted, data.Incident = &until, until, v.Persisted, res.Incident
		d.Incident(&store.Incident{Incident: res.Incident, EventID: id, Time: now, IP: ev.ip.String(), Status: "blocked", Reason: "agent " + tok.Label + ": " + reason,
			Sources: []string{behaviour.AgentSource + tok.ID}})
	}
	d.spend(tok.ID, now)
	res.EventID = id
	d.Emit(id, events.BlockSet, now, data, eventlog.Index{IP: ev.ip.String(), Country: ev.client.Geo.Country, ASN: ev.client.Geo.ASN, Outcome: blockOutcome(*v.Effect),
		Incident: res.Incident, Summary: "agent block " + *v.Effect})
	writeJSON(w, res)
}

// answerRunning answers with the block that stands.
func (s *Server) answerRunning(w http.ResponseWriter, res contractapi.BlockResult, bi behaviour.BlockInfo) {
	until := ts(bi.Until)
	res.Until, res.Incident, res.Persisted = &until, bi.Incident, bi.Persisted
	res.DurationS = min(max(int(bi.Duration/time.Second), contractapi.MinBlockS), events.MaxBlockHostingS)
	if res.NetClass == "" {
		res.NetClass = netClassOf(bi.NetClass)
	}
	writeJSON(w, res)
}

func blockOutcome(effect string) string {
	if effect == contractapi.EffectWouldBlock {
		return "would_block"
	}
	return "blocked"
}

func netClassOf(nc string) string {
	if nc == "" {
		return "unknown"
	}
	return nc
}

func keyBits(ip netip.Addr) int {
	_, bits := behaviour.KeyOf(ip)
	return bits
}

// incidentToLift reads the incident of a lift. The row of a block follows it in
// the background, and an agent may lift right after it set the block: the block
// runs, so its row is what is late. It is written first, because the end of the
// block marks that row and a row that comes later would stay blocked for good.
// Should it not come (a full queue), the block can still be lifted.
func (s *Server) incidentToLift(ctx context.Context, id string) (*store.Incident, error) {
	in, err := s.St.GetIncident(ctx, id)
	if !errors.Is(err, store.ErrNotFound) || !s.Blocks.Engine.IncidentRunning(id) {
		return in, err
	}
	if f := s.Blocks.FlushIncidents; f != nil {
		wait, cancel := context.WithTimeout(ctx, liftFlushWait)
		defer cancel()
		f(wait)
		if in, err = s.St.GetIncident(ctx, id); !errors.Is(err, store.ErrNotFound) {
			return in, err
		}
	}
	return &store.Incident{Incident: id, Time: s.now(), Status: "blocked"}, nil
}

func (s *Server) liftBlock(w http.ResponseWriter, r *http.Request) {
	ci, _ := r.Context().Value(ctxKey{}).(*callInfo)
	if ci == nil {
		Problem(w, http.StatusForbidden, "forbidden", "Not part of the agent API.")
		return
	}
	if !contractapi.AllowsWrite(ci.token.Scope, contractapi.OpLiftBlock) {
		refuseBlock(w, contractapi.CheckLift(contractapi.LiftInput{Scope: ci.token.Scope}))
		return
	}
	if s.Blocks == nil {
		Problem(w, http.StatusNotFound, "not_found", "Blocks are not available on this gateway.")
		return
	}
	var req contractapi.LiftRequest
	if !readBlockBody(w, r, &req) {
		return
	}
	if !validReason(req.Reason) {
		Problem(w, http.StatusBadRequest, "invalid", "The reason has at most 300 characters and no control characters.")
		return
	}
	id := r.PathValue("incident")
	in, err := s.incidentToLift(r.Context(), id)
	status := "blocked"
	switch {
	case errors.Is(err, store.ErrNotFound):
		status = "missing"
	case err != nil:
		Problem(w, http.StatusInternalServerError, "internal", "The incident could not be read.")
		return
	case in.Status == "unblocked":
		status = "unblocked"
	}
	d, c, tok := s.Blocks, s.cfg().AgentAPI, ci.token
	now := s.now()
	d.mu.Lock()
	defer d.mu.Unlock()
	v := contractapi.CheckLift(contractapi.LiftInput{Scope: tok.Scope, Reason: req.Reason, Status: status, Running: d.Engine.IncidentRunning(id),
		Budget: d.budget(tok.ID, c.BlockWritesPerHour, c.MaxAgentBlocks, now)})
	if !v.Allowed {
		refuseBlock(w, v)
		return
	}
	if v.Changed {
		// A node of a group owes the group the lift: noted with the incident
		// before the block ends here, so it is not lost (store/outbox.go).
		if err := s.St.NoteLifts(r.Context(), now, id); err != nil {
			Problem(w, http.StatusInternalServerError, "internal", "The lift could not be stored.")
			return
		}
	}
	if v.Changed && d.Engine.LiftIncident(id) {
		d.spend(tok.ID, now)
		source := ""
		if len(in.Sources) > 0 {
			source = in.Sources[0]
		}
		d.Emit(msg.NewID(), events.BlockLifted, now, events.AgentBlockLifted{Incident: id, Source: source, TokenID: tok.ID, TokenLabel: tok.Label,
			Reason: contractapi.Sanitize(req.Reason, contractapi.MaxReason)}, eventlog.Index{Incident: id, Summary: "agent block lifted"})
		// The stored row follows in the background; the answer already says so.
		in.Status, in.UnblockedAt = "unblocked", now
	}
	writeJSON(w, s.incident(r.Context(), in))
}
