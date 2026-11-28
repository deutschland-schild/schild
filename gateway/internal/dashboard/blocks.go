package dashboard

import (
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"time"

	contractapi "github.com/deutschland-schild/schild/contract/agentapi"
	"github.com/deutschland-schild/schild/contract/events"
	"github.com/deutschland-schild/schild/contract/firewall"
	"github.com/deutschland-schild/schild/contract/msg"
	"github.com/deutschland-schild/schild/gateway/internal/behaviour"
	"github.com/deutschland-schild/schild/gateway/internal/decide"
	"github.com/deutschland-schild/schild/gateway/internal/eventlog"
	"github.com/deutschland-schild/schild/gateway/internal/store"
)

// RunningBlock is one address block that runs (D87).
type RunningBlock struct {
	Client    string `json:"client"`
	Source    string `json:"source"` // scenario | agent
	Scenario  string `json:"scenario,omitempty"`
	TokenID   string `json:"token_id,omitempty"`
	Since     string `json:"since"`
	Until     string `json:"until"`
	DurationS int    `json:"duration_s"`
	Level     int    `json:"level"`
	NetClass  string `json:"net_class"`
	Incident  string `json:"incident"`
	Kept      bool   `json:"kept"`
	// Node is the node of the group that decided the block, NodeSelf whether
	// that is this node; both absent on a single gateway.
	Node     string `json:"node,omitempty"`
	NodeSelf *bool  `json:"node_self,omitempty"`
	Firewall string `json:"firewall"` // off | stale | pending | banned
}

// BlockFirewall is the handoff to the host's firewall as a whole.
type BlockFirewall struct {
	State    string  `json:"state"` // off | stale | ok | error
	Table    string  `json:"table"`
	SyncedAt *string `json:"synced_at,omitempty"`
	Banned   int     `json:"banned,omitempty"`
	Error    string  `json:"error,omitempty"`
}

// BlockList is the answer of listBlocks.
type BlockList struct {
	GeneratedAt string         `json:"generated_at"`
	Items       []RunningBlock `json:"items"`
	Total       int            `json:"total"`
	Firewall    BlockFirewall  `json:"firewall"`
}

// maxBlockList bounds the rows of listBlocks.
const maxBlockList = 500

// listBlocks lists every address block that runs, with the state of the
// handoff to the host's firewall (nftables).
func (s *Server) listBlocks(w http.ResponseWriter, r *http.Request) {
	if !s.behaviourAvailable(w) {
		return
	}
	now := time.Now()
	fw := BlockFirewall{State: "off", Table: firewall.Table}
	var banned map[string]bool
	if s.FirewallState != nil {
		if rep, ok := s.FirewallState(); ok {
			at := ts(rep.At)
			fw.SyncedAt, fw.Banned, fw.Error = &at, rep.Held, firewall.OneLine(rep.Error, 300)
			if rep.Table != "" {
				fw.Table = rep.Table
			}
			switch {
			case now.Sub(rep.At) > firewall.Stale:
				fw.State = "stale"
			case rep.Error != "":
				fw.State = "error"
			default:
				fw.State = "ok"
				// What the firewall applied, by the revision it names; after a
				// restart of the gateway that revision is unknown: pending.
				banned = rep.Clients
			}
		}
	}
	run := s.Behaviour.RunningBlocks()
	out := BlockList{GeneratedAt: ts(now), Items: []RunningBlock{}, Total: len(run), Firewall: fw}
	for _, b := range run[:min(len(run), maxBlockList)] {
		rb := RunningBlock{Client: firewall.ClientOf(b.Key), Since: ts(b.Since), Until: ts(b.Until), DurationS: max(int(b.Duration/time.Second), 1),
			Level: max(b.Level, 1), NetClass: b.NetClass, Incident: b.Incident, Kept: b.Persisted, Firewall: blockFirewall(fw.State, banned, firewall.ClientOf(b.Key))}
		if tok, ok := strings.CutPrefix(b.Scenario, behaviour.AgentSource); ok {
			rb.Source, rb.TokenID = "agent", tok
		} else if b.Scenario == behaviour.DashboardSource {
			rb.Source = "dashboard"
		} else {
			rb.Source, rb.Scenario = "scenario", b.Scenario
		}
		if s.BlockNode != nil {
			if name, self, ok := s.BlockNode(b.Key, b.Incident); ok {
				rb.Node, rb.NodeSelf = name, &self
			}
		}
		out.Items = append(out.Items, rb)
	}
	writeJSON(w, http.StatusOK, out)
}

// blockFirewall is the firewall state of one client: banned or pending while
// the sync is fresh and without error, else the state of the handoff.
func blockFirewall(state string, banned map[string]bool, client string) string {
	switch state {
	case "ok":
		if banned[client] {
			return "banned"
		}
		return "pending"
	case "error":
		return "stale"
	}
	return state
}

// BlockRequest is the body of createBlock (D88): an address blocked by hand.
type BlockRequest struct {
	Address   string `json:"address"`
	DurationS int    `json:"duration_s"`
	Reason    string `json:"reason"`
	SharedOK  bool   `json:"shared_ok"`
}

// blockDurations a block by hand may last: 1 hour, 24 hours, 7 days.
var blockDurations = map[int]bool{3600: true, 86400: true, 604800: true}

// blockRefusals word the refusals of createBlock.
var blockRefusals = map[string]string{
	"own_address":     "Diese Adresse steht unter „Eigene IPs“ oder gehört zu diesem Server. Schild sperrt sie nie, damit du dich nicht aussperrst.",
	"private_address": "Das ist keine öffentliche Adresse (privates Netz, Loopback oder Ähnliches). Von dort kommt kein Besuch aus dem Internet.",
	"shared_address":  "Diese Adresse teilen sich viele Menschen (Mobilfunk, CGNAT oder Tor). Eine Sperre trifft sie alle. Bestätige, wenn du sie trotzdem sperren willst.",
	"test_profile":    "Im Testprofil sperrt Schild niemanden, auch nicht von Hand.",
}

// createBlock blocks one address by hand (D88): the same block as an
// agent's, with source dashboard, an incident and an end. The host's
// firewall gets it with the next answer to `schild firewall run`.
func (s *Server) createBlock(w http.ResponseWriter, r *http.Request) {
	if !s.behaviourAvailable(w) {
		return
	}
	var req BlockRequest
	if !decode(w, r, &req) {
		return
	}
	ip, err := netip.ParseAddr(strings.TrimSpace(req.Address))
	var errs []FieldError
	if err != nil || ip.Zone() != "" {
		errs = append(errs, FieldError{Pointer: "/address", Detail: "eine IPv4- oder IPv6-Adresse, kein Netz und kein Name"})
	}
	if !blockDurations[req.DurationS] {
		errs = append(errs, FieldError{Pointer: "/duration_s", Detail: "1 Stunde, 24 Stunden oder 7 Tage"})
	}
	if !exceptionReason(req.Reason) {
		errs = append(errs, FieldError{Pointer: "/reason", Detail: fmt.Sprintf("eine Zeile, höchstens %d Zeichen", contractapi.MaxReason)})
	}
	if len(errs) > 0 {
		invalid(w, "So lässt sich die Adresse nicht sperren.", errs...)
		return
	}
	ip = ip.Unmap()
	refuse := func(code string) { problem(w, http.StatusConflict, code, blockRefusals[code], nil) }
	switch {
	case s.Gate != nil && s.Gate.Settings().Mode == decide.ModeObserve:
		refuse("test_profile")
		return
	case contractapi.ProtectedAddress(ip):
		refuse("private_address")
		return
	case s.OwnAddress != nil && s.OwnAddress(ip):
		refuse("own_address")
		return
	}
	geo := events.Geo{Country: "ZZ", NetClass: "unknown"}
	if s.GeoOf != nil {
		geo = s.GeoOf(ip)
	}
	if (geo.NetClass == "mobile" || geo.NetClass == "cgnat" || geo.NetClass == "tor") && !req.SharedOK {
		refuse("shared_address")
		return
	}
	if bi, ok := s.Behaviour.ActiveBlock(ip); ok {
		problem(w, http.StatusConflict, "already_blocked", fmt.Sprintf("Diese Adresse ist schon gesperrt, Vorfall %s, bis %s UTC.", bi.Incident, bi.Until.UTC().Format("2006-01-02 15:04")), nil)
		return
	}
	now := s.now()
	reason := contractapi.Sanitize(req.Reason, contractapi.MaxReason)
	incident := s.Behaviour.NewIncident()
	id := msg.NewID()
	bi, created := s.Behaviour.SetAgentBlock(behaviour.AgentBlock{IP: ip, Source: behaviour.DashboardSource, NetClass: geo.NetClass,
		Duration: time.Duration(req.DurationS) * time.Second, Incident: incident, EventID: id, Time: now})
	if !created {
		problem(w, http.StatusConflict, "already_blocked", fmt.Sprintf("Diese Adresse ist schon gesperrt, Vorfall %s.", bi.Incident), nil)
		return
	}
	if s.Gate != nil {
		s.Gate.QueueIncident(&store.Incident{Incident: incident, EventID: id, Time: now, IP: ip.String(), Status: "blocked", Reason: "dashboard: " + reason,
			Sources: []string{behaviour.DashboardSource}})
	}
	key, bits := behaviour.KeyOf(ip)
	until := ts(bi.Until)
	// The block runs in the engine and is kept by its writer, not by this
	// call: the entry is written before the answer (contracts/audit.md
	// section 4).
	en := s.entry(r, "block.set", "createBlock")
	en.Subject, en.Reason = incident, reason
	en.After = map[string]any{"client": ip.String(), "duration_s": req.DurationS, "until": until, "effect": "block"}
	if !s.written(w, s.Audit.Write(r.Context(), en)) {
		return
	}
	if s.Events != nil {
		// The block applies to the TCP peer with this address: attribution tcp_peer.
		s.Events.EmitWithID(id, events.BlockSet, now, events.AgentBlockSet{Actor: "dashboard", Effect: "block", Client: events.Client{IP: ip.String(), Attribution: "tcp_peer", Geo: geo},
			KeyBits: bits, DurationS: req.DurationS, Until: until, Persisted: bi.Persisted, Incident: incident, TargetKind: "address", Reason: reason},
			eventlog.Index{IP: ip.String(), Country: geo.Country, ASN: geo.ASN, Outcome: "blocked", Incident: incident, Summary: "dashboard block"})
	}
	writeJSON(w, http.StatusOK, RunningBlock{Client: firewall.ClientOf(key), Source: "dashboard", Since: ts(now), Until: until, DurationS: req.DurationS, Level: 1,
		NetClass: geo.NetClass, Incident: incident, Kept: bi.Persisted, Firewall: s.firewallStateOf(firewall.ClientOf(key))})
}

// firewallStateOf is the firewall state of one client now, as listBlocks says it.
func (s *Server) firewallStateOf(client string) string {
	if s.FirewallState == nil {
		return "off"
	}
	rep, ok := s.FirewallState()
	switch {
	case !ok:
		return "off"
	case s.now().Sub(rep.At) > firewall.Stale || rep.Error != "":
		return "stale"
	case rep.Clients[client]:
		return "banned"
	}
	return "pending"
}
