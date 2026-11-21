package dashboard

import (
	"net/http"
	"time"
)

// The group of gateways in the dashboard (MVP-27, D103, contracts/
// cluster.md): the mode this gateway runs in. The server only passes on
// what the running node knows (Server.Group); a single gateway needs
// nothing of the group for its answer.

// MaxGroupMembers bounds GroupStatus.Members.
const MaxGroupMembers = 64

// GroupStatus is the answer of getGroupStatus.
type GroupStatus struct {
	Mode        string         `json:"mode"` // single | group
	State       string         `json:"state,omitempty"`
	PausedSince *string        `json:"paused_since,omitempty"`
	GeneratedAt string         `json:"generated_at,omitempty"`
	Group       string         `json:"group,omitempty"`
	Node        *GroupNode     `json:"node,omitempty"`
	Members     []GroupMember  `json:"members,omitempty"`
	Shared      *GroupShared   `json:"shared,omitempty"`
	Counters    *GroupCounters `json:"counters,omitempty"`
	Replaced    *int           `json:"replaced,omitempty"`
	Config      *GroupConfig   `json:"config,omitempty"`
}

// GroupNode is this node in its group.
type GroupNode struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Role string `json:"role"`
}

// GroupMember is one member as this node sees it.
type GroupMember struct {
	ID         string  `json:"id"`
	Name       string  `json:"name"`
	Role       string  `json:"role"`
	Address    string  `json:"address,omitempty"`
	State      string  `json:"state"` // self | ok | unreachable | no_contact | asks_elsewhere | removed
	LastOut    *string `json:"last_out,omitempty"`
	LastIn     *string `json:"last_in,omitempty"`
	Behind     *int    `json:"behind,omitempty"`
	Version    string  `json:"version,omitempty"`
	Config     string  `json:"config,omitempty"` // same | differs | unknown
	Error      string  `json:"error,omitempty"`
	BlocksHeld *int    `json:"blocks_held,omitempty"`
}

// GroupShared counts what this node holds of the group's state.
type GroupShared struct {
	Blocks    int  `json:"blocks"`
	Settings  int  `json:"settings"`
	Access    int  `json:"access"`
	Logins    int  `json:"logins"`
	ShareData bool `json:"share_data"`
}

// GroupCounters are the records of other nodes since the start.
type GroupCounters struct {
	Taken    uint64 `json:"taken"`
	Refused  uint64 `json:"refused"`
	Deferred uint64 `json:"deferred"`
	Unread   uint64 `json:"unread"`
}

// GroupConfig is the hint on config drift.
type GroupConfig struct {
	Version   string   `json:"version"`
	Differing []string `json:"differing"`
}

// ErasureNodes is how far an erasure got in the group.
type ErasureNodes struct {
	Reached []string `json:"reached"`
	Open    []string `json:"open"`
}

// maxErasureNodes bounds each list of ErasureNodes.
const maxErasureNodes = 16

func (e *ErasureNodes) bounded() *ErasureNodes {
	if e == nil {
		return nil
	}
	cut := func(xs []string) []string {
		if xs == nil {
			return []string{}
		}
		return xs[:min(len(xs), maxErasureNodes)]
	}
	return &ErasureNodes{Reached: cut(e.Reached), Open: cut(e.Open)}
}

// Stamp and StampPtr format a time as the API does; StampPtr is nil for
// the zero time.
func Stamp(t time.Time) string     { return ts(t) }
func StampPtr(t time.Time) *string { return tsp(t) }

func (s *Server) getGroupStatus(w http.ResponseWriter, r *http.Request) {
	if s.Group == nil {
		writeJSON(w, http.StatusOK, GroupStatus{Mode: "single"})
		return
	}
	writeJSON(w, http.StatusOK, s.Group())
}
