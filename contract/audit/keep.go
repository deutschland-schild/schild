package audit

import (
	"net/netip"
	"sort"
)

// Changes, credentials and privacy entries are kept audit.keep_days and have
// no cap; sign-ins and refused calls have a fixed age and a cap each.
const (
	// DefaultKeepDays: audit.keep_days when schild.yaml does not set it.
	DefaultKeepDays = 365
	MinKeepDays     = 90
	MaxKeepDays     = 36500
	AccessDays      = 90
	MaxAccessRows   = 20000
	MaxOpenRefused  = 4096
	// TokenEntriesPerHour: what one agent token may write into the log.
	TokenEntriesPerHour = 600
	dayMS               = int64(24 * 3600 * 1000)
	minuteMS            = int64(60 * 1000)
)

// Row of the audit log, as Delete sees it.
type Row struct {
	ID    string
	Class string
	// T in unix ms: the time of the entry, at the latest when this node
	// stored it.
	T int64
}

// Delete returns the ids to delete, oldest first. keepDays 0 is
// audit.keep_days: unlimited.
func Delete(rows []Row, now, keepDays, maxRows int64) []string {
	rs := append([]Row(nil), rows...)
	sort.Slice(rs, func(i, j int) bool {
		if rs[i].T != rs[j].T {
			return rs[i].T < rs[j].T
		}
		return rs[i].ID < rs[j].ID
	})
	n := map[string]int64{}
	for _, r := range rs {
		n[r.Class]++
	}
	out := []string{}
	for _, r := range rs {
		gone := false
		switch r.Class {
		case ClassAccess, ClassRefused:
			gone = r.T <= now-AccessDays*dayMS || n[r.Class] > maxRows
		default:
			gone = keepDays > 0 && r.T <= now-keepDays*dayMS
		}
		if gone {
			n[r.Class]--
			out = append(out, r.ID)
		}
	}
	return out
}

// Call is one refused call.
type Call struct {
	T         int64 // unix ms
	Action    string
	Operation string
	Actor     string // token or portal key, when known
	Address   string
}

// Gathered is an entry of refused calls.
type Gathered struct {
	Action    string `json:"action"`
	Operation string `json:"operation"`
	Actor     string `json:"actor,omitempty"`
	Address   string `json:"address,omitempty"`
	First     int64  `json:"first"`
	Last      int64  `json:"last"`
	Count     int64  `json:"count"`
}

// Gather puts refused calls into one entry per action, operation, actor,
// client (IPv4 address, IPv6 /64) and UTC minute. Beyond maxOpen entries of
// a minute a call counts in the entry of its action, operation and actor
// without an address; those are at most as many as there are tokens and
// portal keys times operations.
func Gather(calls []Call, maxOpen int) []Gathered {
	type key struct{ action, operation, actor, client string }
	out := []Gathered{}
	open := map[key]int{}
	minute, n := int64(-1), 0
	for _, c := range calls {
		if m := c.T / minuteMS; m > minute {
			minute, n = m, 0
			open = map[key]int{}
		}
		k := key{c.Action, c.Operation, c.Actor, clientKey(c.Address)}
		i, ok := open[k]
		if !ok && k.client != "" && n >= maxOpen {
			k.client = ""
			c.Address = ""
			i, ok = open[k]
		}
		if !ok {
			if k.client != "" {
				n++
			}
			open[k] = len(out)
			out = append(out, Gathered{c.Action, c.Operation, c.Actor, c.Address, c.T, c.T, 1})
			continue
		}
		g := &out[i]
		g.Count++
		g.First, g.Last = min(g.First, c.T), max(g.Last, c.T)
	}
	return out
}

func clientKey(s string) string {
	a, err := netip.ParseAddr(s)
	if err != nil || a.Zone() != "" {
		return ""
	}
	a = a.Unmap()
	if a.Is4() {
		return a.String()
	}
	p, _ := a.Prefix(64)
	return p.Addr().String()
}
