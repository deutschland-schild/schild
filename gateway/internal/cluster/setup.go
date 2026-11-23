package cluster

import (
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"sort"
	"strings"
	"time"

	contract "github.com/deutschland-schild/schild/contract/cluster"
)

// What `schild cluster` does on the host, and how a node sets itself up from
// the configuration. Every command works on the files of the data
// directory, also while the gateway runs: the node reads the member list
// from the same database.

func memberOf(name, address string, pub ed25519.PublicKey, now time.Time) (*contract.Member, error) {
	name = strings.TrimSpace(name)
	ap, err := netip.ParseAddrPort(address)
	if err != nil || ap.Addr().IsUnspecified() {
		return nil, fmt.Errorf("%w: address %q is no host:port the other nodes reach", contract.ErrSchema, address)
	}
	if name == "" || len(name) > 63 || strings.ContainsAny(name, " \t\r\n/") {
		return nil, fmt.Errorf("%w: node name %q", contract.ErrSchema, name)
	}
	return &contract.Member{Name: name, Role: contract.RoleGateway, PublicKey: base64.StdEncoding.EncodeToString(pub), Address: ap.String(), Joined: contract.TimeText(now)}, nil
}

// metaHashKey is where a node keeps the key of the keyed hashes of its
// group (16 bytes): the nodes compare hashes of user names and merge
// sketches, so they hash under one key. Every node derives it from the
// group secret (state.enter).
const metaHashKey = "hash_key"

// HashKey returns the group's hash key of a data directory; ok false: the
// node belongs to no group.
func HashKey(dir string) (key [16]byte, ok bool) {
	s, err := openState(dir, false, nil)
	if err != nil {
		return key, false
	}
	defer s.close()
	v, err := s.meta(metaHashKey)
	if err != nil || len(v) != 16 {
		return key, false
	}
	copy(key[:], v)
	return key, true
}

// Remove ends the membership of a node, named by its name or id: from then
// on no member talks to it and none takes a record it signs. The tombstone
// keeps the member's key, so what it decided before still verifies.
func Remove(dir, who string, now func() time.Time) (contract.Entry, error) {
	s, err := openState(dir, false, now)
	if err != nil {
		return contract.Entry{}, err
	}
	defer s.close()
	if s.group == "" {
		return contract.Entry{}, ErrNoGroup
	}
	ro, err := s.roster()
	if err != nil {
		return contract.Entry{}, err
	}
	var found []contract.Entry
	for _, e := range ro.Members() {
		if !e.Removed && (e.ID == who || e.Member.Name == who) {
			found = append(found, e)
		}
	}
	switch len(found) {
	case 0:
		return contract.Entry{}, fmt.Errorf("cluster: no member %q", who)
	case 1:
	default:
		return contract.Entry{}, fmt.Errorf("cluster: %d members are named %q, use the node id", len(found), who)
	}
	m := found[0].Member
	_, err = s.publish(contract.ClassMembers, found[0].ID, &m, true, time.Time{})
	return found[0], err
}

// MemberStatus is one row of Status.
type MemberStatus struct {
	contract.Entry
	Self bool
	// OutOK and InOK: the last call to and from the member, as the running
	// node saw it. Zero: none.
	OutOK, InOK time.Time
	Error       string
	// Behind is how many records the member has that this node lacks.
	Behind uint64
	// Clock is the member's clock minus this node's, as the running node
	// noted it at ClockAt (NoteClock); ClockAt zero: nothing noted.
	Clock   time.Duration
	ClockAt time.Time
}

// markClock is the note of a member's clock: "<difference ms>:<noted at, unix ms>".
const markClock = "clock:"

// markClockOut is the note that this node left traffic because its clock is
// off the group's: "<noted at, unix ms>", "" when it is not.
const markClockOut = "clock_out"

// NoteClockOut keeps for `schild cluster status` that this node left
// traffic because of its clock, or that it is back.
func (n *Node) NoteClockOut(out bool) error {
	v := ""
	if out {
		v = fmt.Sprint(n.now().UnixMilli())
	}
	return n.SetMark(markClockOut, v)
}

// NoteClock keeps how far the clock of a member is off this node's, for
// `schild cluster status`, which reads the store and not the process.
//
// Kept in memory and written with the view of the peers (saveStatus), not
// into the store: a note per member and minute would be a commit each.
func (n *Node) NoteClock(member string, skew time.Duration) error {
	n.pmu.Lock()
	if n.clocks == nil {
		n.clocks = map[string]statusClock{}
	}
	if _, known := n.clocks[member]; !known && len(n.clocks) >= 4*MaxGateways {
		n.pmu.Unlock()
		return errors.New("cluster: too many clock notes")
	}
	n.clocks[member] = statusClock{SkewMS: skew.Milliseconds(), At: n.now().UnixMilli()}
	n.pmu.Unlock()
	// Written at once: the command line shows it without waiting for the
	// next view of the peers.
	n.saveStatus()
	return nil
}

// Status is what `schild cluster status` prints.
type Status struct {
	Group   string
	Node    string
	Members []MemberStatus
	// Records held per class, and the counters of the running node.
	Records  map[string]int
	Counters map[string]uint64
	// Seen is when the running node last wrote its view; zero: it does not run.
	Seen time.Time
	// Replaced counts the values this node gave up for the group's at its
	// first sync; they are kept in cluster.db.
	Replaced int
	// ClockOut: when the running node last noted that it left traffic
	// because its clock is off the group's (NoteClockOut); zero: it did not.
	ClockOut time.Time
}

// ReadStatus reads the state of the group from the data directory.
func ReadStatus(dir string, now func() time.Time) (*Status, error) {
	s, err := openState(dir, false, now)
	if err != nil {
		return nil, err
	}
	defer s.close()
	if s.group == "" {
		return nil, ErrNoGroup
	}
	ro, err := s.roster()
	if err != nil {
		return nil, err
	}
	st := &Status{Group: s.group, Node: s.id, Records: map[string]int{}, Counters: map[string]uint64{}}
	type row struct {
		out, in, behind int64
		err             string
	}
	peers := map[string]row{}
	// What the running node wrote last (saveStatus). A node of an earlier
	// build wrote the same into tables of the store; without the file they
	// are read, so a status right after an update still shows the last view.
	view, fromFile := readStatusView(dir)
	if fromFile {
		for id, p := range view.Peers {
			peers[id] = row{out: p.OutOK, in: p.InOK, behind: int64(p.Behind), err: p.Error}
		}
	} else {
		rows, err := s.db.Query(`SELECT node, out_ok_ms, in_ok_ms, error, behind FROM peers`)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var id string
			var r row
			if err := rows.Scan(&id, &r.out, &r.in, &r.err, &r.behind); err != nil {
				rows.Close()
				return nil, err
			}
			peers[id] = r
		}
		rows.Close()
	}
	at := func(ms int64) time.Time {
		if ms == 0 {
			return time.Time{}
		}
		return time.UnixMilli(ms).UTC()
	}
	for _, e := range ro.Members() {
		p := peers[e.ID]
		m := MemberStatus{Entry: e, Self: e.ID == s.id, OutOK: at(p.out), InOK: at(p.in), Error: p.err, Behind: uint64(p.behind)}
		if c, ok := view.Clocks[e.ID]; ok {
			m.Clock, m.ClockAt = time.Duration(c.SkewMS)*time.Millisecond, at(c.At)
		} else if v, err := s.meta("mark:" + markClock + e.ID); err == nil {
			// The note of an earlier build.
			var skew, noted int64
			if _, err := fmt.Sscanf(string(v), "%d:%d", &skew, &noted); err == nil {
				m.Clock, m.ClockAt = time.Duration(skew)*time.Millisecond, at(noted)
			}
		}
		st.Members = append(st.Members, m)
	}
	rows, err := s.db.Query(`SELECT class, count(*) FROM records WHERE state = ? AND deleted = 0 GROUP BY class`, stateWinner)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var c string
		var n int
		if err := rows.Scan(&c, &n); err == nil {
			st.Records[c] = n
		}
	}
	rows.Close()
	if fromFile {
		for k, n := range view.Counters {
			st.Counters[k] = n
		}
	} else {
		if rows, err = s.db.Query(`SELECT k, n FROM counters`); err != nil {
			return nil, err
		}
		for rows.Next() {
			var k string
			var n int64
			if err := rows.Scan(&k, &n); err == nil {
				st.Counters[k] = uint64(n)
			}
		}
		rows.Close()
	}
	_ = s.db.QueryRow(`SELECT count(*) FROM replaced`).Scan(&st.Replaced)
	if v, err := s.meta("mark:" + markClockOut); err == nil {
		var noted int64
		if _, err := fmt.Sscanf(string(v), "%d", &noted); err == nil && noted > 0 {
			st.ClockOut = time.UnixMilli(noted).UTC()
		}
	}
	if fromFile {
		st.Seen = at(view.At)
		return st, nil
	}
	var seen int64
	if err := s.db.QueryRow(`SELECT CAST(v AS INTEGER) FROM meta WHERE k = 'status_ms'`).Scan(&seen); err == nil {
		st.Seen = at(seen)
	} else if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	return st, nil
}

// ErrRemovedSelf: this node was removed from its group.
var ErrRemovedSelf = errors.New("cluster: this node was removed from its group")

// NewSecret makes a group secret: 32 random bytes in hex.
func NewSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// ReadSecret reads the group secret of cluster.secret_file. Its owner and
// its group may read it (0600, 0640, 0440: a deployment may keep it as
// root:schild); nobody else may read it, and nobody but the owner write it.
// The node key stays for its owner alone (loadKey).
func ReadSecret(path string) ([]byte, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("cluster.secret_file: %w", err)
	}
	if perm := fi.Mode().Perm(); perm&0o027 != 0 {
		return nil, fmt.Errorf("cluster.secret_file %s has mode %04o: others may read it or its group may write it; make it the service user's: chown schild:schild %s && chmod 0640 %s", path, perm, path, path)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cluster.secret_file: %w", err)
	}
	secret := []byte(strings.TrimSpace(string(raw)))
	if len(secret) < contract.MinSecret {
		return nil, fmt.Errorf("cluster.secret_file %s: %w", path, contract.ErrSecret)
	}
	return secret, nil
}

// Configure sets this node up from the configuration alone: with the group
// secret it lets itself into the secret's group, under its name and
// address. It changes nothing when the node is set up already, and writes
// the member record again when name or address changed in schild.yaml. A
// deployment runs it on every node through the start of schild; nothing
// goes from node to node by hand.
//
// A node that belongs to another group than the secret names moves to the
// secret's group and takes along what it held (move.go); moved then says
// what happened. That is how a group secret is replaced: the new file on
// every node, and a restart of each.
func Configure(dir, name, address string, secret []byte, now func() time.Time) (group string, moved *Moved, err error) {
	gk, err := contract.GroupKey(secret)
	if err != nil {
		return "", nil, err
	}
	s, err := openState(dir, true, now)
	if err != nil {
		return "", nil, err
	}
	defer s.close()
	m, err := memberOf(name, address, s.pub, s.now())
	if err != nil {
		return "", nil, err
	}
	group = m.AdmitWith(gk, s.pub)
	switch s.group {
	case group:
	case "":
		if err := s.enter(group, secret); err != nil {
			return "", nil, err
		}
	default:
		s.close()
		moved, err = move(dir, name, address, secret, now)
		if err != nil {
			return "", nil, fmt.Errorf("cluster: this node is in group %s and the secret is of group %s; the move failed and the node stays where it was: %w", s.group, group, err)
		}
		return group, moved, nil
	}
	recs, _, err := s.winners(contract.ClassMembers)
	if err != nil {
		return "", nil, err
	}
	for _, r := range recs {
		if r.ID != s.id {
			continue
		}
		if r.Deleted {
			return "", nil, ErrRemovedSelf
		}
		if cur, err := contract.DecodeMember(r); err == nil {
			if cur.Name == m.Name && cur.Address == m.Address && cur.AdmitKey == m.AdmitKey {
				return group, nil, nil // set up already
			}
			m.Joined = cur.Joined
		}
	}
	_, err = s.publish(contract.ClassMembers, s.id, m, false, time.Time{})
	return group, nil, err
}

// Identity returns the node id of a data directory; ok false: the node
// belongs to no group.
func Identity(dir string) (id string, ok bool) {
	s, err := openState(dir, false, nil)
	if err != nil {
		return "", false
	}
	defer s.close()
	return s.id, s.group != ""
}

// MaxGateways is the size a group of this version takes: a full mesh
// between the gateways, tested with three. More are refused rather than
// tried.
const MaxGateways = 16

var errFull = errors.New("cluster: the group is full")

// full reports whether the group holds as many gateways as this version
// takes.
func (n *Node) full() bool {
	n.rmu.RLock()
	defer n.rmu.RUnlock()
	count := 0
	for _, e := range n.roster.Members() {
		if !e.Removed {
			count++
		}
	}
	return count >= MaxGateways
}

// Live is Status as the running node holds it: members, contacts and
// counters from memory, the number of records per class from its own
// database. The dashboard reads it; nothing is asked of another node.
func (n *Node) Live() (*Status, error) {
	st := &Status{Group: n.group, Node: n.id, Records: map[string]int{}, Seen: n.now(),
		Counters: map[string]uint64{"applied": n.Applied.Load(), "rejected": n.Rejected.Load(), "deferred": n.Deferred.Load(), "unread": n.Unread.Load()}}
	n.rmu.RLock()
	members := n.roster.Members()
	n.rmu.RUnlock()
	type contact struct {
		out, in time.Time
		err     string
		behind  uint64
	}
	seen := map[string]contact{}
	n.pmu.Lock()
	for id, p := range n.peers {
		p.mu.Lock()
		seen[id] = contact{out: p.outOK, in: p.inOK, err: p.err, behind: p.behind}
		p.mu.Unlock()
	}
	n.pmu.Unlock()
	for _, e := range members {
		c := seen[e.ID]
		st.Members = append(st.Members, MemberStatus{Entry: e, Self: e.ID == n.id, OutOK: c.out, InOK: c.in, Error: c.err, Behind: c.behind})
	}
	rows, err := n.db.Query(`SELECT class, count(*) FROM records WHERE state = ? AND deleted = 0 GROUP BY class`, stateWinner)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var c string
		var k int
		if err := rows.Scan(&c, &k); err == nil {
			st.Records[c] = k
		}
	}
	rows.Close()
	_ = n.db.QueryRow(`SELECT count(*) FROM replaced`).Scan(&st.Replaced)
	return st, nil
}

// Acked returns which of the gateways of the group said they hold the
// records of this node up to seq, and which did not (yet), by name. A
// gateway this node does not reach is among the open ones.
func (n *Node) Acked(seq uint64) (reached, open []string) {
	n.pmu.Lock()
	defer n.pmu.Unlock()
	for _, p := range n.peers {
		p.mu.Lock()
		if p.inSeq >= seq {
			reached = append(reached, p.name)
		} else {
			open = append(open, p.name)
		}
		p.mu.Unlock()
	}
	sort.Strings(reached)
	sort.Strings(open)
	return reached, open
}
