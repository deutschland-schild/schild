package cluster

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"sort"
	"strings"
	"time"

	contract "github.com/deutschland-schild/schild/contract/cluster"
)

// What `schild cluster` does on the host. Every command works on the files
// of the data directory, also while the gateway runs: the node reads the
// member list and the invites from the same database.

var errInvite = errors.New("cluster: join code not valid")

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

// Init makes this node the first of a new group and returns the group id.
func Init(dir, name, address string, now func() time.Time) (group string, err error) {
	s, err := openState(dir, true, now)
	if err != nil {
		return "", err
	}
	defer s.close()
	if s.group != "" {
		return "", ErrHasGroup
	}
	m, err := memberOf(name, address, s.pub, s.now())
	if err != nil {
		return "", err
	}
	s.group = contract.GroupID(s.pub)
	tx, err := s.db.Begin()
	if err != nil {
		return "", err
	}
	if err := setMeta(tx, "group", []byte(s.group)); err != nil {
		tx.Rollback()
		return "", err
	}
	hk := make([]byte, 16)
	if _, err := rand.Read(hk); err != nil {
		tx.Rollback()
		return "", err
	}
	if err := setMeta(tx, metaHashKey, hk); err != nil {
		tx.Rollback()
		return "", err
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	if _, err := s.publish(contract.ClassMembers, s.id, m, false, time.Time{}); err != nil {
		return "", err
	}
	return s.group, nil
}

// metaHashKey is where a node keeps the key of the keyed hashes of its
// group (16 bytes): the nodes compare hashes of user names and merge
// sketches, so they hash under one key. The founder makes it, a node that
// joins gets it with the member list, and a group set up by configuration
// derives it from the group secret.
const metaHashKey = "hash_key"

// HashKey returns the group's hash key of a data directory; ok false: the
// node belongs to no group, or to one from before the key existed.
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

// Invite makes a join code of this node: one use, valid for an hour.
func Invite(dir string, now func() time.Time) (code string, expires time.Time, err error) {
	s, err := openState(dir, false, now)
	if err != nil {
		return "", time.Time{}, err
	}
	defer s.close()
	if s.group == "" {
		return "", time.Time{}, ErrNoGroup
	}
	code, hash, err := contract.NewJoinCode(s.pub)
	if err != nil {
		return "", time.Time{}, err
	}
	expires = s.now().Add(contract.JoinCodeTTL)
	_, err = s.db.Exec(`INSERT INTO invites(hash, role, expires_ms) VALUES(?, ?, ?)`, hash, contract.RoleGateway, expires.UnixMilli())
	return code, expires, err
}

// admit takes a join code and writes the member record of the new key.
func (n *Node) admit(key ed25519.PublicKey, secret []byte, name, address string) ([][]byte, error) {
	m, err := memberOf(name, address, key, n.now())
	if err != nil {
		return nil, err
	}
	now := n.now().UnixMilli()
	res, err := n.db.Exec(`UPDATE invites SET used_ms = ? WHERE hash = ? AND used_ms = 0 AND expires_ms > ?`, now, contract.JoinHash(secret), now)
	if err != nil {
		return nil, err
	}
	if c, _ := res.RowsAffected(); c != 1 {
		return nil, errInvite
	}
	if _, err := n.publish(contract.ClassMembers, contract.NodeID(key), m, false, time.Time{}); err != nil {
		return nil, err
	}
	_, raws, err := n.winners(contract.ClassMembers)
	return raws, err
}

// Join brings this node into the group of the node at address, with a join
// code that node gave out. It talks to that node only when its key fits the
// code, and takes the member list it answers with only when every record
// leads back to the group id.
func Join(ctx context.Context, dir, name, advertise, address, code string, now func() time.Time) (group string, members int, err error) {
	secret, fp, err := contract.ParseJoinCode(code)
	if err != nil {
		return "", 0, err
	}
	s, err := openState(dir, true, now)
	if err != nil {
		return "", 0, err
	}
	defer s.close()
	if s.group != "" {
		return "", 0, ErrHasGroup
	}
	if _, err := memberOf(name, advertise, s.pub, s.now()); err != nil {
		return "", 0, err
	}
	cert, err := selfCert(s.key)
	if err != nil {
		return "", 0, err
	}
	var inviter ed25519.PublicKey
	c := meshClient(cert, func(k ed25519.PublicKey) bool {
		inviter = k
		return contract.SameFingerprint(contract.Fingerprint(k), fp)
	}, 20*time.Second)
	defer c.CloseIdleConnections()
	var resp joinResponse
	if err := postJSON(ctx, c, "https://"+address+pathJoin, joinRequest{Secret: base64.StdEncoding.EncodeToString(secret), Name: name, Address: advertise}, &resp); err != nil {
		return "", 0, fmt.Errorf("cluster: join %s: %w", address, err)
	}
	// Check the member list: the founder's record first (it needs nobody),
	// then whatever a known member signed, until nothing more fits.
	ro := contract.NewRoster(resp.Group)
	type item struct {
		rec contract.Record
		raw []byte
	}
	var todo, taken []item
	for _, raw := range resp.Records {
		var it item
		if len(raw) <= contract.MaxRecord && json.Unmarshal(raw, &it.rec) == nil && it.rec.Class == contract.ClassMembers {
			it.raw = raw
			todo = append(todo, it)
		}
	}
	sort.SliceStable(todo, func(i, j int) bool { return todo[i].rec.HLC < todo[j].rec.HLC })
	for progress := true; progress; {
		progress = false
		rest := todo[:0]
		for _, it := range todo {
			if ro.Check(&it.rec, s.now()) == nil {
				ro.Set(&it.rec)
				taken = append(taken, it)
				progress = true
			} else {
				rest = append(rest, it)
			}
		}
		todo = rest
	}
	if _, ok := ro.ActiveKey(inviter, contract.RoleGateway); !ok {
		return "", 0, errors.New("cluster: the answering node is no member of the group it names")
	}
	if _, ok := ro.ActiveKey(s.pub, contract.RoleGateway); !ok {
		return "", 0, errors.New("cluster: the answer does not admit this node")
	}
	tx, err := s.db.Begin()
	if err != nil {
		return "", 0, err
	}
	defer tx.Rollback()
	if err := setMeta(tx, "group", []byte(resp.Group)); err != nil {
		return "", 0, err
	}
	if hk, err := base64.StdEncoding.DecodeString(resp.HashKey); err == nil && len(hk) == 16 {
		if err := setMeta(tx, metaHashKey, hk); err != nil {
			return "", 0, err
		}
	}
	// The vector stays where it is: these are the member records only, the
	// first sync brings everything, these again.
	for _, it := range taken {
		if _, err := put(tx, &it.rec, it.raw); err != nil {
			return "", 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return "", 0, err
	}
	active := 0
	for _, e := range ro.Members() {
		if !e.Removed {
			active++
		}
	}
	return resp.Group, active, nil
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
	at := func(ms int64) time.Time {
		if ms == 0 {
			return time.Time{}
		}
		return time.UnixMilli(ms).UTC()
	}
	for _, e := range ro.Members() {
		p := peers[e.ID]
		st.Members = append(st.Members, MemberStatus{Entry: e, Self: e.ID == s.id, OutOK: at(p.out), InOK: at(p.in), Error: p.err, Behind: uint64(p.behind)})
	}
	if rows, err = s.db.Query(`SELECT class, count(*) FROM records WHERE state = ? AND deleted = 0 GROUP BY class`, stateWinner); err != nil {
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
	_ = s.db.QueryRow(`SELECT count(*) FROM replaced`).Scan(&st.Replaced)
	var seen int64
	if err := s.db.QueryRow(`SELECT CAST(v AS INTEGER) FROM meta WHERE k = 'status_ms'`).Scan(&seen); err == nil {
		st.Seen = at(seen)
	} else if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	return st, nil
}

// ErrOtherGroup: the secret of the configuration names another group than
// the one this node belongs to.
var ErrOtherGroup = errors.New("cluster: this node belongs to another group than cluster.secret_file names")

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

// ReadSecret reads the group secret of cluster.secret_file. Like the node
// key, the file is for its owner only.
func ReadSecret(path string) ([]byte, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("cluster.secret_file: %w", err)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("cluster.secret_file %s is readable by others (mode %04o): chmod 600", path, fi.Mode().Perm())
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
func Configure(dir, name, address string, secret []byte, now func() time.Time) (group string, err error) {
	gk, err := contract.GroupKey(secret)
	if err != nil {
		return "", err
	}
	s, err := openState(dir, true, now)
	if err != nil {
		return "", err
	}
	defer s.close()
	m, err := memberOf(name, address, s.pub, s.now())
	if err != nil {
		return "", err
	}
	group = m.AdmitWith(gk, s.pub)
	switch s.group {
	case group:
	case "":
		tx, err := s.db.Begin()
		if err != nil {
			return "", err
		}
		if err := setMeta(tx, "group", []byte(group)); err != nil {
			tx.Rollback()
			return "", err
		}
		hk := sha256.Sum256(append([]byte("schild-group-hash-key:"), secret...))
		if err := setMeta(tx, metaHashKey, hk[:16]); err != nil {
			tx.Rollback()
			return "", err
		}
		if err := tx.Commit(); err != nil {
			return "", err
		}
		s.group = group
	default:
		return "", fmt.Errorf("%w (it is in %s; the secret is of %s). To move the node, delete %s", ErrOtherGroup, s.group, group, dir)
	}
	recs, _, err := s.winners(contract.ClassMembers)
	if err != nil {
		return "", err
	}
	for _, r := range recs {
		if r.ID != s.id {
			continue
		}
		if r.Deleted {
			return "", ErrRemovedSelf
		}
		if cur, err := contract.DecodeMember(r); err == nil {
			if cur.Name == m.Name && cur.Address == m.Address && cur.AdmitKey == m.AdmitKey {
				return group, nil // set up already
			}
			m.Joined = cur.Joined
		}
	}
	_, err = s.publish(contract.ClassMembers, s.id, m, false, time.Time{})
	return group, err
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
