//go:build !release

package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"time"

	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/cluster"
	"github.com/deutschland-schild/schild/contract/vectors"
)

// D105 (MVP-27, cluster.md): whether a node of a group takes a record, and
// whether it replaces the one held. The expected results are written out
// here, not computed: the Go and the Python implementation both have to
// arrive at them.

func clusterKey(name string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("schild-cluster-test-key:" + name))
	return ed25519.NewKeyFromSeed(seed[:])
}

func clusterPub(k ed25519.PrivateKey) ed25519.PublicKey { return k.Public().(ed25519.PublicKey) }
func clusterID(k ed25519.PrivateKey) string             { return cluster.NodeID(clusterPub(k)) }

func genClusterRecord(g *gen) {
	const c = "cluster-record"
	ctx := vectors.Context{}
	// The clock of the checking node is Now; the group was set up an hour before.
	t0 := Now.Add(-time.Hour)
	h := func(d time.Duration) uint64 { return cluster.HLCOf(t0.Add(d)) }
	a, b, cc, x := clusterKey("web-1"), clusterKey("web-2"), clusterKey("web-3"), clusterKey("stranger")
	// The group of the secret every node of the vectors holds (admit.go).
	gk, err := cluster.GroupKey([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		panic(err)
	}
	group := cluster.GroupID(clusterPub(gk))
	b64 := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

	rec := func(signer ed25519.PrivateKey, class, id string, seq, hlc uint64, deleted bool, expires string, data any) *cluster.Record {
		r := &cluster.Record{V: cluster.Version, Group: group, Class: class, ID: id, Origin: clusterID(signer), Seq: seq, HLC: hlc, Deleted: deleted, Expires: expires}
		if err := r.Sign(signer, data); err != nil {
			panic(err)
		}
		return r
	}
	member := func(k ed25519.PrivateKey, name, role, address string) cluster.Member {
		return cluster.Member{Name: name, Role: role, PublicKey: base64.StdEncoding.EncodeToString(clusterPub(k)), Address: address, Joined: cluster.TimeText(t0)}
	}
	// admitted is the member with the admission of the group secret.
	admitted := func(k ed25519.PrivateKey, name, address string) cluster.Member {
		mm := member(k, name, cluster.RoleGateway, address)
		mm.AdmitWith(gk, clusterPub(k))
		return mm
	}
	mrec := func(signer, of ed25519.PrivateKey, seq, hlc uint64, deleted bool, m cluster.Member) *cluster.Record {
		return rec(signer, cluster.ClassMembers, clusterID(of), seq, hlc, deleted, "", m)
	}
	first := mrec(a, a, 1, h(0), false, admitted(a, "web-1", "10.0.0.1:8790"))
	second := mrec(b, b, 1, h(time.Second), false, admitted(b, "web-2", "10.0.0.2:8790"))
	third := mrec(cc, cc, 1, h(2*time.Second), false, admitted(cc, "web-3", "10.0.0.3:8790"))
	thirdGone := mrec(a, cc, 5, h(30*time.Minute), true, admitted(cc, "web-3", "10.0.0.3:8790"))
	roster := []*cluster.Record{first, second, third, thirdGone}

	until := cluster.TimeText(Now.Add(time.Hour))
	const incident = "K7QF-2M9X"
	ibData := func(client string, bits int, scope string) cluster.IncidentBlock {
		return cluster.IncidentBlock{Client: client, Bits: bits, Scope: scope, Source: "behaviour:path_probing", Level: 1, Since: cluster.TimeText(Now.Add(-time.Minute)), Until: until,
			DurationS: 3660, NetClass: "hosting", Node: "web-2"}
	}
	blockData := func(client string, bits int) cluster.IncidentBlock { return ibData(client, bits, cluster.ScopeGateway) }
	// block is the block of one incident; most vectors carry one.
	block := func(signer ed25519.PrivateKey, seq, hlc uint64, client string) *cluster.Record {
		return rec(signer, cluster.ClassIncidentBlocks, incident, seq, hlc, false, until, blockData(client, 32))
	}
	in := func(members []*cluster.Record, r, held *cluster.Record) m {
		if members == nil {
			members = []*cluster.Record{}
		}
		x := m{"group": group, "members": members, "record": r}
		if held != nil {
			x["held"] = held
		}
		return x
	}
	yes, no := true, false
	taken := func(name, desc string, input m, replaces *bool) {
		g.addResult(c, name, true, "", desc, ctx, mustJSON(input), input, cluster.VectorResult{Taken: true, Replaces: replaces})
	}
	refused := func(reason, name, desc string, input m) {
		g.addResult(c, name, true, "", desc, ctx, mustJSON(input), input, cluster.VectorResult{Reason: reason})
	}
	bad := func(name, desc string, input any) {
		g.add(c, name, false, contract.CodeSchema, desc, ctx, mustJSON(input), input)
	}

	// ---- taken
	taken("admitted-by-secret", "A node's record of itself needs no member: it carries the admission of the group secret.", in(nil, first, nil), nil)
	taken("member-admitted", "The next node lets itself in the same way.", in([]*cluster.Record{first}, second, nil), nil)
	taken("block-of-another-member", "A block another member signed.", in(roster, block(a, 9, h(40*time.Minute), "203.0.113.7"), nil), nil)
	taken("clock-59s-ahead", "A clock up to 60 s ahead of the receiver passes.", in(roster, block(b, 1, cluster.HLCOf(Now.Add(59*time.Second)), "203.0.113.7"), nil), nil)
	taken("removed-member-before", "What a member signed before its removal stands: a node that joins later reads it the same.",
		in(roster, block(cc, 1, h(20*time.Minute), "203.0.113.8"), nil), nil)
	taken("member-removed", "The tombstone of a member keeps its data, with the key.", in([]*cluster.Record{first, second, third}, thirdGone, nil), nil)
	entry := func(class, thing, key string, seq uint64, deleted bool, expires string, data any) *cluster.Record {
		return rec(b, class, cluster.EntryID(thing, key), seq, h(42*time.Minute), deleted, expires, data)
	}
	gone := cluster.TimeText(Now.Add(30 * 24 * time.Hour))
	taken("settings-entry", "One setting of the overlay is one record: its key names the path.",
		in(roster, entry(cluster.ClassSettings, "settings_overlay_v1", `["rules","crs","state"]`, 3, false, "", cluster.NewValue(`["rules","crs","state"]`, []byte(`"detect"`), "web-2")), nil), nil)
	taken("access-allowlist-row", "One row of the allowlist is one record.",
		in(roster, entry(cluster.ClassAccess, "allowlist", `["al_1"]`, 4, false, "", cluster.NewValue(`["al_1"]`, []byte(`["al_1","203.0.113.7"]`), "web-2")), nil), nil)
	taken("logins-row-removed", "A removed entry is a tombstone with its key, no value and an end.",
		in(roster, entry(cluster.ClassLogins, "sessions", `["abc"]`, 5, true, gone, cluster.Value{K: `["abc"]`, Node: "web-2"}), nil), nil)
	taken("settings-whole-value", "A value that is one piece has the key \"\".",
		in(roster, entry(cluster.ClassSettings, "agent_pseudonym_key_v1", "", 6, false, "", cluster.NewValue("", []byte{1, 2, 3}, "web-2")), nil), nil)
	taken("erasure", "An erased address, kept 31 days.",
		in(roster, rec(b, cluster.ClassErasure, "203.0.113.7", 6, h(43*time.Minute), false, cluster.TimeText(Now.Add(31*24*time.Hour)), cluster.Erasure{IP: "203.0.113.7", Node: "web-2"}), nil), nil)
	certDir := "certificates/acme-v02.api.letsencrypt.org-directory/shop.example"
	taken("certificate-directory", "A certificate, its key and its metadata are one record.",
		in(roster, rec(b, cluster.ClassCertificates, certDir, 7, h(44*time.Minute), false, "",
			cluster.Files{Files: map[string]string{"shop.example.crt": b64("crt"), "shop.example.key": b64("key"), "shop.example.json": b64("{}")}, Node: "web-2"}), nil), nil)
	taken("certificate-file", "Everything else of the storage is one file per record, under the name \"\".",
		in(roster, rec(b, cluster.ClassCertificates, "challenge_tokens/shop.example.json", 8, h(44*time.Minute), false, "", cluster.Files{Files: map[string]string{"": b64("token")}, Node: "web-2"}), nil), nil)
	taken("certificate-tombstone", "A tombstone of the storage has no files.",
		in(roster, rec(b, cluster.ClassCertificates, "challenge_tokens/shop.example.json", 9, h(45*time.Minute), true, "", cluster.Files{Node: "web-2"}), nil), nil)

	job := func(id string, deleted bool, data any) *cluster.Record {
		return rec(b, cluster.ClassJobs, id, 10, h(46*time.Minute), deleted, "", data)
	}
	taken("job", "When a task that runs once for the group last started.", in(roster, job("human_check_keys", false, cluster.Job{At: cluster.TimeText(Now.Add(-time.Minute)), Node: "web-2"}), nil), nil)
	refused("schema", "job-name", "A job is named in lower case, without spaces.", in(roster, job("Send Report", false, cluster.Job{At: cluster.TimeText(Now), Node: "web-2"}), nil))
	refused("schema", "job-without-time", "A job says when it started.", in(roster, job("human_check_keys", false, cluster.Job{Node: "web-2"}), nil))
	refused("schema", "job-deleted", "A job is never removed, only run again.", in(roster, job("human_check_keys", true, cluster.Job{At: cluster.TimeText(Now), Node: "web-2"}), nil))

	// Admission by the group secret.
	self := func(k ed25519.PrivateKey, admitWith ed25519.PrivateKey, admitFor ed25519.PublicKey, name string, hlc uint64) *cluster.Record {
		mm := member(k, name, cluster.RoleGateway, "10.0.0.5:8790")
		mm.AdmitWith(admitWith, admitFor)
		return mrec(k, k, 1, hlc, false, mm)
	}
	other, _ := cluster.GroupKey([]byte("another-secret-another-secret-00"))
	refused("origin", "admitted-by-another-secret", "The admission of another secret is of another group.", in(nil, self(x, other, clusterPub(x), "evil", h(0)), nil))
	refused("origin", "admission-copied", "The admission of one node does not fit another key.", in(nil, self(x, gk, clusterPub(b), "evil", h(0)), nil))
	refused("origin", "member-admits-a-stranger", "A member cannot let in a key the secret did not admit.",
		in(roster, mrec(a, x, 6, h(40*time.Minute), false, member(x, "web-4", cluster.RoleGateway, "10.0.0.4:8790")), nil))

	// ---- which record is the state
	older, newer := block(b, 1, h(40*time.Minute), "203.0.113.7"), block(a, 9, h(41*time.Minute), "203.0.113.7")
	taken("replaces-later-clock", "The later clock replaces the held record.", in(roster, newer, older), &yes)
	taken("replaces-not-earlier-clock", "An earlier clock does not, whatever order the two arrive in.", in(roster, older, newer), &no)
	session := cluster.EntryID("sessions", `["abc"]`)
	sameWrite := rec(a, cluster.ClassLogins, session, 9, h(41*time.Minute), false, "", cluster.NewValue(`["abc"]`, []byte(`["abc"]`), "web-1"))
	sameGone := rec(b, cluster.ClassLogins, session, 2, h(41*time.Minute), true, gone, cluster.Value{K: `["abc"]`, Node: "web-2"})
	taken("replaces-tombstone-same-clock", "At the same clock a tombstone beats a write: the entry is gone.", in(roster, sameGone, sameWrite), &yes)
	taken("replaces-not-write-same-clock", "And the write does not beat the tombstone.", in(roster, sameWrite, sameGone), &no)
	fromA, fromB := block(a, 9, h(41*time.Minute), "203.0.113.7"), block(b, 1, h(41*time.Minute), "203.0.113.7")
	greater, lesser := fromA, fromB
	if clusterID(b) > clusterID(a) {
		greater, lesser = fromB, fromA
	}
	taken("replaces-greater-origin", "At the same clock and kind the greater origin wins, on every node the same.", in(roster, greater, lesser), &yes)
	taken("replaces-not-lesser-origin", "The lesser origin does not.", in(roster, lesser, greater), &no)

	// ---- refused, in the order of the checks
	withV := block(b, 1, h(40*time.Minute), "203.0.113.7")
	withV.V = 2
	refused("version", "version-2", "A record of another version stays unread.", in(roster, withV, nil))
	og := block(b, 1, h(40*time.Minute), "203.0.113.7")
	og.Group = "g-00000000000000000000000000000000"
	refused("group", "another-group", "A record of another group.", in(roster, og, nil))
	refused("class", "unknown-class", "A class this version does not have: kept unread, for a later build.", in(roster, rec(b, "tokens", "x", 1, h(40*time.Minute), false, "", m{"v": ""}), nil))
	refused("schema", "seq-zero", "Sequence numbers start at 1.", in(roster, rec(b, cluster.ClassIncidentBlocks, incident, 0, h(40*time.Minute), false, until, blockData("203.0.113.7", 32)), nil))
	refused("schema", "expires-no-time", "expires is a time in UTC with seconds.", in(roster, rec(b, cluster.ClassErasure, "203.0.113.7", 6, h(43*time.Minute), false, "tomorrow", cluster.Erasure{IP: "203.0.113.7"}), nil))
	refused("schema", "expires-with-offset", "No offsets: UTC, written with Z.", in(roster, rec(b, cluster.ClassErasure, "203.0.113.7", 6, h(43*time.Minute), false, "2026-11-26T13:00:00+01:00", cluster.Erasure{IP: "203.0.113.7"}), nil))
	refused("clock", "clock-61s-ahead", "A clock more than 60 s ahead of the receiver is not taken yet.", in(roster, block(b, 1, cluster.HLCOf(Now.Add(61*time.Second)), "203.0.113.7"), nil))
	refused("origin", "stranger", "A key that is no member.", in(roster, block(x, 1, h(40*time.Minute), "203.0.113.7"), nil))
	refused("origin", "stranger-admits-itself", "A stranger's record of itself without the admission of the group secret.",
		in(roster, mrec(x, x, 1, h(40*time.Minute), false, member(x, "evil", cluster.RoleGateway, "10.0.0.9:8790")), nil))
	refused("origin", "member-not-yet-known", "The member record of the origin has not arrived: asked for again.", in([]*cluster.Record{first}, block(b, 1, h(40*time.Minute), "203.0.113.7"), nil))
	refused("removed", "removed-member-after", "What a removed member signs after its removal.", in(roster, block(cc, 2, h(35*time.Minute), "203.0.113.8"), nil))
	refused("removed", "removed-member-lets-itself-in", "A removed member cannot let itself in again, although it holds the secret.",
		in(roster, mrec(cc, cc, 3, h(36*time.Minute), false, admitted(cc, "web-3", "10.0.0.3:8790")), nil))
	bent := block(b, 1, h(40*time.Minute), "203.0.113.7")
	bent.Data = block(b, 1, h(40*time.Minute), "203.0.113.8").Data
	refused("signature", "data-changed", "Other data under the signature.", in(roster, bent, nil))
	swapped := block(b, 1, h(40*time.Minute), "203.0.113.7")
	swapped.Sig = block(b, 2, h(40*time.Minute), "203.0.113.7").Sig
	refused("signature", "signature-of-another-record", "The signature of the same data under another sequence number.", in(roster, swapped, nil))
	moved := rec(b, cluster.ClassAccess, cluster.EntryID("allowlist", "x"), 4, h(42*time.Minute), false, "", cluster.NewValue("x", []byte(`{}`), "web-2"))
	moved.Class, moved.ID = cluster.ClassLogins, cluster.EntryID("users", "x")
	refused("signature", "moved-to-another-class", "A value moved to another class and thing.", in(roster, moved, nil))
	later := block(b, 1, h(40*time.Minute), "203.0.113.7")
	later.HLC++
	refused("signature", "clock-changed", "A later clock under the old signature.", in(roster, later, nil))
	notB := block(b, 1, h(40*time.Minute), "203.0.113.7")
	notB.Origin = clusterID(a)
	refused("signature", "origin-changed", "A record of one member named as another's.", in(roster, notB, nil))
	shortSig := block(b, 1, h(40*time.Minute), "203.0.113.7")
	shortSig.Sig = "AAAA"
	refused("signature", "signature-too-short", "A signature that is none.", in(roster, shortSig, nil))

	// The rules of the classes come last: they need the signature first.
	sb := func(name, desc string, expires string, data any) {
		refused("schema", name, desc, in(roster, rec(b, cluster.ClassIncidentBlocks, incident, 1, h(40*time.Minute), false, expires, data), nil))
	}
	sb("block-not-canonical", "The client is written the one way an address is written.", until, blockData("2001:DB8:1:2::", 64))
	sb("block-no-address", "A client that is no address.", until, blockData("everyone", 32))
	long := blockData("203.0.113.7", 32)
	long.Until = cluster.TimeText(Now.Add(8 * 24 * time.Hour))
	sb("block-over-7-days", "No block of the group runs longer than 7 days.", long.Until, long)
	lvl := blockData("203.0.113.7", 32)
	lvl.Level = 0
	sb("block-level-zero", "The ladder starts at 1.", until, lvl)
	sb("block-unknown-field", "Data with a field the class does not have.", until,
		m{"client": "203.0.113.7", "bits": 32, "scope": cluster.ScopeGateway, "source": "dashboard", "level": 1, "since": cluster.TimeText(Now.Add(-time.Minute)), "until": until, "duration_s": 3660, "net_class": "", "node": "", "allow": true})
	refused("schema", "member-id-not-of-key", "The id of a member is the hash of its key.",
		in(roster, rec(a, cluster.ClassMembers, "n-00000000000000000000000000000000", 6, h(40*time.Minute), false, "", member(x, "web-4", cluster.RoleGateway, "10.0.0.4:8790")), nil))
	refused("schema", "member-unknown-role", "A role this version does not have.", in(roster, mrec(a, x, 6, h(40*time.Minute), false, member(x, "web-4", "admin", "10.0.0.4:8790")), nil))
	refused("schema", "member-name-with-space", "A name is one word.", in(roster, mrec(a, x, 6, h(40*time.Minute), false, member(x, "web 4", cluster.RoleGateway, "10.0.0.4:8790")), nil))
	refused("schema", "member-address-host-name", "An address is an IP address and a port.", in(roster, mrec(a, x, 6, h(40*time.Minute), false, member(x, "web-4", cluster.RoleGateway, "web-4.internal:8790")), nil))
	half := member(x, "web-4", cluster.RoleGateway, "10.0.0.4:8790")
	half.AdmitKey = base64.StdEncoding.EncodeToString(clusterPub(gk))
	refused("schema", "member-half-an-admission", "admit_public_key and admit come both or not at all.", in(roster, mrec(a, x, 6, h(40*time.Minute), false, half), nil))
	refused("schema", "value-unknown-thing", "A thing the class does not have.",
		in(roster, entry(cluster.ClassSettings, "installed_at_v1", "", 3, false, "", cluster.NewValue("", nil, "web-2")), nil))
	refused("schema", "value-thing-of-another-class", "users is of class logins.",
		in(roster, entry(cluster.ClassAccess, "users", `["admin"]`, 3, false, "", cluster.NewValue(`["admin"]`, nil, "web-2")), nil))
	refused("schema", "value-whole-thing", "A thing is not one record: every entry is one.",
		in(roster, rec(b, cluster.ClassAccess, "allowlist", 3, h(42*time.Minute), false, "", cluster.NewValue("", nil, "web-2")), nil))
	refused("schema", "value-id-not-of-key", "The id of an entry is the hash of its key.",
		in(roster, entry(cluster.ClassAccess, "allowlist", `["al_1"]`, 3, false, "", cluster.NewValue(`["al_2"]`, nil, "web-2")), nil))
	refused("schema", "value-tombstone-with-value", "A tombstone has no value.",
		in(roster, entry(cluster.ClassAccess, "allowlist", `["al_1"]`, 3, true, gone, cluster.NewValue(`["al_1"]`, []byte("x"), "web-2")), nil))
	refused("schema", "value-tombstone-without-end", "A tombstone names when it is dropped.",
		in(roster, entry(cluster.ClassAccess, "allowlist", `["al_1"]`, 3, true, "", cluster.Value{K: `["al_1"]`}), nil))
	refused("schema", "value-no-base64", "The value is standard base64.",
		in(roster, entry(cluster.ClassSettings, "human_check_v1", "a", 3, false, "", m{"key": "a", "value": "%%%", "node": "web-2"}), nil))
	refused("schema", "erasure-of-another-address", "The id of an erasure is its address.",
		in(roster, rec(b, cluster.ClassErasure, "203.0.113.7", 6, h(43*time.Minute), false, cluster.TimeText(Now.Add(time.Hour)), cluster.Erasure{IP: "203.0.113.8"}), nil))
	refused("schema", "erasure-without-end", "An erasure names when it is dropped.", in(roster, rec(b, cluster.ClassErasure, "203.0.113.7", 6, h(43*time.Minute), false, "", cluster.Erasure{IP: "203.0.113.7"}), nil))
	files := func(name, desc, id string, deleted bool, f cluster.Files) {
		refused("schema", name, desc, in(roster, rec(b, cluster.ClassCertificates, id, 7, h(44*time.Minute), deleted, "", f), nil))
	}
	one := map[string]string{"": b64("x")}
	files("files-path-leaves-storage", "A path with .. leaves the storage.", "../schild.yaml", false, cluster.Files{Files: one})
	files("files-absolute-path", "A path is relative.", "/etc/passwd", false, cluster.Files{Files: one})
	files("files-name-with-directory", "A file name is one element.", certDir, false, cluster.Files{Files: map[string]string{"../../x": b64("x")}})
	files("files-file-and-directory", "A record is a file or a directory, not both.", certDir, false, cluster.Files{Files: map[string]string{"": b64("x"), "a": b64("y")}})
	files("files-none", "A record that is no tombstone has files.", certDir, false, cluster.Files{})
	files("files-tombstone-with-files", "A tombstone has none.", certDir, true, cluster.Files{Files: one})
	noData := block(b, 1, h(40*time.Minute), "203.0.113.7")
	if err := noData.Sign(b, nil); err != nil {
		panic(err)
	}
	refused("schema", "block-without-data", "A record of a class with data, without data.", in(roster, noData, nil))

	// ---- everything set at runtime is shared: class settings takes every key of the store (initiator, 2026-11-22)
	taken("settings-any-key", "Class settings takes every key of the store as a thing: a setting of a feature this contract does not name.",
		in(roster, entry(cluster.ClassSettings, "notify_channels_v1", `l["mail-1"]`, 7, false, "", cluster.NewValue(`l["mail-1"]`, []byte(`{"id":"mail-1"}`), "web-2")), nil), nil)
	refused("schema", "value-key-not-a-name", "A key of class settings is a lower-case name.",
		in(roster, entry(cluster.ClassSettings, "Notify-Channels", "", 3, false, "", cluster.NewValue("", nil, "web-2")), nil))
	refused("schema", "value-key-too-long", "A key of class settings has at most 64 characters.",
		in(roster, entry(cluster.ClassSettings, "a"+strings.Repeat("b", 64), "", 3, false, "", cluster.NewValue("", nil, "web-2")), nil))
	refused("schema", "value-any-key-of-access", "Only class settings takes keys it does not name: access is a closed list.",
		in(roster, entry(cluster.ClassAccess, "notify_channels_v1", "", 3, false, "", cluster.NewValue("", nil, "web-2")), nil))
	refused("schema", "value-per-node-key", "A key that describes one node never travels.",
		in(roster, entry(cluster.ClassSettings, "dashboard_setup_code_v1", "", 3, false, "", cluster.NewValue("", []byte("x"), "web-2")), nil))

	// ---- inputs that are no input
	good := block(b, 1, h(40*time.Minute), "203.0.113.7")
	asMap := func(r *cluster.Record, change func(m)) m {
		x := m{"v": r.V, "group": r.Group, "class": r.Class, "id": r.ID, "origin": r.Origin, "seq": r.Seq, "hlc": r.HLC, "expires": r.Expires, "data": r.Data, "sig": r.Sig}
		change(x)
		return x
	}
	bad("no-record", "The record is missing.", m{"group": group, "members": []any{}})
	bad("no-members", "The member list is missing.", m{"group": group, "record": good})
	bad("no-group", "The group is missing.", m{"members": []any{}, "record": good})
	bad("group-no-id", "A group id is g- and 32 hex digits.", m{"group": "my-group", "members": []any{}, "record": good})
	bad("members-no-list", "The member list is a list.", m{"group": group, "members": first, "record": good})
	bad("unknown-field", "A field the input does not have.", m{"group": group, "members": []any{}, "record": good, "now": "2026-10-26T12:00:00Z"})
	bad("record-without-signature", "A record has a signature field.", m{"group": group, "members": []any{}, "record": asMap(good, func(x m) { delete(x, "sig") })})
	bad("record-seq-negative", "Sequence numbers are not negative.", m{"group": group, "members": []any{}, "record": asMap(good, func(x m) { x["seq"] = -1 })})
	bad("record-version-text", "The version is a number.", m{"group": group, "members": []any{}, "record": asMap(good, func(x m) { x["v"] = "1" })})
	bad("record-deleted-text", "deleted is true or false.", m{"group": group, "members": []any{}, "record": asMap(good, func(x m) { x["deleted"] = "no" })})
	bad("record-unknown-field", "A record has the fields of section 2 and no others.", m{"group": group, "members": []any{}, "record": asMap(good, func(x m) { x["priority"] = 1 })})
	bad("record-null", "The record is an object.", m{"group": group, "members": []any{}, "record": nil})
	many := make([]*cluster.Record, 17)
	for i := range many {
		many[i] = first
	}
	bad("too-many-members", "At most 16 member records in a vector.", m{"group": group, "members": many, "record": good})

	// ---- blocks by incident (D109)
	ib := func(signer ed25519.PrivateKey, seq, hlc uint64, incident string, data any) *cluster.Record {
		return rec(signer, cluster.ClassIncidentBlocks, incident, seq, hlc, false, until, data)
	}
	liftEnd := cluster.TimeText(Now.Add(169 * time.Hour))
	il := func(signer ed25519.PrivateKey, seq, hlc uint64, incident string) *cluster.Record {
		return rec(signer, cluster.ClassLifts, incident, seq, hlc, false, liftEnd, cluster.IncidentLift{Node: "web-1"})
	}
	taken("incident-block", "A block is one record; its id is the incident number.", in(roster, ib(b, 1, h(40*time.Minute), "K7QF-2M9X", ibData("203.0.113.7", 32, cluster.ScopeGateway)), nil), nil)
	taken("incident-block-second-of-client", "A second block of the same client is a record of its own, under its own incident.",
		in(roster, ib(a, 9, h(40*time.Minute), "R3TV-8HNC", ibData("203.0.113.7", 32, cluster.ScopeGateway)), nil), nil)
	taken("incident-block-ipv6", "The client of IPv6 is the first address of the /64.", in(roster, ib(b, 1, h(40*time.Minute), "K7QF-2M9X", ibData("2001:db8:1:2::", 64, cluster.ScopeGateway)), nil), nil)
	refused("schema", "incident-block-of-website", "This version has one scope, the gateway. A block of one website comes as a later record version.", in(roster, ib(b, 1, h(40*time.Minute), "K7QF-2M9X", ibData("203.0.113.7", 32, "website:shop")), nil))
	taken("incident-lift", "A lift is a record of its own; its id is the incident it ends, and it carries no address.", in(roster, il(a, 9, h(41*time.Minute), "K7QF-2M9X"), nil), nil)
	taken("incident-lift-of-unknown-block", "A lift needs no block record: it may arrive first.", in(roster, il(a, 9, h(41*time.Minute), "ZZZZ-9999"), nil), nil)
	taken("incident-lift-replaces-earlier-lift", "Two lifts of one incident are two records of one thing; the later is the state.",
		in(roster, il(a, 9, h(42*time.Minute), "K7QF-2M9X"), il(b, 2, h(41*time.Minute), "K7QF-2M9X")), &yes)
	si := func(name, desc string, r *cluster.Record) { refused("schema", name, desc, in(roster, r, nil)) }
	si("incident-block-id-is-address", "The id of a block is its incident, not its client.", ib(b, 1, h(40*time.Minute), "203.0.113.7", ibData("203.0.113.7", 32, cluster.ScopeGateway)))
	si("incident-block-id-lower-case", "An incident number has capital letters, digits and hyphens.", ib(b, 1, h(40*time.Minute), "k7qf-2m9x", ibData("203.0.113.7", 32, cluster.ScopeGateway)))
	si("incident-block-tombstone", "A block record is never a tombstone: a lift is a record of class lifts.",
		rec(b, cluster.ClassIncidentBlocks, "K7QF-2M9X", 2, h(41*time.Minute), true, until, ibData("203.0.113.7", 32, cluster.ScopeGateway)))
	si("incident-block-without-scope", "A block names its scope.", ib(b, 1, h(40*time.Minute), "K7QF-2M9X", ibData("203.0.113.7", 32, "")))
	si("incident-block-unknown-scope", "A scope this version does not have.", ib(b, 1, h(40*time.Minute), "K7QF-2M9X", ibData("203.0.113.7", 32, "everywhere")))
	si("incident-block-with-incident-field", "The incident is the id; the data has no such field.", ib(b, 1, h(40*time.Minute), "K7QF-2M9X",
		m{"client": "203.0.113.7", "bits": 32, "scope": cluster.ScopeGateway, "source": "dashboard", "level": 1, "since": cluster.TimeText(Now.Add(-time.Minute)), "until": until, "duration_s": 3660, "incident": "K7QF-2M9X", "net_class": "", "node": ""}))
	si("incident-block-ipv4-with-64-bits", "IPv4 is one address, 32 bits.", ib(b, 1, h(40*time.Minute), "K7QF-2M9X", ibData("203.0.113.7", 64, cluster.ScopeGateway)))
	si("incident-block-expires-not-until", "A block is dropped when it ends: expires is until.",
		rec(b, cluster.ClassIncidentBlocks, "K7QF-2M9X", 1, h(40*time.Minute), false, cluster.TimeText(Now.Add(2*time.Hour)), ibData("203.0.113.7", 32, cluster.ScopeGateway)))
	si("incident-lift-tombstone", "A lift is never a tombstone.", rec(a, cluster.ClassLifts, "K7QF-2M9X", 9, h(41*time.Minute), true, liftEnd, cluster.IncidentLift{Node: "web-1"}))
	si("incident-lift-without-end", "A lift names when it is dropped.", rec(a, cluster.ClassLifts, "K7QF-2M9X", 9, h(41*time.Minute), false, "", cluster.IncidentLift{Node: "web-1"}))
	si("incident-lift-with-address", "A lift carries no address.", rec(a, cluster.ClassLifts, "K7QF-2M9X", 9, h(41*time.Minute), false, liftEnd, m{"node": "web-1", "client": "203.0.113.7"}))
	si("incident-lift-id-is-address", "The id of a lift is the incident.", il(a, 9, h(41*time.Minute), "203.0.113.7"))

	// ---- class blocks of 0.1.0-alpha.6 is gone (cluster.md section 16)
	si("blocks-of-alpha-6", "A block of class blocks, as 0.1.0-alpha.6 wrote it: this version does not have the class, and the record is refused for good, not kept unread.",
		rec(b, cluster.RetiredClassBlocks, "203.0.113.7", 1, h(40*time.Minute), false, until,
			m{"client": "203.0.113.7", "bits": 32, "source": "behaviour:path_probing", "level": 1, "since": cluster.TimeText(Now.Add(-time.Minute)), "until": until, "duration_s": 3660, "incident": "K7QF-2M9X", "net_class": "hosting", "node": "web-2"}))
	si("blocks-lift-of-alpha-6", "Its lift, a tombstone of class blocks, is refused the same way.",
		rec(b, cluster.RetiredClassBlocks, "203.0.113.7", 2, h(41*time.Minute), true, liftEnd, m{"incident": "K7QF-2M9X", "node": "web-2"}))
}
