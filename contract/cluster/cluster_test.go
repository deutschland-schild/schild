package cluster

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"testing"
	"time"
)

var t0 = time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)

func key(seed byte) (ed25519.PublicKey, ed25519.PrivateKey) {
	s := make([]byte, ed25519.SeedSize)
	for i := range s {
		s[i] = seed
	}
	k := ed25519.NewKeyFromSeed(s)
	return k.Public().(ed25519.PublicKey), k
}

// testGroupKey is the group key of the test group, from its secret.
var testGroupKey, _ = GroupKey([]byte("0123456789abcdef0123456789abcdef"))

func testGroup() string { return GroupID(testGroupKey.Public().(ed25519.PublicKey)) }

// memberRecord is the member record of pub, admitted by the secret of the
// test group.
func memberRecord(t *testing.T, group string, signer ed25519.PrivateKey, seq uint64, hlc uint64, pub ed25519.PublicKey, name string, deleted bool) *Record {
	t.Helper()
	return memberRecordOf(t, group, signer, seq, hlc, pub, name, deleted, true)
}

func memberRecordOf(t *testing.T, group string, signer ed25519.PrivateKey, seq uint64, hlc uint64, pub ed25519.PublicKey, name string, deleted, admitted bool) *Record {
	t.Helper()
	r := &Record{V: Version, Group: group, Class: ClassMembers, ID: NodeID(pub), Origin: NodeID(signer.Public().(ed25519.PublicKey)), Seq: seq, HLC: hlc, Deleted: deleted}
	m := Member{Name: name, Role: RoleGateway, PublicKey: base64.StdEncoding.EncodeToString(pub), Address: "10.0.0.1:8790", Joined: TimeText(t0)}
	if admitted {
		m.AdmitWith(testGroupKey, pub)
	}
	if err := r.Sign(signer, m); err != nil {
		t.Fatal(err)
	}
	return r
}

func blockRecord(t *testing.T, group string, signer ed25519.PrivateKey, seq, hlc uint64, client string) *Record {
	t.Helper()
	until := TimeText(t0.Add(time.Hour))
	r := &Record{V: Version, Group: group, Class: ClassBlocks, ID: client, Origin: NodeID(signer.Public().(ed25519.PublicKey)), Seq: seq, HLC: hlc, Expires: until}
	b := Block{Client: client, Bits: 32, Source: "behaviour:path_probing", Level: 1, Since: TimeText(t0), Until: until, DurationS: 3600, Incident: "S-1", NetClass: "hosting", Node: "web-1"}
	if err := r.Sign(signer, b); err != nil {
		t.Fatal(err)
	}
	return r
}

func group(t *testing.T) (*Roster, ed25519.PrivateKey, ed25519.PrivateKey) {
	t.Helper()
	pa, ka := key(1)
	pb, kb := key(2)
	ro := NewRoster(testGroup())
	first := memberRecord(t, ro.Group, ka, 1, HLCOf(t0), pa, "web-1", false)
	if err := ro.Check(first, t0); err != nil {
		t.Fatalf("first member: %v", err)
	}
	ro.Set(first)
	second := memberRecord(t, ro.Group, kb, 1, HLCOf(t0)+1, pb, "web-2", false)
	if err := ro.Check(second, t0); err != nil {
		t.Fatalf("second member: %v", err)
	}
	ro.Set(second)
	return ro, ka, kb
}

func TestRosterTakesWhatMembersSign(t *testing.T) {
	ro, _, kb := group(t)
	if err := ro.Check(blockRecord(t, ro.Group, kb, 1, HLCOf(t0), "203.0.113.7"), t0); err != nil {
		t.Fatalf("block of a member: %v", err)
	}
}

func TestRosterRefuses(t *testing.T) {
	ro, ka, kb := group(t)
	_, kc := key(3) // never admitted
	pc := kc.Public().(ed25519.PublicKey)
	good := func() *Record { return blockRecord(t, ro.Group, kb, 1, HLCOf(t0), "203.0.113.7") }
	cases := []struct {
		name string
		rec  func() *Record
		want error
	}{
		{"unknown version", func() *Record { r := good(); r.V = 2; return r }, ErrVersion},
		{"another group", func() *Record { return blockRecord(t, "g-other", kb, 1, HLCOf(t0), "203.0.113.7") }, ErrGroup},
		{"stranger signs a block", func() *Record { return blockRecord(t, ro.Group, kc, 1, HLCOf(t0), "203.0.113.7") }, ErrOrigin},
		{"stranger admits itself", func() *Record { return memberRecordOf(t, ro.Group, kc, 1, HLCOf(t0), pc, "evil", false, false) }, ErrOrigin},
		{"member lets in a key without the secret", func() *Record {
			return memberRecordOf(t, ro.Group, ka, 3, HLCOf(t0)+2, pc, "web-3", false, false)
		}, ErrOrigin},
		{"data changed after signing", func() *Record {
			r := good()
			other := blockRecord(t, ro.Group, kb, 1, HLCOf(t0), "203.0.113.8")
			r.Data = other.Data
			return r
		}, ErrSignature},
		{"signature of another record", func() *Record {
			r := good()
			r.Sig = blockRecord(t, ro.Group, kb, 2, HLCOf(t0), "203.0.113.7").Sig
			return r
		}, ErrSignature},
		{"moved to another class", func() *Record { r := good(); r.Class = ClassMembers; return r }, ErrSignature},
		{"clock a day ahead", func() *Record { return blockRecord(t, ro.Group, kb, 1, HLCOf(t0.Add(24*time.Hour)), "203.0.113.7") }, ErrClock},
		{"id is not the client", func() *Record {
			r := good()
			r.ID = "203.0.113.9"
			_ = r.Sign(kb, Block{Client: "203.0.113.7", Bits: 32, Source: "dashboard", Level: 1, Since: TimeText(t0), Until: r.Expires, DurationS: 3600})
			return r
		}, ErrSchema},
		{"block outlives the cap", func() *Record {
			r := good()
			until := TimeText(t0.Add(30 * 24 * time.Hour))
			r.Expires = until
			_ = r.Sign(kb, Block{Client: "203.0.113.7", Bits: 32, Source: "dashboard", Level: 1, Since: TimeText(t0), Until: until, DurationS: 3600})
			return r
		}, ErrSchema},
		{"unknown field", func() *Record {
			r := good()
			_ = r.Sign(kb, map[string]any{"client": "203.0.113.7", "allow": true})
			return r
		}, ErrSchema},
		{"member id does not fit its key", func() *Record {
			r := memberRecord(t, ro.Group, ka, 3, HLCOf(t0)+2, pc, "web-3", false)
			r.ID = "n-00000000000000000000000000000000"
			_ = r.Sign(ka, Member{Name: "web-3", Role: RoleGateway, PublicKey: base64.StdEncoding.EncodeToString(pc), Address: "10.0.0.3:8790", Joined: TimeText(t0)})
			return r
		}, ErrSchema},
	}
	for _, c := range cases {
		if err := ro.Check(c.rec(), t0); !errors.Is(err, c.want) {
			t.Errorf("%s: got %v, want %v", c.name, err, c.want)
		}
	}
}

func TestRemovedMember(t *testing.T) {
	ro, ka, kb := group(t)
	pb := kb.Public().(ed25519.PublicKey)
	before := blockRecord(t, ro.Group, kb, 1, HLCOf(t0)+5, "203.0.113.7")
	gone := memberRecord(t, ro.Group, ka, 3, HLCOf(t0.Add(time.Minute)), pb, "web-2", true)
	if err := ro.Check(gone, t0.Add(time.Minute)); err != nil {
		t.Fatalf("removal: %v", err)
	}
	ro.Set(gone)
	if _, ok := ro.ActiveKey(pb); ok {
		t.Fatal("a removed member is still active")
	}
	if err := ro.Check(before, t0.Add(time.Minute)); err != nil {
		t.Errorf("a record from before the removal no longer verifies: %v", err)
	}
	after := blockRecord(t, ro.Group, kb, 2, HLCOf(t0.Add(2*time.Minute)), "203.0.113.8")
	if err := ro.Check(after, t0.Add(2*time.Minute)); !errors.Is(err, ErrRemoved) {
		t.Errorf("a record from after the removal: got %v, want %v", err, ErrRemoved)
	}
	// It cannot let itself in again.
	back := memberRecord(t, ro.Group, kb, 3, HLCOf(t0.Add(3*time.Minute)), pb, "web-2", false)
	if err := ro.Check(back, t0.Add(3*time.Minute)); !errors.Is(err, ErrRemoved) {
		t.Errorf("a removed member admits itself: got %v", err)
	}
}

func TestWins(t *testing.T) {
	a := &Record{HLC: 10, Origin: "n-a", Seq: 1}
	b := &Record{HLC: 11, Origin: "n-a", Seq: 2}
	if !Wins(b, a) || Wins(a, b) {
		t.Error("the later clock must win")
	}
	block := &Record{HLC: 10, Origin: "n-b", Seq: 7}
	lift := &Record{HLC: 10, Origin: "n-a", Seq: 3, Deleted: true}
	if !Wins(lift, block) || Wins(block, lift) {
		t.Error("at the same clock a tombstone must beat a write")
	}
	x := &Record{HLC: 10, Origin: "n-a", Seq: 9}
	y := &Record{HLC: 10, Origin: "n-b", Seq: 1}
	if !Wins(y, x) || Wins(x, y) {
		t.Error("at the same clock the greater origin must win, on every node the same")
	}
}

func TestClock(t *testing.T) {
	var c Clock
	a := c.Next(t0)
	b := c.Next(t0)
	back := c.Next(t0.Add(-time.Hour)) // the wall clock went back
	if !(a < b && b < back) {
		t.Fatalf("clock went back: %d %d %d", a, b, back)
	}
	c.Observe(HLCOf(t0.Add(30 * time.Second)))
	if n := c.Next(t0); n <= HLCOf(t0.Add(30*time.Second)) {
		t.Error("a write after a seen record must be later than it")
	}
	if got := HLCTime(HLCOf(t0) + 3); !got.Equal(t0) {
		t.Errorf("HLCTime: %v", got)
	}
}

func TestAdmissionByTheGroupSecret(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	gk, err := GroupKey(secret)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := GroupKey(secret[:31]); !errors.Is(err, ErrSecret) {
		t.Errorf("a short secret: %v", err)
	}
	self := func(k ed25519.PrivateKey, gk ed25519.PrivateKey, group string, hlc uint64) *Record {
		pub := k.Public().(ed25519.PublicKey)
		m := Member{Name: "web", Role: RoleGateway, PublicKey: base64.StdEncoding.EncodeToString(pub), Address: "10.0.0.1:8790", Joined: TimeText(t0)}
		g := m.AdmitWith(gk, pub)
		if group == "" {
			group = g
		}
		r := &Record{V: Version, Group: group, Class: ClassMembers, ID: NodeID(pub), Origin: NodeID(pub), Seq: 1, HLC: hlc}
		if err := r.Sign(k, m); err != nil {
			t.Fatal(err)
		}
		return r
	}
	pa, ka := key(1)
	_, kb := key(2)
	group := GroupID(gk.Public().(ed25519.PublicKey))
	ro := NewRoster(group)
	// Two nodes let themselves in, each with its own key.
	for _, k := range []ed25519.PrivateKey{ka, kb} {
		r := self(k, gk, "", HLCOf(t0))
		if err := ro.Check(r, t0); err != nil {
			t.Fatalf("a node with the secret: %v", err)
		}
		ro.Set(r)
	}
	if _, ok := ro.ActiveKey(pa, RoleGateway); !ok {
		t.Fatal("an admitted node is no member")
	}
	// Another secret is another group key: no way into this group.
	other, _ := GroupKey([]byte("another-secret-another-secret-00"))
	_, kc := key(3)
	if err := ro.Check(self(kc, other, group, HLCOf(t0)), t0); !errors.Is(err, ErrOrigin) {
		t.Errorf("a node with another secret: %v", err)
	}
	// The admission of one node does not carry another key.
	stolen := self(ka, gk, "", HLCOf(t0))
	m, _ := DecodeMember(stolen)
	pc := kc.Public().(ed25519.PublicKey)
	forged := Member{Name: "evil", Role: RoleGateway, PublicKey: base64.StdEncoding.EncodeToString(pc), Address: "10.0.0.9:8790", Joined: TimeText(t0), AdmitKey: m.AdmitKey, Admit: m.Admit}
	fr := &Record{V: Version, Group: group, Class: ClassMembers, ID: NodeID(pc), Origin: NodeID(pc), Seq: 1, HLC: HLCOf(t0)}
	_ = fr.Sign(kc, forged)
	if err := ro.Check(fr, t0); !errors.Is(err, ErrOrigin) {
		t.Errorf("a copied admission: %v", err)
	}
	// A removed node stays out, although it holds the secret.
	pb := kb.Public().(ed25519.PublicKey)
	gone := self(kb, gk, "", HLCOf(t0.Add(time.Minute)))
	gone.Origin, gone.Seq, gone.Deleted = NodeID(pa), 2, true
	mb, _ := DecodeMember(gone)
	_ = gone.Sign(ka, mb)
	if err := ro.Check(gone, t0.Add(time.Minute)); err != nil {
		t.Fatalf("removal: %v", err)
	}
	ro.Set(gone)
	if err := ro.Check(self(kb, gk, "", HLCOf(t0.Add(2*time.Minute))), t0.Add(2*time.Minute)); !errors.Is(err, ErrRemoved) {
		t.Errorf("a removed node lets itself in again: %v", err)
	}
	if _, ok := ro.ActiveKey(pb); ok {
		t.Error("a removed node is active")
	}
}

func TestValuesAndErasure(t *testing.T) {
	ro, _, kb := group(t)
	origin := NodeID(kb.Public().(ed25519.PublicKey))
	rec := func(class, id string, deleted bool, data any, expires string) *Record {
		r := &Record{V: Version, Group: ro.Group, Class: class, ID: id, Origin: origin, Seq: 1, HLC: HLCOf(t0), Deleted: deleted, Expires: expires}
		if err := r.Sign(kb, data); err != nil {
			t.Fatal(err)
		}
		return r
	}
	later := TimeText(t0.Add(30 * 24 * time.Hour))
	good := []*Record{
		rec(ClassAccess, EntryID("allowlist", `["al_1"]`), false, NewValue(`["al_1"]`, []byte(`["al_1","203.0.113.7"]`), "web-2"), ""),
		rec(ClassSettings, EntryID("settings_overlay_v1", `["retention","events_days"]`), false, NewValue(`["retention","events_days"]`, []byte(`30`), "web-2"), ""),
		rec(ClassLogins, EntryID("users", `["admin"]`), true, &Value{K: `["admin"]`, Node: "web-2"}, later),
		rec(ClassSettings, EntryID("agent_pseudonym_key_v1", ""), false, NewValue("", []byte{1, 2, 3}, "web-2"), ""),
		rec(ClassErasure, "203.0.113.7", false, Erasure{IP: "203.0.113.7", Node: "web-2"}, TimeText(t0.Add(ErasureKeepS*time.Second))),
	}
	for _, r := range good {
		if err := ro.Check(r, t0); err != nil {
			t.Errorf("%s/%s: %v", r.Class, r.ID, err)
		}
	}
	bad := map[string]*Record{
		"a thing the class does not have":   rec(ClassAccess, EntryID("users", "x"), false, NewValue("x", nil, "web-2"), ""),
		"a setting nobody shares":           rec(ClassSettings, EntryID("installed_at_v1", ""), false, NewValue("", nil, "web-2"), ""),
		"the whole thing as one record":     rec(ClassAccess, "allowlist", false, NewValue("", nil, "web-2"), ""),
		"id is not the hash of the key":     rec(ClassAccess, EntryID("allowlist", "a"), false, NewValue("b", nil, "web-2"), ""),
		"a tombstone with a value":          rec(ClassAccess, EntryID("allowlist", "a"), true, NewValue("a", []byte("x"), "web-2"), later),
		"a tombstone without an end":        rec(ClassAccess, EntryID("allowlist", "a"), true, &Value{K: "a"}, ""),
		"value is no base64":                rec(ClassSettings, EntryID("human_check_v1", "a"), false, map[string]string{"key": "a", "value": "%%%"}, ""),
		"erasure without an end":            rec(ClassErasure, "203.0.113.7", false, Erasure{IP: "203.0.113.7"}, ""),
		"erasure of another address":        rec(ClassErasure, "203.0.113.7", false, Erasure{IP: "203.0.113.8"}, TimeText(t0.Add(time.Hour))),
		"erasure of something that is none": rec(ClassErasure, "everything", false, Erasure{IP: "everything"}, TimeText(t0.Add(time.Hour))),
	}
	for name, r := range bad {
		if err := ro.Check(r, t0); !errors.Is(err, ErrSchema) {
			t.Errorf("%s: got %v", name, err)
		}
	}
}

func TestCertificateFiles(t *testing.T) {
	ro, _, kb := group(t)
	origin := NodeID(kb.Public().(ed25519.PublicKey))
	b64 := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	rec := func(id string, f Files, deleted bool) *Record {
		r := &Record{V: Version, Group: ro.Group, Class: ClassCertificates, ID: id, Origin: origin, Seq: 1, HLC: HLCOf(t0), Deleted: deleted}
		if err := r.Sign(kb, f); err != nil {
			t.Fatal(err)
		}
		return r
	}
	dir := "certificates/acme-v02.api.letsencrypt.org-directory/shop.example"
	good := []*Record{
		rec(dir, Files{Files: map[string]string{"shop.example.crt": b64("c"), "shop.example.key": b64("k"), "shop.example.json": b64("{}")}, Node: "web-2"}, false),
		rec("challenge_tokens/shop.example.json", Files{Files: map[string]string{"": b64("t")}, Node: "web-2"}, false),
		rec("challenge_tokens/shop.example.json", Files{Node: "web-2"}, true),
	}
	for _, r := range good {
		if err := ro.Check(r, t0); err != nil {
			t.Errorf("%s: %v", r.ID, err)
		}
	}
	bad := map[string]*Record{
		"a path out of the storage":      rec("../schild.yaml", Files{Files: map[string]string{"": b64("x")}}, false),
		"an absolute path":               rec("/etc/passwd", Files{Files: map[string]string{"": b64("x")}}, false),
		"a file name with a directory":   rec(dir, Files{Files: map[string]string{"../../x": b64("x")}}, false),
		"a file and a directory at once": rec(dir, Files{Files: map[string]string{"": b64("x"), "a": b64("y")}}, false),
		"no files":                       rec(dir, Files{}, false),
		"a tombstone with files":         rec(dir, Files{Files: map[string]string{"a": b64("x")}}, true),
		"content that is no base64":      rec(dir, Files{Files: map[string]string{"a": "%%"}}, false),
	}
	for name, r := range bad {
		if err := ro.Check(r, t0); !errors.Is(err, ErrSchema) {
			t.Errorf("%s: got %v", name, err)
		}
	}
}
