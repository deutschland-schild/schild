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

func memberRecord(t *testing.T, group string, signer ed25519.PrivateKey, seq uint64, hlc uint64, pub ed25519.PublicKey, name string, deleted bool) *Record {
	t.Helper()
	r := &Record{V: Version, Group: group, Class: ClassMembers, ID: NodeID(pub), Origin: NodeID(signer.Public().(ed25519.PublicKey)), Seq: seq, HLC: hlc, Deleted: deleted}
	m := Member{Name: name, Role: RoleGateway, PublicKey: base64.StdEncoding.EncodeToString(pub), Address: "10.0.0.1:8790", Joined: TimeText(t0)}
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
	ro := NewRoster(GroupID(pa))
	founder := memberRecord(t, ro.Group, ka, 1, HLCOf(t0), pa, "web-1", false)
	if err := ro.Check(founder, t0); err != nil {
		t.Fatalf("founder: %v", err)
	}
	ro.Set(founder)
	second := memberRecord(t, ro.Group, ka, 2, HLCOf(t0)+1, pb, "web-2", false)
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
	_, kc := key(3) // never joined
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
		{"stranger admits itself", func() *Record { return memberRecord(t, ro.Group, kc, 1, HLCOf(t0), pc, "evil", false) }, ErrOrigin},
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

func TestJoinCode(t *testing.T) {
	pa, _ := key(1)
	code, hash, err := NewJoinCode(pa)
	if err != nil {
		t.Fatal(err)
	}
	secret, fp, err := ParseJoinCode(" " + code + "\n")
	if err != nil {
		t.Fatal(err)
	}
	if !SameFingerprint(fp, Fingerprint(pa)) {
		t.Error("the code does not name the inviting key")
	}
	if string(JoinHash(secret)) != string(hash) {
		t.Error("the stored hash does not fit the secret")
	}
	pb, _ := key(2)
	if SameFingerprint(fp, Fingerprint(pb)) {
		t.Error("another key fits the code")
	}
	for _, bad := range []string{"", "abc", code[:len(code)-2], code + "aa"} {
		if _, _, err := ParseJoinCode(bad); err == nil {
			t.Errorf("code %q parsed", bad)
		}
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
	// Two nodes let themselves in, each with its own key, neither is a founder.
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
