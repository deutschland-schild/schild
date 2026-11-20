package label

import "testing"

func TestSignParseRoundTrip(t *testing.T) {
	secret := []byte("test-secret-0123456789")
	in := Label{Class: Malicious, Scenario: "T02", Source: "sqlmap", Technique: "sqli", ExpectBlock: true, Seq: 17}
	hdr, err := Sign(secret, in)
	if err != nil {
		t.Fatal(err)
	}
	out, err := Parse(secret, hdr)
	if err != nil {
		t.Fatal(err)
	}
	if out != in {
		t.Fatalf("round trip mismatch: %+v vs %+v", out, in)
	}
}

func TestSignDeterministic(t *testing.T) {
	secret := []byte("k")
	l := Label{Class: Canary, Scenario: "T01", Canary: "CANARY-1", Seq: 3}
	a, _ := Sign(secret, l)
	b, _ := Sign(secret, l)
	if a != b {
		t.Fatalf("signatures differ for same input: %q vs %q", a, b)
	}
}

func TestParseRejectsForgery(t *testing.T) {
	good := []byte("real-secret")
	wrong := []byte("attacker-secret")
	hdr, _ := Sign(good, Label{Class: Benign, Scenario: "T01"})
	if _, err := Parse(wrong, hdr); err != ErrBadSignature {
		t.Fatalf("forged label accepted or wrong error: %v", err)
	}
}

func TestParseRejectsTampered(t *testing.T) {
	secret := []byte("s")
	hdr, _ := Sign(secret, Label{Class: Benign, Scenario: "T01"})
	// Flip a payload byte.
	b := []byte(hdr)
	b[0] ^= 0x01
	if _, err := Parse(secret, string(b)); err == nil {
		t.Fatal("tampered label accepted")
	}
}

func TestParseMissing(t *testing.T) {
	if _, err := Parse([]byte("s"), ""); err != ErrNoLabel {
		t.Fatalf("empty header: want ErrNoLabel, got %v", err)
	}
	if _, err := Parse([]byte("s"), "   "); err != ErrNoLabel {
		t.Fatalf("blank header: want ErrNoLabel, got %v", err)
	}
}

func TestSignRejectsBadClass(t *testing.T) {
	if _, err := Sign([]byte("s"), Label{Class: "nonsense"}); err == nil {
		t.Fatal("invalid class accepted")
	}
}

func TestExpectedOutcome(t *testing.T) {
	for c, want := range map[Class]bool{Benign: false, GoodBot: false, Canary: false, Malicious: true, Bypass: true} {
		if ExpectedOutcome(c) != want {
			t.Errorf("ExpectedOutcome(%s) = %v, want %v", c, ExpectedOutcome(c), want)
		}
	}
}
