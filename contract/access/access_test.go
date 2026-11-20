package access

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var t0 = time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)

func TestValidateFieldNames(t *testing.T) {
	p := Protection{Website: "a.example", Scope: ScopeSite}
	err := p.CheckShape()
	fe, ok := err.(*FieldError)
	if !ok || fe.Field != "password" {
		t.Fatalf("no way in: %v", err)
	}
	p.Password, p.Addresses = true, []string{"10.0.0.0/8"}
	if fe, ok := p.CheckShape().(*FieldError); !ok || fe.Field != "addresses" {
		t.Fatalf("wide network: %v", fe)
	}
}

func TestSession(t *testing.T) {
	key := []byte(strings.Repeat("k", KeyLen))
	v := SessionValue(key, "a.example", 7, t0.Add(SessionTTL))
	if got := VerifySession(key, v, "a.example", 7, t0); got != SessionValid {
		t.Fatalf("valid: %s", got)
	}
	for name, got := range map[string]string{
		"other epoch":   VerifySession(key, v, "a.example", 8, t0),
		"other website": VerifySession(key, v, "b.example", 7, t0),
		"expired":       VerifySession(key, v, "a.example", 7, t0.Add(SessionTTL)),
		"other key":     VerifySession([]byte(strings.Repeat("x", KeyLen)), v, "a.example", 7, t0),
		"tampered":      VerifySession(key, strings.Replace(v, ".7.", ".8.", 1), "a.example", 8, t0),
		"garbage":       VerifySession(key, "1.x.y", "a.example", 7, t0),
		"no key":        VerifySession(nil, v, "a.example", 7, t0),
	} {
		if got != SessionInvalid {
			t.Errorf("%s: %s", name, got)
		}
	}
	if got := VerifySession(key, "", "a.example", 7, t0); got != SessionNone {
		t.Errorf("empty: %s", got)
	}
}

func TestActiveFile(t *testing.T) {
	dir := t.TempDir()
	if _, err := ReadActive(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing file read as known state: %v", err) // D71: unknown is no "no lock"
	}
	marker := filepath.Join(dir, ActiveDir, ActiveMarker)
	on := Active{Protections: []ActiveRecord{{Website: "a.example", Scope: ScopeSite}}}
	if err := WriteActive(dir, on); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("marker: %v", err)
	}
	a, err := ReadActive(dir)
	if err != nil || !a.InForce() {
		t.Fatalf("read back: %+v %v", a, err)
	}
	if err := WriteActive(dir, Active{}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("marker stays: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, ActiveDir, ActiveFile), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadActive(dir); err == nil {
		t.Fatal("broken file read as no protection")
	}
}
