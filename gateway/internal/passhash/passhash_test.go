package passhash

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestHashAndCheck(t *testing.T) {
	h := Hash("korrekt-pferd-batterie")
	if !strings.HasPrefix(h, "$argon2id$v=19$m=19456,t=2,p=1$") {
		t.Fatalf("encoding: %s", h)
	}
	if !Check(h, "korrekt-pferd-batterie") {
		t.Fatal("right password refused")
	}
	if Check(h, "korrekt-pferd-batteriE") || Check(h, "") {
		t.Fatal("wrong password accepted")
	}
	if a, b := Hash("same"), Hash("same"); a == b {
		t.Fatal("no fresh salt")
	}
}

// TestCheckRefusesBrokenEncodings: a damaged or altered stored hash never
// matches, never panics and never makes argon2 allocate beyond the bound.
func TestCheckRefusesBrokenEncodings(t *testing.T) {
	salt := base64.RawStdEncoding.EncodeToString([]byte("0123456789abcdef"))
	key := base64.RawStdEncoding.EncodeToString(make([]byte, 32))
	enc := func(v, params, s, k string) string { return "$argon2id$" + v + "$" + params + "$" + s + "$" + k }
	for name, h := range map[string]string{
		"empty":          "",
		"argon2i":        "$argon2i$v=19$m=19456,t=2,p=1$" + salt + "$" + key,
		"version":        enc("v=16", "m=19456,t=2,p=1", salt, key),
		"time 0":         enc("v=19", "m=19456,t=0,p=1", salt, key),          // argon2 panics
		"threads 0":      enc("v=19", "m=19456,t=2,p=0", salt, key),          // argon2 panics
		"memory 4 TiB":   enc("v=19", "m=4294967295,t=1,p=1", salt, key),     // would allocate it
		"time huge":      enc("v=19", "m=19456,t=4294967295,p=1", salt, key), // would run for ever
		"empty key":      enc("v=19", "m=19456,t=2,p=1", salt, ""),           // would match anything
		"short key":      enc("v=19", "m=19456,t=2,p=1", salt, base64.RawStdEncoding.EncodeToString(make([]byte, 4))),
		"empty salt":     enc("v=19", "m=19456,t=2,p=1", "", key),
		"bad base64":     enc("v=19", "m=19456,t=2,p=1", salt, "!!"),
		"params garbled": enc("v=19", "m=x,t=2,p=1", salt, key),
	} {
		func() {
			defer func() {
				if p := recover(); p != nil {
					t.Errorf("%s: panic %v", name, p)
				}
			}()
			if Check(h, "") || Check(h, "anything") {
				t.Errorf("%s: matched", name)
			}
		}()
	}
}
