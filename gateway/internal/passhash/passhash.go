// Package passhash hashes and checks passwords with Argon2id: the dashboard
// login and the shared password of the access lock (D56) use the same
// parameters.
package passhash

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	argonTime    = 2
	argonMemory  = 19456 // KiB (OWASP minimum for argon2id)
	argonThreads = 1
	argonKeyLen  = 32
)

// Bounds of an encoded hash that Check accepts. Hashes come from schild's
// own store, but a damaged or altered row must not make Check panic
// (argon2 panics on a time or thread count of 0), allocate gigabytes, or
// accept every password (an empty key equals an empty result). They leave
// room for stronger parameters than the ones Hash uses today.
const (
	minSaltLen = 8
	minKeyLen  = 16
	maxKeyLen  = 64
	maxTime    = 16
	maxMemory  = 256 << 10 // KiB (256 MiB)
	maxThreads = 16
)

// Hash returns an encoded argon2id hash.
func Hash(pw string) string {
	salt := make([]byte, 16)
	_, _ = rand.Read(salt)
	key := argon2.IDKey([]byte(pw), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key))
}

// Check verifies pw against an encoded argon2id hash. An encoding outside
// the bounds above never matches.
func Check(encoded, pw string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" || parts[2] != "v=19" {
		return false
	}
	var m uint32
	var t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
		return false
	}
	if t < 1 || t > maxTime || p < 1 || p > maxThreads || m < 8*uint32(p) || m > maxMemory {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(salt) < minSaltLen {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(want) < minKeyLen || len(want) > maxKeyLen {
		return false
	}
	got := argon2.IDKey([]byte(pw), salt, t, m, p, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}
