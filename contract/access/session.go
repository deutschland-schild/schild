package access

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"strconv"
	"strings"
	"time"
)

// CookieName is the session cookie of a login (D56): host-only, Path=/,
// Secure, HttpOnly, SameSite=Lax.
const CookieName = "__Host-schild_access"

// PromLogins is the counter of login attempts by result (ok, wrong,
// locked_out, busy).
const PromLogins = "schild_access_logins_total"

// SessionTTL is how long a login holds.
const SessionTTL = 12 * time.Hour

// KeyLen is the length of the per-gateway session key.
const KeyLen = 32

const sessionDomain = "schild-access/1\n"

var b64 = base64.RawURLEncoding

// SessionValue returns the cookie value for website at epoch, valid until
// expiry: "1.<website, base64url>.<epoch>.<expiry, unix seconds>.<mac>",
// mac = HMAC-SHA256(key, "schild-access/1\n" + the part before it),
// base64url without padding. The epoch changes with every change of the
// protection, so an old cookie never verifies again.
func SessionValue(key []byte, website string, epoch uint64, expiry time.Time) string {
	payload := "1." + b64.EncodeToString([]byte(website)) + "." + strconv.FormatUint(epoch, 10) + "." + strconv.FormatInt(expiry.Unix(), 10)
	return payload + "." + b64.EncodeToString(sessionMAC(key, payload))
}

func sessionMAC(key []byte, payload string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(sessionDomain))
	m.Write([]byte(payload))
	return m.Sum(nil)
}

// VerifySession returns SessionValid when value is a cookie of website at
// epoch that has not expired at now, SessionNone for an empty value and
// SessionInvalid for anything else.
func VerifySession(key []byte, value, website string, epoch uint64, now time.Time) string {
	if value == "" {
		return SessionNone
	}
	if len(value) > 512 || len(key) == 0 {
		return SessionInvalid
	}
	i := strings.LastIndexByte(value, '.')
	if i < 0 {
		return SessionInvalid
	}
	payload, macPart := value[:i], value[i+1:]
	mac, err := b64.DecodeString(macPart)
	if err != nil || !hmac.Equal(mac, sessionMAC(key, payload)) {
		return SessionInvalid
	}
	parts := strings.Split(payload, ".")
	if len(parts) != 4 || parts[0] != "1" {
		return SessionInvalid
	}
	site, err := b64.DecodeString(parts[1])
	if err != nil || string(site) != website {
		return SessionInvalid
	}
	ep, err := strconv.ParseUint(parts[2], 10, 64)
	if err != nil || ep != epoch {
		return SessionInvalid
	}
	exp, err := strconv.ParseInt(parts[3], 10, 64)
	if err != nil || !time.Unix(exp, 0).After(now) {
		return SessionInvalid
	}
	return SessionValid
}
