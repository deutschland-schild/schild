package humancheck

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"strconv"
	"strings"
	"time"
)

// CookieName is the host-only clearance cookie (MVP-12).
const CookieName = "__Host-schild_clr"

// KeyLen is the length in bytes of k_challenge and k_clear.
const KeyLen = 32

const (
	challengePrefix = "schild-ch1."
	challengeDomain = "schild/challenge/1\n"
	clearanceDomain = "schild/clearance/1\n"
)

var (
	b64    = base64.RawURLEncoding
	b32Low = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)
)

// ChallengePayload is the JSON payload inside a schild-ch1 token.
type ChallengePayload struct {
	V         int    `json:"v"`
	Alg       string `json:"alg"`
	Salt      string `json:"salt"`
	Challenge string `json:"challenge"`
	Max       int    `json:"max"`
	Exp       int64  `json:"exp"`
	Host      string `json:"host"`
	Ret       string `json:"ret"`
}

// SafeReturnPath normalizes a return path to a safe same-origin path.
// Unsafe values fall back to "/".
func SafeReturnPath(raw string) string {
	if raw == "" || raw[0] != '/' || strings.HasPrefix(raw, "//") || strings.ContainsRune(raw, '\\') {
		return "/"
	}
	for i := 0; i < len(raw); i++ {
		if raw[i] < 0x20 || raw[i] == 0x7f {
			return "/"
		}
	}
	if len(raw) > 2048 {
		return "/"
	}
	return raw
}

// NewPrefix generates a random per-instance endpoint prefix "/_s-<8 base32>/".
func NewPrefix() string {
	var buf [5]byte
	_, _ = rand.Read(buf[:])
	return "/_s-" + b32Low.EncodeToString(buf[:]) + "/"
}

// ValidPrefix reports whether p is a valid per-instance endpoint prefix.
func ValidPrefix(p string) bool {
	if !strings.HasPrefix(p, "/_s-") || !strings.HasSuffix(p, "/") {
		return false
	}
	mid := p[4 : len(p)-1]
	if len(mid) < 6 || len(mid) > 24 {
		return false
	}
	for i := 0; i < len(mid); i++ {
		c := mid[i]
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) {
			return false
		}
	}
	return true
}

// UAHash returns the hex SHA-256 of the User-Agent string.
func UAHash(ua string) string {
	sum := sha256.Sum256([]byte(ua))
	return hex.EncodeToString(sum[:])
}

// PoWHash computes hex(sha256(salt || decimal(n))).
func PoWHash(salt string, n int) string {
	sum := sha256.Sum256([]byte(salt + strconv.Itoa(n)))
	return hex.EncodeToString(sum[:])
}

// IssueChallenge creates a signed challenge token with a random salt and
// secret solution n in [0, max].
func IssueChallenge(key []byte, host, ipPrefix, ua, ret string, max int, now time.Time) (string, ChallengePayload, error) {
	if len(key) == 0 {
		return "", ChallengePayload{}, errors.New("empty challenge key")
	}
	if max < MinDifficulty || max > MaxDifficulty {
		max = DefaultDifficulty
	}
	var saltBytes [16]byte
	if _, err := rand.Read(saltBytes[:]); err != nil {
		return "", ChallengePayload{}, err
	}
	salt := hex.EncodeToString(saltBytes[:])
	nBig, err := rand.Int(rand.Reader, big.NewInt(int64(max)+1))
	if err != nil {
		return "", ChallengePayload{}, err
	}
	p := ChallengePayload{
		V:         1,
		Alg:       "SHA-256",
		Salt:      salt,
		Challenge: PoWHash(salt, int(nBig.Int64())),
		Max:       max,
		Exp:       now.Add(MaxChallengeTTL).Unix(),
		Host:      strings.ToLower(host),
		Ret:       SafeReturnPath(ret),
	}
	tok, err := SignChallenge(key, ipPrefix, ua, p)
	return tok, p, err
}

// SignChallenge signs a ChallengePayload into a schild-ch1 token.
func SignChallenge(key []byte, ipPrefix, ua string, p ChallengePayload) (string, error) {
	raw, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	pb64 := b64.EncodeToString(raw)
	mac := challengeMAC(key, p.Host, ipPrefix, ua, pb64)
	return challengePrefix + pb64 + "." + b64.EncodeToString(mac), nil
}

func challengeMAC(key []byte, host, ipPrefix, ua, payloadB64 string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(challengeDomain))
	m.Write([]byte(strings.ToLower(host)))
	m.Write([]byte("\n"))
	m.Write([]byte(ipPrefix))
	m.Write([]byte("\n"))
	m.Write([]byte(UAHash(ua)))
	m.Write([]byte("\n"))
	m.Write([]byte(payloadB64))
	return m.Sum(nil)
}

// VerifyChallenge validates a schild-ch1 token against any of keys (current
// and previous rotated key), host, ipPrefix, ua and now. If checkPoW is true,
// it also verifies sha256(salt || number) == challenge.
func VerifyChallenge(keys [][]byte, token, host, ipPrefix, ua string, number int, checkPoW bool, now time.Time) (ChallengePayload, error) {
	if !strings.HasPrefix(token, challengePrefix) || len(token) > 1536 {
		return ChallengePayload{}, errors.New("malformed token")
	}
	rest := strings.TrimPrefix(token, challengePrefix)
	dot := strings.IndexByte(rest, '.')
	if dot <= 0 || dot == len(rest)-1 || strings.IndexByte(rest[dot+1:], '.') >= 0 {
		return ChallengePayload{}, errors.New("malformed token")
	}
	pb64, mb64 := rest[:dot], rest[dot+1:]
	mac, err := b64.DecodeString(mb64)
	if err != nil || len(mac) != sha256.Size {
		return ChallengePayload{}, errors.New("bad mac encoding")
	}
	hostLow := strings.ToLower(host)
	matched := false
	for _, k := range keys {
		if len(k) == 0 {
			continue
		}
		if hmac.Equal(mac, challengeMAC(k, hostLow, ipPrefix, ua, pb64)) {
			matched = true
			break
		}
	}
	if !matched {
		return ChallengePayload{}, errors.New("invalid mac")
	}
	raw, err := b64.DecodeString(pb64)
	if err != nil {
		return ChallengePayload{}, errors.New("bad payload encoding")
	}
	var p ChallengePayload
	if err := json.Unmarshal(raw, &p); err != nil {
		return ChallengePayload{}, errors.New("bad payload json")
	}
	if p.V != 1 || p.Alg != "SHA-256" || len(p.Salt) < 16 || len(p.Challenge) != 64 {
		return ChallengePayload{}, errors.New("invalid payload fields")
	}
	if p.Max < MinDifficulty || p.Max > MaxDifficulty {
		return ChallengePayload{}, errors.New("invalid difficulty")
	}
	if strings.ToLower(p.Host) != hostLow {
		return ChallengePayload{}, errors.New("host mismatch")
	}
	if p.Exp <= now.Unix() || p.Exp > now.Add(MaxChallengeTTL+time.Minute).Unix() {
		return ChallengePayload{}, errors.New("expired")
	}
	p.Ret = SafeReturnPath(p.Ret)
	if checkPoW {
		if number < 0 || number > p.Max {
			return ChallengePayload{}, errors.New("number out of range")
		}
		if PoWHash(p.Salt, number) != p.Challenge {
			return ChallengePayload{}, errors.New("wrong solution")
		}
	}
	return p, nil
}

// RoundExpiryMinute rounds t up to the next whole minute (unix seconds).
func RoundExpiryMinute(t time.Time) int64 {
	u := t.Unix()
	return ((u + 59) / 60) * 60
}

// ClearanceValue builds an identifier-free __Host-schild_clr cookie value.
func ClearanceValue(key []byte, host, kind, ipPrefix, ua string, expiry time.Time) string {
	exp := strconv.FormatInt(RoundExpiryMinute(expiry), 10)
	mac := clearanceMAC(key, host, kind, exp, ipPrefix, ua)
	return "c1." + kind + "." + exp + "." + b64.EncodeToString(mac)
}

func clearanceMAC(key []byte, host, kind, exp, ipPrefix, ua string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(clearanceDomain))
	m.Write([]byte(strings.ToLower(host)))
	m.Write([]byte("\n"))
	m.Write([]byte(kind))
	m.Write([]byte("\n"))
	m.Write([]byte(exp))
	m.Write([]byte("\n"))
	m.Write([]byte(ipPrefix))
	m.Write([]byte("\n"))
	m.Write([]byte(UAHash(ua)))
	sum := m.Sum(nil)
	return sum[:16] // 128-bit MAC, compact and identifier-free
}

// VerifyClearance checks a __Host-schild_clr cookie value against keys and
// returns ClearanceNone, ClearancePoW, ClearanceNoJS, or ClearanceInvalid.
func VerifyClearance(keys [][]byte, value, host, ipPrefix, ua string, now time.Time) string {
	if value == "" {
		return ClearanceNone
	}
	if len(value) > 128 {
		return ClearanceInvalid
	}
	parts := strings.Split(value, ".")
	if len(parts) != 4 || parts[0] != "c1" {
		return ClearanceInvalid
	}
	kind, expStr, macStr := parts[1], parts[2], parts[3]
	if kind != ClearancePoW && kind != ClearanceNoJS {
		return ClearanceInvalid
	}
	exp, err := strconv.ParseInt(expStr, 10, 64)
	if err != nil || exp <= now.Unix() {
		return ClearanceInvalid
	}
	mac, err := b64.DecodeString(macStr)
	if err != nil || len(mac) != 16 {
		return ClearanceInvalid
	}
	for _, k := range keys {
		if len(k) == 0 {
			continue
		}
		if hmac.Equal(mac, clearanceMAC(k, host, kind, expStr, ipPrefix, ua)) {
			return kind
		}
	}
	return ClearanceInvalid
}
