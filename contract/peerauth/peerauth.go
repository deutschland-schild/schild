// Package peerauth authenticates requests between labs on the feed port
// (contracts v0.1, contracts/cosign.md): a lab answers GET /v0/collecting
// (rule texts that are not public yet) only to configured peers that sign
// the request with one of their rules keys.
//
// Header (one line, five space-separated tokens, fixed order):
//
//	Schild-Peer-Auth: v1 lab=<peer lab id> keyid=<keyid> ts=<RFC 3339 UTC> sig=<standard base64>
//
// The signature is Ed25519 over DSSE PAE(PayloadType, message) with
//
//	schild.peer-request/1\n
//	method:<GET|POST>\n
//	path:<request path>\n
//	target:<lab id of the receiving lab>\n
//	from:<lab id of the sender>\n
//	keyid:<keyid>\n
//	ts:<ts>\n
//	body:<sha256:hex of the request body; sha256 of "" for GET>\n
//
// The receiving lab accepts the request when the key is configured for that
// peer lab with purpose rules, the signature verifies and ts is within the
// clock skew (120 s) of its own clock in either direction.
package peerauth

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/dsse"
	"github.com/deutschland-schild/schild/contract/keys"
	"github.com/deutschland-schild/schild/contract/msg"
)

// Header is the request header carrying the peer signature.
const Header = "Schild-Peer-Auth"

// PayloadType separates peer request signatures from every signed document.
const PayloadType = "application/vnd.schild.peer-request.v0+text"

// Window is the accepted clock difference in either direction.
const Window = contract.MaxClockSkew

var (
	idRe    = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	keyidRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._/-]{0,127}$`)
	tsRe    = regexp.MustCompile(`^20[0-9]{2}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$`)
)

// Request is what the receiving lab verifies.
type Request struct {
	Method     string
	Path       string
	Target     string // the receiving lab's own id
	BodySHA256 string // "sha256:<hex>"
	Header     string // Schild-Peer-Auth value
}

// Auth is a parsed header.
type Auth struct {
	Lab, KeyID, TS string
	Sig            []byte
}

// BodyDigest returns "sha256:<hex>" of a request body.
func BodyDigest(body []byte) string {
	h := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(h[:])
}

// Message returns the signed message text.
func Message(method, path, target, from, keyid, ts, body string) []byte {
	return []byte("schild.peer-request/1\n" +
		"method:" + method + "\n" +
		"path:" + path + "\n" +
		"target:" + target + "\n" +
		"from:" + from + "\n" +
		"keyid:" + keyid + "\n" +
		"ts:" + ts + "\n" +
		"body:" + body + "\n")
}

// Sign returns the header value for a request from lab `from` to lab `target`.
func Sign(s *keys.Signer, from, method, path, target string, body []byte, now time.Time) (string, error) {
	ts := msg.FormatTime(now.UTC())
	m := Message(method, path, target, from, s.KeyID(), ts, BodyDigest(body))
	sig, err := s.Sign(dsse.PAE(PayloadType, m))
	if err != nil {
		return "", err
	}
	return "v1 lab=" + from + " keyid=" + s.KeyID() + " ts=" + ts + " sig=" + base64.StdEncoding.EncodeToString(sig), nil
}

// SetHeader signs req (body may be nil) and sets the header.
func SetHeader(req *http.Request, s *keys.Signer, from, target string, body []byte, now time.Time) error {
	v, err := Sign(s, from, req.Method, req.URL.Path, target, body, now)
	if err != nil {
		return err
	}
	req.Header.Set(Header, v)
	return nil
}

// Parse splits a header value. Syntax errors are code malformed, field
// format errors code schema.
func Parse(v string) (*Auth, error) {
	parts := strings.Split(v, " ")
	if len(parts) != 5 || parts[0] != "v1" {
		return nil, contract.Errf(contract.CodeMalformed, "header must be: v1 lab=.. keyid=.. ts=.. sig=..")
	}
	want := []string{"lab=", "keyid=", "ts=", "sig="}
	vals := make([]string, 4)
	for i, p := range parts[1:] {
		val, ok := strings.CutPrefix(p, want[i])
		if !ok {
			return nil, contract.Errf(contract.CodeMalformed, "token %d must start with %s", i+2, want[i])
		}
		vals[i] = val
	}
	sig, err := dsse.DecodeBase64(vals[3])
	if err != nil {
		return nil, contract.Errf(contract.CodeMalformed, "sig: %v", err)
	}
	if !idRe.MatchString(vals[0]) || !keyidRe.MatchString(vals[1]) || !tsRe.MatchString(vals[2]) {
		return nil, contract.Errf(contract.CodeSchema, "lab, keyid or ts has a wrong format")
	}
	if _, err := msg.ParseTime(vals[2]); err != nil {
		return nil, contract.Errf(contract.CodeSchema, "ts: %v", err)
	}
	return &Auth{Lab: vals[0], KeyID: vals[1], TS: vals[2], Sig: sig}, nil
}

// Verify checks a request against the trust store of the receiving lab: the
// key must be trusted with purpose rules and belong to the lab named in the
// header. It returns the authenticated peer lab id.
func Verify(r Request, trust *keys.TrustStore, now time.Time) (string, error) {
	a, err := Parse(r.Header)
	if err != nil {
		return "", err
	}
	k, ok := trust.Lookup(a.KeyID)
	if !ok || !k.Allows(contract.PurposeRules) || k.Lab != a.Lab {
		return "", contract.Errf(contract.CodeSignature, "key %s is not a rules key of lab %s", a.KeyID, a.Lab)
	}
	m := Message(r.Method, r.Path, r.Target, a.Lab, a.KeyID, a.TS, r.BodySHA256)
	if len(a.Sig) != ed25519.SignatureSize || !ed25519.Verify(k.Public, dsse.PAE(PayloadType, m), a.Sig) {
		return "", contract.Errf(contract.CodeSignature, "signature does not verify")
	}
	ts, _ := msg.ParseTime(a.TS)
	if ts.After(now.Add(Window)) {
		return "", contract.Errf(contract.CodeClockSkew, "ts %s is in the future", a.TS)
	}
	if ts.Before(now.Add(-Window)) {
		return "", contract.Errf(contract.CodeExpired, "ts %s is older than %s", a.TS, Window)
	}
	return a.Lab, nil
}

// VerifyHTTP verifies an incoming request (body already read).
func VerifyHTTP(r *http.Request, body []byte, self string, trust *keys.TrustStore, now time.Time) (string, error) {
	return Verify(Request{Method: r.Method, Path: r.URL.Path, Target: self, BodySHA256: BodyDigest(body), Header: r.Header.Get(Header)}, trust, now)
}
