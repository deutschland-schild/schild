//go:build !release

package main

import (
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/dsse"
	"github.com/deutschland-schild/schild/contract/msg"
	"github.com/deutschland-schild/schild/contract/testkeys"
	"github.com/deutschland-schild/schild/contract/vectors"
)

func baseSignal(name string) msg.Signal {
	return msg.Signal{
		Schema:     msg.SchemaSignal,
		ID:         uuid("signal-" + name),
		Kind:       "tip",
		TimeBucket: ts(-5 * time.Minute),
		ActionSig:  "login-burst/wp-admin",
		RequestSig: msg.RequestSig(msg.RequestShape{Method: "POST", PathTemplate: "/wp-login.php", ParamNames: []string{"log", "pwd", "wp-submit"}, ContentType: "application/x-www-form-urlencoded", RuleIDs: []int{930120, 949110}}),
		WAFRules:   []int{930120, 949110},
		Score:      72,
		Category:   "wordpress-login-bruteforce",
		Origin:     msg.Origin{Country: "NL", ASN: 14061, NetClass: "hosting", Attribution: "tcp_peer", Protected: false},
		Agent:      msg.Agent{Family: "python-requests", Major: 2, Bot: false},
	}
}

func baseFeedback(name string) msg.Feedback {
	return msg.Feedback{
		Schema:        msg.SchemaFeedback,
		ID:            uuid("feedback-" + name),
		TimeBucket:    ts(-10 * time.Minute),
		RuleID:        "schild-2026-0412",
		BundleVersion: 42,
		Verdict:       "false_positive",
		DecidedBy:     "operator",
		LocalAction:   "suspended",
		MatchShape:    msg.MatchShape{Location: "ARGS:text", ContentType: "application/json", LenBucket: "256-1k"},
	}
}

func genEnvelope(g *gen) {
	const c = "envelope"
	ctx := func() vectors.Context { x := ctxDefault(); x.Kind = string(contract.KindSignal); return x }
	p := mustJSON(baseSignal("env"))
	pt := contract.KindSignal.PayloadType()

	g.valid(c, "single-signature", "DSSE envelope with one valid Ed25519 signature over PAE.", ctx(), signed(contract.KindSignal, p, "site-a"), decodedOf(p))
	// Multi-signature envelopes: kinds other than signal and feedback.
	ackCtx := func() vectors.Context { x := ctxDefault(); x.Kind = string(contract.KindAck); return x }
	ap := mustJSON(baseAck("env"))
	apt := contract.KindAck.PayloadType()
	e := sign(apt, ap, "evil", "lab-a")
	g.valid(c, "untrusted-plus-trusted", "An untrusted signature is ignored as long as one trusted signature verifies (ack).", ackCtx(), envBytes(e), decodedOf(ap))
	e = sign(apt, ap, "lab-a")
	e.Signatures = append([]dsse.Signature{{KeyID: "unknown-key", Sig: e.Signatures[0].Sig}}, e.Signatures...)
	g.valid(c, "unknown-keyid-ignored", "A signature with an unknown keyid is ignored (ack).", ackCtx(), envBytes(e), decodedOf(ap))
	e = sign(apt, ap, "lab-a")
	e.Signatures = append(e.Signatures, e.Signatures[0])
	g.valid(c, "duplicate-signature", "The same signature twice counts once and is harmless (ack).", ackCtx(), envBytes(e), decodedOf(ap))
	e = sign(apt, ap, "lab-a", "lab-b")
	g.valid(c, "two-lab-signatures", "Two trusted signatures; one of them belongs to the lab named in the ack.", ackCtx(), envBytes(e), decodedOf(ap))
	raw := signed(contract.KindSignal, p, "site-a")
	g.valid(c, "whitespace", "Insignificant JSON whitespace around the envelope is allowed.", ctx(), []byte("\n  "+string(raw)+"  \n"), decodedOf(p))

	good := string(signed(contract.KindSignal, p, "site-a"))
	g.invalid(c, "top-level-array", contract.CodeMalformed, "Top level must be an object.", ctx(), []byte("["+good+"]"), nil)
	g.invalid(c, "not-json", contract.CodeMalformed, "Not JSON at all.", ctx(), []byte("payloadType=signal"), nil)
	g.invalid(c, "duplicate-key", contract.CodeMalformed, "Duplicate key payloadType (parsers that keep the last value could be tricked).", ctx(),
		[]byte(strings.Replace(good, `{"payloadType":`, `{"payloadType":"application/vnd.schild.feedback.v0+json","payloadType":`, 1)), nil)
	g.invalid(c, "trailing-data", contract.CodeMalformed, "Data after the envelope.", ctx(), []byte(good+`{}`), nil)
	m := toMap(sign(pt, p, "site-a"))
	m["note"] = "hello"
	g.invalid(c, "extra-field", contract.CodeEnvelope, "Unknown envelope field.", ctx(), mustJSON(m), nil)
	e = sign(pt, p, "site-a")
	e.Signatures = nil
	m = toMap(e)
	m["signatures"] = []any{}
	g.invalid(c, "no-signatures", contract.CodeEnvelope, "Empty signature list.", ctx(), mustJSON(m), nil)
	pp := p
	for len(pp)%3 != 1 {
		pp = append(append([]byte(nil), pp...), ' ')
	}
	e = sign(pt, pp, "site-a")
	e.Payload = strings.TrimRight(e.Payload, "=")
	g.invalid(c, "unpadded-base64", contract.CodeEnvelope, "Payload base64 without padding.", ctx(), envBytes(e), nil)
	e = sign(pt, p, "site-a")
	e.Payload = base64.URLEncoding.EncodeToString([]byte{0xfb, 0xff, 0xfe})
	g.invalid(c, "urlsafe-base64", contract.CodeEnvelope, "URL-safe base64 alphabet.", ctx(), envBytes(e), nil)
	e = sign(pt, []byte("A"), "site-a")
	e.Payload = "QR==" // non-zero padding bits: decodes to "A" in lax decoders
	g.invalid(c, "non-canonical-base64", contract.CodeEnvelope, "Non-canonical base64 (padding bits set) must be rejected.", ctx(), envBytes(e), nil)
	e = sign(pt, p, "site-a")
	e.Signatures[0].Sig = e.Signatures[0].Sig[:84] + "A=="
	g.invalid(c, "short-signature", contract.CodeEnvelope, "Signature of the wrong length.", ctx(), envBytes(e), nil)
	e = sign(pt, p, "site-a")
	e.Signatures[0].KeyID = "Site A"
	g.invalid(c, "bad-keyid", contract.CodeEnvelope, "keyid with characters outside the allowed set.", ctx(), envBytes(e), nil)
	e = sign("application/json", p, "site-a")
	g.invalid(c, "generic-payload-type", contract.CodeEnvelope, "payloadType outside the Schild namespace.", ctx(), envBytes(e), nil)
	e = sign(contract.KindFeedback.PayloadType(), p, "site-a")
	g.invalid(c, "wrong-payload-type", contract.CodePayloadType, "Signal payload signed under the feedback payloadType (domain separation).", ctx(), envBytes(e), decodedOf(p))
	g.invalid(c, "wrong-key", contract.CodeSignature, "Signed only by an untrusted key.", ctx(), signed(contract.KindSignal, p, "evil"), decodedOf(p))
	e = sign(pt, p, "site-b", "site-c")
	g.invalid(c, "signal-two-signatures", contract.CodeEnvelope, "A signal has exactly one sender: two site signatures (two issuers) would make the tip count twice.", ctx(), envBytes(e), decodedOf(p))
	e = sign(pt, p, "evil", "site-a")
	g.invalid(c, "signal-untrusted-plus-trusted", contract.CodeEnvelope, "Also an extra untrusted signature makes a signal envelope invalid.", ctx(), envBytes(e), decodedOf(p))
	e = sign(pt, p, "site-a")
	e.Signatures[0].KeyID = "test-site-b"
	g.invalid(c, "keyid-relabelled", contract.CodeSignature, "keyid is binding: a valid site-a signature labelled with the key id of site-b does not verify (no trial verification against other keys).", ctx(), envBytes(e), decodedOf(p))
	e = sign(pt, p, "site-a")
	rawSig := testkeys.Signer("site-a")
	sig, _ := rawSig.Sign(p) // signature over the raw payload instead of PAE
	e.Signatures[0].Sig = base64.StdEncoding.EncodeToString(sig)
	g.invalid(c, "signature-without-pae", contract.CodeSignature, "Signature over the raw payload instead of PAE(payloadType, payload).", ctx(), envBytes(e), decodedOf(p))
	e = sign(pt, p, "site-a")
	other := sign(pt, mustJSON(baseSignal("other")), "site-a")
	e.Signatures = other.Signatures
	g.invalid(c, "signature-of-other-payload", contract.CodeSignature, "Valid signature, but over a different payload.", ctx(), envBytes(e), decodedOf(p))
	g.invalid(c, "key-wrong-purpose", contract.CodeSignature, "Signed by a trusted lab key that may not sign signals.", ctx(), signed(contract.KindSignal, p, "lab-a"), decodedOf(p))
	x := ctx()
	x.Trust = []string{"site-b"}
	g.invalid(c, "key-not-in-trust", contract.CodeSignature, "Signer is a test key that this context does not trust.", x, signed(contract.KindSignal, p, "site-a"), decodedOf(p))
}

func genSignal(g *gen) {
	const c = "signal"
	k := contract.KindSignal
	base := func(n string) map[string]any { return toMap(baseSignal(n)) }
	sg := func(m any, signer string) []byte { return signed(k, mustJSON(m), signer) }

	s := base("minimal")
	g.valid(c, "minimal", "All required positive-list fields, no ja4.", ctxDefault(), sg(s, "site-a"), decodedOf(mustJSON(s)))
	s = base("ja4")
	s["ja4"] = "t13d1516h2_8daaf6152771_e5627efa2ab1"
	g.valid(c, "with-ja4", "Optional JA4 fingerprint (prototype and alpha only).", ctxDefault(), sg(s, "site-b"), decodedOf(mustJSON(s)))
	s = base("mobile")
	set(s, "time_bucket", ts(-15*time.Minute))
	set(s, "origin", map[string]any{"country": "DE", "asn": 3320, "net_class": "mobile", "attribution": "trusted_proxy", "protected": true})
	set(s, "agent", map[string]any{"family": "chrome", "major": 130, "bot": false})
	set(s, "action_sig", "sqli/rest-api")
	set(s, "category", "sql-injection")
	set(s, "waf_rules", []int{942100})
	set(s, "score", 100)
	g.valid(c, "mobile-protected", "Mobile network behind a trusted proxy, sender on the protection list.", ctxDefault(), sg(s, "site-c"), decodedOf(mustJSON(s)))
	s = base("old")
	set(s, "time_bucket", ts(-23*time.Hour-55*time.Minute))
	g.valid(c, "almost-too-old", "time_bucket 23h55m old, inside the 24 h window.", ctxDefault(), sg(s, "site-a"), decodedOf(mustJSON(s)))
	x := ctxDefault()
	x.Now = ts(-1 * time.Minute)
	s = base("skew")
	set(s, "time_bucket", ts(0))
	g.valid(c, "within-clock-skew", "Bucket starts 60 s after the verifier clock: inside the 120 s skew.", x, sg(s, "site-a"), decodedOf(mustJSON(s)))
	s = base("float-int")
	raw := strings.Replace(string(mustJSON(s)), `"score":72`, `"score":72.0`, 1)
	g.valid(c, "integral-float", "score written as 72.0 is an integer in JSON Schema; both implementations must accept it.", ctxDefault(), signed(k, []byte(raw), "site-a"), decodedOf([]byte(raw)))
	s = base("asn-32bit")
	set(s, "origin", map[string]any{"country": "DE", "asn": 213230, "net_class": "residential", "attribution": "tcp_peer", "protected": false})
	set(s, "waf_rules", []int{920350, 930120, 949110})
	g.valid(c, "asn-32bit-sorted-rules", "32-bit ASN and three rule ids in ascending order.", ctxDefault(), sg(s, "site-b"), decodedOf(mustJSON(s)))
	x = ctxDefault()
	x.SeenIDs = []string{uuid("signal-something-else")}
	s = base("unseen")
	g.valid(c, "not-a-replay", "A different id was seen before; this one is new.", x, sg(s, "site-a"), decodedOf(mustJSON(s)))

	// invalid
	s = base("big")
	pad := strings.Repeat(" ", 17*1024)
	g.invalid(c, "oversize-envelope", contract.CodeOversize, "Envelope larger than 16 KiB.", ctxDefault(), []byte(string(sg(s, "site-a"))+pad), nil)
	big := strings.Replace(string(mustJSON(s)), `{"`, "{"+strings.Repeat(" ", 4200)+`"`, 1)
	g.invalid(c, "oversize-payload", contract.CodeOversize, "Decoded payload larger than 4 KiB.", ctxDefault(), signed(k, []byte(big), "site-a"), nil)
	g.invalid(c, "wrong-key", contract.CodeSignature, "Signed by an untrusted key.", ctxDefault(), sg(base("evil"), "evil"), decodedOf(mustJSON(base("evil"))))
	g.invalid(c, "wrong-payload-type", contract.CodePayloadType, "Signal signed as feedback.", ctxDefault(), signed(contract.KindFeedback, mustJSON(base("pt")), "site-a"), nil)
	g.invalid(c, "payload-not-json", contract.CodeMalformed, "Signed payload is not JSON.", ctxDefault(), signed(k, []byte("ip=203.0.113.7"), "site-a"), nil)
	dup := strings.Replace(string(mustJSON(base("dup"))), `{"`, `{"score":0,"`, 1)
	g.invalid(c, "payload-duplicate-key", contract.CodeMalformed, "Duplicate key score inside the signed payload.", ctxDefault(), signed(k, []byte(dup), "site-a"), nil)
	lone := strings.Replace(string(mustJSON(base("lone"))), `"wordpress-login-bruteforce"`, `"x\ud800"`, 1)
	g.invalid(c, "lone-surrogate", contract.CodeMalformed, "Escaped lone UTF-16 surrogate in a string.", ctxDefault(), signed(k, []byte(lone), "site-a"), nil)
	deep := `{"waf_rules":` + strings.Repeat("[", 40) + strings.Repeat("]", 40) + `}`
	g.invalid(c, "payload-too-deep", contract.CodeMalformed, "Nesting deeper than 32 levels.", ctxDefault(), signed(k, []byte(deep), "site-a"), nil)
	g.invalid(c, "bom", contract.CodeMalformed, "UTF-8 byte order mark before the envelope.", ctxDefault(), append([]byte("\xef\xbb\xbf"), sg(base("bom"), "site-a")...), nil)
	for _, f := range []struct {
		name, path string
		val        any
		desc       string
	}{
		{"ip", "ip", "203.0.113.7", "Visitor IP: never part of a signal (E4)."},
		{"ip-hash", "ip_hash", "sha256:" + strings.Repeat("ab", 32), "Hashed IP: still personal data, never allowed."},
		{"ip-prefix-nested", "origin.ip_prefix", "203.0.113.0/24", "Truncated IP nested in origin."},
		{"url", "url", "https://shop.example/login?user=alice", "URL with query string."},
		{"host", "host", "shop.example", "Hostname of the site (site identifier)."},
		{"user-agent", "User-Agent", "Mozilla/5.0 (X11; Linux x86_64)", "Full user agent, any capitalisation."},
		{"cookies", "cookies", map[string]any{"session": "abc"}, "Cookies."},
		{"site-id", "site_id", "site-123", "Site identifier."},
		{"client-ip-camel", "clientIp", "203.0.113.7", "camelCase spelling: keys are compared without case, '-', '_' and '.'."},
		{"x-real-ip-nested", "agent.X-Real-IP", "203.0.113.7", "Proxy header name nested in agent."},
		{"referer", "referer", "https://shop.example/", "Referer carries the site's host."},
		{"keyid", "key_id", "test-site-a", "Key id inside the payload (the sender is identified by the envelope only)."},
	} {
		s = base("forbidden-" + f.name)
		set(s, f.path, f.val)
		g.invalid(c, "forbidden-"+f.name, contract.CodeForbiddenField, f.desc, ctxDefault(), sg(s, "site-a"), decodedOf(mustJSON(s)))
	}
	s = base("forbidden-dotted-key")
	s["origin"].(map[string]any)["Client.IP"] = "203.0.113.7"
	g.invalid(c, "forbidden-dotted-key", contract.CodeForbiddenField, "Dotted, mixed-case key Client.IP nested in origin.", ctxDefault(), sg(s, "site-a"), decodedOf(mustJSON(s)))
	s = base("forbidden-in-array")
	set(s, "waf_rules", []any{930120, map[string]any{"ip": "203.0.113.7"}})
	g.invalid(c, "forbidden-in-array", contract.CodeForbiddenField, "Forbidden key inside an object smuggled into an array.", ctxDefault(), sg(s, "site-a"), decodedOf(mustJSON(s)))
	for _, f := range []struct {
		name string
		mut  func(map[string]any)
		desc string
	}{
		{"unknown-field", func(m map[string]any) { m["extra"] = 1 }, "Unknown field: positive list, never ignored."},
		{"unicode-key-ip", func(m map[string]any) { m["\u0131p"] = "203.0.113.7" }, "Key with a dotless i: only ASCII is case-folded, so it is not on the forbidden list, but it is not on the positive list either (schema)."},
		{"asn-ipv4-integer", func(m map[string]any) { m["origin"].(map[string]any)["asn"] = 3405803783 }, "203.0.113.7 written as an integer in the asn field."},
		{"action-sig-hash", func(m map[string]any) { m["action_sig"] = "sqli/" + strings.Repeat("ab", 32) }, "A hash (for example of an IP) hidden in action_sig."},
		{"action-sig-decimal-ip", func(m map[string]any) { m["action_sig"] = "probe/3405803783" }, "IPv4 as decimal number in action_sig."},
		{"action-sig-ipv6", func(m map[string]any) { m["action_sig"] = "probe/2001-db8-85a3-8a2e-370-7334" }, "Dashed IPv6 address in action_sig."},
		{"action-sig-base64", func(m map[string]any) { m["action_sig"] = "x/ywaacq==" }, "Base64 blob in action_sig."},
		{"action-sig-too-long", func(m map[string]any) { m["action_sig"] = "probe/" + strings.Repeat("a", 59) }, "action_sig longer than 64 characters."},
		{"category-hex", func(m map[string]any) { m["category"] = "scan-deadbeefcafe" }, "Hex blob in category."},
		{"category-oversized", func(m map[string]any) { m["category"] = strings.Repeat("a", 2000) }, "Oversized string."},
		{"agent-family-ip", func(m map[string]any) { m["agent"].(map[string]any)["family"] = "203.0.113.7" }, "IP address as agent family."},
		{"agent-family-host", func(m map[string]any) { m["agent"].(map[string]any)["family"] = "shop.example" }, "Host name as agent family (no dots)."},
		{"agent-family-hex", func(m map[string]any) { m["agent"].(map[string]any)["family"] = "c0a80001ff" }, "Hex blob as agent family."},
		{"waf-rules-unsorted", func(m map[string]any) { m["waf_rules"] = []int{949110, 930120} }, "waf_rules out of order (the order would be a side channel; canonical is ascending)."},
		{"missing-origin", func(m map[string]any) { delete(m, "origin") }, "Required field missing."},
		{"score-string", func(m map[string]any) { m["score"] = "72" }, "Wrong type."},
		{"score-range", func(m map[string]any) { m["score"] = 101 }, "Score outside 0..100."},
		{"action-sig-ip", func(m map[string]any) { m["action_sig"] = "probe/203.0.113.7" }, "IP-like value hidden in action_sig."},
		{"action-sig-query", func(m map[string]any) { m["action_sig"] = "login?user=alice" }, "Query string in action_sig."},
		{"category-ip", func(m map[string]any) { m["category"] = "scan-192-0-2-1" }, "IP-like value hidden in category."},
		{"bucket-unaligned", func(m map[string]any) { m["time_bucket"] = ts(-3 * time.Minute) }, "time_bucket not on a 5-minute boundary."},
		{"bucket-seconds", func(m map[string]any) { m["time_bucket"] = ts(-5*time.Minute + 7*time.Second) }, "time_bucket with seconds."},
		{"bucket-invalid-date", func(m map[string]any) { m["time_bucket"] = "2026-02-30T10:00:00Z" }, "Impossible date."},
		{"kind-evidence", func(m map[string]any) { m["kind"] = "evidence" }, "Clients only send tips; evidence comes from labs."},
		{"country-lowercase", func(m map[string]any) { m["origin"].(map[string]any)["country"] = "nl" }, "Country not upper case."},
		{"attribution-header", func(m map[string]any) { m["origin"].(map[string]any)["attribution"] = "x_forwarded_for" }, "Untrusted attribution never produces a signal (G5)."},
		{"waf-rules-empty", func(m map[string]any) { m["waf_rules"] = []int{} }, "No rule ids."},
		{"agent-extra", func(m map[string]any) { m["agent"].(map[string]any)["version"] = "2.31.0" }, "Full version instead of major only."},
		{"ja4-malformed", func(m map[string]any) { m["ja4"] = "not-a-ja4" }, "Malformed JA4."},
		{"schema-version", func(m map[string]any) { m["schema"] = "schild.signal/0.2" }, "Old signal format (0.2 had IP fields)."},
		{"id-not-uuid", func(m map[string]any) { m["id"] = "1" }, "id must be a random UUID v4."},
	} {
		s = base(f.name)
		f.mut(s)
		g.invalid(c, f.name, contract.CodeSchema, f.desc, ctxDefault(), sg(s, "site-a"), decodedOf(mustJSON(s)))
	}
	s = base("future")
	set(s, "time_bucket", ts(10*time.Minute))
	g.invalid(c, "clock-skew", contract.CodeClockSkew, "time_bucket 10 minutes in the future.", ctxDefault(), sg(s, "site-a"), decodedOf(mustJSON(s)))
	s = base("expired")
	set(s, "time_bucket", ts(-48*time.Hour))
	g.invalid(c, "expired", contract.CodeExpired, "time_bucket older than 24 h.", ctxDefault(), sg(s, "site-a"), decodedOf(mustJSON(s)))
	s = base("replay")
	x = ctxDefault()
	x.SeenIDs = []string{s["id"].(string)}
	g.invalid(c, "replay", contract.CodeReplay, "Same signal id submitted again.", x, sg(s, "site-a"), decodedOf(mustJSON(s)))
}

func genFeedback(g *gen) {
	const c = "feedback"
	k := contract.KindFeedback
	base := func(n string) map[string]any { return toMap(baseFeedback(n)) }
	sg := func(m any, signer string) []byte { return signed(k, mustJSON(m), signer) }

	f := base("basic")
	g.valid(c, "suspended", "Operator marked a network rule as false positive and suspended it locally.", ctxDefault(), sg(f, "site-a"), decodedOf(mustJSON(f)))
	f = base("shadow")
	f["local_action"] = "shadow"
	f["match_shape"] = map[string]any{"location": "REQUEST_COOKIES_NAMES", "len_bucket": "0-16"}
	g.valid(c, "shadow-no-content-type", "Shadow locally; content_type is optional.", ctxDefault(), sg(f, "site-b"), decodedOf(mustJSON(f)))
	f = base("unchanged")
	f["local_action"] = "unchanged"
	f["match_shape"] = map[string]any{"location": "REQUEST_HEADERS:Referer", "content_type": "none", "len_bucket": "64-256"}
	g.valid(c, "unchanged", "Feedback without local change.", ctxDefault(), sg(f, "site-c"), decodedOf(mustJSON(f)))
	f = base("multipart")
	f["match_shape"] = map[string]any{"location": "FILES:upload", "content_type": "multipart/form-data", "len_bucket": "16k+"}
	f["bundle_version"] = 1
	g.valid(c, "multipart", "Match in an uploaded file name.", ctxDefault(), sg(f, "site-a"), decodedOf(mustJSON(f)))
	f = base("old")
	f["time_bucket"] = ts(-20 * time.Hour)
	g.valid(c, "twenty-hours-old", "Buffered feedback, still inside 24 h.", ctxDefault(), sg(f, "site-a"), decodedOf(mustJSON(f)))

	g.invalid(c, "oversize", contract.CodeOversize, "Envelope larger than 16 KiB.", ctxDefault(), []byte(string(sg(base("big"), "site-a"))+strings.Repeat("\n", 17*1024)), nil)
	g.invalid(c, "wrong-key", contract.CodeSignature, "Untrusted signer.", ctxDefault(), sg(base("evil"), "evil"), nil)
	g.invalid(c, "lab-key", contract.CodeSignature, "Labs do not send feedback.", ctxDefault(), sg(base("lab"), "lab-b"), nil)
	g.invalid(c, "wrong-payload-type", contract.CodePayloadType, "Feedback signed as signal.", ctxDefault(), signed(contract.KindSignal, mustJSON(base("pt")), "site-a"), nil)
	f = base("content")
	f["match_shape"].(map[string]any)["value"] = "SELECT * FROM users"
	g.invalid(c, "match-content", contract.CodeSchema, "Matched content is never sent, only its shape.", ctxDefault(), sg(f, "site-a"), decodedOf(mustJSON(f)))
	f = base("automatic")
	f["decided_by"] = "auto"
	g.invalid(c, "not-operator", contract.CodeSchema, "Only a human operator creates feedback (K6).", ctxDefault(), sg(f, "site-a"), decodedOf(mustJSON(f)))
	f = base("verdict")
	f["verdict"] = "true_positive"
	g.invalid(c, "verdict", contract.CodeSchema, "Only false_positive feedback exists.", ctxDefault(), sg(f, "site-a"), decodedOf(mustJSON(f)))
	f = base("location")
	f["match_shape"].(map[string]any)["location"] = "REMOTE_ADDR"
	g.invalid(c, "location", contract.CodeSchema, "Location outside the allowed variables.", ctxDefault(), sg(f, "site-a"), decodedOf(mustJSON(f)))
	f = base("location-ip")
	f["match_shape"].(map[string]any)["location"] = "ARGS:203.0.113.7"
	g.invalid(c, "location-ip", contract.CodeSchema, "Address-like parameter name in the match location.", ctxDefault(), sg(f, "site-a"), decodedOf(mustJSON(f)))
	f = base("two-signers")
	g.invalid(c, "two-signatures", contract.CodeEnvelope, "Feedback has exactly one sender.", ctxDefault(), signed(k, mustJSON(f), "site-a", "site-b"), nil)
	f = base("rule")
	f["rule_id"] = "942100"
	g.invalid(c, "rule-id", contract.CodeSchema, "Feedback is about network rules only.", ctxDefault(), sg(f, "site-a"), decodedOf(mustJSON(f)))
	f = base("email")
	f["email"] = "admin@shop.example"
	g.invalid(c, "forbidden-email", contract.CodeForbiddenField, "Contact data never leaves the server.", ctxDefault(), sg(f, "site-a"), decodedOf(mustJSON(f)))
	f = base("query")
	f["match_shape"].(map[string]any)["query"] = "q=1"
	g.invalid(c, "forbidden-nested-query", contract.CodeForbiddenField, "Forbidden field nested in match_shape.", ctxDefault(), sg(f, "site-a"), decodedOf(mustJSON(f)))
	f = base("future")
	f["time_bucket"] = ts(5 * time.Minute)
	g.invalid(c, "clock-skew", contract.CodeClockSkew, "time_bucket 5 minutes in the future.", ctxDefault(), sg(f, "site-a"), decodedOf(mustJSON(f)))
	f = base("expired")
	f["time_bucket"] = ts(-25 * time.Hour)
	g.invalid(c, "expired", contract.CodeExpired, "Older than 24 h.", ctxDefault(), sg(f, "site-a"), decodedOf(mustJSON(f)))
	f = base("replay")
	x := ctxDefault()
	x.SeenIDs = []string{f["id"].(string)}
	g.invalid(c, "replay", contract.CodeReplay, "Same feedback id again.", x, sg(f, "site-a"), decodedOf(mustJSON(f)))
	g.invalid(c, "malformed", contract.CodeMalformed, "Truncated JSON.", ctxDefault(), []byte(`{"payloadType":"application/vnd.schild.feedback.v0+json","payload":`), nil)
}

func baseAck(name string) msg.Ack {
	return msg.Ack{
		Schema:    msg.SchemaAck,
		Lab:       "lab-a",
		IssuedAt:  ts(-2 * time.Second),
		InReplyTo: uuid("submission-" + name),
		Accepted:  []string{uuid("signal-1"), uuid("signal-2")},
		Duplicate: []string{},
		Rejected:  []msg.Rejected{},
		Control:   msg.Control{RetryAfterMS: 0, MaxBatch: 64, Reason: "ok"},
	}
}

func genAck(g *gen) {
	const c = "ack"
	k := contract.KindAck
	base := func(n string) map[string]any { return toMap(baseAck(n)) }
	sg := func(m any, signer string) []byte { return signed(k, mustJSON(m), signer) }

	a := base("ok")
	g.valid(c, "accepted", "Two signals durably queued.", ctxDefault(), sg(a, "lab-a"), decodedOf(mustJSON(a)))
	a = base("full")
	a["lab"] = "lab-b"
	a["accepted"] = []string{}
	a["control"] = map[string]any{"retry_after_ms": 5000, "max_batch": 16, "reason": "queue_full"}
	g.valid(c, "queue-full", "Full queue answers at once with retry_after_ms (never a timeout).", ctxDefault(), sg(a, "lab-b"), decodedOf(mustJSON(a)))
	a = base("mixed")
	a["lab"] = "lab-c"
	a["duplicate"] = []string{uuid("signal-3")}
	a["rejected"] = []any{map[string]any{"id": uuid("signal-4"), "reason": "schema"}, map[string]any{"id": msg.NilID, "reason": "malformed"}}
	g.valid(c, "mixed", "Accepted, duplicate and rejected ids.", ctxDefault(), sg(a, "lab-c"), decodedOf(mustJSON(a)))
	a = base("bound")
	x := ctxDefault()
	x.ExpectedInReplyTo = a["in_reply_to"].(string)
	g.valid(c, "bound-to-request", "in_reply_to matches the submission.", x, sg(a, "lab-a"), decodedOf(mustJSON(a)))
	a = base("rate")
	a["accepted"] = []string{}
	a["rejected"] = []any{map[string]any{"id": uuid("signal-5"), "reason": "quota"}}
	a["control"] = map[string]any{"retry_after_ms": 60000, "max_batch": 1, "reason": "rate_limited"}
	g.valid(c, "rate-limited", "Client over its rate.", ctxDefault(), sg(a, "lab-a"), decodedOf(mustJSON(a)))

	g.invalid(c, "site-key", contract.CodeSignature, "Signed by a site key, not a lab key.", ctxDefault(), sg(base("site"), "site-a"), nil)
	a = base("foreign")
	a["lab"] = "lab-b"
	g.invalid(c, "foreign-lab", contract.CodeSignature, "lab-a key signs an ack claiming to come from lab-b.", ctxDefault(), sg(a, "lab-a"), decodedOf(mustJSON(a)))
	g.invalid(c, "rules-only-key", contract.CodeSignature, "lab-d may sign rules but not acks.", ctxDefault(), sg(base("d"), "lab-d"), nil)
	g.invalid(c, "wrong-key", contract.CodeSignature, "Untrusted lab.", ctxDefault(), sg(base("evil"), "evil"), nil)
	g.invalid(c, "wrong-payload-type", contract.CodePayloadType, "Ack signed as checkpoint.", ctxDefault(), signed(contract.KindCheckpoint, mustJSON(base("pt")), "lab-a"), nil)
	a = base("noretry")
	a["control"] = map[string]any{"retry_after_ms": 0, "max_batch": 64, "reason": "queue_full"}
	g.invalid(c, "full-without-retry", contract.CodeSchema, "queue_full must carry retry_after_ms > 0.", ctxDefault(), sg(a, "lab-a"), decodedOf(mustJSON(a)))
	a = base("okretry")
	a["control"] = map[string]any{"retry_after_ms": 100, "max_batch": 64, "reason": "ok"}
	g.invalid(c, "ok-with-retry", contract.CodeSchema, "reason ok means retry_after_ms 0.", ctxDefault(), sg(a, "lab-a"), decodedOf(mustJSON(a)))
	a = base("reason")
	a["rejected"] = []any{map[string]any{"id": uuid("x"), "reason": "because"}}
	g.invalid(c, "unknown-reason", contract.CodeSchema, "Unknown rejection reason.", ctxDefault(), sg(a, "lab-a"), decodedOf(mustJSON(a)))
	a = base("many")
	var ids []string
	for i := 0; i < 257; i++ {
		ids = append(ids, uuid(fmt.Sprintf("many-%d", i)))
	}
	a["accepted"] = ids
	g.invalid(c, "too-many-ids", contract.CodeSchema, "More than 256 ids.", ctxDefault(), sg(a, "lab-a"), nil)
	a = base("future")
	a["issued_at"] = ts(10 * time.Minute)
	g.invalid(c, "clock-skew", contract.CodeClockSkew, "Ack from the future.", ctxDefault(), sg(a, "lab-a"), decodedOf(mustJSON(a)))
	a = base("old")
	a["issued_at"] = ts(-10 * time.Minute)
	g.invalid(c, "expired", contract.CodeExpired, "Ack older than 5 minutes.", ctxDefault(), sg(a, "lab-a"), decodedOf(mustJSON(a)))
	a = base("replay")
	x = ctxDefault()
	x.ExpectedInReplyTo = uuid("submission-other")
	g.invalid(c, "replay", contract.CodeReplay, "Old ack replayed for another submission.", x, sg(a, "lab-a"), decodedOf(mustJSON(a)))
	g.invalid(c, "oversize", contract.CodeOversize, "Envelope larger than 64 KiB.", ctxDefault(), []byte(string(sg(base("big"), "lab-a"))+strings.Repeat(" ", 65*1024)), nil)
}

func genSubmission(g *gen) {
	const c = "submission"
	sig := func(n string) map[string]any {
		return toMap(sign(contract.KindSignal.PayloadType(), mustJSON(baseSignal(n)), "site-a"))
	}
	fb := func(n string) map[string]any {
		return toMap(sign(contract.KindFeedback.PayloadType(), mustJSON(baseFeedback(n)), "site-a"))
	}
	sub := func(n string, envs ...any) map[string]any {
		return map[string]any{"request_id": uuid("submission-" + n), "envelopes": envs}
	}
	s := sub("one", sig("s1"))
	g.valid(c, "one-signal", "One signal envelope.", vectors.Context{}, mustJSON(s), s)
	s = sub("mixed", sig("s2"), fb("f1"), sig("s3"))
	g.valid(c, "mixed", "Signals and feedback in one request.", vectors.Context{}, mustJSON(s), s)
	var many []any
	for i := 0; i < 64; i++ {
		many = append(many, sig(fmt.Sprintf("m%d", i)))
	}
	s = sub("max", many...)
	g.valid(c, "sixty-four", "Maximum batch of 64 envelopes.", vectors.Context{}, mustJSON(s), nil)
	bad := sign(contract.KindSignal.PayloadType(), mustJSON(baseSignal("x")), "evil")
	s = sub("untrusted", toMap(bad))
	g.valid(c, "untrusted-inner", "The submission schema does not verify signatures; the lab rejects that envelope in the ack.", vectors.Context{}, mustJSON(s), s)
	s = sub("feedback", fb("f2"))
	g.valid(c, "feedback-only", "Feedback only.", vectors.Context{}, mustJSON(s), s)

	s = sub("empty")
	s["envelopes"] = []any{}
	g.invalid(c, "empty", contract.CodeSchema, "No envelopes.", vectors.Context{}, mustJSON(s), s)
	s = sub("too-many", append(many, sig("m64"))...)
	g.invalid(c, "sixty-five", contract.CodeSchema, "More than 64 envelopes.", vectors.Context{}, mustJSON(s), nil)
	s = sub("noid", sig("n"))
	delete(s, "request_id")
	g.invalid(c, "missing-request-id", contract.CodeSchema, "request_id is required.", vectors.Context{}, mustJSON(s), s)
	s = sub("badid", sig("b"))
	s["request_id"] = "req-1"
	g.invalid(c, "bad-request-id", contract.CodeSchema, "request_id must be a UUID v4.", vectors.Context{}, mustJSON(s), s)
	s = sub("extra", sig("e"))
	s["site"] = "shop.example"
	g.invalid(c, "site-field", contract.CodeSchema, "No site identifier in the transport body.", vectors.Context{}, mustJSON(s), s)
	inner := sig("inner")
	inner["comment"] = "x"
	s = sub("inner", inner)
	g.invalid(c, "inner-extra-field", contract.CodeSchema, "Envelope with an unknown field.", vectors.Context{}, mustJSON(s), s)
	s = sub("string", "not-an-envelope")
	g.invalid(c, "string-envelope", contract.CodeSchema, "Envelope must be an object.", vectors.Context{}, mustJSON(s), s)
	g.invalid(c, "malformed", contract.CodeMalformed, "Not JSON.", vectors.Context{}, []byte(`{"request_id":`), nil)
	g.invalid(c, "array", contract.CodeMalformed, "Top level must be an object.", vectors.Context{}, []byte(`[]`), nil)
	s = sub("dup", sig("d"))
	raw := strings.Replace(string(mustJSON(s)), `{"envelopes"`, `{"request_id":"`+uuid("x")+`","envelopes"`, 1)
	g.invalid(c, "duplicate-key", contract.CodeMalformed, "Duplicate request_id.", vectors.Context{}, []byte(raw), nil)
}
