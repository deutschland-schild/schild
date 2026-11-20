//go:build !release

package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"time"

	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/dsse"
	"github.com/deutschland-schild/schild/contract/logtree"
	"github.com/deutschland-schild/schild/contract/peerauth"
	"github.com/deutschland-schild/schild/contract/testkeys"
	"github.com/deutschland-schild/schild/contract/vectors"
)

// ---- v0.1: public log tree (RFC 6962) ----

func logEntries(n int) []logtree.Entry {
	kinds := []string{"proposal", "checkpoint", "bundle", "withdrawal"}
	out := make([]logtree.Entry, n)
	for i := range out {
		k := kinds[i%len(kinds)]
		d := sha256.Sum256([]byte("schild/vector-log/" + string(rune('a'+i%26)) + strings.Repeat("x", i)))
		e := logtree.Entry{Index: uint64(i), Time: ts(time.Duration(i-n) * time.Minute), Kind: k, Ref: refFor(k, i),
			Digest: "sha256:" + hex.EncodeToString(d[:]), Summary: summaryFor(k, i)}
		if k != "proposal" {
			h := sha256.Sum256([]byte("schild/vector-envelope/" + e.Ref))
			s := "sha256:" + hex.EncodeToString(h[:])
			e.EnvelopeSHA256 = &s
		}
		out[i] = e
	}
	return out
}

func refFor(kind string, i int) string {
	switch kind {
	case "proposal":
		return "prop-" + pad4(i+1)
	default:
		return itoa(i + 1)
	}
}

func summaryFor(kind string, i int) string {
	switch kind {
	case "proposal":
		return "proposal prop-" + pad4(i+1) + " approved: rule schild-2026-" + pad4(i+1) + " virtual_patch, max challenge, approvals from 2 organisations"
	case "checkpoint":
		return "checkpoint " + itoa(i+1) + ": bundle " + itoa(i/4) + ", withdrawal 0"
	case "bundle":
		return "bundle " + itoa(i+1) + " published: 1 rules, 3 operators"
	}
	return "withdrawal " + itoa(i+1) + " effective: scope all, up to bundle " + itoa(i)
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for ; i > 0; i /= 10 {
		b = append([]byte{byte('0' + i%10)}, b...)
	}
	return string(b)
}

func pad4(i int) string { s := itoa(i); return strings.Repeat("0", max(0, 4-len(s))) + s }

func rootOf(es []logtree.Entry) string {
	var f logtree.Frontier
	for _, e := range es {
		f.Append(logtree.LeafHash(logtree.LeafData(e)))
	}
	return logtree.Format(f.Root())
}

func logDoc(es []logtree.Entry, size int, root string) map[string]any {
	items := make([]any, len(es))
	for i, e := range es {
		m := map[string]any{"index": e.Index, "time": e.Time, "kind": e.Kind, "ref": e.Ref, "digest": e.Digest, "summary": e.Summary, "envelope_sha256": nil}
		if e.EnvelopeSHA256 != nil {
			m["envelope_sha256"] = *e.EnvelopeSHA256
		}
		items[i] = m
	}
	return map[string]any{"entries": items, "head": map[string]any{"size": size, "root": root}}
}

func genLogTree(g *gen) {
	const c = "log-tree"
	ctx := vectors.Context{}
	add := func(valid bool, code contract.Code, name, desc string, m map[string]any) {
		g.add(c, name, valid, code, desc, ctx, mustJSON(m), nil)
	}
	for _, n := range []int{0, 1, 2, 3, 8, 13} {
		es := logEntries(n)
		add(true, "", "size-"+itoa(n), "RFC 6962 tree hash over "+itoa(n)+" leaves matches the signed head.", logDoc(es, n, rootOf(es)))
	}

	es := logEntries(5)
	root := rootOf(es)
	add(false, contract.CodeLogRoot, "wrong-root", "Head root of another log.", logDoc(es, 5, rootOf(logEntries(6)[:5][:4])))
	add(false, contract.CodeSchema, "size-mismatch", "Head names 6 entries, the copy has 5.", logDoc(es, 6, root))
	gap := append(append([]logtree.Entry{}, es[:2]...), es[3:]...)
	add(false, contract.CodeSchema, "index-gap", "Entry 2 is missing.", logDoc(gap, 4, rootOf(gap)))
	add(false, contract.CodeSchema, "not-from-zero", "The copy must start at index 0.", logDoc(es[1:], 4, rootOf(es[1:])))
	swapped := append([]logtree.Entry{}, es...)
	swapped[1], swapped[2] = swapped[2], swapped[1]
	add(false, contract.CodeSchema, "reordered", "Entries out of order.", logDoc(swapped, 5, root))
	changed := append([]logtree.Entry{}, es...)
	changed[3].Summary = "bundle 4 published: 2 rules, 3 operators"
	add(false, contract.CodeLogRoot, "summary-changed", "A summary changed after the head was signed.", logDoc(changed, 5, root))
	dropped := append([]logtree.Entry{}, es...)
	dropped[2].EnvelopeSHA256 = nil
	add(false, contract.CodeLogRoot, "envelope-hash-dropped", "The envelope hash of a bundle entry was removed.", logDoc(dropped, 5, root))
	// A head computed as the v0 hash chain (sha256(prev || leaf)) is not the tree hash.
	prev := logtree.EmptyRoot()
	for _, e := range es {
		h := sha256.New()
		h.Write(prev[:])
		lh := sha256.Sum256(logtree.LeafData(e))
		h.Write(lh[:])
		copy(prev[:], h.Sum(nil))
	}
	add(false, contract.CodeLogRoot, "hash-chain-root", "A v0 hash-chain head is not the RFC 6962 root.", logDoc(es, 5, logtree.Format(prev)))
	// Leaves hashed without the 0x00 prefix (second-preimage protection missing).
	var raw []logtree.Hash
	for _, e := range es {
		raw = append(raw, sha256.Sum256(logtree.LeafData(e)))
	}
	add(false, contract.CodeLogRoot, "no-leaf-prefix", "Leaf hashes without the 0x00 prefix.", logDoc(es, 5, logtree.Format(logtree.Root(raw))))
	m := logDoc(es, 5, root)
	m["entries"].([]any)[0].(map[string]any)["kind"] = "signal"
	add(false, contract.CodeSchema, "unknown-kind", "Unknown entry kind.", m)
	m = logDoc(es, 5, root)
	m["entries"].([]any)[0].(map[string]any)["summary"] = "line one\nline two"
	add(false, contract.CodeSchema, "summary-newline", "Summaries are one line of printable ASCII.", m)
	m = logDoc(es, 5, root)
	m["entries"].([]any)[0].(map[string]any)["site"] = "shop.example"
	add(false, contract.CodeSchema, "extra-field", "Unknown entry field.", m)
	m = logDoc(es, 5, "sha256:"+strings.Repeat("A", 64))
	add(false, contract.CodeSchema, "root-format", "Root must be lower-case sha256 hex.", m)
	m = logDoc(es[:1], 1, rootOf(es[:1]))
	m["entries"].([]any)[0].(map[string]any)["envelope_sha256"] = "sha256:abc"
	add(false, contract.CodeSchema, "envelope-hash-format", "Envelope hash must be sha256 hex or null.", m)
	dup := strings.Replace(string(mustJSON(logDoc(es[:1], 1, rootOf(es[:1])))), `"head":{`, `"head":{"size":2,`, 1)
	g.add(c, "duplicate-key", false, contract.CodeMalformed, "Duplicate key in the head.", ctx, []byte(dup), nil)
}

// ---- v0.1: peer-authenticated feed requests ----

var emptyBody = peerauth.BodyDigest(nil)

func peerHeader(signer, lab, method, path, target string, body []byte, at time.Time) string {
	v, err := peerauth.Sign(testkeys.Signer(signer), lab, method, path, target, body, at)
	if err != nil {
		panic(err)
	}
	return v
}

func peerDoc(method, path, target, body, auth string) map[string]any {
	return map[string]any{"method": method, "path": path, "target": target, "body_sha256": body, "authorization": auth}
}

func genPeerRequest(g *gen) {
	const c = "peer-request"
	ctx := vectors.Context{Trust: []string{"lab-a", "lab-a2", "lab-b", "lab-c", "lab-d", "site-a"}}
	add := func(valid bool, code contract.Code, name, desc string, m map[string]any) {
		g.add(c, name, valid, code, desc, ctx, mustJSON(m), nil)
	}
	const coll = "/v0/collecting"
	body := []byte(`{"kind":"rule-bundle","digest":"sha256:` + strings.Repeat("ab", 32) + `","signature":{"keyid":"test-lab-b","sig":"AAAA"}}`)

	add(true, "", "collecting-lab-b", "lab-b asks lab-a for items to co-sign.", peerDoc("GET", coll, "lab-a", emptyBody, peerHeader("lab-b", "lab-b", "GET", coll, "lab-a", nil, Now)))
	add(true, "", "collecting-lab-c", "lab-c asks lab-a.", peerDoc("GET", coll, "lab-a", emptyBody, peerHeader("lab-c", "lab-c", "GET", coll, "lab-a", nil, Now.Add(-30*time.Second))))
	add(true, "", "collecting-to-lab-d", "lab-a asks lab-d (any configured peer may ask any other).", peerDoc("GET", coll, "lab-d", emptyBody, peerHeader("lab-a", "lab-a", "GET", coll, "lab-d", nil, Now)))
	add(true, "", "post-with-body", "A signed POST binds the body digest.", peerDoc("POST", "/v0/signatures", "lab-a", peerauth.BodyDigest(body), peerHeader("lab-b", "lab-b", "POST", "/v0/signatures", "lab-a", body, Now)))
	add(true, "", "ts-past-edge", "ts 120 s in the past is still inside the window.", peerDoc("GET", coll, "lab-a", emptyBody, peerHeader("lab-b", "lab-b", "GET", coll, "lab-a", nil, Now.Add(-120*time.Second))))
	add(true, "", "ts-future-edge", "ts 120 s in the future is still inside the window.", peerDoc("GET", coll, "lab-a", emptyBody, peerHeader("lab-c", "lab-c", "GET", coll, "lab-a", nil, Now.Add(120*time.Second))))
	add(true, "", "same-operator-lab", "lab-a2 (second lab of operator a) asks lab-b; independence is counted elsewhere.", peerDoc("GET", coll, "lab-b", emptyBody, peerHeader("lab-a2", "lab-a2", "GET", coll, "lab-b", nil, Now)))
	// v0.2 (D24): peer labs sign their stream subscription so the lab lists
	// them as kind peer_lab (dashboard Relay.kind).
	add(true, "", "stream-subscription", "v0.2: lab-b subscribes to lab-a's stream as a peer lab.", peerDoc("GET", "/v0/stream", "lab-a", emptyBody, peerHeader("lab-b", "lab-b", "GET", "/v0/stream", "lab-a", nil, Now)))

	ok := peerHeader("lab-b", "lab-b", "GET", coll, "lab-a", nil, Now)
	add(false, contract.CodeSignature, "untrusted-key", "Signed by a key the lab does not trust.", peerDoc("GET", coll, "lab-a", emptyBody, peerHeader("evil", "lab-b", "GET", coll, "lab-a", nil, Now)))
	add(false, contract.CodeSignature, "site-key", "A site key has no rules purpose.", peerDoc("GET", coll, "lab-a", emptyBody, peerHeader("site-a", "lab-b", "GET", coll, "lab-a", nil, Now)))
	add(false, contract.CodeSignature, "lab-mismatch", "Header names lab-c, the key belongs to lab-b.", peerDoc("GET", coll, "lab-a", emptyBody, peerHeader("lab-b", "lab-c", "GET", coll, "lab-a", nil, Now)))
	add(false, contract.CodeSignature, "other-target", "Signed for lab-c, replayed to lab-a.", peerDoc("GET", coll, "lab-a", emptyBody, peerHeader("lab-b", "lab-b", "GET", coll, "lab-c", nil, Now)))
	add(false, contract.CodeSignature, "other-path", "Signed for another path.", peerDoc("GET", coll, "lab-a", emptyBody, peerHeader("lab-b", "lab-b", "GET", "/v0/log", "lab-a", nil, Now)))
	add(false, contract.CodeSignature, "other-body", "Body differs from the signed digest.", peerDoc("POST", "/v0/signatures", "lab-a", peerauth.BodyDigest(append(body, ' ')), peerHeader("lab-b", "lab-b", "POST", "/v0/signatures", "lab-a", body, Now)))
	add(false, contract.CodeSignature, "keyid-swapped", "Signature of lab-b presented under the key id of lab-c.", peerDoc("GET", coll, "lab-a", emptyBody, strings.Replace(strings.Replace(ok, "keyid=test-lab-b", "keyid=test-lab-c", 1), "lab=lab-b", "lab=lab-c", 1)))
	add(false, contract.CodeExpired, "too-old", "ts 10 minutes old.", peerDoc("GET", coll, "lab-a", emptyBody, peerHeader("lab-b", "lab-b", "GET", coll, "lab-a", nil, Now.Add(-10*time.Minute))))
	add(false, contract.CodeClockSkew, "future", "ts 5 minutes in the future.", peerDoc("GET", coll, "lab-a", emptyBody, peerHeader("lab-b", "lab-b", "GET", coll, "lab-a", nil, Now.Add(5*time.Minute))))
	add(false, contract.CodeMalformed, "wrong-version", "Unknown header version.", peerDoc("GET", coll, "lab-a", emptyBody, strings.Replace(ok, "v1 ", "v2 ", 1)))
	parts := strings.Split(ok, " ")
	add(false, contract.CodeMalformed, "token-order", "Tokens in another order.", peerDoc("GET", coll, "lab-a", emptyBody, strings.Join([]string{parts[0], parts[2], parts[1], parts[3], parts[4]}, " ")))
	add(false, contract.CodeMalformed, "missing-token", "Signature token missing.", peerDoc("GET", coll, "lab-a", emptyBody, strings.Join(parts[:4], " ")))
	sig, _ := dsse.DecodeBase64(strings.TrimPrefix(parts[4], "sig="))
	b64 := base64.StdEncoding.EncodeToString(sig)
	nonCanon := b64[:len(b64)-3] + string(nonCanonical(b64[len(b64)-3])) + "=="
	add(false, contract.CodeMalformed, "non-canonical-sig", "Non-canonical base64 (padding bits set).", peerDoc("GET", coll, "lab-a", emptyBody, strings.Join(append(parts[:4:4], "sig="+nonCanon), " ")))
	add(false, contract.CodeSchema, "ts-format", "ts must be RFC 3339 UTC with Z and whole seconds.", peerDoc("GET", coll, "lab-a", emptyBody, strings.Replace(ok, "ts="+Now.Format("2006-01-02T15:04:05Z"), "ts=2026-10-26T12:00:00.5Z", 1)))
	add(false, contract.CodeSchema, "method", "Only GET and POST.", peerDoc("DELETE", coll, "lab-a", emptyBody, ok))
	m := peerDoc("GET", coll, "lab-a", emptyBody, ok)
	delete(m, "body_sha256")
	add(false, contract.CodeSchema, "missing-field", "body_sha256 is required.", m)
	add(false, contract.CodeSignature, "stream-signature-at-collecting", "v0.2: a stream subscription signature presented at /v0/collecting.", peerDoc("GET", coll, "lab-a", emptyBody, peerHeader("lab-b", "lab-b", "GET", "/v0/stream", "lab-a", nil, Now)))
}

// nonCanonical returns a base64 character that decodes to the same 6 bits'
// top 2 bits but sets padding bits (for a string ending in "x==").
func nonCanonical(c byte) byte {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	i := strings.IndexByte(alphabet, c)
	return alphabet[(i&^0x0f)|0x01]
}
