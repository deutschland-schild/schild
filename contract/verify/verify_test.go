//go:build !release

package verify

import (
	"testing"
	"time"

	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/dsse"
	"github.com/deutschland-schild/schild/contract/jsonx"
	"github.com/deutschland-schild/schild/contract/keys"
	"github.com/deutschland-schild/schild/contract/msg"
	"github.com/deutschland-schild/schild/contract/testkeys"
)

var now = time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)

func bundle(version uint64) []byte {
	b, _ := jsonx.Marshal(msg.Bundle{Schema: msg.SchemaBundle, BundleID: "schild-main", Version: version,
		IssuedAt: msg.FormatTime(now.Add(-time.Hour)), Expires: msg.FormatTime(now.Add(24 * time.Hour)), Rules: []msg.Rule{}})
	return b
}

func signedBy(kind contract.Kind, payload []byte, names ...string) []byte {
	var s []dsse.Signer
	for _, n := range names {
		s = append(s, testkeys.Signer(n))
	}
	env, _ := dsse.Sign(kind.PayloadType(), payload, s...)
	b, _ := env.Marshal()
	return b
}

func TestThresholdDefaultsAndFloor(t *testing.T) {
	for _, c := range []struct{ k, want int }{{0, 3}, {1, 2}, {2, 2}, {5, 5}} {
		if got := (&Context{Threshold: c.k}).EffectiveThreshold(); got != c.want {
			t.Errorf("k=%d -> %d, want %d", c.k, got, c.want)
		}
	}
	ts := testkeys.TrustStore("lab-a", "lab-b", "lab-c")
	raw := signedBy(contract.KindBundle, bundle(1), "lab-a", "lab-b")
	if _, err := Signed(contract.KindBundle, raw, &Context{Now: now, Trust: ts}); contract.CodeOf(err) != contract.CodeThreshold {
		t.Fatalf("default k=3 must reject two operators: %v", err)
	}
	res, err := Signed(contract.KindBundle, raw, &Context{Now: now, Trust: ts, Threshold: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Operators) != 2 || res.Value.(*msg.Bundle).Version != 1 || res.Digest != msg.Digest(bundle(1)) {
		t.Fatalf("result %+v", res)
	}
}

func TestOperatorMapping(t *testing.T) {
	ts := testkeys.TrustStore("lab-a", "lab-a2")
	raw := signedBy(contract.KindBundle, bundle(1), "lab-a", "lab-a2")
	ctx := &Context{Now: now, Trust: ts, Threshold: 2}
	if _, err := Signed(contract.KindBundle, raw, ctx); contract.CodeOf(err) != contract.CodeThreshold {
		t.Fatal("same operator counted twice")
	}
	ctx.OperatorOf = func(k *keys.TrustedKey) string { return "sim-" + k.Lab }
	if _, err := Signed(contract.KindBundle, raw, ctx); err != nil {
		t.Fatalf("simulated operators: %v", err)
	}
}

func TestRollbackStateAndSkip(t *testing.T) {
	ts := testkeys.TrustStore("lab-a", "lab-b")
	raw := signedBy(contract.KindBundle, bundle(5), "lab-a", "lab-b")
	ctx := &Context{Now: now, Trust: ts, Threshold: 2, State: State{BundleVersion: 6}}
	if _, err := Signed(contract.KindBundle, raw, ctx); contract.CodeOf(err) != contract.CodeRollback {
		t.Fatalf("rollback: %v", err)
	}
	ctx.SkipState = true
	if _, err := Signed(contract.KindBundle, raw, ctx); err != nil {
		t.Fatalf("skip state: %v", err)
	}
}

func TestReplayAndSeen(t *testing.T) {
	p, _ := jsonx.Marshal(msg.Signal{Schema: msg.SchemaSignal, ID: "0d6f3c5e-8a51-4c47-9a0e-2f1b7c9d4e10", Kind: "tip", TimeBucket: msg.TimeBucket(now, 5),
		ActionSig: "scan/env-file", RequestSig: msg.RequestSig(msg.RequestShape{Method: "GET", PathTemplate: "/.env"}), WAFRules: []int{930130},
		Score: 50, Category: "scanner", Origin: msg.Origin{Country: "ZZ", ASN: 0, NetClass: "unknown", Attribution: "tcp_peer"}, Agent: msg.Agent{Family: "other", Major: 0}})
	raw := signedBy(contract.KindSignal, p, "site-c")
	seen := map[string]bool{}
	ctx := &Context{Now: now, Trust: testkeys.TrustStore("site-c"), Seen: func(id string) bool { return seen[id] }}
	res, err := Signed(contract.KindSignal, raw, ctx)
	if err != nil {
		t.Fatal(err)
	}
	if res.Signers[0].Issuer != "issuer-test-2" {
		t.Fatal("issuer")
	}
	seen[res.Value.(*msg.Signal).ID] = true
	if _, err := Signed(contract.KindSignal, raw, ctx); contract.CodeOf(err) != contract.CodeReplay {
		t.Fatalf("replay: %v", err)
	}
}

// A context without a trust store trusts nobody; it used to panic on the
// first signature (nil *keys.TrustStore).
func TestNilTrustStore(t *testing.T) {
	ctx := &Context{Now: now}
	if _, err := Signed(contract.KindBundle, signedBy(contract.KindBundle, bundle(1), "lab-a", "lab-b", "lab-c"), ctx); contract.CodeOf(err) != contract.CodeThreshold {
		t.Fatalf("bundle: %v", err)
	}
	cp := signedBy(contract.KindCheckpoint, []byte(`{}`), "lab-a")
	ev := []byte(`{"type":"schild.dist.checkpoint.v1","id":"a-1","envelope":` + string(cp) + `}`)
	if _, err := Document(DocStream, ev, ctx); contract.CodeOf(err) != contract.CodeSignature {
		t.Fatalf("stream: %v", err)
	}
}

func TestUnknownKind(t *testing.T) {
	if _, err := Signed("nope", []byte(`{}`), &Context{}); err == nil || contract.CodeOf(err) != "" {
		t.Fatal("unknown kind")
	}
	if _, err := Document("nope", []byte(`{}`), &Context{}); err == nil {
		t.Fatal("unknown doc")
	}
}

func TestCheckForbidden(t *testing.T) {
	v, _ := jsonx.Parse([]byte(`{"a":[{"b":{"X-Forwarded-For":"1"}}]}`))
	if contract.CodeOf(CheckForbidden(v)) != contract.CodeForbiddenField {
		t.Fatal("nested header not found")
	}
}

func BenchmarkVerifySignal(b *testing.B) {
	p, _ := jsonx.Marshal(msg.Signal{Schema: msg.SchemaSignal, ID: msg.NewID(), Kind: "tip", TimeBucket: msg.TimeBucket(now, 5),
		ActionSig: "scan/env-file", RequestSig: msg.RequestSig(msg.RequestShape{Method: "GET", PathTemplate: "/.env"}), WAFRules: []int{930130},
		Score: 50, Category: "scanner", Origin: msg.Origin{Country: "ZZ", NetClass: "unknown", Attribution: "tcp_peer"}, Agent: msg.Agent{Family: "other"}})
	raw := signedBy(contract.KindSignal, p, "site-a")
	ctx := &Context{Now: now, Trust: testkeys.TrustStore("site-a")}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := Signed(contract.KindSignal, raw, ctx); err != nil {
			b.Fatal(err)
		}
	}
}
