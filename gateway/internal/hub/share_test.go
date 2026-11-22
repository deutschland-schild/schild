package hub_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/contract/crowdsec"
	"github.com/deutschland-schild/schild/gateway/internal/hub"
)

func gz(t *testing.T, raw []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	_, _ = w.Write(raw)
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// One node of a group downloads a new index; the other takes it from that
// node and runs the same rules, under the time of the first download.
func TestIndexOfAMemberIsTakenLikeADownload(t *testing.T) {
	ctx := context.Background()
	a := newEnv(t, setup{auto: true})
	if _, _, ok := a.src.SharedIndex(); ok {
		t.Fatal("a node that downloaded nothing has an index to hand on")
	}
	a.serve(index("one", "two", "three", "four", "five"))
	a.src.Check(ctx)
	info, blob, ok := a.src.SharedIndex()
	if !ok || len(info.Digest) != 64 || info.FetchedAt == "" {
		t.Fatalf("after its download the node has nothing to hand on: %+v", info)
	}

	b := newEnv(t, setup{auto: true})
	later := a.now.Load().Add(10 * time.Minute)
	b.now.Store(&later)
	if !b.src.WantsIndex(info) {
		t.Fatal("a node on its image does not want a downloaded index")
	}
	reqs := b.reqs.Load()
	if err := b.src.TakeIndex(ctx, info, blob); err != nil {
		t.Fatal(err)
	}
	if b.reqs.Load() != reqs {
		t.Error("taking an index from a member asked the hub")
	}
	sa, sb := a.status2(), b.status2()
	if sb.SetSource != crowdsec.SetStored || sb.RulesLoaded != 5 || loadedCount(b) != 5 {
		t.Fatalf("the second node does not run the index: %+v", sb)
	}
	if sa.IndexSHA256 != sb.IndexSHA256 {
		t.Errorf("the nodes run different sets: %s, %s", sa.IndexSHA256, sb.IndexSHA256)
	}
	// The rule that is new counts from the first download on both nodes,
	// not from the moment the second node took it: they settle together.
	seen := func(e *env) string {
		for _, r := range e.src.Rules() {
			if strings.HasSuffix(r.View.Name, "vpatch-five") {
				return r.View.FirstSeen
			}
		}
		return ""
	}
	if fa, fb := seen(a), seen(b); fa == "" || fa != fb {
		t.Errorf("the new rule was first seen at %q on the first node and %q on the second", fa, fb)
	}
	// It passed this node's own update: one accepted event, as for a download.
	if ev := b.events(t); len(ev) != 1 || ev[0].Outcome != "accepted" || ev[0].RulesLoaded != 5 {
		t.Fatalf("events of the second node: %+v", ev)
	}
	// The same index again is not wanted, and the node can hand it on itself.
	if b.src.WantsIndex(info) {
		t.Error("a node wants the index it runs")
	}
	if got, _, ok := b.src.SharedIndex(); !ok || got != info {
		t.Errorf("the second node hands on %+v, took %+v", got, info)
	}
	// An older download of a member does not take a newer one back.
	older := info
	older.Digest = strings.Repeat("0", 64)
	older.FetchedAt = a.now.Load().Add(-time.Hour).Format(time.RFC3339)
	if b.src.WantsIndex(older) {
		t.Error("a node wants an index downloaded before the one it runs")
	}
}

func TestIndexOfAMemberIsCheckedLikeADownload(t *testing.T) {
	ctx := context.Background()
	a := newEnv(t, setup{auto: true})
	a.serve(index("one", "two", "three", "four", "five"))
	a.src.Check(ctx)
	info, blob, _ := a.src.SharedIndex()

	// Not the bytes that were announced.
	b := newEnv(t, setup{auto: true})
	other := gz(t, index("one", "two", "three", "four", "evil"))
	if err := b.src.TakeIndex(ctx, info, other); err == nil || !strings.Contains(err.Error(), "digest") {
		t.Errorf("an index with another digest: %v", err)
	}
	if err := b.src.TakeIndex(ctx, info, []byte("no gzip")); err == nil {
		t.Error("bytes that are no gzip were taken")
	}
	if st := b.status2(); st.SetSource != crowdsec.SetImage {
		t.Errorf("a refused index changed the running set: %+v", st)
	}

	// What the node would refuse from the hub it refuses from a member, once.
	empty := index()
	c := newEnv(t, setup{auto: true})
	bad := hub.IndexInfo{Digest: digest(empty), FetchedAt: c.now.Load().Format(time.RFC3339)}
	if err := c.src.TakeIndex(ctx, bad, gz(t, empty)); err == nil {
		t.Error("an index without rules was taken")
	}
	if st := c.status2(); st.SetSource != crowdsec.SetImage || st.RulesLoaded != 4 {
		t.Errorf("after the refusal the node runs %+v", st)
	}
	if c.src.WantsIndex(bad) {
		t.Error("a node wants again the index it just refused")
	}

	// Nodes that must not update take nothing.
	for name, s := range map[string]setup{"updates off": {auto: false}, "rules off": {auto: true, state: crowdsec.StateOff}, "another pin": {auto: true, pin: strings.Repeat("b", 40)}} {
		d := newEnv(t, s)
		if d.src.WantsIndex(info) {
			t.Errorf("%s: the node wants the index of a member", name)
		}
		_ = d.src.TakeIndex(ctx, info, blob)
		if st := d.status2(); st.SetSource == crowdsec.SetStored && st.IndexSHA256 == info.Digest {
			t.Errorf("%s: the node took the index of a member", name)
		}
	}
	// From the future, or from long ago.
	e := newEnv(t, setup{auto: true})
	for name, at := range map[string]time.Time{"an hour ahead": e.now.Load().Add(time.Hour), "two months old": e.now.Load().Add(-60 * 24 * time.Hour)} {
		in := info
		in.FetchedAt = at.Format(time.RFC3339)
		if e.src.WantsIndex(in) {
			t.Errorf("a node wants an index downloaded %s", name)
		}
	}
}

func digest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
