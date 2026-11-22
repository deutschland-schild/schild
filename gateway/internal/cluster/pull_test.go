package cluster

import (
	"bytes"
	"context"
	"sync/atomic"
	"testing"
	"time"
)

// A long answer travels compressed and arrives as it was made; a short one
// and one in a compact form of its own are sent as they are. A member can
// be told alone.
func TestLongAnswersTravelCompressedAndATellGoesToOneMember(t *testing.T) {
	a, b, c := threeNodes(t)
	long := append(append([]byte(`{"rows":"`), bytes.Repeat([]byte("abcdefgh"), 40000)...), `"}`...)
	block := append([]byte("SRQ1"), bytes.Repeat([]byte{0, 1, 2, 3}, 2000)...)
	a.node.OnAsk("long", func(string, []byte) ([]byte, error) { return long, nil })
	a.node.OnAsk("short", func(string, []byte) ([]byte, error) { return []byte(`{"ok":true}`), nil })
	a.node.OnAsk("block", func(string, []byte) ([]byte, error) { return block, nil })
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	waitFor(t, "web-2 reaches web-1", func() bool {
		for _, id := range b.node.Reachable() {
			if id == a.node.ID() {
				return true
			}
		}
		return false
	})
	for kind, want := range map[string][]byte{"long": long, "short": []byte(`{"ok":true}`), "block": block} {
		got, err := b.node.Ask(ctx, a.node.ID(), kind, []byte(`{}`))
		if err != nil {
			t.Fatalf("ask %s: %v", kind, err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("ask %s: %d bytes arrived, %d were sent, or they differ", kind, len(got), len(want))
		}
	}

	if got := a.node.Compressed.Load(); got != 1 {
		t.Errorf("%d answers were sent compressed, want 1: the long one, not the short one and not the one in a form of its own", got)
	}

	var toB, toC atomic.Int32
	b.node.OnTell("word", func(string, []byte) { toB.Add(1) })
	c.node.OnTell("word", func(string, []byte) { toC.Add(1) })
	waitFor(t, "web-1 reaches both", func() bool { return len(a.node.Reachable()) == 2 })
	a.node.TellTo(ctx, []string{b.node.ID()}, "word", []byte(`1`))
	waitFor(t, "web-2 was told", func() bool { return toB.Load() == 1 })
	time.Sleep(300 * time.Millisecond)
	if toC.Load() != 0 {
		t.Error("a word for web-2 alone reached web-3")
	}
	a.node.Tell(ctx, "word", []byte(`2`))
	waitFor(t, "both were told", func() bool { return toB.Load() == 2 && toC.Load() == 1 })
}

// A command on the host writes into the store of a running node. The calls
// of the other members that wait for news are woken by one look of the
// node, and the member learns of it within about a second.
func TestWaitingMembersLearnOfAWriteFromTheHost(t *testing.T) {
	a, b, c := threeNodes(t)
	waitFor(t, "web-2 reaches both", func() bool { return len(b.node.Reachable()) == 2 })
	if !b.node.IsMember(c.node.ID()) {
		t.Fatal("web-2 does not know web-3")
	}
	// What `schild cluster remove` does, from outside the running node: it
	// writes into the store of web-1 and wakes nobody.
	start := time.Now()
	if _, err := Remove(a.dir, "web-3", nil); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "web-2 knows that web-3 was removed", func() bool { return !b.node.IsMember(c.node.ID()) })
	if d := time.Since(start); d > 3*time.Second {
		t.Errorf("web-2 learned of the removal after %s", d.Round(10*time.Millisecond))
	}
}
