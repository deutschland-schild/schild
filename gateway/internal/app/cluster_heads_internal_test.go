package app

import (
	"encoding/json"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/gateway/internal/reqring"
)

func headsOnly() *groupData {
	return &groupData{heads: newHeadsState(time.Unix(1795000000, 0))}
}

// When a node asks a member: always while the member said nothing yet (an
// earlier build never does), when the member said that something moved,
// when it restarted, and after the safety time whatever was said.
func TestWhenANodeAsksAMember(t *testing.T) {
	g := headsOnly()
	const peer = "n-00000000000000000000000000000001"
	now := time.Unix(1795000100, 0)
	if e, i, r := g.wants(peer, now); !e || !i || !r {
		t.Fatal("a member that said nothing is not asked every round")
	}
	g.takeHeads(peer, heads{Boot: "b1", Store: 7, Requests: 40})
	if !g.heads.kicked[peer] {
		t.Fatal("the word of a member did not wake the pull")
	}
	if e, i, r := g.wants(peer, now); !e || !i || !r {
		t.Fatal("after its first word a member is not asked for everything")
	}
	// The node pulled everything the word covered.
	p := g.heads.pull[peer]
	p.events, p.incidents, p.requests, p.eOK, p.iOK, p.rOK = 7, 7, 40, true, true, true
	p.lastE, p.lastI, p.lastR = now, now, now
	if e, i, r := g.wants(peer, now.Add(time.Second)); e || i || r {
		t.Fatalf("nothing moved and the member is asked: events %v incidents %v requests %v", e, i, r)
	}
	// Requests moved: only they are asked for.
	g.takeHeads(peer, heads{Boot: "b1", Store: 7, Requests: 41})
	if e, i, r := g.wants(peer, now.Add(time.Second)); e || i || !r {
		t.Fatalf("requests moved: events %v incidents %v requests %v", e, i, r)
	}
	p.requests = 41
	// An event or an incident was written: both are asked for, requests not.
	g.takeHeads(peer, heads{Boot: "b1", Store: 8, Requests: 41})
	if e, i, r := g.wants(peer, now.Add(time.Second)); !e || !i || r {
		t.Fatalf("the store moved: events %v incidents %v requests %v", e, i, r)
	}
	p.events, p.incidents = 8, 8
	// While requests keep coming the node asks again by itself.
	p.hot = true
	if _, _, r := g.wants(peer, now.Add(time.Second)); !r {
		t.Fatal("a member that just gave requests is not asked again")
	}
	p.hot = false
	// Nothing said for longer than the safety time: asked all the same.
	if e, i, r := g.wants(peer, now.Add(safetyOf(peer)+time.Second)); !e || !i || !r {
		t.Fatal("after the safety time a silent member is not asked")
	}
	if s := safetyOf(peer); s < pullSafety || s > pullSafety+pullSafetySpread {
		t.Fatalf("safety time %s outside its bounds", s)
	}
	// The member restarted: its numbers mean nothing of before.
	g.takeHeads(peer, heads{Boot: "b2", Store: 8, Requests: 41})
	if e, i, r := g.wants(peer, now.Add(time.Second)); !e || !i || !r {
		t.Fatal("a member that restarted is not asked for everything")
	}
	// A word without a name of its run, or with an endless one, is not kept.
	g2 := headsOnly()
	g2.takeHeads(peer, heads{Store: 1})
	g2.takeHeads(peer, heads{Boot: string(make([]byte, 65)), Store: 1})
	if len(g2.heads.pull) != 0 {
		t.Fatal("a word that names no run was kept")
	}
}

// The answer with requests reads in both forms and says the same, and a
// broken compact answer is refused as a whole.
func TestAnswerWithRequestsInBothForms(t *testing.T) {
	rows := []reqring.Entry{
		{T: 1795000000123, Seq: 11, Client: netip.MustParseAddr("203.0.113.7"), Site: "shop.example", Host: "shop.example", RawPath: "/a", Template: "/a", UA: "curl/8", Status: 200, Country: [2]byte{'D', 'E'}},
		{T: 1795000000456, Seq: 12, Client: netip.MustParseAddr("2001:db8::9"), Site: "shop.example", Host: "shop.example", RawPath: "/b/7", Template: "/b/{n}", UA: "curl/8", Status: 403, Outcome: reqring.OutBlockedWAF,
			EventID: "0195f3c2-7b1e-7c3a-9d11-5a4b3c2d1e0f", Rules: [3]string{"942100"}, NRules: 1, Score: 5, Pin: true},
	}
	ans := requestsAnswer{Epoch: "n-1@abc", First: 3, Next: 12, Rows: rows, Heads: &heads{Boot: "b1", Store: 9, Requests: 13}}
	js, err := json.Marshal(ans)
	if err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string][]byte{"JSON": js, "compact": encodeRequestsBlock(&ans)} {
		got, err := decodeRequestsAnswer(raw, 100)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got.Epoch != ans.Epoch || got.First != 3 || got.Next != 12 || got.Heads == nil || *got.Heads != *ans.Heads || !reflect.DeepEqual(got.Rows, rows) {
			t.Errorf("%s: read %+v, heads %+v", name, got, got.Heads)
		}
	}
	// An answer of the build before: JSON without heads.
	ans.Heads = nil
	js, _ = json.Marshal(ans)
	if got, err := decodeRequestsAnswer(js, 100); err != nil || got.Heads != nil || len(got.Rows) != 2 {
		t.Errorf("an answer without heads: %+v, %v", got, err)
	}
	blk := encodeRequestsBlock(&ans)
	if got, err := decodeRequestsAnswer(blk, 100); err != nil || got.Heads != nil {
		t.Errorf("a compact answer without heads: %+v, %v", got, err)
	}
	for cut := len(blockMagic); cut < len(blk); cut++ {
		if _, err := decodeRequestsAnswer(blk[:cut], 100); err == nil {
			t.Fatalf("a compact answer cut at %d of %d bytes was taken", cut, len(blk))
		}
	}
	if _, err := decodeRequestsAnswer(blk, 1); err == nil {
		t.Error("a compact answer with more requests than asked for was taken")
	}
}
