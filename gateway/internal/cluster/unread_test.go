package cluster

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	contract "github.com/deutschland-schild/schild/contract/cluster"
)

// A record of a class this build does not have is kept as it came, counted
// as unread and handed on; it is not refused (cluster.md section 4, 3a).
func TestRecordOfAnUnknownClassIsKeptUnreadAndHandedOn(t *testing.T) {
	a := newTestNode(t, "web-1")
	group := inGroup(t, testSecret, a)
	a.start()
	origin := "n-0000000000000000000000000000ffff"
	rec := &contract.Record{V: contract.Version, Group: group, Class: "things_of_a_later_build", ID: "x", Origin: origin, Seq: 1, HLC: contract.HLCOf(time.Now())}
	raw, _ := json.Marshal(rec)
	refused := a.node.Rejected.Load()
	if _, _, err := a.node.takeRecords([]json.RawMessage{raw}, map[string]uint64{origin: 1}, true); err != nil {
		t.Fatal(err)
	}
	if got := a.node.Unread.Load(); got != 1 {
		t.Fatalf("unread counter %d, want 1", got)
	}
	if got := a.node.Rejected.Load(); got != refused {
		t.Fatalf("the record was counted as refused (%d -> %d)", refused, got)
	}
	var n int
	if err := a.node.db.QueryRow(`SELECT count(*) FROM records WHERE state = ? AND class = ?`, stateUnread, rec.Class).Scan(&n); err != nil || n != 1 {
		t.Fatalf("%d unread records of the class (%v), want 1", n, err)
	}
	recs, _, _, err := a.node.afterOf(context.Background(), map[string]uint64{origin: 1}, map[string]uint64{}, 10)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range recs {
		found = found || string(r) == string(raw)
	}
	if !found {
		t.Fatal("the unread record is not handed on to a member that asks")
	}
	// From a sender that may be no member nothing unread is stored.
	rec2 := *rec
	rec2.Seq = 2
	raw2, _ := json.Marshal(&rec2)
	if _, _, err := a.node.takeRecords([]json.RawMessage{raw2}, nil, false); err != nil {
		t.Fatal(err)
	}
	if err := a.node.db.QueryRow(`SELECT count(*) FROM records WHERE state = ?`, stateUnread).Scan(&n); err != nil || n != 1 {
		t.Fatalf("%d unread records after a stranger's record (%v), want 1", n, err)
	}
}

// What a node kept unread while it ran an earlier build is read when it
// starts with a build that knows the class: the record becomes the state,
// its handler runs, and nothing stays unread.
func TestUnreadRecordsAreReadAtTheStartOfALaterBuild(t *testing.T) {
	a, b := newTestNode(t, "web-1"), newTestNode(t, "web-2")
	inGroup(t, testSecret, a, b)
	a.start()
	b.start()
	knowEachOther(t, a, b)
	until := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	blk := &contract.IncidentBlock{Client: "203.0.113.7", Bits: 32, Scope: contract.ScopeGateway, Source: "dashboard", Level: 1,
		Since: contract.TimeText(until.Add(-time.Hour)), Until: contract.TimeText(until), DurationS: 3600, NetClass: "hosting", Node: "web-2"}
	if _, err := b.node.Publish(contract.ClassIncidentBlocks, "K7QF-2M9X", blk, false, until); err != nil {
		t.Fatal(err)
	}
	held := func() int {
		recs, err := a.node.State(contract.ClassIncidentBlocks)
		if err != nil {
			t.Fatal(err)
		}
		return len(recs)
	}
	waitFor(t, "web-1 holds the block", func() bool { return held() == 1 })
	// As an earlier build left it: the record is there, unread.
	if _, err := a.node.db.Exec(`UPDATE records SET state = ? WHERE class = ?`, stateUnread, contract.ClassIncidentBlocks); err != nil {
		t.Fatal(err)
	}
	if held() != 0 {
		t.Fatal("the unread record still counts as state")
	}
	ran := make(chan string, 4)
	a.node.On(contract.ClassIncidentBlocks, func(r *contract.Record) { ran <- r.ID })
	if err := a.node.readUnread(); err != nil {
		t.Fatal(err)
	}
	if held() != 1 {
		t.Fatal("the record kept unread is not the state after it was read")
	}
	select {
	case id := <-ran:
		if id != "K7QF-2M9X" {
			t.Fatalf("handler ran for %q", id)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the handler of the class did not run for the record read at the start")
	}
	var n int
	if err := a.node.db.QueryRow(`SELECT count(*) FROM records WHERE state = ?`, stateUnread).Scan(&n); err != nil || n != 0 {
		t.Fatalf("%d records stay unread (%v)", n, err)
	}
}
