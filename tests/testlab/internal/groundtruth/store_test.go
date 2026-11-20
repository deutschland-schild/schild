package groundtruth

import (
	"testing"

	"github.com/deutschland-schild/schild/testlab/internal/label"
)

func TestPutGetAll(t *testing.T) {
	s, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	l := label.Label{Class: label.Malicious, Scenario: "T02", Source: "sqlmap", ExpectBlock: true, Seq: 1}
	rec := FromLabel("req-00000001", l, "a.example", "POST", "/login", "203.0.113.5")
	if err := s.Put(rec); err != nil {
		t.Fatal(err)
	}
	got, ok, err := s.Get("req-00000001")
	if err != nil || !ok {
		t.Fatalf("get: ok=%v err=%v", ok, err)
	}
	if got.Class != label.Malicious || !got.ExpectBlock || got.Host != "a.example" || !got.Labelled {
		t.Fatalf("unexpected record: %+v", got)
	}

	// Unknown id.
	if _, ok, _ := s.Get("nope"); ok {
		t.Fatal("got a record for an unknown id")
	}

	// Upsert replaces.
	rec.Class = label.Benign
	rec.ExpectBlock = false
	if err := s.Put(rec); err != nil {
		t.Fatal(err)
	}
	got, _, _ = s.Get("req-00000001")
	if got.Class != label.Benign || got.ExpectBlock {
		t.Fatalf("upsert did not replace: %+v", got)
	}

	n, _ := s.Count()
	if n != 1 {
		t.Fatalf("count = %d, want 1", n)
	}

	all, err := s.All()
	if err != nil || len(all) != 1 {
		t.Fatalf("all: len=%d err=%v", len(all), err)
	}
}

func TestPutEmptyID(t *testing.T) {
	s, _ := Open(":memory:")
	defer s.Close()
	if err := s.Put(Record{}); err == nil {
		t.Fatal("empty request_id accepted")
	}
}

func TestOrdering(t *testing.T) {
	s, _ := Open(":memory:")
	defer s.Close()
	for i := 3; i >= 1; i-- {
		_ = s.Put(Record{RequestID: string(rune('a' + i)), Seq: i, Class: label.Benign, Labelled: true})
	}
	all, _ := s.All()
	if len(all) != 3 || all[0].Seq != 1 || all[2].Seq != 3 {
		t.Fatalf("ordering wrong: %+v", all)
	}
}
