package stream

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/contract"
)

func TestIDs(t *testing.T) {
	id := FormatID("r1a", 42)
	ep, seq, err := ParseID(id)
	if err != nil || ep != "r1a" || seq != 42 {
		t.Fatalf("%s -> %s %d %v", id, ep, seq, err)
	}
	for _, bad := range []string{"", "-1", "r1a-", "R1A-1", "r1a:1", "abcdefghijklmnopq-1", "r-x", "r-123456789012345678901"} {
		if _, _, err := ParseID(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestWriteRead(t *testing.T) {
	var buf bytes.Buffer
	ev := &Event{Type: TypeHeartbeat, ID: FormatID("ep", 7), Relay: &Relay{ID: "relay-1", Time: "2026-10-26T12:00:00Z"}, Checkpoint: json.RawMessage(`{"payloadType":"x"}`)}
	if err := WriteRetry(&buf, RetryMS); err != nil {
		t.Fatal(err)
	}
	if err := WriteComment(&buf, "keep\nalive"); err != nil {
		t.Fatal(err)
	}
	if err := WriteEvent(&buf, ev); err != nil {
		t.Fatal(err)
	}
	r := NewReader(&buf)
	f, err := r.Next()
	if err != nil {
		t.Fatal(err)
	}
	if f.Event != TypeHeartbeat || f.ID != "ep-7" || !strings.Contains(f.Data, `"relay-1"`) {
		t.Fatalf("frame %+v", f)
	}
	var got Event
	if err := json.Unmarshal([]byte(f.Data), &got); err != nil || got.ID != ev.ID {
		t.Fatalf("decode: %v", err)
	}
	if _, err := r.Next(); err != io.EOF {
		t.Fatalf("want EOF, got %v", err)
	}
	if r.LastEventID() != "ep-7" {
		t.Fatal("last id")
	}
}

func TestReaderSpecDetails(t *testing.T) {
	in := "data: a\r\ndata:b\r\rid: x-1\ndata\n\n: comment\nevent: e\nretry: 50\ndata: c\n\nid: bad\x00\ndata: d\n\n"
	r := NewReader(strings.NewReader(in))
	f, err := r.Next()
	if err != nil || f.Data != "a\nb" || f.ID != "" {
		t.Fatalf("frame1 %+v %v", f, err)
	}
	f, err = r.Next()
	if err != nil || f.Data != "c" || f.Event != "e" || f.Retry != 50 || f.ID != "x-1" {
		t.Fatalf("frame3 %+v %v", f, err)
	}
	f, err = r.Next()
	if err != nil || f.ID != "x-1" {
		t.Fatalf("id with NUL must be ignored: %+v %v", f, err)
	}
}

func TestPriority(t *testing.T) {
	if !(Priority(TypeWithdrawal) < Priority(TypeBundle) && Priority(TypeBundle) < Priority(TypeCheckpoint) && Priority(TypeCheckpoint) < Priority(TypeHeartbeat)) {
		t.Fatal("priority order")
	}
}

func TestFreshness(t *testing.T) {
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	f := NewFreshness(0)
	if !f.Frozen(now) {
		t.Fatal("no checkpoint yet must count as frozen")
	}
	f.Observe(now.Add(-time.Minute))
	f.Observe(now.Add(-time.Hour)) // older never wins
	if f.Frozen(now) {
		t.Fatal("fresh")
	}
	if !f.Frozen(now.Add(FreezeAfter)) {
		t.Fatal("must be frozen after FreezeAfter")
	}
}

func TestOversize(t *testing.T) {
	ev := &Event{Type: TypeBundle, ID: "e-1", Envelope: json.RawMessage(`"` + strings.Repeat("a", 70000) + `"`)}
	if err := WriteEvent(io.Discard, ev); err == nil {
		t.Fatal("oversize event written")
	}
	if BundleURLPath("schild-main", 42) != "/v0/bundles/schild-main/42.json" {
		t.Fatal("bundle path")
	}
}

// A relay is untrusted: data lines without an empty line must not grow the
// reader's memory without bound (stream.md: one event, one data line <= 64 KiB).
func TestReaderFrameBound(t *testing.T) {
	line := "data: " + strings.Repeat("a", 60<<10) + "\n"
	r := NewReader(strings.NewReader(strings.Repeat(line, 1000)))
	if _, err := r.Next(); contract.CodeOf(err) != contract.CodeOversize {
		t.Fatalf("want oversize, got %v", err)
	}
	r = NewReader(strings.NewReader(strings.Repeat("data:\n", 200000)))
	if _, err := r.Next(); contract.CodeOf(err) != contract.CodeOversize {
		t.Fatalf("empty data lines: want oversize, got %v", err)
	}
	// Exactly MaxStreamEventBytes of joined data is still one frame.
	half := contract.MaxStreamEventBytes / 2
	in := "data: " + strings.Repeat("b", half) + "\ndata: " + strings.Repeat("c", contract.MaxStreamEventBytes-half-1) + "\n\n"
	f, err := NewReader(strings.NewReader(in)).Next()
	if err != nil || len(f.Data) != contract.MaxStreamEventBytes {
		t.Fatalf("frame at the limit: %v", err)
	}
	over := "data: " + strings.Repeat("b", half) + "\ndata: " + strings.Repeat("c", contract.MaxStreamEventBytes-half) + "\n\n"
	if _, err := NewReader(strings.NewReader(over)).Next(); contract.CodeOf(err) != contract.CodeOversize {
		t.Fatalf("one byte over the limit: %v", err)
	}
}
