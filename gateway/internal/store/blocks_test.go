package store

import (
	"context"
	"testing"

	"github.com/deutschland-schild/schild/contract/events"
)

func TestKeptBlocks(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	b4 := events.ActiveBlock{ClientKey: "198.51.100.7", KeyBits: 32, NetClass: "hosting", Source: "behaviour:login_bruteforce", Level: 4, DurationS: 604800,
		Since: "2026-10-29T10:00:00Z", Until: "2026-11-05T10:00:00Z", Incident: "inc-1"}
	b6 := b4
	b6.ClientKey, b6.KeyBits, b6.Until = "2001:db8:1:2::", 64, "2026-11-05T11:00:00Z"
	for _, b := range []events.ActiveBlock{b4, b6} {
		if err := s.PutBlock(ctx, b); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.ListBlocks(ctx)
	if err != nil || len(got) != 2 || got[0] != b4 || got[1] != b6 {
		t.Fatalf("list: %v %+v", err, got)
	}
	// Art. 17: deleting an address removes its kept block (IPv6 by /64).
	if _, err := s.DeleteIP(ctx, "2001:db8:1:2:aaaa::1", false, func(b []byte, _ string) []byte { return b }); err != nil {
		t.Fatal(err)
	}
	got, _ = s.ListBlocks(ctx)
	if len(got) != 1 || got[0] != b4 {
		t.Fatalf("after delete: %+v", got)
	}
	if err := s.DeleteBlock(ctx, "198.51.100.7"); err != nil {
		t.Fatal(err)
	}
	if got, _ = s.ListBlocks(ctx); len(got) != 0 {
		t.Fatalf("after DeleteBlock: %+v", got)
	}
}
