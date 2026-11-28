package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

// The group's sync reads a value, builds the next from it and stores it. A
// value somebody wrote in between must not be written over.
func TestSwapStoresOnlyOverTheValueThatWasRead(t *testing.T) {
	s := open(t)
	ctx := context.Background()

	// Nothing there, and the caller read nothing.
	if err := s.Swap(ctx, "k", nil, []byte("one")); err != nil {
		t.Fatal(err)
	}
	// Somebody wrote since the caller read "one".
	if err := s.Put(ctx, "k", []byte("two")); err != nil {
		t.Fatal(err)
	}
	if err := s.Swap(ctx, "k", []byte("one"), []byte("three")); !errors.Is(err, ErrChanged) {
		t.Fatalf("a value that changed was written over: %v", err)
	}
	if v, _ := s.Get(ctx, "k"); string(v) != "two" {
		t.Fatalf("the value is %q, want the one written in between", v)
	}
	// A key made since the caller found none.
	if err := s.Swap(ctx, "k", nil, []byte("three")); !errors.Is(err, ErrChanged) {
		t.Fatalf("a key made meanwhile was written over: %v", err)
	}
	// The value as read: stored, and an empty next removes the key.
	if err := s.Swap(ctx, "k", []byte("two"), []byte("three")); err != nil {
		t.Fatal(err)
	}
	if v, _ := s.Get(ctx, "k"); string(v) != "three" {
		t.Fatalf("the value is %q", v)
	}
	if err := s.Swap(ctx, "k", []byte("three"), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(ctx, "k"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("the key is still there: %v", err)
	}
	// A key removed since the caller read it.
	if err := s.Swap(ctx, "k", []byte("three"), []byte("four")); !errors.Is(err, ErrChanged) {
		t.Fatalf("a key removed meanwhile was made again: %v", err)
	}
}

func TestSwapSharedKeepsARowWrittenSinceTheDump(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	at := time.UnixMilli(1_700_000_000_000)
	if err := s.AddAllow(ctx, &AllowEntry{ID: "al_1", IP: "192.0.2.1", Level: "no_block", Expires: "never", CreatedAt: at, Source: "dashboard"}); err != nil {
		t.Fatal(err)
	}
	read, err := s.DumpShared(ctx, "allowlist")
	if err != nil {
		t.Fatal(err)
	}
	// The dump another node sent: the row is gone there.
	other := open(t)
	next, err := other.DumpShared(ctx, "allowlist")
	if err != nil {
		t.Fatal(err)
	}
	// A row written here since the dump was read.
	if err := s.AddAllow(ctx, &AllowEntry{ID: "al_2", IP: "192.0.2.2", Level: "no_block", Expires: "never", CreatedAt: at, Source: "cli"}); err != nil {
		t.Fatal(err)
	}
	version := s.AllowVersion(ctx)
	if err := s.SwapShared(ctx, "allowlist", read, next); !errors.Is(err, ErrChanged) {
		t.Fatalf("a table that changed was replaced: %v", err)
	}
	if rows, _ := s.ListAllow(ctx); len(rows) != 2 {
		t.Fatalf("the table holds %d rows, want both", len(rows))
	}
	if s.AllowVersion(ctx) != version {
		t.Fatal("a refused swap moved the version of the allowlist")
	}
	// With the table as it is now, the swap is taken.
	read, err = s.DumpShared(ctx, "allowlist")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SwapShared(ctx, "allowlist", read, next); err != nil {
		t.Fatal(err)
	}
	if rows, _ := s.ListAllow(ctx); len(rows) != 0 {
		t.Fatalf("the table holds %d rows after the swap, want none", len(rows))
	}
}
