//go:build linux

package nftfw

import (
	"os"
	"testing"
	"time"
)

// TestKernel runs against the real nftables of the test's network namespace
// (a throwaway container with CAP_NET_ADMIN): SCHILD_NFT_IT=1.
func TestKernel(t *testing.T) {
	if os.Getenv("SCHILD_NFT_IT") != "1" {
		t.Skip("set SCHILD_NFT_IT=1 in a throwaway network namespace with CAP_NET_ADMIN")
	}
	k := Kernel{}
	if err := k.Ensure(); err != nil {
		t.Fatal(err)
	}
	if err := k.Ensure(); err != nil {
		t.Fatalf("again: %v", err)
	}
	els := []Element{{Client: "203.0.113.7", Timeout: 15 * time.Minute}, {Client: "2001:db8:1:2::/64", Timeout: 7 * 24 * time.Hour}, {Client: "127.0.0.1", Timeout: time.Minute}}
	if err := k.Replace(els); err != nil {
		t.Fatal(err)
	}
	held, err := k.Held()
	if err != nil || len(held) != 3 {
		t.Fatalf("held %+v %v", held, err)
	}
	got := map[string]time.Duration{}
	for _, h := range held {
		got[h.Client] = h.Expires
	}
	if got["203.0.113.7"] < 14*time.Minute || got["2001:db8:1:2::/64"] < 6*24*time.Hour || got["127.0.0.1"] == 0 {
		t.Fatalf("timeouts %v", got)
	}
	if os.Getenv("SCHILD_NFT_KEEP") == "1" {
		return // the caller checks that traffic is dropped, then removes
	}
	if err := k.Replace(els[1:2]); err != nil {
		t.Fatal(err)
	}
	if held, _ := k.Held(); len(held) != 1 || held[0].Client != "2001:db8:1:2::/64" {
		t.Fatalf("after a lift: %+v", held)
	}
	if err := k.Remove(); err != nil {
		t.Fatal(err)
	}
	if _, err := k.Held(); err == nil {
		t.Fatal("table still there")
	}
}
