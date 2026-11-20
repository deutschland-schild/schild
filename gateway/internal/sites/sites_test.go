package sites

import (
	"fmt"
	"testing"

	"github.com/deutschland-schild/schild/contract/websites"
)

func TestViewSlotsAndOther(t *testing.T) {
	var blocks []websites.Block
	for i := 0; i < 34; i++ {
		blocks = append(blocks, websites.Block{Addresses: []string{fmt.Sprintf("site%02d.example", i)}, Schild: true})
	}
	blocks = append(blocks, websites.Block{Addresses: []string{"legacy.example"}, Proxies: true})
	blocks = append(blocks, websites.Block{Addresses: []string{":8080"}, Schild: true})
	v := NewView(websites.Input{Mode: websites.ModeIngress, Blocks: blocks, UnprotectedSites: []string{"legacy.example"}})
	if v.Err != nil {
		t.Fatal(v.Err)
	}
	if v.Tracked() != 32 || v.Untracked() != 3 || v.Protected != 35 {
		t.Fatalf("tracked %d untracked %d protected %d", v.Tracked(), v.Untracked(), v.Protected)
	}
	for host, want := range map[string]struct {
		id   string
		slot int
	}{
		"site00.example":      {"site00.example", 0},
		"SITE31.example:443":  {"site31.example", 31},
		"site32.example":      {"site32.example", OtherSlot},
		"legacy.example":      {"legacy.example", NoSlot},
		"unknown.example":     {"_any", OtherSlot},
		"":                    {"_any", OtherSlot},
		"site05.example.:443": {"site05.example", 5},
	} {
		for i := 0; i < 2; i++ { // second round from the cache
			id, slot := v.Resolve(host)
			if id != want.id || slot != want.slot {
				t.Fatalf("%q: %q %d, want %+v", host, id, slot, want)
			}
		}
	}
	if v.SlotName(0) != "site00.example" || v.SlotName(OtherSlot) != websites.OtherSite || v.SlotOf("site32.example") != OtherSlot {
		t.Fatal("slot names")
	}
	if n := testing.AllocsPerRun(100, func() { v.Resolve("site00.example") }); n != 0 {
		t.Fatalf("Resolve allocates on a hit: %v", n)
	}
}

func TestViewProxyAndFallback(t *testing.T) {
	v := NewView(websites.Input{Mode: websites.ModeProxy, SiteHosts: []string{"bücher.example", "www.bücher.example"}})
	if id, slot := v.Resolve("anything"); id != "xn--bcher-kva.example" || slot != 0 || v.Source != websites.SourceProxy {
		t.Fatalf("proxy: %q %d", id, slot)
	}
	d := NewView(websites.Input{Mode: websites.ModeProxy})
	if id, _ := d.Resolve("x"); id != websites.DefaultID {
		t.Fatalf("default: %q", id)
	}
	bad := NewView(websites.Input{Mode: websites.ModeIngress, Blocks: []websites.Block{{Addresses: []string{"a.example"}, Proxies: true}}})
	if bad.Err == nil || len(bad.Websites()) != 1 || bad.Websites()[0].ID != websites.DefaultID {
		t.Fatalf("fallback: %v %+v", bad.Err, bad.Websites())
	}
}

// TestViewDropsOnlyBrokenBlock (D36 fix round 2): a block that is a config
// error on its own is dropped; the other websites stay (no fallback of the
// whole gateway to "default").
func TestViewDropsOnlyBrokenBlock(t *testing.T) {
	v := NewView(websites.Input{Mode: websites.ModeIngress, Blocks: []websites.Block{
		{Addresses: []string{"shop.example"}, Schild: true, Proxies: true},
		{Addresses: []string{"broken.example"}, Proxies: true},
		{Addresses: []string{"blog.example"}, Schild: true, Proxies: true},
	}})
	if v.Err == nil {
		t.Fatal("the derivation error is kept for the report")
	}
	var ids []string
	for _, w := range v.Websites() {
		ids = append(ids, w.ID)
	}
	if fmt.Sprint(ids) != "[shop.example blog.example]" {
		t.Fatalf("websites %v", ids)
	}
	if id, _ := v.Resolve("blog.example"); id != "blog.example" {
		t.Fatalf("blog resolves to %q", id)
	}
}
