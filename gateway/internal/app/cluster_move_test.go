//go:build !release

package app_test

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	contract "github.com/deutschland-schild/schild/contract/cluster"
	"github.com/deutschland-schild/schild/gateway/internal/app"
	"github.com/deutschland-schild/schild/gateway/internal/apptest"
	"github.com/deutschland-schild/schild/gateway/internal/cluster"
)

// secretGroup is two gateways set up by configuration, with an old and a
// new group secret on disk: a node moves by a restart with the new file.
type secretGroup struct {
	a, b                 *groupNode
	oldSecret, newSecret string
	caddyfile            string
}

func newSecretGroup(t *testing.T, caddyfile string) *secretGroup {
	t.Helper()
	// Two groups run in this process for a while, and the keyed hashes of
	// the behaviour engine are one per process.
	t.Cleanup(app.OneGroupHashKey())
	dir := t.TempDir()
	write := func(name string) string {
		secret, err := cluster.NewSecret()
		if err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(secret+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	sg := &secretGroup{oldSecret: write("old.secret"), newSecret: write("new.secret"), caddyfile: caddyfile,
		a: &groupNode{dir: t.TempDir(), addr: apptest.FreeAddr(t), name: "web-1"},
		b: &groupNode{dir: t.TempDir(), addr: apptest.FreeAddr(t), name: "web-2"}}
	sg.start(t, sg.a, sg.oldSecret)
	sg.start(t, sg.b, sg.oldSecret)
	return sg
}

func (sg *secretGroup) start(t *testing.T, g *groupNode, secretFile string) {
	t.Helper()
	g.h = apptest.New(t, apptest.Options{Dir: g.dir, Caddyfile: sg.caddyfile,
		Extra: fmt.Sprintf("cluster: {enabled: true, listen: %q, secret_file: %q, peers: [%q, %q]}\n", g.addr, secretFile, sg.a.addr, sg.b.addr)})
}

// move restarts a node with the new secret file, as a deployment does.
func (sg *secretGroup) move(t *testing.T, g *groupNode) {
	t.Helper()
	if err := g.h.Stop(); err != nil {
		t.Fatal(err)
	}
	sg.start(t, g, sg.newSecret)
	if g.h.App.Cluster == nil {
		t.Fatalf("%s: no cluster node after the move", g.name)
	}
}

func held(t *testing.T, g *groupNode, class string) int {
	t.Helper()
	recs, err := g.h.App.Cluster.State(class)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, r := range recs {
		if !r.Deleted {
			n++
		}
	}
	return n
}

// What happened before and during the change of the secret reads the same
// after it: a release made in the old group while the other server was
// already in the new one ends the block there too, a setting changed in the
// new group is not taken back by the old value the second server brings,
// and an address erased on either side stays erased on both.
func TestNewGroupSecretKeepsLiftsSettingsAndErasures(t *testing.T) {
	sg := newSecretGroup(t, "")
	a, b := sg.a, sg.b
	ctx := context.Background()
	const lifted, kept, erasedBefore, erasedBetween = "203.0.113.190", "203.0.113.191", "203.0.113.192", "203.0.113.193"

	a.block(lifted, "S-LIFTED", 15*time.Minute)
	a.block(kept, "S-KEPT", 15*time.Minute)
	b.h.WaitFor("web-2 holds both blocks", func() bool { return b.blocked(lifted) == "S-LIFTED" && b.blocked(kept) == "S-KEPT" })
	first, second := "observe", "block"
	if b.h.App.Behaviour.Mode("path_probing") == first {
		first, second = second, first
	}
	if _, err := a.h.App.ApplyBehaviour(ctx, map[string]string{"path_probing": first}, nil, nil); err != nil {
		t.Fatal(err)
	}
	b.h.WaitFor("web-2 took the scenario mode of web-1", func() bool { return b.h.App.Behaviour.Mode("path_probing") == first })
	for _, ip := range []string{erasedBefore, erasedBetween} {
		b.h.Visit("GET", "/?q=<script>alert(1)</script>", ip, "", "")
	}
	b.h.Flush()
	a.h.Login()
	if code, body := a.h.API("POST", "/privacy/delete", map[string]any{"ip": erasedBefore, "confirm": true}); code != 200 {
		t.Fatalf("erasure on web-1: %d %s", code, body)
	}
	b.h.WaitFor("web-2 erased the first address", func() bool { return eventsOf(t, b, erasedBefore) == 0 })
	if eventsOf(t, b, erasedBetween) == 0 {
		t.Fatal("web-2 holds no event of the second address")
	}

	// web-2 moves. It keeps the blocks, the setting and the erasure.
	sg.move(t, b)
	if b.blocked(lifted) != "S-LIFTED" || b.blocked(kept) != "S-KEPT" {
		t.Fatalf("web-2 lost blocks over the move: %q, %q", b.blocked(lifted), b.blocked(kept))
	}
	if b.h.App.Behaviour.Mode("path_probing") != first {
		t.Fatal("web-2 lost the scenario mode over the move")
	}
	if held(t, b, contract.ClassErasure) == 0 {
		t.Fatal("web-2 lost the erasure over the move")
	}
	// In between: web-2 changes the setting in the new group; web-1, still in
	// the old one, releases a block and erases an address.
	if _, err := b.h.App.ApplyBehaviour(ctx, map[string]string{"path_probing": second}, nil, nil); err != nil {
		t.Fatal(err)
	}
	if n := a.h.App.Behaviour.Release(netip.MustParseAddr(lifted)); n != 1 {
		t.Fatalf("release on web-1 ended %d blocks", n)
	}
	if code, body := a.h.API("POST", "/privacy/delete", map[string]any{"ip": erasedBetween, "confirm": true}); code != 200 {
		t.Fatalf("erasure on web-1: %d %s", code, body)
	}
	time.Sleep(1500 * time.Millisecond)
	if b.blocked(lifted) == "" || eventsOf(t, b, erasedBetween) == 0 || a.h.App.Behaviour.Mode("path_probing") != first {
		t.Fatal("something crossed between the old and the new group")
	}

	// web-1 follows.
	sg.move(t, a)
	for _, g := range []*groupNode{a, b} {
		g.h.WaitFor(g.name+" ended the block that was released in the old group", func() bool { return g.blocked(lifted) == "" })
		g.h.WaitFor(g.name+" runs the setting made in the new group", func() bool { return g.h.App.Behaviour.Mode("path_probing") == second })
		g.h.WaitFor(g.name+" holds both erasures", func() bool { return held(t, g, contract.ClassErasure) == 2 })
	}
	b.h.WaitFor("web-2 erased the address web-1 erased in the old group", func() bool { return eventsOf(t, b, erasedBetween) == 0 })
	// And it stays that way: nobody brings the old block or the old value back.
	time.Sleep(1500 * time.Millisecond)
	for _, g := range []*groupNode{a, b} {
		if g.blocked(lifted) != "" || g.blocked(kept) != "S-KEPT" || g.h.App.Behaviour.Mode("path_probing") != second || eventsOf(t, g, erasedBefore) != 0 {
			t.Errorf("%s after the change: lifted %q, kept %q, mode %s, events of the erased address %d", g.name, g.blocked(lifted), g.blocked(kept),
				g.h.App.Behaviour.Mode("path_probing"), eventsOf(t, g, erasedBefore))
		}
	}
}

// The certificates the group holds come along: after both servers moved,
// each still has the certificate with its key, the new group holds it as a
// record, and the storage is shared as before.
func TestNewGroupSecretKeepsCertificates(t *testing.T) {
	sg := newSecretGroup(t, groupCaddyfile)
	a, b := sg.a, sg.b
	crt, key := certPair(t, "shop.example")
	dir := "certificates/local/shop.example/"
	a.put(t, dir+"shop.example.key", key)
	a.put(t, dir+"shop.example.crt", crt)
	a.put(t, dir+"shop.example.json", []byte(`{"sans":["shop.example"]}`))
	both := func(g *groupNode) bool {
		return g.has(dir+"shop.example.crt", crt) && g.has(dir+"shop.example.key", key)
	}
	b.h.WaitFor("web-2 holds the certificate with its key", func() bool { return both(b) })
	before := held(t, b, contract.ClassCertificates)
	if before == 0 {
		t.Fatal("the group holds no certificate record")
	}

	sg.move(t, b)
	if !both(b) || held(t, b, contract.ClassCertificates) != before {
		t.Fatalf("web-2 after its move: files %v, %d certificate records (before %d)", both(b), held(t, b, contract.ClassCertificates), before)
	}
	sg.move(t, a)
	for _, g := range []*groupNode{a, b} {
		g.h.WaitFor(g.name+" is in step with the other", func() bool { return g.h.App.Cluster.Synced() })
		if !both(g) || held(t, g, contract.ClassCertificates) != before {
			t.Errorf("%s after both moved: files %v, %d certificate records (before %d)", g.name, both(g), held(t, g, contract.ClassCertificates), before)
		}
	}
	// A renewal on web-2 reaches web-1 in the new group.
	crt2, key2 := certPair(t, "shop.example")
	b.put(t, dir+"shop.example.key", key2)
	b.put(t, dir+"shop.example.crt", crt2)
	a.h.WaitFor("web-1 holds the renewed certificate", func() bool { return a.has(dir+"shop.example.crt", crt2) && a.has(dir+"shop.example.key", key2) })
}

// A new secret file that cannot be used moves nothing and stops the start:
// the directory of the old group stays as it is, and with the old file the
// node is back in it.
func TestUnusableNewSecretLeavesTheOldGroup(t *testing.T) {
	sg := newSecretGroup(t, "")
	a, b := sg.a, sg.b
	a.block("203.0.113.200", "S-OLD", 15*time.Minute)
	b.h.WaitFor("web-2 holds the block", func() bool { return b.blocked("203.0.113.200") == "S-OLD" })
	group := b.h.App.Cluster.Group()
	dir := b.clusterDir()
	if err := b.h.Stop(); err != nil {
		t.Fatal(err)
	}
	short := filepath.Join(t.TempDir(), "short.secret")
	if err := os.WriteFile(short, []byte("too-short\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	open := filepath.Join(t.TempDir(), "open.secret")
	secret, _ := cluster.NewSecret()
	if err := os.WriteFile(open, []byte(secret+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, file := range []string{short, open, filepath.Join(t.TempDir(), "missing")} {
		// schild does not start, and says why.
		h := apptest.New(t, apptest.Options{Dir: b.dir, Caddyfile: sg.caddyfile, NewFails: true,
			Extra: fmt.Sprintf("cluster: {enabled: true, listen: %q, secret_file: %q, peers: [%q, %q]}\n", b.addr, file, a.addr, b.addr)})
		if !strings.Contains(h.NewErr.Error(), "cluster.secret_file") {
			t.Errorf("%s: the error does not name the secret file: %v", filepath.Base(file), h.NewErr)
		}
		st, err := cluster.ReadStatus(dir, nil)
		if err != nil || st.Group != group {
			t.Fatalf("%s: the node is in %v (%v), want %s", filepath.Base(file), st, err, group)
		}
		entries, _ := os.ReadDir(filepath.Dir(dir))
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), filepath.Base(dir)+".") {
				t.Fatalf("%s: a directory was set aside or left behind: %s", filepath.Base(file), e.Name())
			}
		}
	}
	sg.start(t, b, sg.oldSecret)
	if b.h.App.Cluster == nil || b.h.App.Cluster.Group() != group {
		t.Fatal("with the old file the node is not back in its group")
	}
	a.block("203.0.113.201", "S-BACK", 15*time.Minute)
	b.h.WaitFor("web-2 takes blocks of its group again", func() bool { return b.blocked("203.0.113.201") == "S-BACK" && b.blocked("203.0.113.200") == "S-OLD" })
}
