//go:build !release

package app_test

import (
	"context"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/gateway/internal/app"
	"github.com/deutschland-schild/schild/gateway/internal/auditlog"
	"github.com/deutschland-schild/schild/gateway/internal/dashboard"
)

// auditEntry is a change as a handler of the dashboard writes it.
func auditEntry(subject string, at time.Time) auditlog.Entry {
	return auditlog.Entry{Action: "allowlist.add", Operation: "dashboard:addAllowlistEntry", Actor: auditlog.Dashboard("admin", "0a1b2c3d"),
		Subject: subject, After: map[string]any{"ip": "203.0.113.7", "level": "no_block"}, Time: at}
}

func (g *groupNode) writeAudit(t *testing.T, subject string, at time.Time) {
	t.Helper()
	if err := g.h.App.Audit.Write(context.Background(), auditEntry(subject, at)); err != nil {
		t.Fatal(err)
	}
}

// auditOf is how many entries a node holds for a subject or, with an
// action, of that action.
func auditOf(t *testing.T, g *groupNode, f auditlog.Filter) int {
	t.Helper()
	items, _, err := g.h.App.Audit.List(context.Background(), f, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	return len(items)
}

// The audit log of a group (contracts/audit.md section 9): an entry is once
// on every node; a node that joins later has the entries of a node that is
// gone from a third; after a cut every entry is once on every node; and
// what is too old for a node's audit.keep_days is not taken there.
func TestGroupAuditLogIsOnceOnEveryNode(t *testing.T) {
	nodes := newGroup(t, "web-1", "web-2", "web-3")
	a, b, c := nodes[0], nodes[1], nodes[2]
	c.extra = "audit: {keep_days: 1}\n"
	a.start(t)
	a.h.WaitFor("the mesh of web-1 listens", func() bool { return a.h.App.Cluster.Addr() != "" })
	b.start(t)
	holds := func(g *groupNode, subject string, n int) {
		t.Helper()
		g.h.WaitFor(g.name+" holds the entry "+subject, func() bool { return auditOf(t, g, auditlog.Filter{SubjectID: subject}) == n })
	}
	a.writeAudit(t, "al_old", time.Now().Add(-72*time.Hour))
	a.writeAudit(t, "al_1", time.Time{})
	holds(b, "al_old", 1)
	holds(b, "al_1", 1)

	// web-1 is gone before web-3 ever runs: web-3 has its entries from web-2.
	if err := a.h.Stop(); err != nil {
		t.Fatal(err)
	}
	c.start(t)
	holds(c, "al_1", 1)

	// Both sides of a cut write.
	b.writeAudit(t, "al_2", time.Time{})
	c.writeAudit(t, "al_3", time.Time{})
	a.start(t)
	a.writeAudit(t, "al_4", time.Time{})
	for _, g := range nodes {
		for _, subject := range []string{"al_1", "al_2", "al_3", "al_4"} {
			holds(g, subject, 1)
		}
		g.h.WaitFor(g.name+" holds the start of every log", func() bool { return auditOf(t, g, auditlog.Filter{Action: "audit.start"}) == 3 })
	}
	// A change that arrives from another node writes no entry there: the
	// setting is changed on web-2 by a call, and every node holds the one
	// entry of web-2.
	days := 11
	call := auditlog.WithOrigin(context.Background(), auditlog.Origin{Operation: "dashboard:updateSettings", Actor: auditlog.Dashboard("admin", "0a1b2c3d")})
	if _, err := b.h.App.Apply(call, dashboard.SettingsPatch{Retention: &dashboard.RetentionPatch{EventsDays: &days}}); err != nil {
		t.Fatal(err)
	}
	for _, g := range nodes {
		g.h.WaitFor(g.name+" holds the setting of web-2 and its entry", func() bool {
			return g.h.App.Config().Retention.EventsDays == days && auditOf(t, g, auditlog.Filter{Action: "settings.set"}) == 1
		})
	}
	// Every node was asked by every node now. What is older than
	// audit.keep_days of web-3 was offered to it with the rest and is not
	// there; nothing arrived twice anywhere.
	time.Sleep(1500 * time.Millisecond)
	for _, g := range nodes {
		want := 1
		if g == c {
			want = 0
		}
		if got := auditOf(t, g, auditlog.Filter{SubjectID: "al_old"}); got != want {
			t.Errorf("%s holds the entry of three days ago %d times, want %d", g.name, got, want)
		}
		for _, subject := range []string{"al_1", "al_2", "al_3", "al_4"} {
			if got := auditOf(t, g, auditlog.Filter{SubjectID: subject}); got != 1 {
				t.Errorf("%s holds %s %d times", g.name, subject, got)
			}
		}
		if got := auditOf(t, g, auditlog.Filter{Action: "settings.set"}); got != 1 {
			t.Errorf("%s holds %d entries of the one change of a setting", g.name, got)
		}
		if got := auditOf(t, g, auditlog.Filter{Action: "audit.start"}); got != 3 {
			t.Errorf("%s holds %d entries audit.start, want one per node", g.name, got)
		}
		if n := g.h.App.Audit.Counters(); n.Differing != 0 || n.Skipped != 0 {
			t.Errorf("%s: %d entries with another content, %d that did not pass", g.name, n.Differing, n.Skipped)
		}
	}
	// The group is quiet now, so nobody asks by itself: the head of web-1
	// says that there is news, and the others ask at once.
	start := time.Now()
	a.writeAudit(t, "al_5", time.Time{})
	holds(b, "al_5", 1)
	holds(c, "al_5", 1)
	if d := time.Since(start); d > 3*time.Second {
		t.Errorf("an entry of web-1 took %s to reach the others", d.Round(10*time.Millisecond))
	}
}

// A member of the build before this one does not know the kind `audit`: it
// is asked now and then, not every second, and everything else goes on.
func TestGroupAuditAsksANodeOfTheBuildBeforeWithoutHarm(t *testing.T) {
	nodes := newGroup(t, "web-1", "web-2")
	a, b := nodes[0], nodes[1]
	undo := app.StartAsBuildBefore()
	a.start(t)
	undo()
	a.h.WaitFor("the mesh of web-1 listens", func() bool { return a.h.App.Cluster.Addr() != "" })
	b.start(t)
	b.writeAudit(t, "al_1", time.Time{})
	b.h.WaitFor("web-2 asked web-1 for its audit log", func() bool { return b.h.App.AuditAsks() >= 1 })
	asked := b.h.App.AuditAsks()
	time.Sleep(4 * time.Second)
	if more := b.h.App.AuditAsks() - asked; more > 1 {
		t.Errorf("web-2 asked a member that does not know the kind %d times in 4 s", more)
	}
	if n := a.h.App.AuditAsks(); n != 0 {
		t.Errorf("the node of the build before asked for the audit log %d times", n)
	}
	// The events of the older node still arrive.
	const ip = "203.0.113.201"
	if resp := a.h.Visit("GET", attack, ip, "", ""); resp.StatusCode == 200 {
		t.Fatal("the attack passed on web-1")
	}
	b.h.WaitFor("web-2 holds the event of web-1", func() bool { return eventsOf(t, b, ip) >= 1 })
}
