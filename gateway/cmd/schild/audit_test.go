//go:build !release

package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	contractaudit "github.com/deutschland-schild/schild/contract/audit"
	"github.com/deutschland-schild/schild/contract/crowdsec"
	"github.com/deutschland-schild/schild/gateway/internal/apptest"
	"github.com/deutschland-schild/schild/gateway/internal/auditlog"
	"github.com/deutschland-schild/schild/gateway/internal/control"
	"github.com/deutschland-schild/schild/gateway/internal/store"
	"github.com/deutschland-schild/schild/gateway/internal/testport"
)

// auditEntry is an audit entry as a test reads it.
type auditEntry struct {
	ID        string `json:"id"`
	Class     string `json:"class"`
	Action    string `json:"action"`
	Operation string `json:"operation"`
	Result    string `json:"result"`
	Actor     struct {
		Kind    string `json:"kind"`
		Account string `json:"account"`
	} `json:"actor"`
	Address string `json:"address"`
	Subject struct {
		Kind string `json:"kind"`
		ID   string `json:"id"`
	} `json:"subject"`
	Website string `json:"website"`
	Change  struct {
		Fields []struct {
			Field  string `json:"field"`
			Change string `json:"change"`
			Before any    `json:"before"`
			After  any    `json:"after"`
			Hidden string `json:"hidden"`
		} `json:"fields"`
	} `json:"change"`
	// raw is the entry as it is stored.
	raw string
}

// field returns "<change> <before> -> <after>" of a changed field, "" when
// the entry does not name it.
func (e auditEntry) field(pointer string) string {
	for _, f := range e.Change.Fields {
		if f.Field == pointer {
			if f.Hidden != "" {
				return f.Change + " hidden:" + f.Hidden
			}
			b, _ := json.Marshal(f.Before)
			a, _ := json.Marshal(f.After)
			return f.Change + " " + string(b) + " -> " + string(a)
		}
	}
	return ""
}

// cliEntries returns the entries of the commands on the host in the data
// directory, oldest first: from audit.db and from the outbox, as `schild
// audit` reads them. The gateway writes entries of its own (audit.start,
// config.apply); they are no part of what a command left.
func cliEntries(t *testing.T, data string) []auditEntry {
	t.Helper()
	st, err := store.Open(filepath.Join(data, "schild.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	l, err := auditlog.OpenRead(ctx, st, filepath.Join(data, auditlog.FileName), "test-node")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	items, next, err := l.List(ctx, auditlog.Filter{Way: auditlog.WayCLI}, "", auditlog.MaxPage)
	if err != nil || next != "" {
		t.Fatalf("list: %v, next %q", err, next)
	}
	out := make([]auditEntry, 0, len(items))
	for i := len(items) - 1; i >= 0; i-- {
		raw, err := json.Marshal(items[i])
		if err != nil {
			t.Fatal(err)
		}
		e := auditEntry{raw: string(raw)}
		if err := json.Unmarshal(raw, &e); err != nil {
			t.Fatal(err)
		}
		out = append(out, e)
	}
	// Entries of one second keep the order of their numbers.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && auditNumber(out[j].ID) < auditNumber(out[j-1].ID); j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// auditNumber is the number of a kept entry of one log.
func auditNumber(id string) int {
	n := 0
	for _, c := range id[strings.LastIndex(id, "-")+1:] {
		n = n*10 + int(c-'0')
	}
	return n
}

// newEntry runs a command and returns the one entry it left. The entry is
// of a command of the account deploy, without an address, and of the
// operation and action given.
func newEntry(t *testing.T, data, action, operation string, run func()) auditEntry {
	t.Helper()
	before := cliEntries(t, data)
	run()
	after := cliEntries(t, data)
	if len(after) != len(before)+1 {
		t.Fatalf("%s: %d new entries, want exactly one: %+v", operation, len(after)-len(before), after[len(before):])
	}
	e := after[len(after)-1]
	if e.Action != action || e.Operation != operation || e.Result != "done" || e.Actor.Kind != "cli" || e.Actor.Account != "deploy" || e.Address != "" {
		t.Fatalf("%s: entry %s", operation, e.raw)
	}
	return e
}

// noEntry runs a command that fails or changes nothing: it leaves no entry.
func noEntry(t *testing.T, data, what string, run func()) {
	t.Helper()
	before := len(cliEntries(t, data))
	run()
	if after := cliEntries(t, data); len(after) != before {
		t.Fatalf("%s: left an entry: %s", what, after[len(after)-1].raw)
	}
}

// serveControl opens the control path of the harness and holds the gateway
// lock, as schild run does. stop ends both, as the end of schild run does.
func serveControl(t *testing.T, h *apptest.Harness) (data string, stop func()) {
	t.Helper()
	data = filepath.Dir(h.App.Store.Path())
	release, err := control.Lock(data)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	srv, err := h.App.ServeControl(ctx, data)
	if err != nil {
		t.Fatal(err)
	}
	stopped := false
	stop = func() {
		if !stopped {
			stopped = true
			srv.Close()
			cancel()
			release()
		}
	}
	t.Cleanup(stop)
	return data, stop
}

// MVP-36: the commands that open the store themselves write their entry in
// the transaction of their change, next to a running gateway and while it
// is stopped; a command that fails leaves none.
func TestAuditStoreCommands(t *testing.T) {
	for _, stopped := range []bool{false, true} {
		name := "running"
		if stopped {
			name = "stopped"
		}
		t.Run(name, func(t *testing.T) {
			t.Setenv("SUDO_USER", "deploy")
			h := apptest.New(t, apptest.Options{})
			cfg := filepath.Join(h.Dir, "schild.yaml")
			data := filepath.Dir(h.App.Store.Path())
			if stopped {
				if err := h.Stop(); err != nil {
					t.Fatal(err)
				}
			}
			token := func(args ...string) (string, error) {
				var out bytes.Buffer
				err := runToken(append(args, "-config", cfg, "-data", data), &out, time.Now)
				return out.String(), err
			}

			var shown string
			e := newEntry(t, data, "token.add", "cli:token add", func() {
				var err error
				if shown, err = token("add", "--scope", "rules:write", "--expires", "30d", "--label", "Laptop"); err != nil {
					t.Fatal(err)
				}
			})
			secret := regexp.MustCompile(`sat1_[A-Za-z0-9_-]{43}`).FindString(shown)
			id := regexp.MustCompile(`tok_[0-9a-f]{12}`).FindString(shown)
			if secret == "" || e.Class != "credential" || e.Subject.Kind != "token" || e.Subject.ID != id || e.Website != "" {
				t.Fatalf("token add: %s", e.raw)
			}
			if e.field("/scope") != `added null -> "rules:write"` || e.field("/label") != `added null -> "Laptop"` || !strings.HasPrefix(e.field("/expires"), `added null -> "20`) {
				t.Fatalf("token add: %s", e.raw)
			}
			// Neither the token nor its hash, under any name.
			if strings.Contains(e.raw, secret) || strings.Contains(e.raw, "sat1_") || strings.Contains(e.raw, "hash") || len(e.Change.Fields) != 3 {
				t.Fatalf("token add records more than scope, label and expiry: %s", e.raw)
			}
			noEntry(t, data, "token add with an unknown scope", func() {
				if _, err := token("add", "--scope", "admin"); err == nil {
					t.Fatal("unknown scope accepted")
				}
			})
			noEntry(t, data, "token list and log", func() {
				if _, err := token("list"); err != nil {
					t.Fatal(err)
				}
				if _, err := token("log"); err != nil {
					t.Fatal(err)
				}
			})
			e = newEntry(t, data, "token.revoke", "cli:token revoke", func() {
				if _, err := token("revoke", id); err != nil {
					t.Fatal(err)
				}
			})
			if e.Subject.ID != id || e.field("/scope") != `removed "rules:write" -> null` || e.field("/label") != `removed "Laptop" -> null` {
				t.Fatalf("token revoke: %s", e.raw)
			}
			noEntry(t, data, "second revoke", func() {
				if _, err := token("revoke", id); err == nil {
					t.Fatal("second revoke accepted")
				}
			})

			e = newEntry(t, data, "allowlist.add", "cli:allow", func() {
				if err := cmdAllow([]string{"203.0.113.7", "-ttl", "24h", "-label", "Office", "-config", cfg, "-data", data}); err != nil {
					t.Fatal(err)
				}
			})
			allowID := e.Subject.ID
			if e.Class != "change" || e.Subject.Kind != "allowlist_entry" || !strings.HasPrefix(allowID, "al_") ||
				e.field("/ip") != `added null -> "203.0.113.7"` || e.field("/label") != `added null -> "Office"` || e.field("/level") != `added null -> "no_block"` {
				t.Fatalf("allow: %s", e.raw)
			}
			noEntry(t, data, "allow list", func() {
				if err := cmdAllow([]string{"list", "-config", cfg, "-data", data}); err != nil {
					t.Fatal(err)
				}
			})
			noEntry(t, data, "allow rm of an unknown id", func() {
				if err := cmdAllow([]string{"rm", "al_nope", "-config", cfg, "-data", data}); err == nil {
					t.Fatal("unknown id removed")
				}
			})
			e = newEntry(t, data, "allowlist.remove", "cli:allow rm", func() {
				if err := cmdAllow([]string{"rm", allowID, "-config", cfg, "-data", data}); err != nil {
					t.Fatal(err)
				}
			})
			if e.Subject.ID != allowID || e.field("/ip") != `removed "203.0.113.7" -> null` {
				t.Fatalf("allow rm: %s", e.raw)
			}
		})
	}
}

// MVP-36: `schild dashboard reset-password` and `setup-code`. The entry
// never holds the code or its hash.
func TestAuditDashboardCommands(t *testing.T) {
	dir := shortDir(t)
	h := apptest.New(t, apptest.Options{Dir: dir})
	data, stopControl := serveControl(t, h)
	ctx := context.Background()

	var code string
	e := newEntry(t, data, "password.setup_code_shown", "cli:dashboard setup-code", func() {
		var err error
		if code, err = setupCode(ctx, data, "deploy"); err != nil {
			t.Fatal(err)
		}
	})
	if e.Class != "credential" || e.Subject.Kind != "user" || len(e.Change.Fields) != 0 || strings.Contains(e.raw, code) {
		t.Fatalf("setup-code: %s", e.raw)
	}
	seed(t, h)
	noEntry(t, data, "setup-code with a password set", func() {
		if _, err := setupCode(ctx, data, "deploy"); err == nil {
			t.Fatal("a setup code although a password is set")
		}
	})
	var r resetResult
	e = newEntry(t, data, "password.reset", "cli:dashboard reset-password", func() {
		var err error
		if r, err = resetPassword(ctx, "test-node", data, "deploy"); err != nil {
			t.Fatal(err)
		}
	})
	if e.Class != "credential" || e.field("/users") != "removed 1 -> null" || !strings.HasPrefix(e.field("/sessions"), "removed ") ||
		len(e.Change.Fields) != 2 || strings.Contains(e.raw, r.Code) {
		t.Fatalf("reset through the gateway: %s", e.raw)
	}
	// The new code works, so the running gateway took it over.
	if got := setupRemote(t, h, r.Code); got != 200 {
		t.Fatalf("setup with the new code: %d", got)
	}

	// Stopped: the command writes the store and the outbox itself.
	if err := h.Stop(); err != nil {
		t.Fatal(err)
	}
	stopControl()
	e = newEntry(t, data, "password.reset", "cli:dashboard reset-password", func() {
		var err error
		if r, err = resetPassword(ctx, "test-node", data, "deploy"); err != nil {
			t.Fatal(err)
		}
	})
	if e.field("/users") != "removed 1 -> null" || strings.Contains(e.raw, r.Code) {
		t.Fatalf("reset while stopped: %s", e.raw)
	}
	// A reset of an access without a user replaces the code: an entry too.
	e = newEntry(t, data, "password.reset", "cli:dashboard reset-password", func() {
		if _, err := resetPassword(ctx, "test-node", data, "deploy"); err != nil {
			t.Fatal(err)
		}
	})
	if e.field("/users") != "removed 0 -> null" {
		t.Fatalf("reset without a user: %s", e.raw)
	}
	// A gateway that holds the data directory and does not answer: refused.
	release, err := control.Lock(data)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	noEntry(t, data, "refused reset", func() {
		if _, err := resetPassword(ctx, "test-node", data, "deploy"); err == nil {
			t.Fatal("reset although the gateway holds the lock")
		}
	})
}

// MVP-36: `schild lock on` and `off` hand the host account over; the
// gateway writes the entry in the transaction of the change.
func TestAuditLockCommands(t *testing.T) {
	h := apptest.New(t, apptest.Options{Dir: shortDir(t)})
	data, _ := serveControl(t, h)
	ctx := context.Background()
	var out bytes.Buffer
	set := lockSpec(nil, nil, []string{"198.51.100.0/24"}, false, "")
	set.Password = "korrekt-pferd"

	e := newEntry(t, data, "access_lock.set", "cli:lock on", func() {
		if err := lockCall(ctx, data, control.Request{Op: control.OpAccessSet, Website: "default", Access: set, HostUser: "deploy"}, &out); err != nil {
			t.Fatal(err)
		}
	})
	if e.Class != "change" || e.Subject.Kind != "website" || e.Website != "default" || e.field("/scope") != `added null -> "site"` {
		t.Fatalf("lock on: %s", e.raw)
	}
	// The password changed, and nothing of it is in the entry.
	if e.field("/password") != "added hidden:secret" || strings.Contains(e.raw, "korrekt-pferd") || strings.Contains(e.raw, "argon") {
		t.Fatalf("lock on: the password: %s", e.raw)
	}
	noEntry(t, data, "lock on an unknown website", func() {
		if err := lockCall(ctx, data, control.Request{Op: control.OpAccessSet, Website: "nope.example", Access: set, HostUser: "deploy"}, &out); err == nil {
			t.Fatal("unknown website locked")
		}
	})
	noEntry(t, data, "lock status", func() {
		if err := lockCall(ctx, data, control.Request{Op: control.OpAccessList, HostUser: "deploy"}, &out); err != nil {
			t.Fatal(err)
		}
	})
	e = newEntry(t, data, "access_lock.remove", "cli:lock off", func() {
		if err := lockCall(ctx, data, control.Request{Op: control.OpAccessRemove, Website: "default", HostUser: "deploy"}, &out); err != nil {
			t.Fatal(err)
		}
	})
	if e.Website != "default" || e.field("/scope") != `removed "site" -> null` {
		t.Fatalf("lock off: %s", e.raw)
	}
	noEntry(t, data, "lock off without a lock", func() {
		if err := lockCall(ctx, data, control.Request{Op: control.OpAccessRemove, Website: "default", HostUser: "deploy"}, &out); err != nil {
			t.Fatal(err)
		}
	})
	// D98: lock off is the way back in from the host, so it ends a
	// maintenance mode too, and says so in the log.
	if _, err := h.App.SetMaintenance(ctx, "default", true, "", "dashboard", "admin"); err != nil {
		t.Fatal(err)
	}
	e = newEntry(t, data, "maintenance.set", "cli:lock off", func() {
		if err := lockCall(ctx, data, control.Request{Op: control.OpAccessRemove, Website: "default", HostUser: "deploy"}, &out); err != nil {
			t.Fatal(err)
		}
	})
	if e.Website != "default" || e.field("/on") != "changed true -> false" {
		t.Fatalf("lock off of a maintenance mode: %s", e.raw)
	}
}

// MVP-36: `schild rules sync` and `reset`. What runs is no part of
// schild.db, so the gateway writes the entry before it answers.
func TestAuditRulesCommands(t *testing.T) {
	h := apptest.New(t, apptest.Options{Dir: shortDir(t)})
	data, stopControl := serveControl(t, h)
	ctx := context.Background()
	rulesDir := filepath.Join(h.Dir, "rules.d")
	if err := os.MkdirAll(rulesDir, 0o700); err != nil {
		t.Fatal(err)
	}
	write := func(text string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(rulesDir, "a.conf"), []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var out bytes.Buffer
	write(`SecRule REQUEST_URI "@beginsWith /x" "id:1000001,phase:1,deny"` + "\n")
	e := newEntry(t, data, "rule_repository.sync", "cli:rules sync", func() {
		if err := syncRules(ctx, data, "local", "deploy", &out); err != nil {
			t.Fatal(err)
		}
	})
	if e.Class != "change" || e.Subject.Kind != "rule_repository" || e.Subject.ID != "local" || e.field("/rules_loaded") != "changed 0 -> 1" {
		t.Fatalf("rules sync: %s", e.raw)
	}
	noEntry(t, data, "a sync that finds nothing new", func() {
		if err := syncRules(ctx, data, "local", "deploy", &out); err != nil {
			t.Fatal(err)
		}
	})
	// Another rule, as many as before: a change, with an entry.
	write(`SecRule REQUEST_URI "@beginsWith /y" "id:1000002,phase:1,deny"` + "\n")
	e = newEntry(t, data, "rule_repository.sync", "cli:rules sync", func() {
		if err := syncRules(ctx, data, "local", "deploy", &out); err != nil {
			t.Fatal(err)
		}
	})
	if len(e.Change.Fields) != 0 {
		t.Fatalf("rules sync with as many rules: %s", e.raw)
	}
	write(`SecRule REQUEST_URI "@nosuchoperator x" "id:1000003,deny"` + "\n")
	noEntry(t, data, "a sync that does not build", func() {
		if err := syncRules(ctx, data, "local", "deploy", &out); err == nil {
			t.Fatal("a broken rule file synced")
		}
	})

	if err := h.App.Store.Put(ctx, crowdsec.StoreKey, []byte(`{"set":{}}`)); err != nil {
		t.Fatal(err)
	}
	e = newEntry(t, data, "rule_repository.reset", "cli:rules reset", func() {
		if err := resetCrowdsec(ctx, "test-node", data, "deploy", &out); err != nil {
			t.Fatal(err)
		}
	})
	if e.Subject.ID != "crowdsec" {
		t.Fatalf("rules reset through the gateway: %s", e.raw)
	}

	// Stopped: the command drops the stored set itself, in one transaction
	// with its entry. Without a stored set nothing changes.
	if err := h.App.Store.Put(ctx, crowdsec.StoreKey, []byte(`{"set":{}}`)); err != nil {
		t.Fatal(err)
	}
	if err := h.Stop(); err != nil {
		t.Fatal(err)
	}
	stopControl()
	e = newEntry(t, data, "rule_repository.reset", "cli:rules reset", func() {
		if err := resetCrowdsec(ctx, "test-node", data, "deploy", &out); err != nil {
			t.Fatal(err)
		}
	})
	if e.Subject.ID != "crowdsec" || e.field("/set") != `changed "stored" -> "image"` {
		t.Fatalf("rules reset while stopped: %s", e.raw)
	}
	noEntry(t, data, "reset while stopped without a stored set", func() {
		if err := resetCrowdsec(ctx, "test-node", data, "deploy", &out); err != nil {
			t.Fatal(err)
		}
	})
	release, err := control.Lock(data)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	noEntry(t, data, "refused reset", func() {
		if err := resetCrowdsec(ctx, "test-node", data, "deploy", &out); err == nil {
			t.Fatal("reset although the gateway holds the lock")
		}
	})
}

// MVP-36: `schild cluster remove` changes the roster, which is no part of
// schild.db: its entry is written before the command reports.
func TestAuditClusterRemove(t *testing.T) {
	t.Setenv("SUDO_USER", "deploy")
	var sec bytes.Buffer
	if err := runCluster([]string{"secret"}, &sec, time.Now); err != nil {
		t.Fatal(err)
	}
	secret := bytes.TrimSpace(sec.Bytes())
	secretFile := filepath.Join(t.TempDir(), "cluster.secret")
	if err := os.WriteFile(secretFile, secret, 0o600); err != nil {
		t.Fatal(err)
	}
	addr1, addr2 := testport.Free(t), testport.Free(t)
	cfg1, data1 := clusterConfig(t, "web-1", addr1, secretFile)
	_, data2 := clusterConfig(t, "web-2", addr2, secretFile)
	runNode(t, data1, "web-1", addr1, secret, nil)
	two := runNode(t, data2, "web-2", addr2, secret, []string{addr1})
	for deadline := time.Now().Add(10 * time.Second); len(two.Reachable()) != 1; time.Sleep(20 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("web-2 did not find web-1")
		}
	}
	// The first command on a node without a store creates it, as `schild
	// allow` does.
	if _, err := clusterCmd(t, cfg1, "status"); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(data1, "schild.db"))
	if err != nil {
		t.Fatal(err)
	}
	st.Close()
	noEntry(t, data1, "remove of an unknown node", func() {
		if _, err := clusterCmd(t, cfg1, "remove", "web-9"); err == nil {
			t.Fatal("an unknown node removed")
		}
	})
	e := newEntry(t, data1, "cluster.remove", "cli:cluster remove", func() {
		if out, err := clusterCmd(t, cfg1, "remove", "web-2"); err != nil {
			t.Fatalf("%v: %s", err, out)
		}
	})
	if e.Class != "change" || e.Subject.Kind != "node" || e.Subject.ID != two.ID() || e.field("/name") != `removed "web-2" -> null` {
		t.Fatalf("cluster remove: %s (node %s)", e.raw, two.ID())
	}
	noEntry(t, data1, "second remove", func() {
		if _, err := clusterCmd(t, cfg1, "remove", "web-2"); err == nil {
			t.Fatal("a removed node removed again")
		}
	})
}

// MVP-36: `schild cluster drain` goes through the control path; the node
// writes the entry before it leaves traffic. A gateway that is no node of a
// group refuses and writes none.
func TestAuditClusterDrain(t *testing.T) {
	alone := apptest.New(t, apptest.Options{Dir: shortDir(t)})
	aloneData, _ := serveControl(t, alone)
	ctx := context.Background()
	noEntry(t, aloneData, "drain of a gateway without a group", func() {
		resp, err := control.Call(ctx, aloneData, control.Request{Op: control.OpDrain, HostUser: "deploy"})
		if err != nil || resp.OK {
			t.Fatalf("drain without a group: %+v, %v", resp, err)
		}
	})

	secretFile := filepath.Join(t.TempDir(), "cluster.secret")
	if err := os.WriteFile(secretFile, []byte(strings.Repeat("ab", 32)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	h := apptest.New(t, apptest.Options{Dir: shortDir(t), Extra: fmt.Sprintf("cluster: {enabled: true, listen: %q, secret_file: %q}\n", apptest.FreeAddr(t), secretFile)})
	if h.App.Cluster == nil {
		t.Fatal("the harness is no node of a group")
	}
	data, _ := serveControl(t, h)
	e := newEntry(t, data, "cluster.drain", "cli:cluster drain", func() {
		resp, err := control.Call(ctx, data, control.Request{Op: control.OpDrain, HostUser: "deploy"})
		if err != nil || !resp.OK {
			t.Fatalf("drain: %+v, %v", resp, err)
		}
	})
	if e.Class != "change" || e.Subject.Kind != "node" || e.Subject.ID != h.App.Cluster.ID() || len(e.Change.Fields) != 0 {
		t.Fatalf("cluster drain: %s", e.raw)
	}
}

// The catalogue of the audit log names every command of schild that writes:
// under the action it records, or under not_audited with the reason
// (contracts/audit.md section 2). The list here is the commands as main
// dispatches them; a new writing command has to be put into both.
func TestAuditCatalogueNamesTheCommands(t *testing.T) {
	writes := []string{
		"cli:allow", "cli:allow rm", "cli:token add", "cli:token revoke",
		"cli:dashboard setup-code", "cli:dashboard reset-password",
		"cli:rules sync", "cli:rules reset", "cli:lock on", "cli:lock off",
		"cli:cluster remove", "cli:cluster drain", "cli:cluster secret",
		"cli:init", "cli:firewall run", "cli:firewall off", "cli:check", "cli:check install", "cli:check uninstall", "cli:geo-fixture",
	}
	inCode := map[string]bool{}
	for _, w := range writes {
		inCode[w] = true
	}
	listed := map[string]bool{}
	for _, a := range contractaudit.Actions.Actions {
		for _, op := range a.Operations {
			if strings.HasPrefix(op, "cli:") {
				listed[op] = true
			}
		}
	}
	for _, o := range contractaudit.Actions.NotAudited {
		if strings.HasPrefix(o.Operation, "cli:") {
			if listed[o.Operation] {
				t.Errorf("%s is audited and in not_audited", o.Operation)
			}
			listed[o.Operation] = true
		}
	}
	for op := range listed {
		if !inCode[op] {
			t.Errorf("the catalogue names %s, which is no writing command of schild", op)
		}
	}
	for op := range inCode {
		if !listed[op] {
			t.Errorf("%s writes and is neither in an action nor in not_audited", op)
		}
	}
}

// MVP-36: `schild audit` lists the entries with each filter, for a person
// and as JSON lines, and prints text from outside escaped.
func TestAuditList(t *testing.T) {
	t.Setenv("SUDO_USER", "deploy")
	h := apptest.New(t, apptest.Options{Dir: shortDir(t)})
	cfg := filepath.Join(h.Dir, "schild.yaml")
	data, _ := serveControl(t, h)
	ctx := context.Background()
	audit := func(args ...string) string {
		t.Helper()
		var out bytes.Buffer
		if err := runAudit(append(args, "-config", cfg, "-data", data), &out, time.Now); err != nil {
			t.Fatalf("audit %v: %v", args, err)
		}
		return out.String()
	}
	if err := cmdAllow([]string{"203.0.113.7", "-ttl", "24h", "-label", "Office Berlin", "-config", cfg, "-data", data}); err != nil {
		t.Fatal(err)
	}
	var tok bytes.Buffer
	if err := runToken([]string{"add", "--label", "Laptop", "-config", cfg, "-data", data}, &tok, time.Now); err != nil {
		t.Fatal(err)
	}
	tokID := regexp.MustCompile(`tok_[0-9a-f]{12}`).FindString(tok.String())
	set := lockSpec(nil, nil, []string{"198.51.100.0/24"}, false, "")
	if err := lockCall(ctx, data, control.Request{Op: control.OpAccessSet, Website: "default", Access: set, HostUser: "deploy"}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	// What an agent token did, with a reason that tries to move the cursor
	// and to turn the direction of the text. The log replaces such
	// characters when it writes; the command escapes what is left.
	agent := auditlog.Entry{Action: "rule.set", Operation: "agent:updateAgentRule", Actor: auditlog.Agent(tokID, "Laptop"), Address: "198.51.100.9",
		Subject: "crs/942100", After: map[string]any{"disabled": true}, Reason: "false positive\x1b[2Jon \"/cart\""}
	if err := h.App.Audit.Write(ctx, agent); err != nil {
		t.Fatal(err)
	}
	// One entry is in audit.db already, the others wait in the outbox or
	// are moved by the gateway: the command reads both.
	if err := h.App.Audit.Move(ctx); err != nil {
		t.Fatal(err)
	}
	if err := cmdAllow([]string{"203.0.113.8", "-config", cfg, "-data", data}); err != nil {
		t.Fatal(err)
	}

	all := audit()
	lines := strings.Split(strings.TrimSpace(all), "\n")
	if !strings.HasPrefix(lines[0], "TIME") || !strings.Contains(lines[0], "WAY") || !strings.Contains(lines[0], "WHO") ||
		!strings.Contains(lines[0], "ACTION") || !strings.Contains(lines[0], "OBJECT") || !strings.Contains(lines[0], "WEBSITE") || !strings.Contains(lines[0], "CHANGE") {
		t.Fatalf("header: %s", lines[0])
	}
	// Newest first.
	if !strings.Contains(lines[1], "203.0.113.8") {
		t.Fatalf("the newest entry is not the first:\n%s", all)
	}
	for _, want := range []string{
		"cli:allow", "deploy", "allowlist.add", "allowlist_entry al_", `+ip=203.0.113.7`, `+label="Office Berlin"`, "+level=no_block",
		"cli:token add", "token.add", "token " + tokID, "+scope=agent:read",
		"cli:lock on", "access_lock.set", "website default", "+scope=site", "+[198.51.100.0/24]",
		"agent:updateAgentRule", tokID + " Laptop from 198.51.100.9", "rule crs/942100", "+disabled=true",
	} {
		if !strings.Contains(all, want) {
			t.Errorf("list lacks %q:\n%s", want, all)
		}
	}
	// Nothing a terminal would act on: no control character but the line
	// ends, and the reason stands quoted.
	for _, r := range all {
		if r != '\n' && (r < 0x20 || r == 0x7f) {
			t.Fatalf("control character %U in the list:\n%q", r, all)
		}
	}
	if !strings.Contains(all, `reason="false positive`) || !strings.Contains(all, `on \"/cart\""`) {
		t.Errorf("the reason is not printed quoted:\n%s", all)
	}

	count := func(s string) int { return len(strings.Split(strings.TrimSpace(s), "\n")) - 1 }
	if got := audit("--action", "allowlist.add"); count(got) != 2 || strings.Contains(got, "token.add") {
		t.Errorf("--action allowlist.add:\n%s", got)
	}
	if got := audit("--website", "default"); count(got) != 1 || !strings.Contains(got, "access_lock.set") {
		t.Errorf("--website default:\n%s", got)
	}
	// --token: what the token did, not the entry about the token itself.
	if got := audit("--token", tokID); count(got) != 1 || !strings.Contains(got, "rule.set") {
		t.Errorf("--token %s:\n%s", tokID, got)
	}
	if got := audit("--since", "1d", "--action", "token.add"); count(got) != 1 {
		t.Errorf("--since 1d:\n%s", got)
	}
	// An entry of two days ago is outside of --since 1d.
	old := agent
	old.Time, old.Subject, old.Reason = time.Now().UTC().Add(-48*time.Hour), "crs/942200", ""
	if err := h.App.Audit.Write(ctx, old); err != nil {
		t.Fatal(err)
	}
	if got := audit("--since", "1d", "--token", tokID); count(got) != 1 || strings.Contains(got, "crs/942200") {
		t.Errorf("--since 1d shows an entry of two days ago:\n%s", got)
	}
	if got := audit("--since", "3d", "--token", tokID); count(got) != 2 {
		t.Errorf("--since 3d:\n%s", got)
	}
	if got := audit("--action", "allowlist.add", "--website", "default"); count(got) != 0 {
		t.Errorf("two filters that fit no entry:\n%s", got)
	}

	// --json: one entry per line, as stored, and reads back as JSON.
	js := strings.Split(strings.TrimSpace(audit("--json", "--token", tokID, "--since", "1d")), "\n")
	if len(js) != 1 {
		t.Fatalf("--json: %d lines", len(js))
	}
	var e auditEntry
	if err := json.Unmarshal([]byte(js[0]), &e); err != nil || e.Action != "rule.set" || e.Address != "198.51.100.9" || e.Subject.ID != "crs/942100" {
		t.Fatalf("--json: %v: %s", err, js[0])
	}
	if n := len(strings.Split(strings.TrimSpace(audit("--json")), "\n")); n != count(audit()) {
		t.Errorf("--json has %d lines, the list %d", n, count(audit()))
	}

	for _, bad := range [][]string{{"--since", "soon"}, {"--nope"}, {"nope"}, {"check", "--json"}} {
		var out bytes.Buffer
		if err := runAudit(append(bad, "-config", cfg, "-data", data), &out, time.Now); err == nil {
			t.Errorf("audit %v accepted", bad)
		}
	}
	// The command reads: it creates no store where there is none.
	empty := t.TempDir()
	if err := runAudit([]string{"-config", cfg, "-data", empty}, &bytes.Buffer{}, time.Now); err == nil || !strings.Contains(err.Error(), "no store") {
		t.Errorf("without a store: %v", err)
	}
	if _, err := os.Stat(filepath.Join(empty, "schild.db")); err == nil {
		t.Error("schild audit created a store")
	}
}

// What is printed for a person never moves a terminal, and a JSON line
// reads back as the entry it was.
func TestAuditVisible(t *testing.T) {
	for in, want := range map[string]string{
		"deploy":           "deploy",
		"":                 `""`,
		"Office Berlin":    `"Office Berlin"`,
		"a\x1b[31mb":       `"a\x1b[31mb"`,
		"a\u202eb":         `"a\u202eb"`,
		"a\u200bb":         `"a\u200bb"`,
		"tab\there":        `"tab\there"`,
		"line\nbreak":      `"line\nbreak"`,
		"x=y":              `"x=y"`,
		"Büro München":     `"Büro München"`,
		"203.0.113.0/24":   "203.0.113.0/24",
		"say \"hi\"":       `"say \"hi\""`,
		"\u0085next":       `"\u0085next"`,
		"bell\a":           `"bell\a"`,
		"back\\slash":      `"back\\slash"`,
		"replaced\ufffdok": "replaced\ufffdok",
	} {
		if got := visible(in); got != want {
			t.Errorf("visible(%q) = %s, want %s", in, got, want)
		}
	}
	in := map[string]any{"reason": "a\u202eb\x7f\u0085<c>\U000e0001", "n": json.Number("3")}
	line, err := jsonLine(in)
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"n":3,"reason":"a\u202eb\u007f\u0085<c>\udb40\udc01"}` + "\n"; string(line) != want {
		t.Fatalf("json line %s, want %s", line, want)
	}
	var back map[string]any
	if err := json.Unmarshal(line, &back); err != nil || back["reason"] != in["reason"] {
		t.Fatalf("the line does not read back: %v %q", err, back["reason"])
	}
}

// MVP-36: `schild audit check` names a hole made by deleting a row from
// audit.db and exits non-zero.
func TestAuditCheck(t *testing.T) {
	t.Setenv("SUDO_USER", "deploy")
	h := apptest.New(t, apptest.Options{Dir: shortDir(t)})
	cfg := filepath.Join(h.Dir, "schild.yaml")
	data := filepath.Dir(h.App.Store.Path())
	ctx := context.Background()
	check := func() (string, error) {
		var out bytes.Buffer
		err := runAudit([]string{"check", "-config", cfg, "-data", data}, &out, time.Now)
		return out.String(), err
	}
	for _, ip := range []string{"203.0.113.1", "203.0.113.2", "203.0.113.3", "203.0.113.4"} {
		if err := cmdAllow([]string{ip, "-config", cfg, "-data", data}); err != nil {
			t.Fatal(err)
		}
	}
	if err := h.App.Audit.Move(ctx); err != nil {
		t.Fatal(err)
	}
	if out, err := check(); err != nil || !strings.Contains(out, "no hole") {
		t.Fatalf("a whole log: %v\n%s", err, out)
	}
	es := cliEntries(t, data)
	if len(es) != 4 {
		t.Fatalf("%d entries", len(es))
	}
	// Somebody with root removes the second and the third entry by hand.
	db, err := sql.Open("sqlite", "file:"+filepath.Join(data, auditlog.FileName)+"?_pragma=busy_timeout(10000)")
	if err != nil {
		t.Fatal(err)
	}
	if r, err := db.Exec(`DELETE FROM entries WHERE id IN (?, ?)`, es[1].ID, es[2].ID); err != nil {
		t.Fatal(err)
	} else if n, _ := r.RowsAffected(); n != 2 {
		t.Fatalf("%d rows deleted", n)
	}
	db.Close()
	out, err := check()
	if err == nil || !strings.Contains(err.Error(), "1 hole, 2 entries missing") {
		t.Fatalf("a hole of two entries: %v\n%s", err, out)
	}
	if !strings.Contains(out, "entries "+es[1].ID+" to "+es[2].ID+" are missing (2)") {
		t.Fatalf("the hole is not named:\n%s", out)
	}
}
