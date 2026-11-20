//go:build !release

package app_test

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/contract/events"
	"github.com/deutschland-schild/schild/gateway/internal/apptest"
	"github.com/deutschland-schild/schild/gateway/internal/store"
)

// TestKeptBlocksRestartDeleteAllowlist: a 7-day block of a data-centre
// address survives a restart (D29 amendment); an Art. 17 deletion and the
// allowlist always win over it.
func TestKeptBlocksRestartDeleteAllowlist(t *testing.T) {
	dir := t.TempDir()
	h := apptest.New(t, apptest.Options{Dir: dir})
	if err := h.Stop(); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(dir, "data", "schild.db"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	row := func(ip string, until time.Time) events.ActiveBlock {
		return events.ActiveBlock{ClientKey: ip, KeyBits: 32, NetClass: "hosting", Source: "behaviour:login_bruteforce", Level: 4, DurationS: 604800,
			Since: until.Add(-7 * 24 * time.Hour).Format(time.RFC3339), Until: until.Format(time.RFC3339), Incident: "inc-" + ip}
	}
	// A residential row of 7 days does not fit its ladder: refused at start.
	wrong := row("203.0.113.53", now.Add(6*24*time.Hour))
	wrong.NetClass = "residential"
	// A residential address (geo: 198.51.100.0/24) stored as hosting: the
	// stored net class is not trusted (D36 fix round 2), the row is dropped.
	lied := row("198.51.100.60", now.Add(6*24*time.Hour))
	for _, b := range []events.ActiveBlock{row("203.0.113.50", now.Add(6*24*time.Hour)), row("203.0.113.51", now.Add(-time.Minute)), row("203.0.113.52", now.Add(time.Hour)), wrong, lied} {
		if err := st.PutBlock(context.Background(), b); err != nil {
			t.Fatal(err)
		}
	}
	// The behaviour hit that started the 7-day block (incident inc-...50).
	hit := map[string]any{"type": events.BehaviourTriggered, "data": map[string]any{"scenario": "login_bruteforce", "scope": "client", "mode": "block", "action": "block",
		"count": 9, "threshold": 5, "window_s": 60, "level": 4, "duration_s": 604800, "incident": "inc-203.0.113.50",
		"client": map[string]any{"ip": "203.0.113.50", "geo": map[string]any{"net_class": "hosting"}}}}
	body, _ := json.Marshal(hit)
	if err := st.InsertEvents(context.Background(), []*store.EventRow{{ID: "hit-50", Time: now.Add(-time.Hour), Type: events.BehaviourTriggered, IP: "203.0.113.50",
		Incident: "inc-203.0.113.50", Outcome: "block", Body: body}}); err != nil {
		t.Fatal(err)
	}
	st.Close()

	h2 := apptest.New(t, apptest.Options{Dir: dir})
	h2.Login()
	for ip, want := range map[string]bool{"203.0.113.50": true, "203.0.113.51": false, "203.0.113.52": true, "203.0.113.53": false, "198.51.100.60": false} {
		bi, ok := h2.App.Behaviour.ActiveBlock(mustAddr(ip))
		if ok != want || (ok && (!bi.Persisted || bi.Duration != 7*24*time.Hour || bi.NetClass != "hosting")) {
			t.Fatalf("%s after restart: %v %+v", ip, ok, bi)
		}
	}
	if r := h2.Visit("GET", "/", "203.0.113.50", "", ""); r.StatusCode != 403 {
		t.Fatalf("restored block not enforced: %d", r.StatusCode)
	}
	rows, _ := h2.App.Store.ListBlocks(context.Background())
	if len(rows) != 2 {
		t.Fatalf("ended or wrong rows not deleted at start: %+v", rows)
	}
	// The restored block is active in the hit list (D36 measurement C).
	code, b := h2.API("GET", "/behaviour/hits?active=true", nil)
	var page struct {
		Items []struct {
			ID     string `json:"id"`
			Active bool   `json:"active"`
		} `json:"items"`
	}
	if code != 200 || json.Unmarshal(b, &page) != nil || len(page.Items) != 1 || page.Items[0].ID != "hit-50" || !page.Items[0].Active {
		t.Fatalf("active hits after restart: %d %s", code, b)
	}
	// Art. 17 deletion lifts the block and removes the row.
	code, b = h2.API("POST", "/privacy/delete", map[string]any{"ip": "203.0.113.50", "confirm": true})
	if code != 200 {
		t.Fatalf("delete: %d %s", code, b)
	}
	h2.App.FlushBlocks()
	if _, ok := h2.App.Behaviour.ActiveBlock(mustAddr("203.0.113.50")); ok {
		t.Fatal("block survived the Art. 17 deletion")
	}
	// The allowlist wins: adding the address ends the block and the row.
	code, b = h2.API("POST", "/allowlist", map[string]any{"ip": "203.0.113.52", "label": "Büro", "level": "no_block", "ttl": "24h"})
	if code != 201 && code != 200 {
		t.Fatalf("allow: %d %s", code, b)
	}
	h2.WaitFor("allowlisted block ended", func() bool {
		_, ok := h2.App.Behaviour.ActiveBlock(mustAddr("203.0.113.52"))
		return !ok
	})
	h2.App.FlushBlocks()
	if rows, _ := h2.App.Store.ListBlocks(context.Background()); len(rows) != 0 {
		t.Fatalf("rows left: %+v", rows)
	}
}

// TestBlockEndAfterRestartAndRelease (D36 fix round 2, re-measurement C):
// a 15 min block that ended with the restart no longer shows a future end,
// and a kept block the operator ends (allowlist) marks its incident
// unblocked, so the UI no longer says "Gesperrt".
func TestBlockEndAfterRestartAndRelease(t *testing.T) {
	dir := t.TempDir()
	h := apptest.New(t, apptest.Options{Dir: dir})
	if err := h.Stop(); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(dir, "data", "schild.db"))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	hit := func(id, ip, netClass, incident string, level, durationS int, until time.Time) {
		body, _ := json.Marshal(map[string]any{"type": events.BehaviourTriggered, "data": map[string]any{"scenario": "login_bruteforce", "scope": "client",
			"mode": "block", "action": "block", "count": 9, "threshold": 5, "window_s": 60, "level": level, "duration_s": durationS,
			"until": until.Format(time.RFC3339), "incident": incident, "client": map[string]any{"ip": ip, "geo": map[string]any{"net_class": netClass}}}})
		if err := st.InsertEvents(ctx, []*store.EventRow{{ID: id, Time: now.Add(-5 * time.Minute), Type: events.BehaviourTriggered, IP: ip,
			Incident: incident, Outcome: "block", Body: body}}); err != nil {
			t.Fatal(err)
		}
		if err := st.InsertIncident(ctx, &store.Incident{Incident: incident, EventID: id, Time: now.Add(-5 * time.Minute), IP: ip, Status: "blocked",
			Sources: []string{"behaviour:login_bruteforce"}}); err != nil {
			t.Fatal(err)
		}
	}
	hit("hit-short", "198.51.100.61", "residential", "K7QM-4XA2", 1, 900, now.Add(10*time.Minute))
	long := now.Add(6 * 24 * time.Hour)
	hit("hit-long", "203.0.113.62", "hosting", "K7QM-4XA3", 4, 604800, long)
	if err := st.PutBlock(ctx, events.ActiveBlock{ClientKey: "203.0.113.62", KeyBits: 32, NetClass: "hosting", Source: "behaviour:login_bruteforce",
		Level: 4, DurationS: 604800, Since: long.Add(-7 * 24 * time.Hour).Format(time.RFC3339), Until: long.Format(time.RFC3339), Incident: "K7QM-4XA3"}); err != nil {
		t.Fatal(err)
	}
	st.Close()

	h2 := apptest.New(t, apptest.Options{Dir: dir})
	h2.Login()
	type incident struct {
		Status      string  `json:"status"`
		UnblockedAt *string `json:"unblocked_at"`
		Block       *struct {
			Until string `json:"until"`
		} `json:"block"`
	}
	get := func(id string) incident {
		code, b := h2.API("GET", "/incidents/"+id, nil)
		var in incident
		if code != 200 || json.Unmarshal(b, &in) != nil || in.Block == nil {
			t.Fatalf("incident %s: %d %s", id, code, b)
		}
		return in
	}
	ended := func(in incident) bool {
		u, err := time.Parse(time.RFC3339, in.Block.Until)
		return err == nil && !u.After(time.Now())
	}
	if in := get("K7QM-4XA2"); !ended(in) || in.Status != "blocked" {
		t.Fatalf("15 min block after the restart: %+v until %s", in, in.Block.Until)
	}
	if in := get("K7QM-4XA3"); ended(in) || in.Status != "blocked" {
		t.Fatalf("kept block after the restart: %+v until %s", in, in.Block.Until)
	}
	code, b := h2.API("POST", "/allowlist", map[string]any{"ip": "203.0.113.62", "label": "Büro", "level": "no_block", "ttl": "24h"})
	if code != 201 && code != 200 {
		t.Fatalf("allow: %d %s", code, b)
	}
	h2.WaitFor("allowlisted block ended", func() bool {
		_, ok := h2.App.Behaviour.ActiveBlock(mustAddr("203.0.113.62"))
		return !ok
	})
	h2.App.FlushBlocks()
	if in := get("K7QM-4XA3"); in.Status != "unblocked" || in.UnblockedAt == nil || !ended(in) {
		t.Fatalf("released block: %+v until %s", in, in.Block.Until)
	}
}
