package scoring

import (
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/deutschland-schild/schild/contract/jsonx"
	"github.com/deutschland-schild/schild/contract/msg"
	"github.com/deutschland-schild/schild/lab/internal/queue"
	"github.com/deutschland-schild/schild/lab/internal/store"
)

func setup(t *testing.T) (*Scorer, *queue.Queue, *store.DB) {
	dir := t.TempDir()
	db, err := store.Open(filepath.Join(dir, "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	q, err := queue.Open(queue.Options{Path: filepath.Join(dir, "q"), NoSync: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { q.Close(); db.Close() })
	return New(q, db, Config{MinIssuers: 3, MaxIssuerShare: 0.34, WindowMinutes: 1440, MinScore: 40}, slog.New(slog.NewTextHandler(io.Discard, nil)), nil), q, db
}

func put(t *testing.T, q *queue.Queue, issuer, key string, s msg.Signal) {
	b, _ := jsonx.Marshal(&s)
	done, err := q.Enqueue([]queue.Item{{Kind: "signal", ID: s.ID, ReceivedMS: time.Now().UnixMilli(), Issuer: issuer, KeyID: key, Payload: b}})
	if err != nil {
		t.Fatal(err)
	}
	<-done
}

func sig(action, reqsig string, score int) msg.Signal {
	return msg.Signal{Schema: msg.SchemaSignal, ID: msg.NewID(), Kind: "tip", TimeBucket: msg.TimeBucket(time.Now(), 5), ActionSig: action,
		RequestSig: reqsig, WAFRules: []int{1}, Score: score, Category: "sqli",
		Origin: msg.Origin{Country: "DE", ASN: 64496, NetClass: "hosting", Attribution: "tcp_peer"}, Agent: msg.Agent{Family: "curl", Major: 8}}
}

func drain(t *testing.T, s *Scorer) {
	for {
		n, err := s.Step(1000)
		if err != nil {
			t.Fatal(err)
		}
		if n == 0 {
			return
		}
	}
}

func TestCountingByIssuerNotByKey(t *testing.T) {
	s, q, db := setup(t)
	rs := msg.RequestSig(msg.RequestShape{Method: "GET", PathTemplate: "/x"})
	// 300 client keys of one issuer, same request signature: one unit.
	for i := 0; i < 300; i++ {
		put(t, q, "issuer-sybil", fmt.Sprint("key-", i), sig("scan/x", rs, 90))
	}
	// Baseline (score below min_score) never counts as a tip.
	put(t, q, "issuer-2", "k2", sig("scan/x", rs, 10))
	drain(t, s)
	db.View(func(tx *bolt.Tx) error {
		p, _, _ := GetPattern(tx, PatternID("scan/x"))
		if p.Window.Issuers != 1 || p.Window.Units != 1 || p.Clients != 301 || p.Signals != 301 || p.Baseline != 1 || p.Status != StatusNew {
			t.Fatalf("pattern %+v", p.Window)
		}
		return nil
	})
	// Two more issuers with tips: observe level (watching).
	put(t, q, "issuer-2", "k2", sig("scan/x", rs, 90))
	put(t, q, "issuer-3", "k3", sig("scan/x", rs, 90))
	drain(t, s)
	db.View(func(tx *bolt.Tx) error {
		p, _, _ := GetPattern(tx, PatternID("scan/x"))
		if p.Window.Issuers != 3 || p.Status != StatusWatching || p.Window.MaxIssuerShare > 0.34 {
			t.Fatalf("three issuers: %+v status %s", p.Window, p.Status)
		}
		return nil
	})
}

func TestDefenceInDepth(t *testing.T) {
	s, q, db := setup(t)
	rs := msg.RequestSig(msg.RequestShape{Method: "GET", PathTemplate: "/x"})
	bad := sig("probe/203-0-113-7", rs, 90) // address hidden in a token
	put(t, q, "i1", "k1", bad)
	canary := sig("scan/y", rs, 90)
	canary.Origin.Protected = true // G6: sender on the protection list
	put(t, q, "i1", "k1", canary)
	dup := sig("scan/z", rs, 90)
	put(t, q, "i1", "k1", dup)
	put(t, q, "i1", "k1", dup) // same id again (after a restart, for example)
	drain(t, s)
	db.View(func(tx *bolt.Tx) error {
		if _, ok, _ := GetPattern(tx, PatternID(bad.ActionSig)); ok {
			t.Fatal("address-like signal stored")
		}
		if _, ok, _ := GetPattern(tx, PatternID("scan/y")); ok {
			t.Fatal("canary signal counted")
		}
		p, _, _ := GetPattern(tx, PatternID("scan/z"))
		if p.Signals != 1 {
			t.Fatalf("duplicate counted twice: %d", p.Signals)
		}
		return nil
	})
	if s.Canary.Get("i1") != 1 {
		t.Fatal("canary hit not counted against the issuer")
	}
	if d := q.Depth(); d[0]+d[1]+d[2] != 0 {
		t.Fatalf("queue not drained: %v", d)
	}
}

func TestPruneRetention(t *testing.T) {
	s, q, db := setup(t)
	rs := msg.RequestSig(msg.RequestShape{Method: "GET", PathTemplate: "/x"})
	put(t, q, "i1", "k1", sig("old/x", rs, 90))
	drain(t, s)
	n, err := Prune(db, time.Now().Add(400*24*time.Hour), 30, 365, 1000)
	if err != nil || n == 0 {
		t.Fatalf("prune: %d %v", n, err)
	}
	db.View(func(tx *bolt.Tx) error {
		if tx.Bucket(store.Signals).Stats().KeyN != 0 || tx.Bucket(store.Patterns).Stats().KeyN != 0 {
			t.Fatal("retention did not delete")
		}
		return nil
	})
}

// Regression (UX review, lab): the pattern list showed the window stored at
// the pattern's last signal while the pattern view and the proposal evidence
// computed it live, so one pattern carried two "largest issuer share" values
// once units aged out of the window. Every read path now uses the live window.
func TestPatternReadsUseLiveWindow(t *testing.T) {
	s, q, db := setup(t)
	now := time.Now().UTC()
	old := msg.TimeBucket(now.Add(-23*time.Hour), 5)
	for i := 0; i < 3; i++ { // three older units of issuer-1 (distinct request shapes)
		v := sig("sqli/api", msg.RequestSig(msg.RequestShape{Method: "GET", PathTemplate: fmt.Sprint("/old/", i)}), 90)
		v.TimeBucket = old
		put(t, q, "issuer-1", "k1", v)
	}
	rs := msg.RequestSig(msg.RequestShape{Method: "GET", PathTemplate: "/api"})
	for _, iss := range []string{"issuer-1", "issuer-2", "issuer-3"} {
		put(t, q, iss, "k-"+iss, sig("sqli/api", rs, 90))
	}
	drain(t, s)
	pid := PatternID("sqli/api")
	cfg := s.Config()
	later := now.Add(2 * time.Hour) // the three old units are out of the 24 h window now
	db.View(func(tx *bolt.Tx) error {
		stored, _, _ := GetPattern(tx, pid)
		if stored.Window.MaxIssuerShare != 0.667 || stored.Status != StatusNew {
			t.Fatalf("stored window at ingest: %+v status %s", stored.Window, stored.Status)
		}
		live := ComputeWindow(tx, pid, later, cfg.Window()) // what the rules engine puts into the evidence
		if live.Units != 3 || live.MaxIssuerShare != 0.333 {
			t.Fatalf("live window: %+v", live)
		}
		items, _ := ListPatterns(tx, PatternFilter{}, later, cfg, 0, 10)
		if len(items) != 1 || items[0].MaxIssuerShare != live.MaxIssuerShare || items[0].Issuers != live.Issuers || items[0].Status != StatusWatching {
			t.Fatalf("list differs from the live window: %+v", items)
		}
		d, ok := Detail(tx, pid, later, cfg, time.Time{}, time.Time{})
		if !ok || d.Pattern.MaxIssuerShare != live.MaxIssuerShare || d.Pattern.Status != StatusWatching {
			t.Fatalf("detail differs from the live window: %+v", d)
		}
		// Filters use the live numbers too.
		if items, _ := ListPatterns(tx, PatternFilter{Status: StatusWatching}, later, cfg, 0, 10); len(items) != 1 {
			t.Fatalf("status filter on the stale status: %d items", len(items))
		}
		return nil
	})
}
