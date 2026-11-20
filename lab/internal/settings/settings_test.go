package settings

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/contract/config"
	"github.com/deutschland-schild/schild/lab/internal/store"
)

const labYAML = `config_version: 0
identity: { operator: op-x, lab: lab-x }
channel: schild-main
keys: [ { keyid: lab-x/all, private_key_file: /etc/schild-lab/keys/lab.key, purposes: [ack, rules, checkpoint] } ]
issuers: [ { id: issuer-1 }, { id: issuer-2 } ]
clients:
  - { keyid: site-1, public_key: "ed25519:4HDXCYuKTC7or+jY5cfx0frqJsA5bTxnc1Ftu0gjb5w=", issuer: issuer-1 }
`

func TestOverlayValidatedAndPersisted(t *testing.T) {
	base, err := config.ParseLab([]byte(labYAML))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "s.db")
	db, _ := store.Open(path)
	m, err := Load(base, db)
	if err != nil {
		t.Fatal(err)
	}
	var seen *config.LabConfig
	m.OnChange = func(c *config.LabConfig) { seen = c }
	if _, err := m.Apply(Patch{Scoring: map[string]any{"min_issuers": 5, "max_issuer_share": 0.25}}); err != nil {
		t.Fatal(err)
	}
	if seen == nil || seen.Scoring.MinIssuers != 5 {
		t.Fatal("change not published")
	}
	// The contract floor holds: min_issuers >= 3, share <= 0.34, no other keys.
	for _, p := range []Patch{
		{Scoring: map[string]any{"min_issuers": 2}},
		{Scoring: map[string]any{"max_issuer_share": 0.5}},
		{Ingest: map[string]any{"queue_max_depth": 10}},
		{Retention: map[string]any{"signals_days": 90}},
	} {
		if _, err := m.Apply(p); err == nil {
			t.Fatalf("patch %+v accepted", p)
		}
	}
	if err := m.RevokeIssuer("issuer-1", "alice", time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := m.RevokeIssuer("nope", "alice", time.Now()); err == nil {
		t.Fatal("unknown issuer revoked")
	}
	if err := m.SetClientQuota("site-1", 9); err != nil {
		t.Fatal(err)
	}
	db.Close()
	// Restart: the overlay comes back.
	db, _ = store.Open(path)
	defer db.Close()
	m, err = Load(base, db)
	if err != nil {
		t.Fatal(err)
	}
	c := m.Config()
	if c.Scoring.MinIssuers != 5 || !c.Issuers[0].Revoked || *c.Clients[0].QuotaPerDay != 9 || base.Scoring.MinIssuers != 3 {
		t.Fatalf("overlay after restart: %+v", c.Scoring)
	}
}
