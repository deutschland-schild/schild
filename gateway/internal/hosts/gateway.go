// Package hosts is the gateway side of MVP-11 (contracts/host-check.md
// sections 1, 3, 5-7) inside `schild run`: it reads the local host report
// directory (mounted read-only), accepts signed agent reports from enrolled
// agents on a separate TLS listener, keeps the last reports per host and
// serves the dashboard operations of the "Server" section.
//
// Isolation: host reports stay on this gateway, and nothing here touches
// request handling or the baseline protection state; a failing agent listener only
// logs.
package hosts

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/config"
	"github.com/deutschland-schild/schild/contract/keys"
	"github.com/deutschland-schild/schild/gateway/internal/hostcheck"
)

// LocalID is the host id of the gateway itself.
const LocalID = "local"

// Gateway holds the host state of one schild.
type Gateway struct {
	db     *sql.DB
	cfg    func() *config.Site
	log    *slog.Logger
	nowFn  func() time.Time
	cert   *tls.Certificate
	pin    string
	sem    chan struct{}
	limits *limiter
	// Agent listener limits (listener.go).
	lim        Limits
	bodies     *budget
	laneBodies *budget
	conns      *limitListener

	// Local check ("Jetzt prüfen"): either in-process (schild runs on the
	// host itself) or a trigger file a systemd path unit on the host
	// watches. Neither: the dashboard explains the timer (503).
	InProcess   bool
	TriggerFile string
	// AgentURL overrides the URL shown in the enrolment command
	// (SCHILD_AGENT_URL); default https://<dashboard host or node_name>:<port>.
	AgentURL string
	// CheckEnv runs in-process checks (tests inject a fixture).
	CheckEnv     hostcheck.Env
	CheckVersion string

	mu         sync.Mutex
	scanAt     time.Time
	badFiles   map[string]bool
	localReq   time.Time
	localState string // "", queued, running
}

// Options of New.
type Options struct {
	DB      *sql.DB
	Config  func() *config.Site
	DataDir string
	Log     *slog.Logger
	Now     func() time.Time
	// Limits of the agent listener; nil: DefaultLimits.
	Limits *Limits
}

// New creates the tables, syncs agents from schild.yaml and loads (or
// creates) the agent listener certificate when agents are enabled.
func New(ctx context.Context, o Options) (*Gateway, error) {
	if _, err := o.DB.ExecContext(ctx, schema+acceptSchema); err != nil {
		return nil, fmt.Errorf("hosts: schema: %w", err)
	}
	log := o.Log
	if log == nil {
		log = slog.Default()
	}
	lim := DefaultLimits
	if o.Limits != nil {
		lim = *o.Limits
	}
	g := &Gateway{db: o.DB, cfg: o.Config, log: log.With("part", "hosts"), nowFn: o.Now, sem: make(chan struct{}, lim.VerifyConcurrency), limits: newLimiter(),
		lim: lim, bodies: &budget{max: lim.BodyBudget}, laneBodies: &budget{max: lim.LaneBudget},
		badFiles: map[string]bool{}, CheckEnv: hostcheck.OSEnv{}}
	if err := g.SyncConfig(ctx); err != nil {
		return nil, err
	}
	if hc := g.cfg().HostCheck; hc != nil && *hc.Agents.Enabled {
		cert, err := loadOrCreateCert(hc.Agents.TLSCert, hc.Agents.TLSKey, filepath.Join(o.DataDir, "agent-tls"), g.cfg().NodeName)
		if err != nil {
			return nil, fmt.Errorf("agent listener TLS: %w", err)
		}
		g.cert = cert
		leaf, _ := x509.ParseCertificate(cert.Certificate[0])
		sum := sha256.Sum256(leaf.Raw)
		g.pin = "sha256:" + hex.EncodeToString(sum[:])
	}
	return g, nil
}

func (g *Gateway) now() time.Time {
	if g.nowFn != nil {
		return g.nowFn().UTC()
	}
	return time.Now().UTC()
}

// Enabled reports whether host_check is configured.
func (g *Gateway) Enabled() bool { return g.cfg().HostCheck != nil }

// AgentsEnabled reports whether the agent listener runs.
func (g *Gateway) AgentsEnabled() bool {
	hc := g.cfg().HostCheck
	return hc != nil && *hc.Agents.Enabled
}

// Pin is the sha256 of the agent listener certificate.
func (g *Gateway) Pin() string { return g.pin }

func (g *Gateway) keep() int {
	if hc := g.cfg().HostCheck; hc != nil && hc.KeepReports > 0 {
		return hc.KeepReports
	}
	return 30
}

func (g *Gateway) interval() time.Duration {
	if hc := g.cfg().HostCheck; hc != nil && hc.Agents.IntervalMinutes > 0 {
		return time.Duration(hc.Agents.IntervalMinutes) * time.Minute
	}
	return 24 * time.Hour
}

func (g *Gateway) reportDir() string {
	if hc := g.cfg().HostCheck; hc != nil && hc.ReportDir != "" {
		return hc.ReportDir
	}
	return hostcheck.DefaultReportDir
}

var agentIDClean = regexp.MustCompile(`[^a-z0-9-]+`)

// newAgentID derives a free agent id from a hostname (never "local").
func (g *Gateway) newAgentID(ctx context.Context, tx *sql.Tx, hostname string) (string, error) {
	base := agentIDClean.ReplaceAllString(strings.SplitN(strings.ToLower(hostname), ".", 2)[0], "-")
	base = strings.Trim(base, "-")
	if base == "" || base == LocalID {
		base = "agent"
	}
	if len(base) > 56 {
		base = base[:56]
	}
	for i := 1; i < 10000; i++ {
		id := base
		if i > 1 {
			id = fmt.Sprintf("%s-%d", base, i)
		}
		var n int
		if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM host_agents WHERE id = ?", id).Scan(&n); err != nil {
			return "", err
		}
		if n == 0 {
			return id, nil
		}
	}
	return "", errors.New("hosts: no free agent id")
}

func fingerprintOf(publicKey string) (string, error) {
	pub, err := keys.ParsePublicKey(publicKey)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(pub)
	return "sha256:" + hex.EncodeToString(h[:]), nil
}

// SyncConfig mirrors host_check.agents.keys into host_agents (source
// config): new keys are enrolled, revoked: true revokes, removed keys are
// dropped (their reports stay until retention).
func (g *Gateway) SyncConfig(ctx context.Context) error {
	cfg := g.cfg()
	want := map[string]config.AgentKey{}
	if cfg.HostCheck != nil {
		if _, _, err := cfg.AgentTrust(); err != nil {
			return err
		}
		for _, k := range cfg.HostCheck.Agents.Keys {
			want[k.KeyID] = k
		}
	}
	tx, err := g.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, "SELECT id, keyid, status FROM host_agents WHERE source = 'config'")
	if err != nil {
		return err
	}
	have := map[string][2]string{}
	for rows.Next() {
		var id, keyid, status string
		if err := rows.Scan(&id, &keyid, &status); err != nil {
			rows.Close()
			return err
		}
		have[keyid] = [2]string{id, status}
	}
	rows.Close()
	now := ms(g.now())
	for keyid, h := range have {
		if _, ok := want[keyid]; !ok {
			if _, err := tx.ExecContext(ctx, "DELETE FROM host_agents WHERE id = ?", h[0]); err != nil {
				return err
			}
		}
	}
	for keyid, k := range want {
		status := "enrolled"
		if k.Revoked {
			status = "revoked"
		}
		if h, ok := have[keyid]; ok {
			if h[1] != status {
				rv := int64(0)
				if status == "revoked" {
					rv = now
				}
				if _, err := tx.ExecContext(ctx, "UPDATE host_agents SET status = ?, revoked_ms = ? WHERE id = ?", status, rv, h[0]); err != nil {
					return err
				}
			}
			continue
		}
		fp, err := fingerprintOf(k.PublicKey)
		if err != nil {
			return err
		}
		host := k.Hostname
		if host == "" {
			host = strings.SplitN(keyid, "/", 2)[0]
		}
		// A key enrolled by code before it moved into schild.yaml.
		if _, err := tx.ExecContext(ctx, "DELETE FROM host_agents WHERE (keyid = ? OR public_key = ?) AND source = 'code'", keyid, k.PublicKey); err != nil {
			return err
		}
		id, err := g.newAgentID(ctx, tx, host)
		if err != nil {
			return err
		}
		rv := int64(0)
		if k.Revoked {
			rv = now
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO host_agents("+agentCols+") VALUES(?, ?, '', ?, ?, ?, ?, 'config', ?, ?, ?, '')",
			id, host, keyid, k.PublicKey, fp, status, now, now, rv); err != nil {
			return fmt.Errorf("hosts: agent %s from schild.yaml: %w", keyid, err)
		}
	}
	return tx.Commit()
}

// trust returns the trust store of agent keys (enrolled and revoked; a
// revoked key must verify to be answered with "revoked") and the revoked
// set. Pending agents are not trusted.
func (g *Gateway) trust(ctx context.Context) (*keys.TrustStore, map[string]bool, error) {
	ts := keys.NewTrustStore()
	revoked := map[string]bool{}
	as, err := g.agents(ctx)
	if err != nil {
		return nil, nil, err
	}
	for _, a := range as {
		if a.Status == "pending" {
			continue
		}
		pub, err := keys.ParsePublicKey(a.PublicKey)
		if err != nil {
			continue
		}
		if err := ts.Add(keys.TrustedKey{KeyID: a.KeyID, Public: pub, Purposes: []contract.Purpose{contract.PurposeAgent}}); err != nil {
			continue
		}
		if a.Status == "revoked" {
			revoked[a.KeyID] = true
		}
	}
	return ts, revoked, nil
}

// ---------------------------------------------------------------- local reports

// ScanLocal imports new reports of `schild check` from the report directory
// (read-only: nothing is written there). Invalid files are logged once and
// skipped.
func (g *Gateway) ScanLocal(ctx context.Context) error {
	if !g.Enabled() {
		return nil
	}
	g.mu.Lock()
	g.scanAt = g.now()
	g.mu.Unlock()
	dir := g.reportDir()
	names, err := hostcheck.List(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	keep := g.keep()
	if len(names) > keep {
		names = names[:keep]
	}
	imported := false
	for _, n := range names {
		id := strings.TrimSuffix(n[len("2006-01-02T15:04:05Z-"):], ".json")
		var c int
		if err := g.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM host_reports WHERE report_id = ?", id).Scan(&c); err != nil {
			return err
		}
		if c > 0 {
			// No break: two runs in one second (the first check of an
			// install and a request right after it) sort by their random
			// id, so a new report can stand behind one already imported.
			continue
		}
		p := filepath.Join(dir, n)
		raw, r, err := hostcheck.ReadReport(p)
		if err == nil && (r.Host.Role != "gateway" || r.ReportID != id) {
			err = errors.New("not a gateway report of this file name")
		}
		if err != nil {
			g.mu.Lock()
			seen := g.badFiles[n]
			g.badFiles[n] = true
			g.mu.Unlock()
			if !seen {
				g.log.Warn("local host report skipped", "file", p, "err", err)
			}
			continue
		}
		received := g.now()
		if st, err := os.Stat(p); err == nil {
			received = st.ModTime().UTC()
		}
		if err := g.insertReport(ctx, LocalID, r, raw, received); err != nil {
			return err
		}
		imported = true
	}
	if imported {
		g.mu.Lock()
		if g.localState == "queued" {
			g.localState = ""
		}
		g.mu.Unlock()
		return g.prune(ctx, LocalID, keep)
	}
	return nil
}

// scanIfStale rescans at most every 5 s (dashboard reads).
func (g *Gateway) scanIfStale(ctx context.Context) {
	g.mu.Lock()
	stale := g.now().Sub(g.scanAt) > 5*time.Second
	g.mu.Unlock()
	if stale {
		if err := g.ScanLocal(ctx); err != nil {
			g.log.Warn("scan local host reports", "err", err)
		}
	}
}

// Loop rescans the report directory, expires nonces and checks the trigger
// file until ctx ends.
func (g *Gateway) Loop(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		if err := g.ScanLocal(ctx); err != nil && ctx.Err() == nil {
			g.log.Warn("scan local host reports", "err", err)
		}
		g.expireNonces(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
