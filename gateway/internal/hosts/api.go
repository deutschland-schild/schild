package hosts

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	hc "github.com/deutschland-schild/schild/contract/hostcheck"
	"github.com/deutschland-schild/schild/gateway/internal/hostcheck"
)

// Errors the dashboard maps to problem codes.
var (
	ErrNotFound            = errNotFound
	ErrCheckRunning        = errors.New("check_running")
	ErrCheckUnavailable    = errors.New("check_unavailable")
	ErrFingerprintMismatch = errors.New("fingerprint_mismatch")
	ErrConfigAgent         = errors.New("config_agent")
	ErrConflict            = errors.New("conflict")
	ErrAgentsDisabled      = errors.New("agents disabled")
)

func (g *Gateway) summary(ctx context.Context, id, hostname, role string, agentID *string, a *agentRow) (HostSummary, error) {
	h := HostSummary{ID: id, Hostname: hostname, Role: role, AgentID: agentID}
	iv := g.interval()
	if role == "gateway" {
		iv = 24 * time.Hour // the systemd timer of schild check
	}
	ivm := int(iv / time.Minute)
	h.IntervalMinutes = &ivm
	hist, err := g.history(ctx, id, 1)
	if err != nil {
		return h, err
	}
	var last time.Time
	if len(hist) > 0 {
		n := hist[0]
		last = n.Received
		h.LastReportAt, h.ReceivedAt = tsp(n.Started), tsp(n.Received)
		h.Counts, h.Unreadable = n.Counts, n.Unreadable
		if body, err := g.newestBody(ctx, id); err == nil && body != nil {
			var r struct {
				Host struct {
					Hostname string `json:"hostname"`
					OS       struct {
						Name string  `json:"name"`
						EOL  *string `json:"eol"`
					} `json:"os"`
				} `json:"host"`
				Run struct {
					DurationMS int64 `json:"duration_ms"`
				} `json:"run"`
			}
			if json.Unmarshal(body, &r) == nil {
				h.OS = &HostOS{Name: r.Host.OS.Name, EOL: r.Host.OS.EOL}
				d := r.Run.DurationMS
				h.DurationMS = &d
				if role == "gateway" && r.Host.Hostname != "" {
					h.Hostname = r.Host.Hostname
				}
			}
		}
	}
	open := h.Counts.Critical + h.Counts.High + h.Counts.Medium + h.Counts.Low
	switch {
	case a != nil && a.Status == "revoked":
		h.Status = "revoked"
	case a != nil:
		// Silent: no accepted report within twice the interval (counted from
		// the confirmation while there is none yet).
		ref := last
		if ref.IsZero() {
			ref = a.Confirmed
		}
		h.Silent = !ref.IsZero() && g.now().Sub(ref) > 2*iv
		switch {
		case h.Silent:
			h.Status = "silent"
		case last.IsZero():
			h.Status = "waiting"
		case open > 0:
			h.Status = "findings"
		default:
			h.Status = "ok"
		}
	case last.IsZero():
		h.Status = "waiting"
	case open > 0:
		h.Status = "findings"
	default:
		h.Status = "ok"
	}
	return h, nil
}

func (g *Gateway) localHostname() string {
	if n := g.cfg().NodeName; n != "" {
		return n
	}
	return LocalID
}

// Hosts returns every host: the gateway first, then agents by hostname.
// Pending agents are no hosts yet.
func (g *Gateway) Hosts(ctx context.Context) ([]HostSummary, error) {
	g.scanIfStale(ctx)
	local, err := g.summary(ctx, LocalID, g.localHostname(), "gateway", nil, nil)
	if err != nil {
		return nil, err
	}
	out := []HostSummary{local}
	as, err := g.agents(ctx)
	if err != nil {
		return nil, err
	}
	var rest []HostSummary
	for _, a := range as {
		if a.Status == "pending" {
			continue
		}
		id := a.ID
		s, err := g.summary(ctx, a.ID, a.Hostname, "agent", &id, a)
		if err != nil {
			return nil, err
		}
		rest = append(rest, s)
	}
	sort.SliceStable(rest, func(i, j int) bool { return rest[i].Hostname < rest[j].Hostname })
	return append(out, rest...), nil
}

// Page cuts a list with an opaque offset cursor.
func Page[T any](items []T, cursor string, limit int) ([]T, *string, error) {
	off := 0
	if cursor != "" {
		b, err := base64.RawURLEncoding.DecodeString(cursor)
		if err != nil {
			return nil, nil, err
		}
		if off, err = strconv.Atoi(strings.TrimPrefix(string(b), "o:")); err != nil || off < 0 {
			return nil, nil, errors.New("bad cursor")
		}
	}
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	if off > len(items) {
		off = len(items)
	}
	end := min(off+limit, len(items))
	var next *string
	if end < len(items) {
		c := base64.RawURLEncoding.EncodeToString([]byte("o:" + strconv.Itoa(end)))
		next = &c
	}
	page := items[off:end]
	if page == nil {
		page = []T{}
	}
	return page, next, nil
}

// Host returns one host with its newest report and history.
func (g *Gateway) Host(ctx context.Context, id string) (*HostDetail, error) {
	hs, err := g.Hosts(ctx)
	if err != nil {
		return nil, err
	}
	for _, h := range hs {
		if h.ID != id {
			continue
		}
		d := &HostDetail{Host: h, History: []HostReportRef{}}
		body, err := g.newestBody(ctx, id)
		if err != nil {
			return nil, err
		}
		if body != nil {
			d.Report = json.RawMessage(body)
		}
		hist, err := g.history(ctx, id, 365)
		if err != nil {
			return nil, err
		}
		for _, r := range hist {
			d.History = append(d.History, HostReportRef{ReportID: r.ReportID, StartedAt: ts(r.Started), ReceivedAt: ts(r.Received), Counts: r.Counts})
		}
		if id != LocalID {
			if d.LastRejected, err = g.lastRejected(ctx, id); err != nil {
				return nil, err
			}
			if body != nil {
				d.Annotations = annotate(body)
			}
		}
		return d, nil
	}
	return nil, ErrNotFound
}

// annotate gives the gateway's own text for every finding of an agent
// report (hostcheck.Catalogue) and whether its fix command is one this
// gateway's checks produce (hostcheck.KnownFix). Title, explanation and fix
// command inside the report are the agent's free text.
func annotate(body []byte) []FindingAnnotation {
	var r struct {
		Findings []struct {
			ID         string  `json:"id"`
			Subject    *string `json:"subject"`
			FixCommand *string `json:"fix_command"`
		} `json:"findings"`
	}
	out := []FindingAnnotation{}
	if json.Unmarshal(body, &r) != nil {
		return out
	}
	for _, f := range r.Findings {
		a := FindingAnnotation{ID: f.ID, Subject: f.Subject}
		if e, ok := hostcheck.Catalogue[f.ID]; ok {
			a.Title, a.Explanation = &e.Title, &e.Explanation
		}
		a.FixVerified = f.FixCommand != nil && hostcheck.KnownFix(f.ID, *f.FixCommand)
		out = append(out, a)
	}
	return out
}

// Summary is the overview's Server card.
func (g *Gateway) Summary(ctx context.Context) (*ServersSummary, error) {
	hs, err := g.Hosts(ctx)
	if err != nil {
		return nil, err
	}
	s := &ServersSummary{Hosts: int64(len(hs))}
	for _, h := range hs {
		if h.Status == "revoked" {
			s.Hosts--
			continue
		}
		s.Findings.Critical += h.Counts.Critical
		s.Findings.High += h.Counts.High
		s.Findings.Medium += h.Counts.Medium
		s.Findings.Low += h.Counts.Low
		s.Findings.Info += h.Counts.Info
		s.Unreadable += h.Unreadable
		if h.Silent {
			s.Silent++
		}
	}
	as, err := g.agents(ctx)
	if err != nil {
		return nil, err
	}
	var pending int64
	for _, a := range as {
		if a.Status == "pending" {
			pending++
		}
	}
	s.PendingAgents = &pending
	return s, nil
}

func (g *Gateway) agentView(ctx context.Context, a *agentRow) (Agent, error) {
	v := Agent{ID: a.ID, Hostname: a.Hostname, KeyID: a.KeyID, Fingerprint: a.Fingerprint, Status: a.Status, Source: a.Source,
		CreatedAt: ts(a.Created), ConfirmedAt: tsp(a.Confirmed), RevokedAt: tsp(a.Revoked)}
	if a.Label != "" {
		l := a.Label
		v.Label = &l
	}
	if a.Status != "pending" {
		id := a.ID
		s, err := g.summary(ctx, a.ID, a.Hostname, "agent", &id, a)
		if err != nil {
			return v, err
		}
		v.LastReportAt, v.Silent = s.LastReportAt, s.Silent
	}
	return v, nil
}

// Agents lists agents (optionally by status).
func (g *Gateway) Agents(ctx context.Context, status string) ([]Agent, error) {
	as, err := g.agents(ctx)
	if err != nil {
		return nil, err
	}
	out := []Agent{}
	for _, a := range as {
		if status != "" && a.Status != status {
			continue
		}
		v, err := g.agentView(ctx, a)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

// codeAlphabet is the contract's code alphabet (no I, O, 0, 1).
const codeAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

// NewCode returns a one-time code XXXX-XXXX-XXXX-XXXX (80 bits).
func NewCode() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	out := make([]byte, 0, 19)
	for i, c := range b {
		if i > 0 && i%4 == 0 {
			out = append(out, '-')
		}
		out = append(out, codeAlphabet[int(c)%len(codeAlphabet)]) // 256 % 32 == 0: no bias
	}
	return string(out)
}

func codeHash(code string) string {
	h := sha256.Sum256([]byte("schild/agent-enrolment/v0\x00" + strings.ToUpper(code)))
	return hex.EncodeToString(h[:])
}

// CreateEnrolment stores a new one-time code (only its hash) and returns
// the command for the app VM. requestHost is the dashboard's Host header,
// used for the gateway URL unless SCHILD_AGENT_URL is set.
func (g *Gateway) CreateEnrolment(ctx context.Context, label string, ttlMinutes int, requestHost string) (*Enrolment, error) {
	if !g.AgentsEnabled() {
		return nil, ErrAgentsDisabled
	}
	if ttlMinutes <= 0 {
		ttlMinutes = g.cfg().HostCheck.Agents.EnrolmentCodeMinutes
	}
	if ttlMinutes <= 0 {
		ttlMinutes = 30
	}
	code := NewCode()
	now := g.now()
	exp := now.Add(time.Duration(ttlMinutes) * time.Minute)
	if _, err := g.db.ExecContext(ctx, "DELETE FROM host_enrolments WHERE used_ms = 0 AND expires_ms < ?", ms(now.Add(-24*time.Hour))); err != nil {
		return nil, err
	}
	if _, err := g.db.ExecContext(ctx, "INSERT INTO host_enrolments(code_hash, label, created_ms, expires_ms) VALUES(?, ?, ?, ?)", codeHash(code), label, ms(now), ms(exp)); err != nil {
		return nil, err
	}
	u := g.agentURL(requestHost)
	e := &Enrolment{Code: code, ExpiresAt: ts(exp), GatewayURL: u, GatewayName: g.cfg().NodeName, GatewayPin: g.pin,
		Command: "sudo schild-agent enrol --gateway " + u + " --gateway-name " + g.cfg().NodeName + " --pin " + g.pin + " --code " + code}
	if label != "" {
		e.Label = &label
	}
	return e, nil
}

// dnsNameRe is a host name as the enrolment command may carry it.
var dnsNameRe = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\.?$`)

func (g *Gateway) agentURL(requestHost string) string {
	if g.AgentURL != "" {
		return strings.TrimSuffix(g.AgentURL, "/")
	}
	if v := os.Getenv("SCHILD_AGENT_URL"); v != "" {
		return strings.TrimSuffix(v, "/")
	}
	port := "8790"
	host := ""
	if lh, lp, err := net.SplitHostPort(g.cfg().HostCheck.Agents.Listen); err == nil {
		port = lp
		if a, err := netip.ParseAddr(lh); err == nil && !a.IsUnspecified() && !a.IsLoopback() {
			host = lh
		}
	}
	if host == "" {
		h := requestHost
		if hh, _, err := net.SplitHostPort(requestHost); err == nil {
			h = hh
		}
		h = strings.Trim(h, "[]")
		a, err := netip.ParseAddr(h)
		// The URL goes into a command the operator runs with sudo, and Go
		// lets $ ( ) ; & through in a Host header: only an address or a
		// plain DNS name is taken from it.
		if h != "" && h != "localhost" && (err == nil && !a.IsLoopback() || err != nil && dnsNameRe.MatchString(h)) {
			host = h
		}
	}
	if host == "" {
		host = g.cfg().NodeName
	}
	return "https://" + net.JoinHostPort(host, port)
}

// Confirm enrols a pending agent after the admin compared fingerprints.
func (g *Gateway) Confirm(ctx context.Context, id, fingerprint, label string) (*Agent, error) {
	a, err := g.agent(ctx, "id", id)
	if err != nil {
		return nil, err
	}
	if a.Status != "pending" {
		return nil, ErrConflict
	}
	if !strings.EqualFold(strings.TrimSpace(fingerprint), a.Fingerprint) {
		return nil, ErrFingerprintMismatch
	}
	if label == "" {
		label = a.Label
	}
	res, err := g.db.ExecContext(ctx, "UPDATE host_agents SET status = 'enrolled', confirmed_ms = ?, label = ? WHERE id = ? AND status = 'pending'", ms(g.now()), label, id)
	if err != nil {
		return nil, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil, ErrConflict
	}
	g.log.Info("agent confirmed", "agent", id, "keyid", a.KeyID)
	return g.view(ctx, id)
}

// Revoke puts an agent's key on the revocation list (also rejects a pending
// one). Agents from schild.yaml are revoked there.
func (g *Gateway) Revoke(ctx context.Context, id, note string) (*Agent, error) {
	a, err := g.agent(ctx, "id", id)
	if err != nil {
		return nil, err
	}
	if a.Source == "config" {
		return nil, ErrConfigAgent
	}
	if a.Status == "revoked" {
		return nil, ErrConflict
	}
	if _, err := g.db.ExecContext(ctx, "UPDATE host_agents SET status = 'revoked', revoked_ms = ?, note = ? WHERE id = ?", ms(g.now()), note, id); err != nil {
		return nil, err
	}
	g.log.Info("agent revoked", "agent", id, "keyid", a.KeyID)
	return g.view(ctx, id)
}

func (g *Gateway) view(ctx context.Context, id string) (*Agent, error) {
	a, err := g.agent(ctx, "id", id)
	if err != nil {
		return nil, err
	}
	v, err := g.agentView(ctx, a)
	return &v, err
}

// RunLocalCheck asks for a check of the gateway host ("Jetzt prüfen").
func (g *Gateway) RunLocalCheck(ctx context.Context) (*LocalCheckRun, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()
	if g.localState != "" && now.Sub(g.localReq) < 15*time.Minute {
		return nil, ErrCheckRunning
	}
	switch {
	case g.InProcess:
		g.localReq, g.localState = now, "running"
		go g.runInProcess()
		return &LocalCheckRun{RequestedAt: ts(now), State: "running"}, nil
	case g.TriggerFile != "":
		if st, err := os.Stat(g.TriggerFile); err == nil && now.Sub(st.ModTime()) < 15*time.Minute {
			g.localReq, g.localState = st.ModTime().UTC(), "queued"
			return nil, ErrCheckRunning
		}
		if err := os.WriteFile(g.TriggerFile, []byte(ts(now)+"\n"), 0o640); err != nil {
			g.log.Warn("local check trigger file not written", "file", g.TriggerFile, "err", err)
			return nil, ErrCheckUnavailable
		}
		g.localReq, g.localState = now, "queued"
		return &LocalCheckRun{RequestedAt: ts(now), State: "queued"}, nil
	}
	return nil, ErrCheckUnavailable
}

func (g *Gateway) runInProcess() {
	defer func() {
		if p := recover(); p != nil {
			g.log.Error("local check panicked", "panic", p)
		}
		g.mu.Lock()
		g.localState = ""
		g.mu.Unlock()
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	r := hostcheck.Run(ctx, g.CheckEnv, hostcheck.Options{Role: hc.RoleGateway, SchildVersion: g.CheckVersion,
		Previous: hostcheck.Latest(g.reportDir()), Caddyfile: g.cfg().Ingress.Caddyfile})
	b, err := hostcheck.Marshal(r)
	if err != nil {
		g.log.Error("local check report invalid, not stored", "err", err)
		return
	}
	if _, err := hostcheck.WriteReport(g.reportDir(), r, b, g.keep()); err != nil {
		g.log.Error("local check report not written", "dir", g.reportDir(), "err", err)
		return
	}
	if err := g.ScanLocal(ctx); err != nil {
		g.log.Warn("scan local host reports", "err", err)
	}
}
