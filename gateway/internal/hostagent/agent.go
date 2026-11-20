// Package hostagent is the agent of `schild-agent` (MVP-11, contracts/host-check.md
// sections 3, 5 and 6): it runs the read-only host checks on an app VM,
// signs the report with its own Ed25519 key and pushes it to the gateway
// schild over TLS with a pinned certificate.
//
// The agent has no listener and accepts no commands: the only thing it reads
// from the gateway is the ack (status, error, retry_after_s). It talks to
// nothing but the configured gateway URL (no proxy, no redirects) and never
// to a lab.
package hostagent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/dsse"
	hc "github.com/deutschland-schild/schild/contract/hostcheck"
	"github.com/deutschland-schild/schild/contract/jsonx"
	"github.com/deutschland-schild/schild/contract/keygen"
	"github.com/deutschland-schild/schild/contract/keys"
	"github.com/deutschland-schild/schild/contract/msg"
	"github.com/deutschland-schild/schild/contract/verify"
	"github.com/deutschland-schild/schild/gateway/internal/hostcheck"
)

// DefaultDir holds the agent key and state (outside any checkout).
const DefaultDir = "/etc/schild-agent"

// State is agent.json: what `schild-agent enrol` learned. It holds no
// secret; the private key lives in KeyFile (mode 0600).
type State struct {
	GatewayURL      string   `json:"gateway_url"`
	GatewayName     string   `json:"gateway_name"`
	Pin             string   `json:"pin"`
	KeyID           string   `json:"keyid"`
	KeyFile         string   `json:"key_file"`
	Fingerprint     string   `json:"fingerprint"`
	Hostname        string   `json:"hostname"`
	EnrolledAt      string   `json:"enrolled_at"`
	IntervalMinutes int      `json:"interval_minutes,omitempty"`
	Apps            []string `json:"apps,omitempty"`
}

// StateFile returns <dir>/agent.json.
func StateFile(dir string) string { return filepath.Join(dir, "agent.json") }

// LoadState reads agent.json.
func LoadState(dir string) (*State, error) {
	b, err := os.ReadFile(StateFile(dir))
	if err != nil {
		return nil, fmt.Errorf("agent not enrolled (%w); run: schild-agent enrol --gateway URL --pin sha256:... --code CODE --gateway-name NAME", err)
	}
	var s State
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

func saveState(dir string, s *State) error {
	b, _ := json.MarshalIndent(s, "", "  ")
	tmp := StateFile(dir) + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o640); err != nil {
		return err
	}
	return os.Rename(tmp, StateFile(dir))
}

// Fingerprint is sha256 of the 32 public key bytes ("sha256:<hex>").
func Fingerprint(pub ed25519.PublicKey) string {
	h := sha256.Sum256(pub)
	return "sha256:" + hex.EncodeToString(h[:])
}

var (
	pinRe     = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	codeRe    = regexp.MustCompile(`^[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}$`)
	idRe      = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	hostRe    = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,252}$`)
	zeroNonce = strings.Repeat("0", 32)
)

// AgentKeyHeader carries the agent's key id with every report (a lane hint
// for the gateway's limits, never trusted on its own).
const AgentKeyHeader = "Schild-Agent-Key"

// Client talks to one gateway with a pinned certificate.
type Client struct {
	URL  string
	HTTP *http.Client
}

// NewClient returns a client that accepts only the gateway certificate whose
// DER sha256 equals pin. No proxy, no redirects.
func NewClient(gatewayURL, pin string) (*Client, error) {
	u, err := url.Parse(gatewayURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" {
		return nil, fmt.Errorf("gateway URL must be https://host:port, got %q", gatewayURL)
	}
	pin = strings.ToLower(pin)
	if !pinRe.MatchString(pin) {
		return nil, fmt.Errorf("pin must be sha256:<64 hex>, got %q", pin)
	}
	want, _ := hex.DecodeString(strings.TrimPrefix(pin, "sha256:"))
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		// The gateway certificate is usually self-signed; trust comes from the
		// pin taken from the dashboard, checked below on every handshake.
		InsecureSkipVerify: true, //nolint:gosec // replaced by VerifyConnection (pinning)
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("gateway sent no certificate")
			}
			got := sha256.Sum256(cs.PeerCertificates[0].Raw)
			if !bytes.Equal(got[:], want) {
				return fmt.Errorf("gateway certificate sha256:%x does not match the pin", got)
			}
			return nil
		},
	}
	tr := &http.Transport{Proxy: nil, TLSClientConfig: tlsCfg, DialContext: (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
		TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 60 * time.Second, MaxIdleConns: 1, ForceAttemptHTTP2: false}
	return &Client{URL: strings.TrimSuffix(u.String(), "/"), HTTP: &http.Client{Transport: tr, Timeout: 2 * time.Minute,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

// CertPin returns the pin of a certificate (sha256 of the DER bytes).
func CertPin(c *x509.Certificate) string {
	h := sha256.Sum256(c.Raw)
	return "sha256:" + hex.EncodeToString(h[:])
}

// post sends an envelope and returns the verified ack. Only status, error
// and retry_after_s are used; anything else the gateway might send is
// ignored by construction (the ack schema has no other fields).
//
// keyid (reports only) goes into the Schild-Agent-Key header: the gateway
// uses it before reading the body to give enrolled agents their own request
// budget and memory reserve (host-check.md section 6); it is a hint, the
// signature decides.
func (c *Client) post(ctx context.Context, path string, body []byte, nonce, keyid string) (*hc.Ack, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URL+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if keyid != "" {
		req.Header.Set(AgentKeyHeader, keyid)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, contract.MaxAgentAckBytes+1))
	if err != nil {
		return nil, err
	}
	if _, err := verify.Document(verify.DocAgentAck, raw, &verify.Context{}); err != nil {
		return nil, fmt.Errorf("gateway answered HTTP %d without a valid ack: %v", resp.StatusCode, err)
	}
	var ack hc.Ack
	if err := json.Unmarshal(raw, &ack); err != nil {
		return nil, err
	}
	if ack.Nonce != nonce && ack.Nonce != zeroNonce {
		return nil, fmt.Errorf("ack answers nonce %s, sent %s", ack.Nonce, nonce)
	}
	return &ack, nil
}

func newNonce() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// EnrolOptions of `schild-agent enrol`.
type EnrolOptions struct {
	Dir         string
	GatewayURL  string
	GatewayName string
	Pin         string
	Code        string
	KeyID       string // default <hostname>/agent/<yyyy-mm>
	Hostname    string
	Now         func() time.Time
	Out         io.Writer
	// Client overrides the pinned client (tests).
	Client *Client
}

// Enrol creates the agent key (mode 0600, never overwritten), sends a
// self-signed enrolment request with the one-time code and stores the state
// when the gateway answers pending. The key never leaves the host.
func Enrol(ctx context.Context, o EnrolOptions) (*State, error) {
	now := time.Now
	if o.Now != nil {
		now = o.Now
	}
	if o.Out == nil {
		o.Out = io.Discard
	}
	o.Code = strings.ToUpper(strings.TrimSpace(o.Code))
	if !codeRe.MatchString(o.Code) {
		return nil, errors.New("code must look like XXXX-XXXX-XXXX-XXXX (from the dashboard)")
	}
	if !idRe.MatchString(o.GatewayName) {
		return nil, fmt.Errorf("gateway name %q must be the gateway's node_name (shown in the enrolment command)", o.GatewayName)
	}
	host := strings.ToLower(o.Hostname)
	if host == "" {
		h, _ := os.Hostname()
		host = strings.ToLower(h)
	}
	if !hostRe.MatchString(host) {
		return nil, fmt.Errorf("hostname %q does not fit the contract; pass --hostname", host)
	}
	cl := o.Client
	if cl == nil {
		var err error
		if cl, err = NewClient(o.GatewayURL, o.Pin); err != nil {
			return nil, err
		}
	}
	if _, err := os.Stat(StateFile(o.Dir)); err == nil {
		return nil, fmt.Errorf("%s exists: this host is already enrolled; remove the directory to enrol again with a new key", StateFile(o.Dir))
	}
	if err := os.MkdirAll(o.Dir, 0o750); err != nil {
		return nil, err
	}
	keyid := o.KeyID
	if keyid == "" {
		short := strings.SplitN(host, ".", 2)[0]
		keyid = short + "/agent/" + now().UTC().Format("2006-01")
	}
	keyFile := filepath.Join(o.Dir, "agent.key")
	k, err := keygen.NewSigningKey(keyFile, keyid, "")
	if err != nil {
		return nil, err
	}
	fp := Fingerprint(k.Public)
	fmt.Fprintf(o.Out, "agent key %s created in %s (mode 0600, stays on this host)\nfingerprint: %s\ncompare it with the one the dashboard shows before you confirm the agent there.\n", keyid, keyFile, fp)
	signer, err := keys.LoadSigner(keyid, keyFile)
	if err != nil {
		return nil, err
	}
	nonce := newNonce()
	e := hc.Enrolment{Schema: hc.SchemaEnrolment, Gateway: o.GatewayName, Code: o.Code, KeyID: keyid, PublicKey: keys.FormatPublicKey(k.Public),
		Hostname: host, IssuedAt: msg.FormatTime(now()), Nonce: nonce}
	payload, err := jsonx.Marshal(e)
	if err != nil {
		return nil, err
	}
	env, err := dsse.Sign(hc.EnrolmentPayloadType, payload, signer)
	if err != nil {
		return nil, err
	}
	body, _ := env.Marshal()
	ack, err := cl.post(ctx, "/v0/agent/enrol", body, nonce, "")
	if err != nil {
		_ = os.Remove(keyFile)
		return nil, fmt.Errorf("enrolment not delivered (key removed, run the command again): %w", err)
	}
	switch ack.Status {
	case "pending", "accepted", "duplicate":
	default:
		_ = os.Remove(keyFile)
		code := ""
		if ack.Error != nil {
			code = *ack.Error
		}
		return nil, fmt.Errorf("gateway answered %s %s (key removed). A code works once and only until it expires; create a new one in the dashboard", ack.Status, code)
	}
	st := &State{GatewayURL: cl.URL, GatewayName: o.GatewayName, Pin: strings.ToLower(o.Pin), KeyID: keyid, KeyFile: keyFile, Fingerprint: fp,
		Hostname: host, EnrolledAt: msg.FormatTime(now())}
	if err := saveState(o.Dir, st); err != nil {
		return nil, err
	}
	fmt.Fprintln(o.Out, "enrolment received by the gateway; confirm the agent in the dashboard (Server > Agents), then start `schild-agent run`.")
	return st, nil
}

// Agent runs checks and delivers reports.
type Agent struct {
	State    *State
	Signer   dsse.Signer
	Client   *Client
	Env      hostcheck.Env
	Apps     []string
	Version  string
	Interval time.Duration
	Log      *slog.Logger
	Now      func() time.Time
	// Backoff tuning (tests).
	BaseDelay, MaxDelay time.Duration
	sleep               func(ctx context.Context, d time.Duration) bool

	// last is the previous report of this process (logs.large_file growth
	// per day). The agent keeps no reports on disk.
	mu   sync.Mutex
	last *hc.Report
}

// New loads key and state from dir.
func New(dir string, log *slog.Logger) (*Agent, error) {
	st, err := LoadState(dir)
	if err != nil {
		return nil, err
	}
	signer, err := keys.LoadSigner(st.KeyID, st.KeyFile)
	if err != nil {
		return nil, err
	}
	if keys.Release && keys.IsTestKey(st.KeyID, signer.Public()) {
		return nil, errors.New("release builds refuse test keys")
	}
	if log == nil {
		log = slog.Default()
	}
	warnKeyMode(log, st.KeyFile)
	cl, err := NewClient(st.GatewayURL, st.Pin)
	if err != nil {
		return nil, err
	}
	iv := 24 * time.Hour
	if st.IntervalMinutes > 0 {
		iv = time.Duration(st.IntervalMinutes) * time.Minute
	}
	return &Agent{State: st, Signer: signer, Client: cl, Env: hostcheck.OSEnv{}, Apps: st.Apps, Interval: iv, Log: log}, nil
}

// warnKeyMode warns when other users can read or change the agent key:
// with it anybody on this host can sign reports as this agent. enrol and
// init create it with mode 0600; a key passed to init with --key keeps its
// own mode (a warning, not a refusal: the test lab mounts a TEST ONLY key
// read-only with 0644).
func warnKeyMode(log *slog.Logger, path string) {
	st, err := os.Stat(path)
	if err != nil {
		return
	}
	if m := st.Mode().Perm(); m&0o077 != 0 {
		log.Warn("agent key is accessible to other users; anybody who can read it can sign reports as this agent: chmod 600 it",
			"key_file", path, "mode", fmt.Sprintf("%04o", m))
	}
}

func (a *Agent) now() time.Time {
	if a.Now != nil {
		return a.Now().UTC()
	}
	return time.Now().UTC()
}

// Check runs the checks once and returns the marshalled report.
func (a *Agent) Check(ctx context.Context) (*hc.Report, error) {
	a.mu.Lock()
	prev := a.last
	a.mu.Unlock()
	r := hostcheck.Run(ctx, a.Env, hostcheck.Options{Role: hc.RoleAgent, AgentKeyID: a.State.KeyID, Hostname: a.State.Hostname,
		SchildVersion: a.Version, Apps: a.Apps, Previous: prev})
	if _, err := hostcheck.Marshal(r); err != nil {
		// Value-free: contract errors quote the offending value.
		return nil, fmt.Errorf("own host report fails the contract (%s), not sent", contract.SafeDetail(err))
	}
	a.mu.Lock()
	a.last = r
	a.mu.Unlock()
	return r, nil
}

// ErrRejected is returned when the gateway rejected a report; the same
// message is never resent.
var ErrRejected = errors.New("gateway rejected the report")

// RetryError carries the gateway's retry hint.
type RetryError struct{ After time.Duration }

func (e *RetryError) Error() string { return fmt.Sprintf("gateway busy, retry after %s", e.After) }

// Deliver signs the report with a fresh nonce and issued_at and posts it.
func (a *Agent) Deliver(ctx context.Context, r *hc.Report) (*hc.Ack, error) {
	nonce := newNonce()
	p := hc.AgentReport{Schema: hc.SchemaAgentReport, Gateway: a.State.GatewayName, IssuedAt: msg.FormatTime(a.now()), Nonce: nonce, Report: *r}
	payload, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	env, err := dsse.Sign(contract.KindAgentReport.PayloadType(), payload, a.Signer)
	if err != nil {
		return nil, err
	}
	body, _ := env.Marshal()
	ack, err := a.Client.post(ctx, "/v0/agent/report", body, nonce, a.Signer.KeyID())
	if err != nil {
		return nil, err
	}
	switch ack.Status {
	case "accepted", "duplicate":
		return ack, nil
	case "retry":
		return ack, &RetryError{After: time.Duration(min(max(ack.RetryAfterS, 1), 86400)) * time.Second}
	default:
		code := ""
		if ack.Error != nil {
			code = *ack.Error
		}
		return ack, fmt.Errorf("%w: %s %s", ErrRejected, ack.Status, code)
	}
}

func jitter(d time.Duration, frac float64) time.Duration {
	if d <= 0 {
		return 0
	}
	n, _ := rand.Int(rand.Reader, big.NewInt(1000))
	f := 1 - frac + 2*frac*float64(n.Int64())/1000
	return time.Duration(float64(d) * f)
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// RunOnce checks and delivers, retrying with exponential backoff (30 s
// doubling, jitter, capped at MaxDelay and at deadline: the next regular
// run). It re-signs every attempt.
func (a *Agent) RunOnce(ctx context.Context, deadline time.Time) error {
	r, err := a.Check(ctx)
	if err != nil {
		return err
	}
	base, maxD := a.BaseDelay, a.MaxDelay
	if base == 0 {
		base = 30 * time.Second
	}
	if maxD == 0 {
		maxD = time.Hour
	}
	sleep := a.sleep
	if sleep == nil {
		sleep = sleepCtx
	}
	delay := base
	for attempt := 1; ; attempt++ {
		ack, err := a.Deliver(ctx, r)
		if err == nil {
			a.log().Info("host report delivered", "status", ack.Status, "findings", len(r.Findings), "attempt", attempt)
			return nil
		}
		if errors.Is(err, ErrRejected) {
			a.log().Error("host report rejected; not resent", "err", err)
			return err
		}
		wait := jitter(delay, 0.2)
		var re *RetryError
		if errors.As(err, &re) && re.After > wait {
			wait = re.After
		}
		if !deadline.IsZero() && a.now().Add(wait).After(deadline) {
			a.log().Warn("gateway not reachable until the next regular run; giving up this report", "err", err, "attempts", attempt)
			return err
		}
		a.log().Warn("host report not delivered, retrying", "err", err, "attempt", attempt, "retry_in", wait.Round(time.Second))
		if !sleep(ctx, wait) {
			return ctx.Err()
		}
		delay = min(delay*2, maxD)
	}
}

// Run loops: one check and delivery per interval (with up to 10 % jitter so
// many agents do not hit the gateway at the same second).
func (a *Agent) Run(ctx context.Context) error {
	sleep := a.sleep
	if sleep == nil {
		sleep = sleepCtx
	}
	if !sleep(ctx, jitter(time.Minute, 1)/2) {
		return nil
	}
	for {
		next := a.now().Add(a.Interval)
		if err := a.RunOnce(ctx, next); err != nil && ctx.Err() == nil {
			a.log().Warn("run finished without delivery", "err", err)
		}
		wait := time.Until(next) + jitter(a.Interval/10, 1)/2
		if wait < time.Minute {
			wait = time.Minute
		}
		if !sleep(ctx, wait) {
			return nil
		}
	}
}

func (a *Agent) log() *slog.Logger {
	if a.Log != nil {
		return a.Log
	}
	return slog.Default()
}
