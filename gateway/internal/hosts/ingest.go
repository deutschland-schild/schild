package hosts

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/dsse"
	hc "github.com/deutschland-schild/schild/contract/hostcheck"
	"github.com/deutschland-schild/schild/contract/msg"
	"github.com/deutschland-schild/schild/contract/verify"
	"github.com/deutschland-schild/schild/gateway/internal/hostcheck"
	"github.com/deutschland-schild/schild/gateway/internal/ratelog"
)

// zeroNonce answers requests whose nonce cannot be read.
var zeroNonce = strings.Repeat("0", 32)

// Handler serves the agent listener: POST /v0/agent/report,
// POST /v0/agent/enrol, GET /healthz. Nothing else; the answer is always an
// ack, never an instruction.
func (g *Gateway) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v0/agent/report", g.serveReport)
	mux.HandleFunc("POST /v0/agent/enrol", g.serveEnrol)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok\n") })
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { http.Error(w, "not found", http.StatusNotFound) })
	return mux
}

// ErrNoListen: host_check.agents.listen is not set. There is no default
// address: the operator picks the (private) interface explicitly.
var ErrNoListen = errors.New("host_check.agents.listen is not set; the agent listener does not start without an explicit address (bind it to the interface the app VMs reach, firewall it from everything else)")

// Server returns the TLS server of the agent listener, or ErrNoListen.
func (g *Gateway) Server() (*http.Server, error) {
	hc := g.cfg().HostCheck
	if hc == nil || hc.Agents.Listen == "" {
		return nil, ErrNoListen
	}
	l := g.lim
	return &http.Server{Addr: hc.Agents.Listen, Handler: g.Handler(),
		// Headers (and the TLS handshake, which uses the smallest of these
		// timeouts) within HeaderTimeout; the body deadline is set per
		// request from its length and MinBodyRate.
		ReadHeaderTimeout: l.HeaderTimeout, ReadTimeout: 0, WriteTimeout: 30 * time.Second, IdleTimeout: l.IdleTimeout,
		MaxHeaderBytes: 8 << 10, TLSConfig: tlsConfig(g.cert), ConnState: trackConnState,
		ErrorLog: slogErrorLog(g.log)}, nil
}

// ListenAndServeTLS serves srv behind the connection limits. It returns
// when the listener fails or srv is shut down.
func (g *Gateway) ListenAndServeTLS(srv *http.Server) error {
	ln, err := net.Listen("tcp", srv.Addr)
	if err != nil {
		return err
	}
	g.conns = newLimitListener(ln, g.lim.MaxConns, g.lim.MaxConnsPerPeer)
	return srv.ServeTLS(g.conns, "", "")
}

// ack writes the answer. HTTP status per host-check.md section 6.
func (g *Gateway) ack(w http.ResponseWriter, status, nonce, code string, retry int) {
	g.ackHTTP(w, status, nonce, code, retry, 0)
}

// ackHTTP is ack with an explicit HTTP status (411 for a missing
// Content-Length); httpStatus 0 maps as usual.
func (g *Gateway) ackHTTP(w http.ResponseWriter, status, nonce, code string, retry, httpStatus int) {
	a := hc.Ack{Schema: hc.SchemaAck, Status: status, Nonce: nonce, ReceivedAt: msg.FormatTime(g.now())}
	if !nonceRe(nonce) {
		a.Nonce = zeroNonce
	}
	if status == "rejected" {
		a.Error = &code
	}
	http := 200
	switch status {
	case "retry":
		a.RetryAfterS = retry
		http = 503
		if code == "rate" {
			http = 429
		}
		w.Header().Set("Retry-After", strconv.Itoa(retry))
	case "rejected":
		switch code {
		case string(contract.CodeOversize):
			http = 413
		case string(contract.CodeSignature):
			http = 401
		case string(contract.CodeRevoked), string(contract.CodeTestKey):
			http = 403
		case string(contract.CodeReplay), "enrolment_code":
			http = 409
		default:
			http = 400
		}
	}
	if httpStatus != 0 {
		http = httpStatus
	}
	b, _ := json.Marshal(a)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http)
	_, _ = w.Write(b)
}

func nonceRe(s string) bool {
	if len(s) != 32 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// peekNonce reads the nonce from an unverified envelope (only to address
// the ack; nothing is trusted from it).
func peekNonce(raw []byte) (nonce, keyid, digest string) {
	var env dsse.Envelope
	if json.Unmarshal(raw, &env) != nil {
		return "", "", ""
	}
	if len(env.Signatures) > 0 {
		keyid = env.Signatures[0].KeyID
	}
	p, err := env.DecodePayload()
	if err != nil {
		return "", keyid, ""
	}
	var x struct {
		Nonce string `json:"nonce"`
	}
	_ = json.Unmarshal(p, &x)
	sum := sha256.Sum256(p)
	return x.Nonce, keyid, hex.EncodeToString(sum[:])
}

func (g *Gateway) acquire() bool {
	select {
	case g.sem <- struct{}{}:
		return true
	default:
		return false
	}
}

func (g *Gateway) release() { <-g.sem }

// bodyResult of readBody.
type bodyResult int

const (
	bodyOK bodyResult = iota
	bodyNoLength
	bodyOversize
	bodyBusy
	bodyBroken
)

// readBody reads a request body only when it is affordable: the
// Content-Length must be declared and at most max, and that many bytes must
// fit into the body budget (pool), which stays reserved until done is
// called. The body must arrive at MinBodyRate. Nothing is read otherwise.
func (g *Gateway) readBody(w http.ResponseWriter, r *http.Request, max int, pool *budget) (raw []byte, done func(), res bodyResult) {
	n := r.ContentLength
	switch {
	case n < 0:
		return nil, nil, bodyNoLength
	case n > int64(max):
		return nil, nil, bodyOversize
	}
	if !pool.take(n) {
		return nil, nil, bodyBusy
	}
	done = func() { pool.give(n) }
	rc := http.NewResponseController(w)
	_ = rc.SetReadDeadline(time.Now().Add(2*time.Second + time.Duration(n*int64(time.Second)/g.lim.MinBodyRate)))
	buf := make([]byte, n)
	if _, err := io.ReadFull(http.MaxBytesReader(w, r.Body, n), buf); err != nil {
		done()
		return nil, nil, bodyBroken
	}
	// The deadline is for the body only. Once the body is read, net/http
	// watches the connection with a background read; a deadline that
	// expired then would cancel the request's context during the
	// verification and the store write (a busy store waits up to 10 s).
	_ = rc.SetReadDeadline(time.Time{})
	return buf, done, bodyOK
}

// closeAfter makes the server close the connection after the answer when
// the body was not read (no draining of attacker-sized bodies).
func closeAfter(w http.ResponseWriter) { w.Header().Set("Connection", "close") }

// codes that come after the signature check in the verification order: the
// sender is known, so the rejection can be shown at its host.
var afterSignature = map[string]bool{string(contract.CodeRevoked): true, string(contract.CodeForbiddenField): true, string(contract.CodeForbiddenContent): true,
	string(contract.CodeSchema): true, string(contract.CodeClockSkew): true, string(contract.CodeExpired): true, string(contract.CodeChannel): true, string(contract.CodeReplay): true}

func (g *Gateway) serveReport(w http.ResponseWriter, r *http.Request) {
	now := g.now()
	peer := peerKey(r)
	// An enrolled agent names its key in a header: its own request budget
	// and a reserved slice of the body budget, so a flood from other
	// addresses does not keep it in retry. The header is only a hint; the
	// signature decides, and a mismatch is charged to the address too.
	lane := ""
	if k := r.Header.Get(AgentKeyHeader); k != "" && len(k) <= 128 {
		if a, err := g.agent(r.Context(), "keyid", k); err == nil && a.Status == "enrolled" {
			lane = a.ID
		}
	}
	rateKey, rateMax, pool := peer, g.lim.PeerRequests, g.bodies
	if lane != "" {
		rateKey, rateMax, pool = "agent:"+lane, g.lim.AgentRequests, g.laneBodies
	}
	if !g.limits.allow(rateKey, now, rateMax) {
		closeAfter(w)
		g.ack(w, "retry", "", "rate", 60)
		return
	}
	raw, done, res := g.readBody(w, r, contract.LimitsFor(contract.KindAgentReport).MaxEnvelopeBytes, pool)
	switch res {
	case bodyNoLength:
		closeAfter(w)
		g.ackHTTP(w, "rejected", "", string(contract.CodeMalformed), 0, http.StatusLengthRequired)
		return
	case bodyOversize:
		closeAfter(w)
		g.ack(w, "rejected", "", string(contract.CodeOversize), 0)
		return
	case bodyBusy:
		// Busy is the gateway's state, not the sender's doing: not counted.
		g.limits.refund(rateKey)
		closeAfter(w)
		g.ack(w, "retry", "", "", 30)
		return
	case bodyBroken:
		closeAfter(w)
		g.ack(w, "rejected", "", string(contract.CodeMalformed), 0)
		return
	}
	defer done()
	nonce, keyid, digest := peekNonce(raw)
	if !g.acquire() {
		g.limits.refund(rateKey)
		g.ack(w, "retry", nonce, "", 30)
		return
	}
	defer g.release()
	ctx := r.Context()
	status, code, detail := g.Ingest(ctx, raw)
	signedByEnrolled := status == "accepted" || status == "duplicate" || (code != "" && afterSignature[code])
	if code != "" && afterSignature[code] {
		if a, err := g.agent(ctx, "keyid", keyid); err == nil {
			g.recordReject(ctx, a.ID, code, detail)
		}
	}
	switch {
	case lane != "" && (!signedByEnrolled || keyid != r.Header.Get(AgentKeyHeader)):
		// A lane claim the signature does not back: the address pays too.
		g.limits.allow(peer, now, g.lim.PeerRequests)
	case lane == "" && signedByEnrolled && status != "retry":
		// An enrolled agent without the header (older agent): its request
		// moves from the address budget to the agent's.
		// Once the agent's own budget is used up, the address keeps the
		// charge (no way around both budgets by leaving the header out).
		if a, err := g.agent(ctx, "keyid", keyid); err == nil && g.limits.allow("agent:"+a.ID, now, g.lim.AgentRequests) {
			g.limits.refund(peer)
		}
	}
	if status == "retry" {
		g.limits.refund(rateKey)
	}
	if code == string(contract.CodeReplay) {
		// The same message again (ack lost): duplicate, not an attack.
		if d, ok := g.nonceDigest(ctx, nonce); ok && d == digest {
			g.ack(w, "duplicate", nonce, "", 0)
			return
		}
	}
	if status == "rejected" {
		ratelog.Warn(g.log, "agent report rejected", "code", code, "detail", detail, "peer", peer)
	}
	g.ack(w, status, nonce, code, 30)
}

// Ingest verifies and stores one agent report envelope. It returns the ack
// status and, when rejected, the contract code.
func (g *Gateway) Ingest(ctx context.Context, raw []byte) (status, code, detail string) {
	if !g.AgentsEnabled() {
		return "rejected", string(contract.CodeSignature), "agents are not enabled on this gateway"
	}
	ts, revoked, err := g.trust(ctx)
	if err != nil {
		ratelog.Error(g.log, "agent trust store", "err", err)
		return "retry", "", ""
	}
	vctx := &verify.Context{Now: g.now(), Trust: ts, Gateway: g.cfg().NodeName,
		Revoked: func(k string) bool { return revoked[k] },
		Seen: func(n string) bool {
			_, ok := g.nonceDigest(ctx, n)
			return ok
		}}
	res, err := verify.Signed(contract.KindAgentReport, raw, vctx)
	if err != nil {
		c := string(contract.CodeOf(err))
		if c == "" {
			c = string(contract.CodeMalformed)
		}
		// Value-free: code and JSON pointer only (contract errors quote
		// the offending value; it must not reach the dashboard or logs).
		return "rejected", c, contract.SafeDetail(err)
	}
	ar := res.Value.(*hc.AgentReport)
	a, err := g.agent(ctx, "keyid", res.Signers[0].KeyID)
	if err != nil || a.Status != "enrolled" {
		return "rejected", string(contract.CodeSignature), "agent not enrolled"
	}
	// The report exactly as signed.
	var p struct {
		Report json.RawMessage `json:"report"`
	}
	if err := json.Unmarshal(res.Payload, &p); err != nil {
		return "rejected", string(contract.CodeMalformed), string(contract.CodeMalformed)
	}
	var buf bytes.Buffer
	if err := json.Compact(&buf, p.Report); err != nil {
		return "rejected", string(contract.CodeMalformed), string(contract.CodeMalformed)
	}
	issued, _ := msg.ParseTime(ar.IssuedAt)
	sum := sha256.Sum256(res.Payload)
	tx, err := g.db.BeginTx(ctx, nil)
	if err != nil {
		return "retry", "", ""
	}
	defer tx.Rollback()
	exp := issued.Add(verify.AgentMessageWindow)
	if exp.Before(g.now().Add(verify.AgentMessageWindow)) {
		exp = g.now().Add(verify.AgentMessageWindow)
	}
	resIns, err := tx.ExecContext(ctx, "INSERT OR IGNORE INTO agent_nonces(nonce, digest, expires_ms) VALUES(?, ?, ?)", ar.Nonce, hex.EncodeToString(sum[:]), ms(exp))
	if err != nil {
		return "retry", "", ""
	}
	if n, _ := resIns.RowsAffected(); n == 0 {
		return "rejected", string(contract.CodeReplay), string(contract.CodeReplay) + " at /nonce"
	}
	if err := g.insertReportTx(ctx, tx, a.ID, &ar.Report, buf.Bytes(), g.now()); err != nil {
		ratelog.Error(g.log, "store agent report", "err", err)
		return "retry", "", ""
	}
	if err := tx.Commit(); err != nil {
		return "retry", "", ""
	}
	if err := g.prune(ctx, a.ID, g.keep()); err != nil {
		ratelog.Warn(g.log, "prune host reports", "err", err)
	}
	g.log.Info("agent report accepted", "agent", a.ID, "findings", len(ar.Report.Findings))
	return "accepted", "", ""
}

func (g *Gateway) insertReport(ctx context.Context, hostID string, r *hc.Report, body []byte, received time.Time) error {
	tx, err := g.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := g.insertReportTx(ctx, tx, hostID, r, body, received); err != nil {
		return err
	}
	return tx.Commit()
}

// insertReportTx stores a report; the same report_id twice (a retry after a
// lost ack, re-signed with a new nonce) is stored once.
func (g *Gateway) insertReportTx(ctx context.Context, tx *sql.Tx, hostID string, r *hc.Report, body []byte, received time.Time) error {
	c := hostcheck.Count(r)
	started, err := msg.ParseTime(r.Run.StartedAt)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT OR IGNORE INTO host_reports(host_id, report_id, started_ms, received_ms, critical, high, medium, low, info, unreadable, body)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, hostID, r.ReportID, ms(started), ms(received), c.Critical, c.High, c.Medium, c.Low, c.Info, c.Unreadable, body)
	return err
}

func (g *Gateway) serveEnrol(w http.ResponseWriter, r *http.Request) {
	peer := peerKey(r)
	if !g.limits.allow("enrol-fail:"+peer, g.now(), 0) || !g.limits.allow("enrol:"+peer, g.now(), g.lim.PeerRequests) {
		closeAfter(w)
		g.ack(w, "retry", "", "rate", 900)
		return
	}
	raw, done, res := g.readBody(w, r, contract.MaxEnrolmentBytes, g.bodies)
	switch res {
	case bodyNoLength:
		closeAfter(w)
		g.ackHTTP(w, "rejected", "", string(contract.CodeMalformed), 0, http.StatusLengthRequired)
		return
	case bodyOversize:
		closeAfter(w)
		g.ack(w, "rejected", "", string(contract.CodeOversize), 0)
		return
	case bodyBusy:
		g.limits.refund("enrol:" + peer)
		closeAfter(w)
		g.ack(w, "retry", "", "", 30)
		return
	case bodyBroken:
		closeAfter(w)
		g.ack(w, "rejected", "", string(contract.CodeMalformed), 0)
		return
	}
	defer done()
	nonce, _, _ := peekNonce(raw)
	if !g.acquire() {
		g.limits.refund("enrol:" + peer)
		g.ack(w, "retry", nonce, "", 30)
		return
	}
	defer g.release()
	status, code, detail := g.Enrol(r.Context(), raw)
	if status == "rejected" {
		g.limits.fail("enrol-fail:"+peer, g.now())
		ratelog.Warn(g.log, "agent enrolment rejected", "code", code, "detail", detail, "peer", peer)
	}
	g.ack(w, status, nonce, code, 30)
}

// Enrol verifies an enrolment request, consumes the one-time code and stores
// the agent as pending.
func (g *Gateway) Enrol(ctx context.Context, raw []byte) (status, code, detail string) {
	if !g.AgentsEnabled() {
		return "rejected", "enrolment_code", "agents are not enabled on this gateway"
	}
	vctx := &verify.Context{Now: g.now(), Gateway: g.cfg().NodeName, Seen: func(n string) bool {
		_, ok := g.nonceDigest(ctx, n)
		return ok
	}}
	res, err := verify.AgentEnrolment(raw, vctx)
	if err != nil {
		c := string(contract.CodeOf(err))
		if c == "" {
			c = string(contract.CodeMalformed)
		}
		return "rejected", c, contract.SafeDetail(err)
	}
	e := res.Enrolment
	tx, err := g.db.BeginTx(ctx, nil)
	if err != nil {
		return "retry", "", ""
	}
	defer tx.Rollback()
	// A key id or public key already known: rejected, the code is not
	// consumed.
	var n int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM host_agents WHERE keyid = ? OR public_key = ?", e.KeyID, e.PublicKey).Scan(&n); err != nil {
		return "retry", "", ""
	}
	if n > 0 {
		return "rejected", "enrolment_code", "key id or public key already known"
	}
	h := codeHash(e.Code)
	var label string
	var expires, used int64
	err = tx.QueryRowContext(ctx, "SELECT label, expires_ms, used_ms FROM host_enrolments WHERE code_hash = ?", h).Scan(&label, &expires, &used)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && (used != 0 || fromMS(expires).Before(g.now()))) {
		return "rejected", "enrolment_code", "unknown, used or expired code"
	}
	if err != nil {
		return "retry", "", ""
	}
	id, err := g.newAgentID(ctx, tx, e.Hostname)
	if err != nil {
		return "retry", "", ""
	}
	fp, _ := fingerprintOf(e.PublicKey)
	now := ms(g.now())
	if _, err := tx.ExecContext(ctx, "INSERT INTO host_agents("+agentCols+") VALUES(?, ?, ?, ?, ?, ?, 'pending', 'code', ?, 0, 0, '')",
		id, e.Hostname, label, e.KeyID, e.PublicKey, fp, now); err != nil {
		return "rejected", "enrolment_code", "key already known"
	}
	if _, err := tx.ExecContext(ctx, "UPDATE host_enrolments SET used_ms = ?, agent_id = ? WHERE code_hash = ? AND used_ms = 0", now, id, h); err != nil {
		return "retry", "", ""
	}
	issued, _ := msg.ParseTime(e.IssuedAt)
	if _, err := tx.ExecContext(ctx, "INSERT OR IGNORE INTO agent_nonces(nonce, digest, expires_ms) VALUES(?, ?, ?)", e.Nonce, res.Digest, ms(issued.Add(verify.AgentMessageWindow))); err != nil {
		return "retry", "", ""
	}
	if err := tx.Commit(); err != nil {
		return "retry", "", ""
	}
	g.log.Info("agent enrolment received, waits for confirmation in the dashboard", "agent", id, "hostname", e.Hostname, "fingerprint", fp)
	return "pending", "", ""
}
