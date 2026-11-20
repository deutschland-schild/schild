// Package ingest is the lab's hot path, POST /v0/submit (contracts/auth.md,
// concept 21 §5.0, MVP-03). It does only cheap, bounded work:
//
//  1. size limit, strict JSON, request_id;
//  2. a global in-flight limit (429 rate_limited with a signed ack when hit);
//  3. per envelope: revocation, signature and contract checks through the
//     pluggable authenticator (site key now, tokens in v1), per-key rate
//     limit, per-key and per-issuer daily quota, dedupe by message id;
//  4. tiered admission into the durable queue and one group commit;
//  5. a lab-signed ack - also on 429 and 503, with control.retry_after_ms.
//
// A full queue or a slow disk is answered at once with queue_full and
// retry_after_ms; the handler never waits longer than EnqueueTimeout.
// Scoring, federation and the dashboard run elsewhere.
package ingest

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"hash/fnv"
	"io"
	"log/slog"
	"math"
	"net/http"
	"regexp"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/auth"
	"github.com/deutschland-schild/schild/contract/config"
	"github.com/deutschland-schild/schild/contract/dsse"
	"github.com/deutschland-schild/schild/contract/jsonx"
	"github.com/deutschland-schild/schild/contract/keys"
	"github.com/deutschland-schild/schild/contract/msg"
	"github.com/deutschland-schild/schild/contract/verify"
	"github.com/deutschland-schild/schild/lab/internal/latency"
	"github.com/deutschland-schild/schild/lab/internal/queue"
	"github.com/deutschland-schild/schild/relay/metrics"
)

// Settings that the dashboard may change at runtime.
type Settings struct {
	MaxBodyBytes        int
	MaxEnvelopes        int
	RatePerClientPerMin int
	RetryAfterMS        int
	ReplayWindowS       int
	MinScore            int
}

// Metrics of ingest.
type Metrics struct {
	Ack        *metrics.HistogramVec // seconds, by status
	Envelopes  *metrics.CounterVec   // by result
	RetryAfter *metrics.CounterVec   // by reason
}

// NewMetrics registers ingest metrics.
func NewMetrics(r *metrics.Registry) *Metrics {
	return &Metrics{
		Ack:        r.Histogram("schild_lab_ack_seconds", "Time from request start to the signed ack being written (EventAck, B13).", metrics.LatencyBuckets, "status"),
		Envelopes:  r.Counter("schild_lab_ingest_envelopes_total", "Envelopes by result (accepted, duplicate, rejected_<reason>, deferred_<reason>).", "result"),
		RetryAfter: r.Counter("schild_lab_ingest_retry_after_total", "Acks with retry_after_ms > 0, by reason.", "reason"),
	}
}

type clientInfo struct {
	issuer string
	quota  int64
}

type access struct {
	trust          *keys.TrustStore
	clients        map[string]clientInfo // non-revoked keys
	revokedKeys    map[string]bool       // revoked keys or keys of revoked issuers
	issuerQuota    map[string]int64
	revokedIssuers map[string]bool
}

// Ingest serves POST /v0/submit.
type Ingest struct {
	Lab            string
	Signer         *keys.Signer // purpose ack
	Q              *queue.Queue
	Auth           auth.Authenticator
	Log            *slog.Logger
	Metrics        *Metrics
	Now            func() time.Time
	EnqueueTimeout time.Duration
	// AdmitWait is how long a request may wait for a verification slot
	// before it is answered with rate_limited (default 15 ms).
	AdmitWait time.Duration
	// OnEnqueued is called after a successful commit (wakes the scorer).
	OnEnqueued func()

	settings atomic.Pointer[Settings]
	acc      atomic.Pointer[access]
	sem      chan struct{}
	limiter  [64]bucketShard
	known    sync.Map // action_sig -> struct{}

	Window *latency.Window
	Rate   *latency.Rate
	mu     sync.Mutex
	stats  map[string]*latency.Day // accepted, duplicate, rejected, retry_after, rejected:<reason>
	keyUse map[string]*use
	issUse map[string]*use
}

type use struct {
	accepted latency.Day
	rejected latency.Day
	lastTB   string
}

// New returns an ingest handler. maxInFlight bounds concurrent requests.
func New(lab string, signer *keys.Signer, q *queue.Queue, s Settings, maxInFlight int, log *slog.Logger, m *Metrics) *Ingest {
	if maxInFlight <= 0 {
		// Verification is CPU-bound: more requests in flight than about
		// twice the cores only add queueing delay to every ack.
		maxInFlight = max(2*runtime.GOMAXPROCS(0), 8)
	}
	in := &Ingest{Lab: lab, Signer: signer, Q: q, Auth: auth.SiteKeyAuthenticator{}, Log: log, Metrics: m, Now: time.Now,
		EnqueueTimeout: 500 * time.Millisecond, AdmitWait: 15 * time.Millisecond, sem: make(chan struct{}, maxInFlight),
		Window: latency.New(nil), Rate: latency.NewRate(nil), stats: map[string]*latency.Day{}, keyUse: map[string]*use{}, issUse: map[string]*use{}}
	for i := range in.limiter {
		in.limiter[i].m = map[string]*bucket{}
	}
	in.SetSettings(s)
	in.acc.Store(&access{trust: keys.NewTrustStore(), clients: map[string]clientInfo{}, revokedKeys: map[string]bool{}, issuerQuota: map[string]int64{}, revokedIssuers: map[string]bool{}})
	return in
}

// SetSettings replaces runtime settings.
func (in *Ingest) SetSettings(s Settings) {
	if s.MaxEnvelopes <= 0 || s.MaxEnvelopes > 64 {
		s.MaxEnvelopes = 64
	}
	if s.MaxBodyBytes <= 0 || s.MaxBodyBytes > contract.MaxSubmissionBytes {
		s.MaxBodyBytes = contract.MaxSubmissionBytes
	}
	if s.RetryAfterMS <= 0 {
		s.RetryAfterMS = 5000
	}
	if s.RatePerClientPerMin <= 0 {
		s.RatePerClientPerMin = 600
	}
	if s.ReplayWindowS <= 0 {
		s.ReplayWindowS = int(contract.MaxSignalAge.Seconds())
	}
	in.settings.Store(&s)
}

// Settings returns the runtime settings.
func (in *Ingest) Settings() Settings { return *in.settings.Load() }

// SetClients rebuilds the admitted keys from lab.yaml clients[] and issuers[]
// (and runtime revocations from the dashboard).
func (in *Ingest) SetClients(clients []config.Client, issuers []config.Issuer) error {
	a := &access{clients: map[string]clientInfo{}, revokedKeys: map[string]bool{}, issuerQuota: map[string]int64{}, revokedIssuers: map[string]bool{}}
	for _, i := range issuers {
		q := int64(100000)
		if i.QuotaPerDay != nil {
			q = int64(*i.QuotaPerDay)
		}
		a.issuerQuota[i.ID] = q
		if i.Revoked {
			a.revokedIssuers[i.ID] = true
		}
	}
	cfg := config.LabConfig{Issuers: issuers, Clients: clients}
	ts, err := cfg.ClientTrustStore()
	if err != nil {
		return err
	}
	a.trust = ts
	for _, c := range clients {
		if c.Revoked || a.revokedIssuers[c.Issuer] {
			a.revokedKeys[c.KeyID] = true
			continue
		}
		q := int64(500)
		if c.QuotaPerDay != nil {
			q = int64(*c.QuotaPerDay)
		}
		a.clients[c.KeyID] = clientInfo{issuer: c.Issuer, quota: q}
	}
	in.acc.Store(a)
	return nil
}

// --- rate limiting -----------------------------------------------------------

type bucket struct {
	tokens float64
	last   time.Time
}

type bucketShard struct {
	mu sync.Mutex
	m  map[string]*bucket
}

// allow takes one token for key; it returns the wait until a token is free
// when none is left.
func (in *Ingest) allow(key string, perMin int, now time.Time) (bool, time.Duration) {
	h := fnv.New32a()
	h.Write([]byte(key))
	sh := &in.limiter[h.Sum32()%uint32(len(in.limiter))]
	rate := float64(perMin) / 60
	burst := math.Max(float64(perMin), 1)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	b := sh.m[key]
	if b == nil {
		b = &bucket{tokens: burst, last: now}
		sh.m[key] = b
	}
	b.tokens = math.Min(burst, b.tokens+now.Sub(b.last).Seconds()*rate)
	b.last = now
	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}
	return false, time.Duration((1 - b.tokens) / rate * float64(time.Second))
}

// --- stats ------------------------------------------------------------------

func (in *Ingest) count(name string, n int64, now time.Time) {
	if n == 0 {
		return
	}
	in.mu.Lock()
	d := in.stats[name]
	if d == nil {
		d = &latency.Day{}
		in.stats[name] = d
	}
	in.mu.Unlock()
	d.Add(now, n)
}

func (in *Ingest) useOf(m map[string]*use, k string) *use {
	in.mu.Lock()
	defer in.mu.Unlock()
	u := m[k]
	if u == nil {
		u = &use{}
		m[k] = u
	}
	return u
}

// Stats24h returns a counter of the last 24 h.
func (in *Ingest) Stats24h(name string) int64 {
	in.mu.Lock()
	d := in.stats[name]
	in.mu.Unlock()
	if d == nil {
		return 0
	}
	return d.Sum(in.Now())
}

// RejectedByReason returns rejected counts of the last 24 h by reason.
func (in *Ingest) RejectedByReason() map[string]int64 {
	in.mu.Lock()
	names := make([]string, 0)
	for k := range in.stats {
		names = append(names, k)
	}
	in.mu.Unlock()
	out := map[string]int64{}
	for _, k := range names {
		if r, ok := cutPrefix(k, "rejected:"); ok {
			if n := in.Stats24h(k); n > 0 {
				out[r] = n
			}
		}
	}
	return out
}

func cutPrefix(s, p string) (string, bool) {
	if len(s) >= len(p) && s[:len(p)] == p {
		return s[len(p):], true
	}
	return "", false
}

// KeyUsage returns accepted signals of a key in the last 24 h and the last time bucket.
func (in *Ingest) KeyUsage(keyid string) (int64, string) {
	in.mu.Lock()
	u := in.keyUse[keyid]
	in.mu.Unlock()
	if u == nil {
		return 0, ""
	}
	in.mu.Lock()
	tb := u.lastTB
	in.mu.Unlock()
	return u.accepted.Sum(in.Now()), tb
}

// IssuerUsage returns accepted and rejected envelopes of an issuer in 24 h.
func (in *Ingest) IssuerUsage(issuer string) (int64, int64) {
	in.mu.Lock()
	u := in.issUse[issuer]
	in.mu.Unlock()
	if u == nil {
		return 0, 0
	}
	now := in.Now()
	return u.accepted.Sum(now), u.rejected.Sum(now)
}

// acquire takes an in-flight slot, waiting at most AdmitWait.
func (in *Ingest) acquire() bool {
	select {
	case in.sem <- struct{}{}:
		return true
	default:
	}
	if in.AdmitWait <= 0 {
		return false
	}
	t := time.NewTimer(in.AdmitWait)
	defer t.Stop()
	select {
	case in.sem <- struct{}{}:
		return true
	case <-t.C:
		return false
	}
}

// --- handler -----------------------------------------------------------------

var uuidRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

// ackReasons are the rejection reasons allowed in an ack.
var ackReasons = map[contract.Code]bool{
	contract.CodeOversize: true, contract.CodeMalformed: true, contract.CodeEnvelope: true, contract.CodePayloadType: true,
	contract.CodeSignature: true, contract.CodeForbiddenField: true, contract.CodeSchema: true, contract.CodeClockSkew: true,
	contract.CodeExpired: true, contract.CodeReplay: true, contract.CodeTestKey: true,
}

type peek struct {
	PayloadType string `json:"payloadType"`
	Payload     string `json:"payload"`
	Signatures  []struct {
		KeyID string `json:"keyid"`
	} `json:"signatures"`
}

func messageID(p *peek) string {
	b, err := base64.StdEncoding.DecodeString(p.Payload)
	if err != nil {
		return msg.NilID
	}
	var v struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(b, &v) != nil || !uuidRe.MatchString(v.ID) {
		return msg.NilID
	}
	return v.ID
}

func problem(w http.ResponseWriter, status int, code, detail string) {
	b, _ := json.Marshal(map[string]any{"type": "about:blank", "title": http.StatusText(status), "status": status, "code": code, "detail": detail})
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	w.Write(b)
}

type outcome struct {
	accepted, duplicate []string
	rejected            []msg.Rejected
	queueFull           bool
	rateLimited         bool
	rateWait            time.Duration
}

// ServeHTTP handles POST /v0/submit.
func (in *Ingest) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		problem(w, http.StatusMethodNotAllowed, "invalid", "POST only")
		return
	}
	s := in.Settings()
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, int64(s.MaxBodyBytes)))
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			problem(w, http.StatusRequestEntityTooLarge, string(contract.CodeOversize), "submission too large")
			return
		}
		problem(w, http.StatusBadRequest, string(contract.CodeMalformed), "unreadable body")
		return
	}
	if _, err := jsonx.ParseObject(body); err != nil {
		problem(w, http.StatusBadRequest, string(contract.CodeMalformed), "submission is not strict JSON")
		return
	}
	var sub msg.Submission
	if err := json.Unmarshal(body, &sub); err != nil || !uuidRe.MatchString(sub.RequestID) {
		problem(w, http.StatusBadRequest, string(contract.CodeSchema), "submission needs request_id (uuid v4) and envelopes")
		return
	}
	if len(sub.Envelopes) < 1 || len(sub.Envelopes) > s.MaxEnvelopes {
		problem(w, http.StatusBadRequest, string(contract.CodeSchema), "1..max_batch envelopes per submission")
		return
	}
	var out outcome
	if in.acquire() {
		var finish func(*outcome)
		out, finish = in.process(r.Context(), sub.Envelopes, r.Header.Get("Authorization"), s)
		<-in.sem // the slot covers CPU work only, not the wait for the disk
		finish(&out)
	} else {
		// Overloaded: answer at once instead of queueing for CPU.
		out.rateLimited = true
		out.rateWait = 250 * time.Millisecond
	}
	in.respond(w, sub.RequestID, out, s, start)
}

// process verifies and hands admitted items to the queue writer; the
// returned finish waits for the group commit and fills in accepted ids.
func (in *Ingest) process(ctx context.Context, envs []json.RawMessage, authz string, s Settings) (outcome, func(*outcome)) {
	now := in.Now().UTC()
	acc := in.acc.Load()
	vctx := &verify.Context{Now: now, Trust: acc.trust}
	out := outcome{accepted: []string{}, duplicate: []string{}, rejected: []msg.Rejected{}}
	var items []queue.Item
	reject := func(id string, code contract.Code, issuer string) {
		if !ackReasons[code] && code != "quota" && code != "revoked" {
			code = contract.CodeSchema
		}
		out.rejected = append(out.rejected, msg.Rejected{ID: id, Reason: string(code)})
		in.count("rejected:"+string(code), 1, now)
		if issuer != "" {
			in.useOf(in.issUse, issuer).rejected.Add(now, 1)
		}
	}
	for _, raw := range envs {
		var p peek
		if err := json.Unmarshal(raw, &p); err != nil {
			reject(msg.NilID, contract.CodeMalformed, "")
			continue
		}
		id := messageID(&p)
		var kind contract.Kind
		switch p.PayloadType {
		case contract.KindSignal.PayloadType():
			kind = contract.KindSignal
		case contract.KindFeedback.PayloadType():
			kind = contract.KindFeedback
		default:
			reject(id, contract.CodePayloadType, "")
			continue
		}
		if len(p.Signatures) == 1 && acc.revokedKeys[p.Signatures[0].KeyID] {
			reject(id, "revoked", "")
			continue
		}
		res, sender, err := in.Auth.Open(ctx, kind, raw, authz, vctx)
		if err != nil {
			code := contract.CodeOf(err)
			if code == "" {
				code = contract.CodeSignature
			}
			reject(id, code, "")
			continue
		}
		var msgID, tb string
		var score int
		var actionSig string
		switch v := res.Value.(type) {
		case *msg.Signal:
			msgID, tb, score, actionSig = v.ID, v.TimeBucket, v.Score, v.ActionSig
		case *msg.Feedback:
			msgID, tb = v.ID, v.TimeBucket
		}
		ci := acc.clients[sender.KeyID]
		if acc.revokedIssuers[sender.Issuer] {
			reject(msgID, "revoked", sender.Issuer)
			continue
		}
		if ok, wait := in.allow(sender.KeyID, s.RatePerClientPerMin, now); !ok {
			out.rateLimited = true
			out.rateWait = max(out.rateWait, wait)
			in.count("deferred:rate_limited", 1, now)
			continue
		}
		ku, iu := in.useOf(in.keyUse, sender.KeyID), in.useOf(in.issUse, sender.Issuer)
		if ci.quota >= 0 && ku.accepted.Sum(now) >= ci.quota || iu.accepted.Sum(now) >= acc.issuerQuota[sender.Issuer] {
			reject(msgID, "quota", sender.Issuer)
			continue
		}
		bucketAt, _ := msg.ParseTime(tb)
		exp := bucketAt.Add(time.Duration(s.ReplayWindowS)*time.Second + contract.MaxClockSkew).Unix()
		if !in.Q.Reserve(msgID, exp) {
			out.duplicate = append(out.duplicate, msgID)
			continue
		}
		prio := queue.Repeat
		if kind == contract.KindSignal {
			switch {
			case score < s.MinScore:
				prio = queue.Baseline
			default:
				if _, known := in.known.Load(actionSig); !known {
					prio = queue.NewPattern
				}
			}
		}
		if !in.Q.TryAdmit(prio, 1) {
			in.Q.Release(msgID)
			out.queueFull = true
			continue
		}
		items = append(items, queue.Item{Prio: prio, Kind: string(kind), ID: msgID, ReceivedMS: now.UnixMilli(), Issuer: sender.Issuer,
			KeyID: sender.KeyID, Expires: exp, Payload: res.Payload})
	}
	if len(items) == 0 {
		return out, func(*outcome) {}
	}
	wait := in.commit(items)
	return out, func(out *outcome) {
		if !wait() {
			out.queueFull = true
			return
		}
		for _, it := range items {
			out.accepted = append(out.accepted, it.ID)
			in.useOf(in.keyUse, it.KeyID).accepted.Add(now, 1)
			in.useOf(in.issUse, it.Issuer).accepted.Add(now, 1)
			if it.Kind == string(contract.KindSignal) {
				var a struct {
					ActionSig  string `json:"action_sig"`
					TimeBucket string `json:"time_bucket"`
				}
				if json.Unmarshal(it.Payload, &a) == nil {
					in.known.Store(a.ActionSig, struct{}{})
					u := in.useOf(in.keyUse, it.KeyID)
					in.mu.Lock()
					u.lastTB = a.TimeBucket
					in.mu.Unlock()
				}
			}
		}
		if in.OnEnqueued != nil {
			in.OnEnqueued()
		}
	}
}

// commit hands admitted items to the writer; the returned wait blocks at
// most EnqueueTimeout for the group commit.
func (in *Ingest) commit(items []queue.Item) func() bool {
	done, err := in.Q.EnqueueAdmitted(items)
	if err != nil {
		in.Q.Unadmit(len(items))
		for _, it := range items {
			in.Q.Release(it.ID)
		}
		return func() bool { return false }
	}
	return func() bool { return in.wait(done) }
}

func (in *Ingest) wait(done <-chan error) bool {
	t := time.NewTimer(in.EnqueueTimeout)
	defer t.Stop()
	select {
	case err := <-done:
		return err == nil // on error the writer released the ids
	case <-t.C:
		// Not confirmed in time: answer queue_full now. The ids stay
		// reserved; if the write lands, a retry is reported as duplicate
		// (stored), if it fails the writer releases them.
		in.Log.Warn("queue commit slower than the enqueue timeout", "timeout", in.EnqueueTimeout)
		return false
	}
}

func (in *Ingest) respond(w http.ResponseWriter, requestID string, out outcome, s Settings, start time.Time) {
	now := in.Now().UTC()
	if out.accepted == nil {
		out.accepted, out.duplicate, out.rejected = []string{}, []string{}, []msg.Rejected{}
	}
	ctl := msg.Control{RetryAfterMS: 0, MaxBatch: s.MaxEnvelopes, Reason: "ok"}
	status := http.StatusOK
	switch {
	case out.queueFull:
		ctl.Reason, ctl.RetryAfterMS, status = "queue_full", s.RetryAfterMS, http.StatusServiceUnavailable
	case out.rateLimited:
		ctl.Reason, status = "rate_limited", http.StatusTooManyRequests
		ctl.RetryAfterMS = int(min(max(out.rateWait.Milliseconds(), 1), 600000))
	}
	ack := msg.Ack{Schema: msg.SchemaAck, Lab: in.Lab, IssuedAt: msg.FormatTime(now), InReplyTo: requestID,
		Accepted: out.accepted, Duplicate: out.duplicate, Rejected: out.rejected, Control: ctl}
	payload, err := jsonx.Marshal(&ack)
	var body []byte
	if err == nil {
		var env *dsse.Envelope
		if env, err = dsse.Sign(contract.KindAck.PayloadType(), payload, in.Signer); err == nil {
			body, err = env.Marshal()
		}
	}
	if err != nil {
		in.Log.Error("ack signing failed", "err", err)
		problem(w, http.StatusInternalServerError, "internal", "ack could not be signed")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if ctl.RetryAfterMS > 0 {
		w.Header().Set("Retry-After", itoa(int(math.Ceil(float64(ctl.RetryAfterMS)/1000))))
	}
	w.WriteHeader(status)
	w.Write(body)
	d := time.Since(start)
	in.Window.Observe(d)
	n := int64(len(out.accepted))
	in.Rate.Add(int(n))
	in.count("accepted", n, now)
	in.count("duplicate", int64(len(out.duplicate)), now)
	in.count("rejected", int64(len(out.rejected)), now)
	if ctl.RetryAfterMS > 0 {
		in.count("retry_after", 1, now)
	}
	if m := in.Metrics; m != nil {
		m.Ack.With(itoa(status)).Observe(d.Seconds())
		m.Envelopes.With("accepted").Add(float64(n))
		m.Envelopes.With("duplicate").Add(float64(len(out.duplicate)))
		for _, rj := range out.rejected {
			m.Envelopes.With("rejected_" + rj.Reason).Inc()
		}
		if ctl.RetryAfterMS > 0 {
			m.RetryAfter.With(ctl.Reason).Inc()
		}
	}
}

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}
