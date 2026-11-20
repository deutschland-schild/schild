// Package rules turns patterns into network rules (MVP-03, MVP-10):
// proposals with evidence, the allowed max action from the evidence level
// (concept 18 G2/G3), human approval with an audit trail, bundle assembly
// and signing, withdrawals and the emergency stop, k-of-n co-signing with
// other labs, and publishing to the lab feed.
//
// Nothing is published without a human: a proposal reaches a bundle only
// after an approval, and its max action never exceeds what the evidence
// allows. Tips from clients alone can never reach more than observe.
//
// Co-signing (k-of-n). A lab signs its part and offers the envelope on its
// feed (GET /v0/collecting). A second operator's lab fetches it (peers
// package), shows it to its operators, and after a human confirmed it signs
// the same payload bytes and posts the signature back (POST /v0/signatures)
// - or an operator does the same offline with `schild-lab cosign`. Every lab
// that holds signatures of k distinct operators publishes; clients accept
// only k distinct operators, however many labs of one operator signed.
package rules

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sort"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/dsse"
	"github.com/deutschland-schild/schild/contract/keys"
	"github.com/deutschland-schild/schild/contract/msg"
	"github.com/deutschland-schild/schild/contract/verify"
	"github.com/deutschland-schild/schild/lab/internal/scoring"
	"github.com/deutschland-schild/schild/lab/internal/store"
)

// Publisher puts published envelopes on the lab feed.
type Publisher interface {
	PublishBundle(version uint64, envelope []byte)
	PublishWithdrawal(seq uint64, envelope []byte)
	Changed() // state changed: re-sign the checkpoint now
}

// Courier sends co-signatures to the lab that proposed an item.
type Courier interface {
	SendSignature(peerLab string, kind contract.Kind, digest string, sig dsse.Signature) error
}

// Error is a domain error with an API problem code and HTTP status.
type Error struct {
	Status  int
	Code    string
	Detail  string
	Pointer string
}

func (e *Error) Error() string { return e.Code + ": " + e.Detail }

func errf(status int, code, pointer, format string, a ...any) *Error {
	return &Error{Status: status, Code: code, Pointer: pointer, Detail: fmt.Sprintf(format, a...)}
}

// Config of the engine.
type Config struct {
	Lab, Operator, Channel string
	// Threshold is k for publishing (distinct operators), floor 2, default 3.
	Threshold int
	// RulesSigner is this lab's key with purpose rules.
	RulesSigner *keys.Signer
	// Trust holds every lab key this lab knows (own and peers) with lab and
	// operator; used to count operators.
	Trust *keys.TrustStore
	// Simulated maps lab ids to simulated operators (test profile only,
	// never in release builds). Independence that exists only through this
	// mapping caps rules at observe (E5).
	Simulated map[string]string
	// MaxMatchShare is the local brake share written into rules (G8).
	MaxMatchShare float64
}

// Engine is the rules state machine. All mutations are serialized.
type Engine struct {
	DB        *store.DB
	Cfg       Config
	Publisher Publisher
	Courier   Courier
	Log       *slog.Logger
	Now       func() time.Time
	// Scoring returns the current scoring thresholds.
	Scoring func() scoring.Config
	// ValidityHours returns the default bundle validity.
	ValidityHours func() int

	mu      sync.Mutex
	checkTS *keys.TrustStore
	checkS  []dsse.Signer
}

// New returns an engine.
func New(db *store.DB, cfg Config, log *slog.Logger) (*Engine, error) {
	if cfg.Threshold == 0 {
		cfg.Threshold = contract.DefaultMinIndependentOperators
	}
	if cfg.Threshold < contract.MinIndependentOperatorsFloor {
		cfg.Threshold = contract.MinIndependentOperatorsFloor
	}
	if cfg.MaxMatchShare <= 0 || cfg.MaxMatchShare > 0.05 {
		cfg.MaxMatchShare = 0.001
	}
	if keys.Release && len(cfg.Simulated) > 0 {
		return nil, errors.New("rules: simulated operators are not available in release builds")
	}
	e := &Engine{DB: db, Cfg: cfg, Log: log, Now: time.Now,
		Scoring: func() scoring.Config {
			return scoring.Config{MinIssuers: 3, MaxIssuerShare: 0.34, WindowMinutes: 1440, MinScore: 40}
		},
		ValidityHours: func() int { return 168 }}
	// Two throwaway keys of two throwaway operators: they let the contract
	// verifier (threshold floor 2) run every semantic check on a payload
	// before this lab signs it.
	e.checkTS = keys.NewTrustStore()
	for i := 1; i <= 2; i++ {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		id := fmt.Sprintf("selfcheck-%d", i)
		s, err := keys.NewSigner(id, priv)
		if err != nil {
			return nil, err
		}
		if err := e.checkTS.Add(keys.TrustedKey{KeyID: id, Public: s.Public(), Purposes: []contract.Purpose{contract.PurposeRules}, Operator: id, Lab: id}); err != nil {
			return nil, err
		}
		e.checkS = append(e.checkS, s)
	}
	return e, nil
}

// SetSimulated replaces the simulated operator mapping (tests).
func (e *Engine) operatorOf(k *keys.TrustedKey) string {
	if op, ok := e.Cfg.Simulated[k.Lab]; ok && !keys.Release {
		return op
	}
	return k.Operator
}

func (e *Engine) operatorOfLab(lab, real string) string {
	if op, ok := e.Cfg.Simulated[lab]; ok && !keys.Release {
		return op
	}
	return real
}

// selfCheck runs the full contract verification of a payload.
func (e *Engine) selfCheck(kind contract.Kind, payload []byte, now time.Time) (*verify.Result, error) {
	env, err := dsse.Sign(kind.PayloadType(), payload, e.checkS...)
	if err != nil {
		return nil, err
	}
	raw, err := env.Marshal()
	if err != nil {
		return nil, err
	}
	return verify.Signed(kind, raw, &verify.Context{Now: now, Trust: e.checkTS, Threshold: 2, Channel: e.Cfg.Channel, SkipState: true})
}

// verifyCtx is the context for real envelopes on this lab's channel.
func (e *Engine) verifyCtx(now time.Time, simulated bool) *verify.Context {
	c := &verify.Context{Now: now, Trust: e.Cfg.Trust, Threshold: e.Cfg.Threshold, Channel: e.Cfg.Channel, SkipState: true}
	if simulated && len(e.Cfg.Simulated) > 0 {
		c.OperatorOf = e.operatorOf
	}
	return c
}

// signatures lists the valid trusted signatures of an envelope.
func (e *Engine) signatures(kind contract.Kind, env *dsse.Envelope, payload []byte, signedAt map[string]string, fallback ...string) ([]Signature, []string) {
	pae := dsse.PAE(env.PayloadType, payload)
	var out []Signature
	var ops []string
	seen := map[string]bool{}
	for _, s := range env.Signatures {
		if seen[s.KeyID] {
			continue
		}
		k, ok := e.Cfg.Trust.Lookup(s.KeyID)
		if !ok || !k.Allows(kind.Purpose()) {
			continue
		}
		sig, err := dsse.DecodeBase64(s.Sig)
		if err != nil || !ed25519.Verify(k.Public, pae, sig) {
			continue
		}
		seen[s.KeyID] = true
		op := e.operatorOf(k)
		at := signedAt[k.KeyID]
		if at == "" && len(fallback) > 0 {
			at = fallback[0] // first seen with the record
		}
		out = append(out, Signature{KeyID: k.KeyID, Lab: k.Lab, Operator: op, At: at})
		if !slices.Contains(ops, op) {
			ops = append(ops, op)
		}
	}
	return out, ops
}

func (e *Engine) now() time.Time { return e.Now().UTC().Truncate(time.Second) }

// --- evidence --------------------------------------------------------------

// evidence computes the evidence of a proposal now. withApproval adds a
// prospective approval (to check an approval before storing it).
func (e *Engine) evidence(tx *bolt.Tx, p *Proposal, extra *Approval, simulated bool) (msg.Evidence, *Corpus) {
	var ev msg.Evidence
	repOps, senOps, orgs := map[string]bool{}, map[string]bool{}, map[string]bool{}
	var by []string
	for _, r := range p.Reproductions {
		if r.Status == "reproduced" {
			op := r.Operator
			if simulated {
				op = e.operatorOfLab(r.Lab, r.Operator)
			}
			repOps[op] = true
			if !slices.Contains(by, r.Lab) {
				by = append(by, r.Lab)
			}
		}
	}
	for _, s := range p.Sensors {
		op := s.Operator
		if simulated {
			op = e.operatorOfLab(s.Lab, s.Operator)
		}
		senOps[op] = true
	}
	approvals := p.Approvals
	if extra != nil {
		approvals = append(slices.Clone(approvals), *extra)
	}
	persons := map[string]bool{}
	for _, a := range approvals {
		// One person counts once, with the first organisation they named.
		if persons[a.By] {
			continue
		}
		persons[a.By] = true
		orgs[a.Org] = true
	}
	ev.ReproducedOperators, ev.SensorOperators, ev.HumanApprovalOrgs = len(repOps), len(senOps), len(orgs)
	sort.Strings(by)
	ev.ReproducedBy = by
	if p.PatternID != "" && tx != nil {
		w := scoring.ComputeWindow(tx, p.PatternID, e.now(), e.Scoring().Window())
		ev.TipIssuers, ev.MaxIssuerShare = w.Issuers, w.MaxIssuerShare
	}
	if p.Corpus != nil && p.Corpus.Matches == 0 {
		ev.NegativeCorpus = p.Corpus.Version
	}
	return ev, p.Corpus
}

// Level returns the highest max action the evidence allows ("" = none).
//
//   - G2 table (msg.EvidenceLevel): block needs a virtual patch reproduced
//     by 2 operators and approval in 2 organisations; challenge needs a
//     reproduction or sensors of 2 operators; observe needs a sensor or tips
//     of >= 3 issuers with none above 34 %.
//   - Tips use this lab's stricter thresholds (min_issuers, max_issuer_share).
//   - G3 gate 1: above observe only with a negative corpus run without hits.
//   - E5: independence that exists only through simulated operators caps
//     the level at observe.
func (e *Engine) Level(tx *bolt.Tx, p *Proposal, extra *Approval) (string, msg.Evidence) {
	real, _ := e.evidence(tx, p, extra, false)
	lvl := e.levelOf(p.Class, real, p.Corpus)
	if len(e.Cfg.Simulated) > 0 {
		sim, _ := e.evidence(tx, p, extra, true)
		if sl := e.levelOf(p.Class, sim, p.Corpus); msg.MaxActionRank(sl) > msg.MaxActionRank(lvl) {
			if msg.MaxActionRank(lvl) < msg.MaxActionRank("observe") {
				lvl = "observe"
			}
			return lvl, sim
		}
	}
	return lvl, real
}

func (e *Engine) levelOf(class string, ev msg.Evidence, corpus *Corpus) string {
	lvl := msg.EvidenceLevel(class, ev)
	if lvl == "observe" && ev.SensorOperators == 0 && ev.ReproducedOperators == 0 {
		w := scoring.Window{Issuers: ev.TipIssuers, MaxIssuerShare: ev.MaxIssuerShare}
		if !scoring.MeetsTipThreshold(w, e.Scoring()) {
			lvl = ""
		}
	}
	if msg.MaxActionRank(lvl) > msg.MaxActionRank("observe") && (corpus == nil || corpus.Matches > 0) {
		lvl = "observe"
	}
	return lvl
}

func minAction(a, b string) string {
	if msg.MaxActionRank(a) <= msg.MaxActionRank(b) {
		return a
	}
	return b
}

func ptr[T any](v T) *T { return &v }

func decodeEnvelope(raw []byte) (*dsse.Envelope, []byte, error) {
	var env dsse.Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, nil, err
	}
	p, err := env.DecodePayload()
	return &env, p, err
}
