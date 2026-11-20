package rules

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/dsse"
	"github.com/deutschland-schild/schild/contract/jsonx"
	"github.com/deutschland-schild/schild/contract/msg"
	"github.com/deutschland-schild/schild/contract/verify"
	"github.com/deutschland-schild/schild/lab/internal/publog"
	"github.com/deutschland-schild/schild/lab/internal/store"
)

func verifyEd25519(pub []byte, m, sig []byte) bool {
	return len(pub) == ed25519.PublicKeySize && ed25519.Verify(pub, m, sig)
}

func getWithdrawal(tx *bolt.Tx, seq uint64) (*WithdrawalRecord, bool, error) {
	var w WithdrawalRecord
	ok, err := store.GetJSON(tx, store.Withdrawals, store.U64(seq), &w)
	return &w, ok, err
}

func putWithdrawal(tx *bolt.Tx, w *WithdrawalRecord) error {
	return store.PutJSON(tx, store.Withdrawals, store.U64(w.Seq), w)
}

func findWithdrawalByDigest(tx *bolt.Tx, digest string) *WithdrawalRecord {
	var out *WithdrawalRecord
	_ = tx.Bucket(store.Withdrawals).ForEach(func(_, v []byte) error {
		var w WithdrawalRecord
		if out == nil && json.Unmarshal(v, &w) == nil && w.Digest == digest && w.Status == Collecting {
			out = &w
		}
		return nil
	})
	return out
}

// WithdrawalView renders a record.
func (e *Engine) WithdrawalView(w *WithdrawalRecord) WithdrawalView {
	v := WithdrawalView{Seq: w.Seq, Channel: w.W.BundleID, Scope: w.W.Scope, RuleIDs: w.W.RuleIDs, Reason: w.W.Reason, Note: w.W.Note,
		UpToVersion: w.W.UpToVersion, Status: w.Status, Threshold: e.Cfg.Threshold, ProposedBy: w.ProposedBy, CreatedAt: w.CreatedAt, Signatures: []Signature{}}
	if env, payload, err := decodeEnvelope(w.Envelope); err == nil {
		v.Signatures, _ = e.signatures(contract.KindWithdrawal, env, payload, w.SignedAt, w.CreatedAt)
	}
	if w.EffectiveAt != "" {
		v.EffectiveAt = ptr(w.EffectiveAt)
	}
	return v
}

// ListWithdrawals returns withdrawals newest first (offset cursor).
func (e *Engine) ListWithdrawals(offset, limit int) ([]WithdrawalView, int, error) {
	var out []WithdrawalView
	next := -1
	err := e.DB.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(store.Withdrawals).Cursor()
		i := 0
		for k, v := c.Last(); k != nil; k, v = c.Prev() {
			if i < offset {
				i++
				continue
			}
			if len(out) == limit {
				next = i
				break
			}
			var w WithdrawalRecord
			if json.Unmarshal(v, &w) == nil {
				out = append(out, e.WithdrawalView(&w))
			}
			i++
		}
		return nil
	})
	if out == nil {
		out = []WithdrawalView{}
	}
	return out, next, err
}

var noteRe = regexp.MustCompile(`^[ -~]{0,280}$`)

// CreateWithdrawal signs a withdrawal of single rules or (scope all) the
// emergency stop. It becomes effective once k operators signed.
func (e *Engine) CreateWithdrawal(scope string, ruleIDs []string, reason, note, by string) (WithdrawalView, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.now()
	var view WithdrawalView
	var eff *WithdrawalRecord
	err := e.DB.Update(func(tx *bolt.Tx) error {
		base := newestPublished(tx)
		if base == nil {
			return errf(http.StatusConflict, "conflict", "", "no bundle is published yet, so there is nothing to withdraw")
		}
		note = strings.TrimSpace(note)
		if !noteRe.MatchString(note) {
			return invalid("/note", "note: printable ASCII, at most 280 characters")
		}
		w := msg.Withdrawal{Schema: msg.SchemaWithdrawal, BundleID: e.Cfg.Channel, IssuedAt: msg.FormatTime(now), Scope: scope,
			UpToVersion: base.Version, Reason: reason, Note: note}
		if scope == "rules" {
			var b msg.Bundle
			if err := json.Unmarshal(base.Payload, &b); err != nil {
				return err
			}
			for i, id := range ruleIDs {
				if !slices.ContainsFunc(b.Rules, func(r msg.Rule) bool { return r.RuleID == id }) {
					return invalid(fmt.Sprintf("/rule_ids/%d", i), "rule %s is not in the published bundle %d", id, base.Version)
				}
			}
			w.RuleIDs = slices.Compact(slices.Sorted(slices.Values(ruleIDs)))
		}
		seq := max(highestSeq(tx), e.knownPeerSeq(tx)) + 1
		w.Seq = seq
		payload, err := jsonx.Marshal(&w)
		if err != nil {
			return err
		}
		if _, err := e.selfCheck(contract.KindWithdrawal, payload, now); err != nil {
			code := string(contract.CodeOf(err))
			if code == "" {
				code = "invalid"
			}
			return errf(http.StatusBadRequest, code, "", "withdrawal check failed: %v", err)
		}
		env, err := dsse.Sign(contract.KindWithdrawal.PayloadType(), payload, e.Cfg.RulesSigner)
		if err != nil {
			return err
		}
		raw, err := env.Marshal()
		if err != nil {
			return err
		}
		rec := &WithdrawalRecord{Seq: seq, Status: Collecting, Payload: payload, Digest: msg.Digest(payload), Envelope: raw, W: w,
			SignedAt: map[string]string{e.Cfg.RulesSigner.KeyID(): msg.FormatTime(now)}, ProposedBy: e.Cfg.Lab, CreatedAt: msg.FormatTime(now)}
		if err := putWithdrawal(tx, rec); err != nil {
			return err
		}
		ok, err := e.tryEffective(tx, rec, now)
		if err != nil {
			return err
		}
		if ok {
			eff = rec
		}
		view = e.WithdrawalView(rec)
		return nil
	})
	if eff != nil {
		e.afterEffective(eff)
	}
	e.logAudit("withdrawal signed", "by", by, "scope", scope, "seq", view.Seq, "err", err)
	return view, err
}

func highestSeq(tx *bolt.Tx) uint64 {
	k, _ := tx.Bucket(store.Withdrawals).Cursor().Last()
	return store.FromU64(k)
}

func (e *Engine) knownPeerSeq(tx *bolt.Tx) uint64 {
	var n struct{ V uint64 }
	_, _ = store.GetMeta(tx, "peer_withdrawal_seq", &n)
	return n.V
}

// verifyPublishable verifies k-of-n for kind. With simulated operators
// (test profile), independence through the simulation is accepted only for
// withdrawals and for bundles whose rules are all observe (E5).
func (e *Engine) verifyPublishable(kind contract.Kind, raw []byte, now time.Time) (*verify.Result, error) {
	res, err := verify.Signed(kind, raw, e.verifyCtx(now, false))
	if err == nil || len(e.Cfg.Simulated) == 0 || contract.CodeOf(err) != contract.CodeThreshold {
		return res, err
	}
	res, err2 := verify.Signed(kind, raw, e.verifyCtx(now, true))
	if err2 != nil {
		return nil, err2
	}
	if b, ok := res.Value.(*msg.Bundle); ok {
		for _, r := range b.Rules {
			if r.MaxAction != "observe" {
				return nil, contract.Errf(contract.CodeThreshold, "simulated operators only: rule %s above observe", r.RuleID)
			}
		}
	}
	return res, nil
}

func (e *Engine) tryEffective(tx *bolt.Tx, rec *WithdrawalRecord, now time.Time) (bool, error) {
	if rec.Status != Collecting {
		return false, nil
	}
	res, err := e.verifyPublishable(contract.KindWithdrawal, rec.Envelope, now)
	if err != nil {
		return false, nil
	}
	return true, e.markEffective(tx, rec, now, res.Operators)
}

func (e *Engine) markEffective(tx *bolt.Tx, rec *WithdrawalRecord, now time.Time, operators []string) error {
	rec.Status, rec.EffectiveAt = Effective, msg.FormatTime(now)
	if newest := newestPublished(tx); newest != nil && newest.Version > rec.W.UpToVersion {
		rec.Status = Superseded
	}
	if err := putWithdrawal(tx, rec); err != nil {
		return err
	}
	if rec.Status == Effective {
		if err := tx.Bucket(store.Proposals).ForEach(func(k, v []byte) error {
			var p Proposal
			if json.Unmarshal(v, &p) != nil || p.Status != StatusPublished || p.BundleVersion > rec.W.UpToVersion {
				return nil
			}
			if rec.W.Scope == "all" || slices.Contains(rec.W.RuleIDs, p.RuleID) {
				p.Status = StatusWithdrawn
				return store.PutJSON(tx, store.Proposals, k, &p)
			}
			return nil
		}); err != nil {
			return err
		}
	}
	what := fmt.Sprintf("%d rules", len(rec.W.RuleIDs))
	if rec.W.Scope == "all" {
		what = "all network rules (emergency stop)"
	}
	summary := fmt.Sprintf("withdrawal %d effective: %s up to bundle %d, reason %s, %d operators", rec.Seq, what, rec.W.UpToVersion, rec.W.Reason, len(operators))
	_, err := publog.Append(tx, now, publog.KindWithdrawal, fmt.Sprint(rec.Seq), rec.Digest, summary, rec.Envelope)
	return err
}

func (e *Engine) afterEffective(rec *WithdrawalRecord) {
	e.logAudit("withdrawal effective", "seq", rec.Seq, "scope", rec.W.Scope)
	if e.Publisher != nil {
		e.Publisher.PublishWithdrawal(rec.Seq, rec.Envelope)
		e.Publisher.Changed()
	}
}

// CosignWithdrawal signs a withdrawal proposed by another lab after a human
// confirmed it, sends the signature to that lab and makes it effective
// locally once k operators signed.
func (e *Engine) CosignWithdrawal(seq uint64, by string) (WithdrawalView, error) {
	view, eff, send, err := e.cosignWithdrawal(seq)
	if err == nil && send != nil {
		if serr := send(); serr != nil {
			e.Log.Warn("co-signature not delivered to the proposing lab", "seq", seq, "err", serr)
		}
	}
	if eff != nil {
		e.afterEffective(eff)
	}
	e.logAudit("withdrawal co-signed", "by", by, "seq", seq, "err", err)
	return view, err
}

func (e *Engine) cosignWithdrawal(seq uint64) (WithdrawalView, *WithdrawalRecord, func() error, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.now()
	var view WithdrawalView
	var eff *WithdrawalRecord
	var send func() error
	err := e.DB.Update(func(tx *bolt.Tx) error {
		rec, ok, err := getWithdrawal(tx, seq)
		if err != nil {
			return err
		}
		if !ok {
			return errf(http.StatusNotFound, "not_found", "", "withdrawal %d not found", seq)
		}
		if rec.Status != Collecting {
			return errf(http.StatusConflict, "conflict", "", "withdrawal %d is %s", seq, rec.Status)
		}
		sig, err := e.addOwnSignature(rec.Envelope, rec.Payload, contract.KindWithdrawal)
		if err != nil {
			return err
		}
		rec.Envelope = sig.env
		rec.SignedAt[e.Cfg.RulesSigner.KeyID()] = msg.FormatTime(now)
		if err := putWithdrawal(tx, rec); err != nil {
			return err
		}
		if rec.Source != "" && e.Courier != nil {
			src, digest, s := rec.Source, rec.Digest, sig.sig
			send = func() error { return e.Courier.SendSignature(src, contract.KindWithdrawal, digest, s) }
		}
		ok, err = e.tryEffective(tx, rec, now)
		if err != nil {
			return err
		}
		if ok {
			eff = rec
		}
		view = e.WithdrawalView(rec)
		return nil
	})
	return view, eff, send, err
}
