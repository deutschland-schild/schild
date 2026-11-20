package rules

import (
	"bytes"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"net/http"
	"slices"
	"sort"
	"strings"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/dsse"
	"github.com/deutschland-schild/schild/contract/jsonx"
	"github.com/deutschland-schild/schild/contract/msg"
	"github.com/deutschland-schild/schild/lab/internal/publog"
	"github.com/deutschland-schild/schild/lab/internal/scoring"
	"github.com/deutschland-schild/schild/lab/internal/store"
)

func getBundle(tx *bolt.Tx, v uint64) (*BundleRecord, bool, error) {
	var b BundleRecord
	ok, err := store.GetJSON(tx, store.Bundles, store.U64(v), &b)
	return &b, ok, err
}

func putBundle(tx *bolt.Tx, b *BundleRecord) error {
	return store.PutJSON(tx, store.Bundles, store.U64(b.Version), b)
}

// newestPublished returns the newest published bundle.
func newestPublished(tx *bolt.Tx) *BundleRecord {
	c := tx.Bucket(store.Bundles).Cursor()
	for k, v := c.Last(); k != nil; k, v = c.Prev() {
		var b BundleRecord
		if json.Unmarshal(v, &b) == nil && (b.Status == Published) {
			return &b
		}
	}
	return nil
}

func highestVersion(tx *bolt.Tx) uint64 {
	k, _ := tx.Bucket(store.Bundles).Cursor().Last()
	return store.FromU64(k)
}

// BundleView renders a bundle record.
func (e *Engine) BundleView(b *BundleRecord) BundleView {
	v := BundleView{Channel: e.Cfg.Channel, Version: b.Version, Status: b.Status, IssuedAt: b.IssuedAt, Expires: b.Expires,
		Rules: b.Rules, Threshold: e.Cfg.Threshold, Signatures: []Signature{}, ProposedBy: b.ProposedBy}
	if v.ProposedBy == "" {
		v.ProposedBy = b.Source
	}
	if v.Rules == nil {
		v.Rules = []RuleView{}
	}
	if env, payload, err := decodeEnvelope(b.Envelope); err == nil {
		v.Signatures, _ = e.signatures(contract.KindBundle, env, payload, b.SignedAt, b.CreatedAt)
	}
	if b.Status == Published || b.Status == Superseded || b.Status == Expired {
		v.Digest = b.Digest
		v.Envelope = b.Envelope
	}
	if b.Status == Published {
		if exp, err := msg.ParseTime(b.Expires); err == nil && !exp.After(e.now()) {
			v.Status = Expired
		}
	}
	return v
}

// ListBundles returns bundles newest first (offset cursor).
func (e *Engine) ListBundles(offset, limit int) ([]BundleView, int, error) {
	var out []BundleView
	next := -1
	err := e.DB.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(store.Bundles).Cursor()
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
			var b BundleRecord
			if json.Unmarshal(v, &b) == nil {
				out = append(out, e.BundleView(&b))
			}
			i++
		}
		return nil
	})
	if out == nil {
		out = []BundleView{}
	}
	return out, next, err
}

// GetBundle returns one bundle.
func (e *Engine) GetBundle(version uint64) (BundleView, error) {
	var v BundleView
	err := e.DB.View(func(tx *bolt.Tx) error {
		b, ok, err := getBundle(tx, version)
		if err != nil {
			return err
		}
		if !ok {
			return errf(http.StatusNotFound, "not_found", "", "bundle %d not found", version)
		}
		v = e.BundleView(b)
		return nil
	})
	return v, err
}

// withdrawnRules returns the rules removed by effective withdrawals that
// apply to version (all = emergency stop).
func withdrawnRules(tx *bolt.Tx, version uint64) (all bool, ids map[string]bool) {
	ids = map[string]bool{}
	_ = tx.Bucket(store.Withdrawals).ForEach(func(_, v []byte) error {
		var w WithdrawalRecord
		if json.Unmarshal(v, &w) != nil || w.Status != Effective || w.W.UpToVersion < version {
			return nil
		}
		if w.W.Scope == "all" {
			all = true
		}
		for _, r := range w.W.RuleIDs {
			ids[r] = true
		}
		return nil
	})
	return all, ids
}

// Assemble builds the next bundle version: the rules of the newest published
// bundle (minus withdrawn and removed rules) plus approved proposals, signs
// it with this lab's rules key and offers it for co-signing.
func (e *Engine) Assemble(add, remove []string, validityHours int, by string) (BundleView, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.now()
	var view BundleView
	var publish *BundleRecord
	err := e.DB.Update(func(tx *bolt.Tx) error {
		base := newestPublished(tx)
		var rules []msg.Rule
		prev := map[string]msg.Rule{}
		if base != nil {
			var b msg.Bundle
			if err := json.Unmarshal(base.Payload, &b); err != nil {
				return err
			}
			all, wd := withdrawnRules(tx, base.Version)
			for _, r := range b.Rules {
				prev[r.RuleID] = r
				if all || wd[r.RuleID] || slices.Contains(remove, r.RuleID) {
					continue
				}
				rules = append(rules, r)
			}
		}
		for _, id := range remove {
			if _, ok := prev[id]; !ok {
				return invalid("/remove", "rule %s is not in the current bundle", id)
			}
		}
		validity := time.Duration(e.validity(validityHours)) * time.Hour
		expires := now.Add(validity)
		var proposals []string
		for i, pid := range add {
			p, err := getProposal(tx, pid)
			if err != nil {
				return invalid(fmt.Sprintf("/add/%d", i), "proposal %s not found", pid)
			}
			if p.Status != StatusApproved && p.Status != StatusPublished {
				return errf(http.StatusConflict, "conflict", fmt.Sprintf("/add/%d", i), "proposal %s is %s; only approved proposals go into a bundle", pid, p.Status)
			}
			action := e.finalAction(tx, p)
			if action == "" {
				return errf(http.StatusConflict, "evidence", fmt.Sprintf("/add/%d", i), "proposal %s: the evidence no longer allows any action", pid)
			}
			until := ""
			if action != "observe" {
				u, err := msg.ParseTime(p.MaxActionUntil)
				if err != nil || !u.After(now) {
					return errf(http.StatusConflict, "validity", fmt.Sprintf("/add/%d", i), "proposal %s: max_action_until has passed; approve again with a new date", pid)
				}
				if u.After(expires) {
					u = expires
				}
				if action == "challenge" && u.Sub(now) > contract.MaxChallengeWindow {
					u = now.Add(contract.MaxChallengeWindow)
				}
				until = msg.FormatTime(u)
			}
			r := e.ruleFor(tx, p, action, until, nil)
			rules = slices.DeleteFunc(rules, func(x msg.Rule) bool { return x.RuleID == r.RuleID })
			rules = append(rules, r)
			proposals = append(proposals, p.ID)
		}
		// Carried-over rules: their action window must still fit.
		kept := rules[:0]
		for _, r := range rules {
			if r.MaxActionUntil != "" {
				u, err := msg.ParseTime(r.MaxActionUntil)
				if err != nil || !u.After(now) {
					e.Log.Info("rule dropped from the next bundle: action window ended", "rule", r.RuleID)
					continue
				}
				if u.After(expires) {
					r.MaxActionUntil = msg.FormatTime(expires)
				}
			}
			kept = append(kept, r)
		}
		rules = kept
		sort.SliceStable(rules, func(i, j int) bool { return rules[i].RuleID < rules[j].RuleID })
		if rules == nil {
			rules = []msg.Rule{}
		}
		version := highestVersion(tx) + 1
		if known := e.knownPeerVersion(tx); known >= version {
			version = known + 1
		}
		payload, err := jsonx.Marshal(&msg.Bundle{Schema: msg.SchemaBundle, BundleID: e.Cfg.Channel, Version: version,
			IssuedAt: msg.FormatTime(now), Expires: msg.FormatTime(expires), Rules: rules})
		if err != nil {
			return err
		}
		if _, err := e.selfCheck(contract.KindBundle, payload, now); err != nil {
			code := string(contract.CodeOf(err))
			if code == "" {
				code = "invalid"
			}
			return errf(http.StatusBadRequest, code, "", "bundle check failed: %v", err)
		}
		env, err := dsse.Sign(contract.KindBundle.PayloadType(), payload, e.Cfg.RulesSigner)
		if err != nil {
			return err
		}
		raw, err := env.Marshal()
		if err != nil {
			return err
		}
		views := make([]RuleView, 0, len(rules))
		for _, r := range rules {
			ch := "added"
			if old, ok := prev[r.RuleID]; ok {
				ch = "unchanged"
				if old.MaxAction != r.MaxAction || old.SecLang != r.SecLang || old.Stage != r.Stage || old.Class != r.Class {
					ch = "changed"
				}
			}
			views = append(views, RuleView{RuleID: r.RuleID, Class: r.Class, MaxAction: r.MaxAction, Stage: r.Stage, Change: ch})
		}
		// Earlier own drafts are superseded by this one.
		if err := tx.Bucket(store.Bundles).ForEach(func(k, v []byte) error {
			var b BundleRecord
			if json.Unmarshal(v, &b) == nil && b.Status == Collecting && b.Source == "" {
				b.Status = Superseded
				return putBundle(tx, &b)
			}
			return nil
		}); err != nil {
			return err
		}
		rec := &BundleRecord{Version: version, Status: Collecting, IssuedAt: msg.FormatTime(now), Expires: msg.FormatTime(expires),
			Digest: msg.Digest(payload), Payload: payload, Envelope: raw, Rules: views,
			SignedAt:   map[string]string{e.Cfg.RulesSigner.KeyID(): msg.FormatTime(now)},
			ProposedBy: e.Cfg.Lab, Proposals: proposals, CreatedAt: msg.FormatTime(now)}
		if err := putBundle(tx, rec); err != nil {
			return err
		}
		ok, err := e.tryPublishBundle(tx, rec, now)
		if err != nil {
			return err
		}
		if ok {
			publish = rec
		}
		view = e.BundleView(rec)
		return nil
	})
	if err == nil && publish != nil {
		e.afterPublishBundle(publish)
	}
	e.logAudit("bundle assembled", "by", by, "version", view.Version, "err", err)
	return view, err
}

func (e *Engine) logAudit(m string, args ...any) {
	if e.Log != nil {
		e.Log.Info("audit: "+m, args...)
	}
}

// finalAction is min(requested, allowed by evidence, highest approval).
func (e *Engine) finalAction(tx *bolt.Tx, p *Proposal) string {
	lvl, _ := e.Level(tx, p, nil)
	best := ""
	for _, a := range p.Approvals {
		if msg.MaxActionRank(a.MaxAction) > msg.MaxActionRank(best) {
			best = a.MaxAction
		}
	}
	if best == "" || lvl == "" {
		return ""
	}
	return minAction(minAction(p.RequestedMaxAction, lvl), best)
}

// knownPeerVersion is the highest version offered or published by peers.
func (e *Engine) knownPeerVersion(tx *bolt.Tx) uint64 {
	var n struct{ V uint64 }
	_, _ = store.GetMeta(tx, "peer_bundle_version", &n)
	return n.V
}

// NotePeerVersion records a version seen at a peer (avoids version clashes).
func (e *Engine) NotePeerVersion(v uint64) {
	_ = e.DB.Update(func(tx *bolt.Tx) error {
		var n struct{ V uint64 }
		_, _ = store.GetMeta(tx, "peer_bundle_version", &n)
		if v > n.V {
			n.V = v
			return store.PutMeta(tx, "peer_bundle_version", n)
		}
		return nil
	})
}

// tryPublishBundle publishes rec when signatures of k distinct operators
// are present. With simulated operators (test profile) a bundle whose
// independence exists only through the simulation may carry observe rules
// only.
func (e *Engine) tryPublishBundle(tx *bolt.Tx, rec *BundleRecord, now time.Time) (bool, error) {
	if rec.Status != Collecting {
		return false, nil
	}
	res, err := e.verifyPublishable(contract.KindBundle, rec.Envelope, now)
	if err != nil {
		note := ""
		if contract.CodeOf(err) != contract.CodeThreshold || strings.Contains(err.Error(), "simulated") {
			note = err.Error()
		}
		if note != rec.Note {
			rec.Note = note
			return false, putBundle(tx, rec)
		}
		return false, nil
	}
	if newest := newestPublished(tx); newest != nil && newest.Version >= rec.Version {
		rec.Status, rec.Note = Superseded, fmt.Sprintf("version %d is already published", newest.Version)
		return false, putBundle(tx, rec)
	}
	return true, e.markBundlePublished(tx, rec, now, res.Operators)
}

func (e *Engine) markBundlePublished(tx *bolt.Tx, rec *BundleRecord, now time.Time, operators []string) error {
	if err := tx.Bucket(store.Bundles).ForEach(func(k, v []byte) error {
		var b BundleRecord
		if json.Unmarshal(v, &b) == nil && store.FromU64(k) < rec.Version && (b.Status == Published || b.Status == Collecting) {
			b.Status = Superseded
			return putBundle(tx, &b)
		}
		return nil
	}); err != nil {
		return err
	}
	rec.Status, rec.PublishedAt = Published, msg.FormatTime(now)
	if err := putBundle(tx, rec); err != nil {
		return err
	}
	// Withdrawals for older versions are superseded by this bundle.
	if err := tx.Bucket(store.Withdrawals).ForEach(func(k, v []byte) error {
		var w WithdrawalRecord
		if json.Unmarshal(v, &w) == nil && w.Status == Effective && w.W.UpToVersion < rec.Version {
			w.Status = Superseded
			return store.PutJSON(tx, store.Withdrawals, k, &w)
		}
		return nil
	}); err != nil {
		return err
	}
	var b msg.Bundle
	if err := json.Unmarshal(rec.Payload, &b); err != nil {
		return err
	}
	inBundle := map[string]bool{}
	for _, r := range b.Rules {
		inBundle[r.RuleID] = true
	}
	if err := tx.Bucket(store.Proposals).ForEach(func(k, v []byte) error {
		var p Proposal
		if json.Unmarshal(v, &p) != nil {
			return nil
		}
		switch {
		case inBundle[p.RuleID] && (p.Status == StatusApproved || p.Status == StatusPublished):
			p.Status, p.BundleVersion = StatusPublished, rec.Version
			if p.PatternID != "" {
				_ = scoring.SetStatus(tx, p.PatternID, scoring.StatusPublished, p.ID)
			}
		case !inBundle[p.RuleID] && p.Status == StatusPublished:
			p.Status = StatusWithdrawn
		default:
			return nil
		}
		return store.PutJSON(tx, store.Proposals, k, &p)
	}); err != nil {
		return err
	}
	summary := fmt.Sprintf("bundle %d published (%d rules, %d operators)", rec.Version, len(b.Rules), len(operators))
	if rec.Source != "" {
		summary = fmt.Sprintf("bundle %d published via %s (%d rules, %d operators)", rec.Version, rec.Source, len(b.Rules), len(operators))
	}
	_, err := publog.Append(tx, now, publog.KindBundle, fmt.Sprint(rec.Version), rec.Digest, summary, rec.Envelope)
	return err
}

func (e *Engine) afterPublishBundle(rec *BundleRecord) {
	e.logAudit("bundle published", "version", rec.Version, "digest", rec.Digest)
	if e.Publisher != nil {
		e.Publisher.PublishBundle(rec.Version, rec.Envelope)
		e.Publisher.Changed()
	}
}

// CosignBundle signs a bundle offered by a peer lab (after a human
// confirmed it in the dashboard), sends the signature to that lab and
// publishes locally once k operators signed.
func (e *Engine) CosignBundle(version uint64, by string) (BundleView, error) {
	view, publish, send, err := e.cosignBundle(version)
	// Network and feed work happen outside the engine lock: two labs
	// co-signing each other's items at once must not wait on each other.
	if err == nil && send != nil {
		if serr := send(); serr != nil {
			e.Log.Warn("co-signature not delivered to the proposing lab", "version", version, "err", serr)
		}
	}
	if publish != nil {
		e.afterPublishBundle(publish)
	}
	e.logAudit("bundle co-signed", "by", by, "version", version, "err", err)
	return view, err
}

func (e *Engine) cosignBundle(version uint64) (BundleView, *BundleRecord, func() error, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.now()
	var view BundleView
	var publish *BundleRecord
	var send func() error
	err := e.DB.Update(func(tx *bolt.Tx) error {
		rec, ok, err := getBundle(tx, version)
		if err != nil {
			return err
		}
		if !ok {
			return errf(http.StatusNotFound, "not_found", "", "bundle %d not found", version)
		}
		if rec.Status != Collecting {
			return errf(http.StatusConflict, "conflict", "", "bundle %d is %s", version, rec.Status)
		}
		if _, err := e.selfCheck(contract.KindBundle, rec.Payload, now); err != nil {
			return errf(http.StatusConflict, string(contract.CodeOf(err)), "", "bundle fails the contract checks: %v", err)
		}
		sig, err := e.addOwnSignature(rec.Envelope, rec.Payload, contract.KindBundle)
		if err != nil {
			return err
		}
		rec.Envelope = sig.env
		rec.SignedAt[e.Cfg.RulesSigner.KeyID()] = msg.FormatTime(now)
		if err := putBundle(tx, rec); err != nil {
			return err
		}
		if rec.Source != "" && e.Courier != nil {
			src, digest, s := rec.Source, rec.Digest, sig.sig
			send = func() error { return e.Courier.SendSignature(src, contract.KindBundle, digest, s) }
		}
		ok, err = e.tryPublishBundle(tx, rec, now)
		if err != nil {
			return err
		}
		if ok {
			publish = rec
		}
		view = e.BundleView(rec)
		return nil
	})
	return view, publish, send, err
}

type signed struct {
	env []byte
	sig dsse.Signature
}

// addOwnSignature adds this lab's rules signature to an envelope.
func (e *Engine) addOwnSignature(raw []byte, payload []byte, kind contract.Kind) (*signed, error) {
	env, p, err := decodeEnvelope(raw)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(p, payload) || env.PayloadType != kind.PayloadType() {
		return nil, errf(http.StatusConflict, "envelope", "", "stored envelope does not match its payload")
	}
	for _, s := range env.Signatures {
		if s.KeyID == e.Cfg.RulesSigner.KeyID() {
			return nil, errf(http.StatusConflict, "conflict", "", "this lab already signed")
		}
	}
	if err := env.AddSignature(e.Cfg.RulesSigner); err != nil {
		return nil, err
	}
	out, err := env.Marshal()
	if err != nil {
		return nil, err
	}
	return &signed{env: out, sig: env.Signatures[len(env.Signatures)-1]}, nil
}

// CheckSignature verifies a co-signature against the stored payload without
// the write lock, so that a forged post costs no write and no budget of the
// key it names (D40, contracts/cosign.md).
func (e *Engine) CheckSignature(kind contract.Kind, digest string, s dsse.Signature) error {
	k, ok := e.Cfg.Trust.Lookup(s.KeyID)
	if !ok || !k.Allows(contract.PurposeRules) {
		return errf(http.StatusForbidden, "signature", "", "unknown key %s", s.KeyID)
	}
	return e.DB.View(func(tx *bolt.Tx) error {
		var payload []byte
		switch kind {
		case contract.KindBundle:
			rec := findBundleByDigest(tx, digest)
			if rec == nil {
				return errf(http.StatusNotFound, "not_found", "", "no collecting bundle with digest %s", digest)
			}
			payload = rec.Payload
		case contract.KindWithdrawal:
			rec := findWithdrawalByDigest(tx, digest)
			if rec == nil {
				return errf(http.StatusNotFound, "not_found", "", "no collecting withdrawal with digest %s", digest)
			}
			payload = rec.Payload
		default:
			return errf(http.StatusBadRequest, "payload_type", "", "only bundles and withdrawals are co-signed")
		}
		sig, err := dsse.DecodeBase64(s.Sig)
		if err != nil || !verifyEd25519(k.Public, dsse.PAE(kind.PayloadType(), payload), sig) {
			return errf(http.StatusForbidden, "signature", "", "signature does not verify")
		}
		return nil
	})
}

// AddSignature attaches a co-signature from another lab (POST
// /v0/signatures on the feed). The signature must be valid for the stored
// payload and come from a trusted peer key with purpose rules.
func (e *Engine) AddSignature(kind contract.Kind, digest string, s dsse.Signature) (int, bool, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.now()
	var ops int
	var published bool
	var pubB *BundleRecord
	var pubW *WithdrawalRecord
	err := e.DB.Update(func(tx *bolt.Tx) error {
		k, ok := e.Cfg.Trust.Lookup(s.KeyID)
		if !ok || !k.Allows(contract.PurposeRules) {
			return errf(http.StatusForbidden, "signature", "", "unknown key %s", s.KeyID)
		}
		switch kind {
		case contract.KindBundle:
			rec := findBundleByDigest(tx, digest)
			if rec == nil {
				return errf(http.StatusNotFound, "not_found", "", "no collecting bundle with digest %s", digest)
			}
			env, err := mergeSignature(rec.Envelope, rec.Payload, kind, k.Public, s)
			if err != nil {
				return err
			}
			rec.Envelope = env
			if _, ok := rec.SignedAt[s.KeyID]; !ok {
				rec.SignedAt[s.KeyID] = msg.FormatTime(now)
			}
			if err := putBundle(tx, rec); err != nil {
				return err
			}
			ok, err := e.tryPublishBundle(tx, rec, now)
			if err != nil {
				return err
			}
			if ok {
				pubB, published = rec, true
			}
			ev, p, _ := decodeEnvelope(rec.Envelope)
			_, o := e.signatures(kind, ev, p, nil)
			ops = len(o)
		case contract.KindWithdrawal:
			rec := findWithdrawalByDigest(tx, digest)
			if rec == nil {
				return errf(http.StatusNotFound, "not_found", "", "no collecting withdrawal with digest %s", digest)
			}
			env, err := mergeSignature(rec.Envelope, rec.Payload, kind, k.Public, s)
			if err != nil {
				return err
			}
			rec.Envelope = env
			if _, ok := rec.SignedAt[s.KeyID]; !ok {
				rec.SignedAt[s.KeyID] = msg.FormatTime(now)
			}
			if err := putWithdrawal(tx, rec); err != nil {
				return err
			}
			ok, err := e.tryEffective(tx, rec, now)
			if err != nil {
				return err
			}
			if ok {
				pubW, published = rec, true
			}
			ev, p, _ := decodeEnvelope(rec.Envelope)
			_, o := e.signatures(kind, ev, p, nil)
			ops = len(o)
		default:
			return errf(http.StatusBadRequest, "payload_type", "", "only bundles and withdrawals are co-signed")
		}
		return nil
	})
	if pubB != nil {
		e.afterPublishBundle(pubB)
	}
	if pubW != nil {
		e.afterEffective(pubW)
	}
	return ops, published, err
}

func findBundleByDigest(tx *bolt.Tx, digest string) *BundleRecord {
	var out *BundleRecord
	_ = tx.Bucket(store.Bundles).ForEach(func(_, v []byte) error {
		var b BundleRecord
		if out == nil && json.Unmarshal(v, &b) == nil && b.Digest == digest && b.Status == Collecting {
			out = &b
		}
		return nil
	})
	return out
}

// mergeSignature verifies sig over payload and adds it to the envelope.
func mergeSignature(raw, payload []byte, kind contract.Kind, pub []byte, s dsse.Signature) ([]byte, error) {
	env, p, err := decodeEnvelope(raw)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(p, payload) {
		return nil, errf(http.StatusConflict, "envelope", "", "stored envelope does not match its payload")
	}
	sig, err := dsse.DecodeBase64(s.Sig)
	if err != nil || !verifyEd25519(pub, dsse.PAE(kind.PayloadType(), payload), sig) {
		return nil, errf(http.StatusForbidden, "signature", "", "signature does not verify")
	}
	for _, x := range env.Signatures {
		if x.KeyID == s.KeyID {
			return raw, nil
		}
	}
	if len(env.Signatures) >= 16 {
		return nil, errf(http.StatusConflict, "envelope", "", "envelope already carries 16 signatures")
	}
	env.Signatures = append(env.Signatures, s)
	return env.Marshal()
}

// Collecting returns own items waiting for co-signatures (offered on the
// feed at GET /v0/collecting).
func (e *Engine) Collecting() []CollectingItem {
	var out []CollectingItem
	_ = e.DB.View(func(tx *bolt.Tx) error {
		_ = tx.Bucket(store.Bundles).ForEach(func(_, v []byte) error {
			var b BundleRecord
			if json.Unmarshal(v, &b) == nil && b.Status == Collecting && b.Source == "" {
				out = append(out, CollectingItem{Kind: string(contract.KindBundle), Lab: e.Cfg.Lab, Digest: b.Digest, Envelope: b.Envelope})
			}
			return nil
		})
		_ = tx.Bucket(store.Withdrawals).ForEach(func(_, v []byte) error {
			var w WithdrawalRecord
			if json.Unmarshal(v, &w) == nil && w.Status == Collecting && w.Source == "" {
				out = append(out, CollectingItem{Kind: string(contract.KindWithdrawal), Lab: e.Cfg.Lab, Digest: w.Digest, Envelope: w.Envelope})
			}
			return nil
		})
		return nil
	})
	if out == nil {
		out = []CollectingItem{}
	}
	return out
}

// CollectingItem is one entry of GET /v0/collecting.
type CollectingItem struct {
	Kind     string          `json:"kind"`
	Lab      string          `json:"lab"`
	Digest   string          `json:"digest"`
	Envelope json.RawMessage `json:"envelope"`
}

// OfferFromPeer stores a peer's collecting bundle or withdrawal so this
// lab's operators can review and co-sign it. The payload must pass the
// contract checks and carry a valid signature of the peer lab.
func (e *Engine) OfferFromPeer(peerLab string, kind contract.Kind, raw []byte) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.now()
	env, payload, err := decodeEnvelope(raw)
	if err != nil {
		return err
	}
	if env.PayloadType != kind.PayloadType() {
		return fmt.Errorf("payload type %s", env.PayloadType)
	}
	sigs, _ := e.signatures(kind, env, payload, nil)
	fromPeer := false
	for _, s := range sigs {
		if s.Lab == peerLab {
			fromPeer = true
		}
	}
	if !fromPeer {
		return fmt.Errorf("offer not signed by %s", peerLab)
	}
	res, err := e.selfCheck(kind, payload, now)
	if err != nil {
		return err
	}
	digest := msg.Digest(payload)
	return e.DB.Update(func(tx *bolt.Tx) error {
		switch b := res.Value.(type) {
		case *msg.Bundle:
			old, ok, err := getBundle(tx, b.Version)
			if err != nil {
				return err
			}
			if ok && old.Digest != digest {
				return nil // a different payload under this version: keep ours
			}
			if newest := newestPublished(tx); newest != nil && newest.Version >= b.Version {
				return nil
			}
			e.notePeerVersionTx(tx, b.Version)
			if ok {
				merged, err := unionSignatures(old.Envelope, raw)
				if err != nil {
					return err
				}
				old.Envelope = merged
				return putBundle(tx, old)
			}
			rec := &BundleRecord{Version: b.Version, Status: Collecting, IssuedAt: b.IssuedAt, Expires: b.Expires, Digest: digest,
				Payload: payload, Envelope: raw, Rules: ruleViews(b, nil), SignedAt: map[string]string{}, ProposedBy: peerLab, Source: peerLab,
				CreatedAt: msg.FormatTime(now)}
			for _, s := range sigs {
				rec.SignedAt[s.KeyID] = msg.FormatTime(now)
			}
			return putBundle(tx, rec)
		case *msg.Withdrawal:
			old, ok, err := getWithdrawal(tx, b.Seq)
			if err != nil {
				return err
			}
			if ok && old.Digest != digest {
				return nil
			}
			e.notePeerSeqTx(tx, b.Seq)
			if ok {
				merged, err := unionSignatures(old.Envelope, raw)
				if err != nil {
					return err
				}
				old.Envelope = merged
				return putWithdrawal(tx, old)
			}
			rec := &WithdrawalRecord{Seq: b.Seq, Status: Collecting, Payload: payload, Digest: digest, Envelope: raw, W: *b,
				SignedAt: map[string]string{}, ProposedBy: peerLab, Source: peerLab, CreatedAt: msg.FormatTime(now)}
			for _, s := range sigs {
				rec.SignedAt[s.KeyID] = msg.FormatTime(now)
			}
			return putWithdrawal(tx, rec)
		}
		return nil
	})
}

func (e *Engine) notePeerVersionTx(tx *bolt.Tx, v uint64) {
	var n struct{ V uint64 }
	_, _ = store.GetMeta(tx, "peer_bundle_version", &n)
	if v > n.V {
		_ = store.PutMeta(tx, "peer_bundle_version", struct{ V uint64 }{v})
	}
}

func (e *Engine) notePeerSeqTx(tx *bolt.Tx, s uint64) {
	var n struct{ V uint64 }
	_, _ = store.GetMeta(tx, "peer_withdrawal_seq", &n)
	if s > n.V {
		_ = store.PutMeta(tx, "peer_withdrawal_seq", struct{ V uint64 }{s})
	}
}

// unionSignatures merges the signatures of two envelopes over one payload.
func unionSignatures(a, b []byte) ([]byte, error) {
	ea, pa, err := decodeEnvelope(a)
	if err != nil {
		return nil, err
	}
	eb, pb, err := decodeEnvelope(b)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(pa, pb) {
		return a, nil
	}
	for _, s := range eb.Signatures {
		if !slices.ContainsFunc(ea.Signatures, func(x dsse.Signature) bool { return x.KeyID == s.KeyID }) && len(ea.Signatures) < 16 {
			ea.Signatures = append(ea.Signatures, s)
		}
	}
	return ea.Marshal()
}

func ruleViews(b *msg.Bundle, prev map[string]msg.Rule) []RuleView {
	out := make([]RuleView, 0, len(b.Rules))
	for _, r := range b.Rules {
		ch := ""
		if prev != nil {
			ch = "added"
			if old, ok := prev[r.RuleID]; ok {
				ch = "unchanged"
				if old.MaxAction != r.MaxAction || old.SecLang != r.SecLang {
					ch = "changed"
				}
			}
		}
		out = append(out, RuleView{RuleID: r.RuleID, Class: r.Class, MaxAction: r.MaxAction, Stage: r.Stage, Change: ch})
	}
	return out
}

// ImportPublished stores a k-of-n bundle or withdrawal learned from a peer
// feed (verified here with this lab's trust and threshold), so this lab's
// feed and checkpoint carry the newest state of the channel too.
func (e *Engine) ImportPublished(kind contract.Kind, raw []byte, source string) (bool, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.now()
	res, err := e.verifyPublishable(kind, raw, now)
	if err != nil {
		return false, err
	}
	var pubB *BundleRecord
	var pubW *WithdrawalRecord
	err = e.DB.Update(func(tx *bolt.Tx) error {
		switch v := res.Value.(type) {
		case *msg.Bundle:
			if newest := newestPublished(tx); newest != nil && newest.Version >= v.Version {
				return nil
			}
			old, ok, err := getBundle(tx, v.Version)
			if err != nil {
				return err
			}
			if ok && old.Digest != res.Digest {
				e.Log.Warn("equivocation: peer published another payload under a version this lab holds", "version", v.Version, "source", source)
				return nil
			}
			rec := &BundleRecord{Version: v.Version, Status: Collecting, IssuedAt: v.IssuedAt, Expires: v.Expires, Digest: res.Digest,
				Payload: res.Payload, Envelope: raw, Rules: ruleViews(v, nil), SignedAt: map[string]string{}, ProposedBy: source, Source: source, CreatedAt: msg.FormatTime(now)}
			if ok {
				rec = old
				rec.Envelope = raw
			}
			if err := e.markBundlePublished(tx, rec, now, res.Operators); err != nil {
				return err
			}
			pubB = rec
		case *msg.Withdrawal:
			old, ok, err := getWithdrawal(tx, v.Seq)
			if err != nil {
				return err
			}
			if ok && (old.Status == Effective || old.Status == Superseded) {
				return nil
			}
			if ok && old.Digest != res.Digest {
				e.Log.Warn("equivocation: peer published another withdrawal under a seq this lab holds", "seq", v.Seq, "source", source)
				return nil
			}
			rec := &WithdrawalRecord{Seq: v.Seq, Status: Collecting, Payload: res.Payload, Digest: res.Digest, Envelope: raw, W: *v,
				SignedAt: map[string]string{}, ProposedBy: source, Source: source, CreatedAt: msg.FormatTime(now)}
			if ok {
				rec = old
				rec.Envelope = raw
			}
			if err := e.markEffective(tx, rec, now, res.Operators); err != nil {
				return err
			}
			pubW = rec
		}
		return nil
	})
	if pubB != nil {
		e.afterPublishBundle(pubB)
	}
	if pubW != nil {
		e.afterEffective(pubW)
	}
	return pubB != nil || pubW != nil, err
}

// State is what the checkpoint announces.
type State struct {
	BundleVersion uint64
	BundleDigest  string
	BundleEnv     []byte
	WithdrawalSeq uint64
	Withdrawals   [][]byte // effective withdrawal envelopes, ascending seq
	Log           publog.Head
}

// CurrentState returns the newest published bundle, effective withdrawals
// and the log head.
func (e *Engine) CurrentState() State {
	st := State{BundleDigest: msg.Digest(nil)}
	_ = e.DB.View(func(tx *bolt.Tx) error {
		if b := newestPublished(tx); b != nil {
			st.BundleVersion, st.BundleDigest, st.BundleEnv = b.Version, b.Digest, b.Envelope
		}
		c := tx.Bucket(store.Withdrawals).Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			var w WithdrawalRecord
			if json.Unmarshal(v, &w) != nil {
				continue
			}
			if w.Status == Effective || w.Status == Superseded {
				if w.Seq > st.WithdrawalSeq {
					st.WithdrawalSeq = w.Seq
				}
			}
			if w.Status == Effective {
				st.Withdrawals = append(st.Withdrawals, w.Envelope)
			}
		}
		st.Log = publog.HeadTx(tx)
		return nil
	})
	return st
}

// Fingerprint changes whenever a bundle or withdrawal record changes
// (status, signatures, offers from peers). The dashboard polls it every few
// seconds to notify live views; it reads only the two small buckets.
func (e *Engine) Fingerprint() uint64 {
	h := fnv.New64a()
	_ = e.DB.View(func(tx *bolt.Tx) error {
		for _, b := range [][]byte{store.Bundles, store.Withdrawals} {
			_ = tx.Bucket(b).ForEach(func(k, v []byte) error {
				h.Write(k)
				var r struct {
					Status   string          `json:"status"`
					Envelope json.RawMessage `json:"envelope"`
				}
				_ = json.Unmarshal(v, &r)
				fmt.Fprintf(h, "%s:%d;", r.Status, len(r.Envelope))
				return nil
			})
		}
		return nil
	})
	return h.Sum64()
}
