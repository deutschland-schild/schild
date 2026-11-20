package rules

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/jsonx"
	"github.com/deutschland-schild/schild/contract/msg"
	"github.com/deutschland-schild/schild/contract/seclang"
	"github.com/deutschland-schild/schild/lab/internal/publog"
	"github.com/deutschland-schild/schild/lab/internal/scoring"
	"github.com/deutschland-schild/schild/lab/internal/store"
)

// LocalhostUser is the session user of unauthenticated localhost sessions
// (they may draft but not decide); drafts by it have no named author.
const LocalhostUser = "localhost"

// ProposalInput is the API ProposalInput (create and edit).
type ProposalInput struct {
	PatternID          *string          `json:"pattern_id"`
	Class              *string          `json:"class"`
	SecLang            *string          `json:"seclang"`
	Target             *json.RawMessage `json:"target"`
	RequestedMaxAction *string          `json:"requested_max_action"`
	MaxActionUntil     *string          `json:"max_action_until"`
	Stage              *string          `json:"stage"`
}

// EvidenceInput is the API EvidenceInput.
type EvidenceInput struct {
	Kind          string `json:"kind"`
	Image         string `json:"image"`
	Version       string `json:"version"`
	Request       string `json:"request"`
	Result        string `json:"result"`
	CorpusVersion string `json:"corpus_version"`
	CorpusMatches *int   `json:"corpus_matches"`
}

// ApproveInput is the API ApproveProposal.
type ApproveInput struct {
	MaxAction      string `json:"max_action"`
	MaxActionUntil string `json:"max_action_until"`
	Org            string `json:"org"`
	Note           string `json:"note"`
}

var (
	classes    = []string{"virtual_patch", "heuristic", "behavioral"}
	stages     = []string{"shadow", "canary", "general"}
	actions    = []string{"observe", "challenge", "block"}
	safeToken  = regexp.MustCompile(`^[a-z0-9][a-z0-9._/-]{0,127}$`)
	versionsRe = regexp.MustCompile(`^[<>=!~^*0-9A-Za-z., -]{1,64}$`)
	cveRe      = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,7}$`)
	corpusRe   = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,63}$`)
	printable  = regexp.MustCompile(`^[ -~]{1,200}$`)
	patternRe  = regexp.MustCompile(`^p_[0-9a-f]{16}$`)
)

func getProposal(tx *bolt.Tx, id string) (*Proposal, error) {
	var p Proposal
	ok, err := store.GetJSON(tx, store.Proposals, []byte(id), &p)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errf(http.StatusNotFound, "not_found", "", "proposal %s not found", id)
	}
	return &p, nil
}

func putProposal(tx *bolt.Tx, p *Proposal) error {
	return store.PutJSON(tx, store.Proposals, []byte(p.ID), p)
}

// View renders a proposal for the API with live evidence.
func (e *Engine) View(tx *bolt.Tx, p *Proposal) ProposalView {
	lvl, ev := e.Level(tx, p, nil)
	chk := Check{Valid: true}
	if _, err := seclang.Validate(p.SecLang, seclang.Options{MaxAction: p.RequestedMaxAction}); err != nil {
		chk = Check{Valid: false, Error: err.Error()}
	}
	v := ProposalView{
		ID: p.ID, RuleID: p.RuleID, Status: p.Status, Class: p.Class, Stage: p.Stage, SecLang: p.SecLang, SecLangCheck: chk,
		Target: p.Target, RequestedMaxAction: p.RequestedMaxAction, Approvals: p.Approvals, CreatedAt: p.CreatedAt, UpdatedAt: p.UpdatedAt,
		Evidence: EvidenceView{
			ReproducedOperators: ev.ReproducedOperators, SensorOperators: ev.SensorOperators, TipIssuers: ev.TipIssuers,
			MaxIssuerShare: ev.MaxIssuerShare, HumanApprovalOrgs: ev.HumanApprovalOrgs, NegativeCorpus: p.Corpus, Reproductions: p.Reproductions,
		},
	}
	if v.Approvals == nil {
		v.Approvals = []Approval{}
	}
	if v.Evidence.Reproductions == nil {
		v.Evidence.Reproductions = []Reproduction{}
	}
	if p.PatternID != "" {
		v.PatternID = ptr(p.PatternID)
	}
	if lvl != "" {
		v.AllowedMaxAction = ptr(lvl)
	}
	if p.MaxActionUntil != "" {
		v.MaxActionUntil = ptr(p.MaxActionUntil)
	}
	if p.RejectedReason != "" {
		v.RejectedReason = ptr(p.RejectedReason)
	}
	if p.BundleVersion != 0 {
		v.BundleVersion = ptr(p.BundleVersion)
	}
	if p.CreatedBy != "" && p.CreatedBy != LocalhostUser {
		v.CreatedBy = ptr(p.CreatedBy)
	}
	return v
}

// GetProposal returns the API view of a proposal.
func (e *Engine) GetProposal(id string) (ProposalView, error) {
	var v ProposalView
	err := e.DB.View(func(tx *bolt.Tx) error {
		p, err := getProposal(tx, id)
		if err != nil {
			return err
		}
		v = e.View(tx, p)
		return nil
	})
	return v, err
}

// ListProposals returns proposals (newest first) with an offset cursor.
func (e *Engine) ListProposals(status string, offset, limit int) ([]ProposalView, int, error) {
	var out []ProposalView
	next := -1
	err := e.DB.View(func(tx *bolt.Tx) error {
		var all []*Proposal
		err := tx.Bucket(store.Proposals).ForEach(func(_, v []byte) error {
			var p Proposal
			if json.Unmarshal(v, &p) == nil && (status == "" || p.Status == status) {
				all = append(all, &p)
			}
			return nil
		})
		if err != nil {
			return err
		}
		sort.Slice(all, func(i, j int) bool {
			if all[i].CreatedAt != all[j].CreatedAt {
				return all[i].CreatedAt > all[j].CreatedAt
			}
			return all[i].ID > all[j].ID
		})
		offset = min(offset, len(all))
		end := min(offset+limit, len(all))
		for _, p := range all[offset:end] {
			out = append(out, e.View(tx, p))
		}
		if end < len(all) {
			next = end
		}
		return nil
	})
	if out == nil {
		out = []ProposalView{}
	}
	return out, next, err
}

func invalid(pointer, format string, a ...any) *Error {
	return errf(http.StatusBadRequest, "invalid", pointer, format, a...)
}

func (e *Engine) applyInput(tx *bolt.Tx, p *Proposal, in ProposalInput) error {
	if in.PatternID != nil {
		if *in.PatternID != "" {
			if !patternRe.MatchString(*in.PatternID) {
				return invalid("/pattern_id", "unknown pattern")
			}
			if _, ok, _ := scoring.GetPattern(tx, *in.PatternID); !ok {
				return invalid("/pattern_id", "unknown pattern")
			}
		}
		p.PatternID = *in.PatternID
	}
	if in.Class != nil {
		if !slices.Contains(classes, *in.Class) {
			return invalid("/class", "class must be one of %v", classes)
		}
		p.Class = *in.Class
	}
	if in.Stage != nil {
		if !slices.Contains(stages, *in.Stage) {
			return invalid("/stage", "stage must be one of %v", stages)
		}
		p.Stage = *in.Stage
	}
	if in.RequestedMaxAction != nil {
		if !slices.Contains(actions, *in.RequestedMaxAction) {
			return invalid("/requested_max_action", "max action must be one of %v", actions)
		}
		p.RequestedMaxAction = *in.RequestedMaxAction
	}
	if in.MaxActionUntil != nil {
		if _, err := msg.ParseTime(*in.MaxActionUntil); err != nil && *in.MaxActionUntil != "" {
			return invalid("/max_action_until", "timestamp must be YYYY-MM-DDTHH:MM:SSZ")
		}
		p.MaxActionUntil = *in.MaxActionUntil
	}
	if in.SecLang != nil {
		if len(*in.SecLang) > contract.MaxSecLangBytes {
			return invalid("/seclang", "rule text over %d bytes", contract.MaxSecLangBytes)
		}
		p.SecLang = *in.SecLang
	}
	if in.Target != nil {
		var t Target
		v, err := jsonx.ParseObject(*in.Target)
		if err == nil {
			err = jsonx.Decode(v, &t)
		}
		if err != nil {
			return invalid("/target", "target needs software, versions and optional cve")
		}
		if !safeToken.MatchString(t.Software) {
			return invalid("/target/software", "software must be a lower-case token like wp-plugin/gallery")
		}
		if !versionsRe.MatchString(t.Versions) {
			return invalid("/target/versions", "versions like <2.4.1")
		}
		for i, c := range t.CVE {
			if !cveRe.MatchString(c) {
				return invalid(fmt.Sprintf("/target/cve/%d", i), "CVE id like CVE-2026-12345")
			}
		}
		p.Target = t
	}
	return nil
}

// CreateProposal drafts a proposal. The rule text is checked against the
// SecLang subset at once; an invalid text is stored as a draft with the
// error in seclang_check.
func (e *Engine) CreateProposal(in ProposalInput, by string) (ProposalView, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.now()
	var v ProposalView
	err := e.DB.Update(func(tx *bolt.Tx) error {
		p := &Proposal{Status: StatusDraft, Class: "heuristic", Stage: "shadow", RequestedMaxAction: "observe",
			Target: Target{Software: "generic", Versions: "*"}, CreatedAt: msg.FormatTime(now), UpdatedAt: msg.FormatTime(now), CreatedBy: by,
			Reproductions: []Reproduction{}, Sensors: []Sensor{}, Approvals: []Approval{}}
		if err := e.applyInput(tx, p, in); err != nil {
			return err
		}
		if p.SecLang == "" {
			return invalid("/seclang", "a rule text is required")
		}
		n, err := store.NextCounter(tx, "proposal")
		if err != nil {
			return err
		}
		p.ID = fmt.Sprintf("prop-%04d", n)
		year := now.Year()
		r, err := store.NextCounter(tx, "rule:"+strconv.Itoa(year))
		if err != nil {
			return err
		}
		p.RuleID = fmt.Sprintf("schild-%d-%04d", year, r)
		if err := putProposal(tx, p); err != nil {
			return err
		}
		if p.PatternID != "" {
			if err := scoring.SetStatus(tx, p.PatternID, scoring.StatusProposed, p.ID); err != nil {
				return err
			}
		}
		v = e.View(tx, p)
		return nil
	})
	return v, err
}

// UpdateProposal edits a draft or a proposal in review. Changing what was
// approved (text, class, target, action) clears earlier approvals.
func (e *Engine) UpdateProposal(id string, in ProposalInput) (ProposalView, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	var v ProposalView
	err := e.DB.Update(func(tx *bolt.Tx) error {
		p, err := getProposal(tx, id)
		if err != nil {
			return err
		}
		if p.Status != StatusDraft && p.Status != StatusReview && p.Status != StatusApproved {
			return errf(http.StatusConflict, "conflict", "", "proposal is %s and can no longer be edited", p.Status)
		}
		before := fmt.Sprint(p.SecLang, p.Class, p.Target, p.RequestedMaxAction, p.MaxActionUntil, p.Stage)
		oldPattern := p.PatternID
		if err := e.applyInput(tx, p, in); err != nil {
			return err
		}
		if fmt.Sprint(p.SecLang, p.Class, p.Target, p.RequestedMaxAction, p.MaxActionUntil, p.Stage) != before && len(p.Approvals) > 0 {
			p.Approvals = []Approval{}
			p.Status = StatusReview
		}
		if oldPattern != p.PatternID {
			if oldPattern != "" {
				_ = scoring.SetStatus(tx, oldPattern, scoring.StatusWatching, "")
			}
			if p.PatternID != "" {
				_ = scoring.SetStatus(tx, p.PatternID, scoring.StatusProposed, p.ID)
			}
		}
		p.UpdatedAt = msg.FormatTime(e.now())
		if err := putProposal(tx, p); err != nil {
			return err
		}
		v = e.View(tx, p)
		return nil
	})
	return v, err
}

// AddEvidence attaches a reproduction, a sensor observation or a negative
// corpus result. Reproductions keep the raw request privately; only its
// sha256 is shown and logged.
func (e *Engine) AddEvidence(id string, in EvidenceInput) (ProposalView, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.now()
	var v ProposalView
	err := e.DB.Update(func(tx *bolt.Tx) error {
		p, err := getProposal(tx, id)
		if err != nil {
			return err
		}
		if p.Status == StatusRejected || p.Status == StatusWithdrawn {
			return errf(http.StatusConflict, "conflict", "", "proposal is %s", p.Status)
		}
		at := msg.FormatTime(now)
		switch in.Kind {
		case "reproduction":
			if !printable.MatchString(in.Image) {
				return invalid("/image", "target container image is required (for example wordpress:6.6.2)")
			}
			if !printable.MatchString(in.Version) {
				return invalid("/version", "target software version is required")
			}
			if strings.TrimSpace(in.Request) == "" || len(in.Request) > 65536 {
				return invalid("/request", "the reproducing request is required (raw HTTP, at most 64 KiB)")
			}
			status := in.Result
			if status == "" {
				status = "reproduced"
			}
			if status != "reproduced" && status != "not_reproduced" {
				return invalid("/result", "result must be reproduced or not_reproduced")
			}
			d := msg.Digest([]byte(in.Request))
			if err := tx.Bucket(store.ReproRequests).Put([]byte(d), []byte(in.Request)); err != nil {
				return err
			}
			r := Reproduction{Lab: e.Cfg.Lab, Operator: e.Cfg.Operator, Status: status, Image: in.Image, Version: in.Version, RequestDigest: d, At: &at}
			p.Reproductions = slices.DeleteFunc(p.Reproductions, func(x Reproduction) bool {
				return x.Lab == r.Lab && x.Image == r.Image && x.Version == r.Version
			})
			p.Reproductions = append(p.Reproductions, r)
		case "sensor":
			p.Sensors = slices.DeleteFunc(p.Sensors, func(s Sensor) bool { return s.Lab == e.Cfg.Lab })
			p.Sensors = append(p.Sensors, Sensor{Lab: e.Cfg.Lab, Operator: e.Cfg.Operator, At: at})
		case "negative_corpus":
			if !corpusRe.MatchString(in.CorpusVersion) {
				return invalid("/corpus_version", "corpus version like corpus-2026.10")
			}
			if in.CorpusMatches == nil || *in.CorpusMatches < 0 {
				return invalid("/corpus_matches", "number of matches is required")
			}
			p.Corpus = &Corpus{Version: in.CorpusVersion, Matches: *in.CorpusMatches}
		default:
			return invalid("/kind", "kind must be reproduction, sensor or negative_corpus")
		}
		if p.Status == StatusDraft {
			p.Status = StatusReview
		}
		p.UpdatedAt = at
		if err := putProposal(tx, p); err != nil {
			return err
		}
		v = e.View(tx, p)
		return nil
	})
	return v, err
}

// ruleFor builds the network rule of a proposal with a given action.
func (e *Engine) ruleFor(tx *bolt.Tx, p *Proposal, action, until string, extra *Approval) msg.Rule {
	_, ev := e.Level(tx, p, extra)
	fp := "auto_downgrade"
	if p.Class == "virtual_patch" {
		fp = "narrow_only"
	}
	r := msg.Rule{RuleID: p.RuleID, Class: p.Class, Stage: p.Stage, MaxAction: action, MaxMatchShare: e.Cfg.MaxMatchShare,
		Target: msg.Target{Software: p.Target.Software, Versions: p.Target.Versions, CVE: p.Target.CVE}, Evidence: ev,
		FeedbackPolicy: fp, SecLang: p.SecLang}
	if action == "challenge" || action == "block" {
		r.MaxActionUntil = until
	}
	return r
}

// checkRule runs the contract checks of one rule inside a bundle that would
// be issued now.
func (e *Engine) checkRule(r msg.Rule, now time.Time) error {
	b := msg.Bundle{Schema: msg.SchemaBundle, BundleID: e.Cfg.Channel, Version: 1, IssuedAt: msg.FormatTime(now),
		Expires: msg.FormatTime(now.Add(time.Duration(e.validity(0)) * time.Hour)), Rules: []msg.Rule{r}}
	raw, err := jsonx.Marshal(&b)
	if err != nil {
		return err
	}
	_, err = e.selfCheck(contract.KindBundle, raw, now)
	return err
}

func (e *Engine) validity(h int) int {
	if h <= 0 {
		h = e.ValidityHours()
	}
	return min(max(h, 1), 744)
}

// Approve records a human approval. The approved max action can never
// exceed the requested action nor what the evidence allows (including this
// approval's organisation); the rule must pass the contract checks with it.
func (e *Engine) Approve(id string, in ApproveInput, by string) (ProposalView, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.now()
	var v ProposalView
	err := e.DB.Update(func(tx *bolt.Tx) error {
		p, err := getProposal(tx, id)
		if err != nil {
			return err
		}
		if p.Status != StatusDraft && p.Status != StatusReview && p.Status != StatusApproved {
			return errf(http.StatusConflict, "conflict", "", "proposal is %s", p.Status)
		}
		if by == "" {
			return errf(http.StatusForbidden, "forbidden", "", "an approval needs a named person")
		}
		org := strings.TrimSpace(in.Org)
		if !printable.MatchString(org) {
			return invalid("/org", "name the organisation you approve for")
		}
		if !slices.Contains(actions, in.MaxAction) {
			return invalid("/max_action", "max action must be one of %v", actions)
		}
		// Four eyes (contracts v0.1): the author never approves their own proposal.
		if p.CreatedBy != "" && p.CreatedBy != LocalhostUser && p.CreatedBy == by {
			return errf(http.StatusForbidden, "self_approval", "", "%s drafted this proposal; another person has to approve it", by)
		}
		for _, a := range p.Approvals {
			if a.By == by {
				return errf(http.StatusConflict, "conflict", "", "%s already approved this proposal", by)
			}
		}
		if msg.MaxActionRank(in.MaxAction) > msg.MaxActionRank(p.RequestedMaxAction) {
			return errf(http.StatusConflict, "evidence", "/max_action", "approval %s exceeds the requested %s", in.MaxAction, p.RequestedMaxAction)
		}
		if !hasReproduction(p) {
			return errf(http.StatusConflict, "evidence", "", "a reproduction (reproducing request and target container version) is required before approval")
		}
		a := Approval{By: by, Org: org, At: msg.FormatTime(now), MaxAction: in.MaxAction}
		lvl, _ := e.Level(tx, p, &a)
		if lvl == "" || msg.MaxActionRank(in.MaxAction) > msg.MaxActionRank(lvl) {
			allowed := lvl
			if allowed == "" {
				allowed = "none"
			}
			return errf(http.StatusConflict, "evidence", "/max_action", "the evidence allows at most %s, approval asks for %s", allowed, in.MaxAction)
		}
		until := in.MaxActionUntil
		if until == "" {
			until = p.MaxActionUntil
		}
		if in.MaxAction != "observe" {
			if until == "" {
				return invalid("/max_action_until", "challenge and block need an end date")
			}
			p.MaxActionUntil = until
		}
		if err := e.checkRule(e.ruleFor(tx, p, in.MaxAction, until, &a), now); err != nil {
			code := string(contract.CodeOf(err))
			if code == "" {
				code = "invalid"
			}
			return errf(http.StatusConflict, code, "", "rule check failed: %v", err)
		}
		p.Approvals = append(p.Approvals, a)
		if in.Note != "" {
			p.ApprovalNotes = append(p.ApprovalNotes, by+": "+in.Note)
		}
		p.Status = StatusApproved
		p.UpdatedAt = msg.FormatTime(now)
		if err := putProposal(tx, p); err != nil {
			return err
		}
		orgs, _ := e.evidence(tx, p, nil, false)
		if _, err := publog.Append(tx, now, publog.KindProposal, p.ID, msg.Digest([]byte(p.SecLang)),
			fmt.Sprintf("proposal %s approved: rule %s %s, max %s, approvals from %d organisations", p.ID, p.RuleID, p.Class, in.MaxAction, orgs.HumanApprovalOrgs), nil); err != nil {
			return err
		}
		v = e.View(tx, p)
		return nil
	})
	return v, err
}

func hasReproduction(p *Proposal) bool {
	for _, r := range p.Reproductions {
		if r.Status == "reproduced" && r.RequestDigest != "" && r.Image != "" && r.Version != "" {
			return true
		}
	}
	return false
}

// Reject closes a proposal with a reason (audit trail in the public log;
// the reason text stays in the lab).
func (e *Engine) Reject(id, reason, by string) (ProposalView, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.now()
	var v ProposalView
	err := e.DB.Update(func(tx *bolt.Tx) error {
		p, err := getProposal(tx, id)
		if err != nil {
			return err
		}
		if p.Status == StatusPublished || p.Status == StatusWithdrawn || p.Status == StatusRejected {
			return errf(http.StatusConflict, "conflict", "", "proposal is %s", p.Status)
		}
		reason = strings.TrimSpace(reason)
		if reason == "" || len(reason) > 1000 {
			return invalid("/reason", "a reason is required")
		}
		p.Status, p.RejectedReason, p.RejectedBy = StatusRejected, reason, by
		p.UpdatedAt = msg.FormatTime(now)
		if err := putProposal(tx, p); err != nil {
			return err
		}
		if p.PatternID != "" {
			_ = scoring.SetStatus(tx, p.PatternID, scoring.StatusWatching, "")
		}
		if _, err := publog.Append(tx, now, publog.KindProposal, p.ID, msg.Digest([]byte(p.SecLang)),
			fmt.Sprintf("proposal %s rejected: rule %s", p.ID, p.RuleID), nil); err != nil {
			return err
		}
		v = e.View(tx, p)
		return nil
	})
	return v, err
}

// ReproRequest returns the stored reproducing request (lab-internal).
func (e *Engine) ReproRequest(digest string) (string, bool) {
	var out []byte
	_ = e.DB.View(func(tx *bolt.Tx) error {
		out = slices.Clone(tx.Bucket(store.ReproRequests).Get([]byte(digest)))
		return nil
	})
	return string(out), out != nil
}
