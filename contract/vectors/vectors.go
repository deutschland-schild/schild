// Package vectors loads and runs the golden test vectors of contracts/vectors
// with the Go reference implementation. The Python cross-check
// (contracts/tools/crosscheck.py) runs the same files independently;
// `make contracts-test` fails when the two disagree.
package vectors

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/access"
	"github.com/deutschland-schild/schild/contract/agentapi"
	"github.com/deutschland-schild/schild/contract/bodylimit"
	"github.com/deutschland-schild/schild/contract/bots"
	"github.com/deutschland-schild/schild/contract/cluster"
	"github.com/deutschland-schild/schild/contract/crawlers"
	"github.com/deutschland-schild/schild/contract/crowdsec"
	"github.com/deutschland-schild/schild/contract/geo"
	"github.com/deutschland-schild/schild/contract/humancheck"
	"github.com/deutschland-schild/schild/contract/ingress"
	"github.com/deutschland-schild/schild/contract/jsonx"
	"github.com/deutschland-schild/schild/contract/keys"
	"github.com/deutschland-schild/schild/contract/monitoring"
	"github.com/deutschland-schild/schild/contract/msg"
	"github.com/deutschland-schild/schild/contract/rules"
	"github.com/deutschland-schild/schild/contract/seclang"
	"github.com/deutschland-schild/schild/contract/storage"
	"github.com/deutschland-schild/schild/contract/verify"
	"github.com/deutschland-schild/schild/contract/waitingpage"
	"github.com/deutschland-schild/schild/contract/websites"
)

// Vector is one golden vector file.
type Vector struct {
	Contract     string          `json:"contract"`
	Description  string          `json:"description"`
	Context      Context         `json:"context"`
	InputRaw     string          `json:"input_raw"`
	InputDecoded json.RawMessage `json:"input_decoded,omitempty"`
	Expect       Expect          `json:"expect"`
}

// Context is the verification context of a vector.
type Context struct {
	Now                string            `json:"now"`
	Kind               string            `json:"kind,omitempty"`
	Trust              []string          `json:"trust,omitempty"`
	Threshold          int               `json:"threshold,omitempty"`
	Channel            string            `json:"channel,omitempty"`
	SeenIDs            []string          `json:"seen_ids,omitempty"`
	ExpectedInReplyTo  string            `json:"expected_in_reply_to,omitempty"`
	State              *State            `json:"state,omitempty"`
	SimulatedOperators map[string]string `json:"simulated_operators,omitempty"`
	MaxAction          string            `json:"max_action,omitempty"`
	// v0.3 (host-check.md): key names (as in trust) the gateway revoked, and
	// the gateway node_name agent reports and enrolments must address.
	Revoked []string `json:"revoked,omitempty"`
	Gateway string   `json:"gateway,omitempty"`
}

// State mirrors verify.State in JSON.
type State struct {
	BundleVersion    uint64            `json:"bundle_version,omitempty"`
	BundleDigest     string            `json:"bundle_digest,omitempty"`
	WithdrawalSeq    uint64            `json:"withdrawal_seq,omitempty"`
	WithdrawalDigest string            `json:"withdrawal_digest,omitempty"`
	CheckpointSeq    map[string]uint64 `json:"checkpoint_seq,omitempty"`
	CheckpointDigest map[string]string `json:"checkpoint_digest,omitempty"`
}

// Expect is the expected verdict. v0.5: classifier vectors (bot-match,
// geo-map, website-derive, website-status, website-exception,
// website-visitor, waiting-page, storage-bounds, ingress-order,
// request-recheck, crowdsec-hub, rule-effect, body-limits, agent-block, access-gate, crawler-policy, cluster-record) also expect a result for
// valid inputs.
type Expect struct {
	Valid  bool            `json:"valid"`
	Error  string          `json:"error,omitempty"`
	Result json.RawMessage `json:"result,omitempty"`
}

// Verdict is the result of running one vector.
type Verdict struct {
	File   string          `json:"file"`
	Valid  bool            `json:"valid"`
	Error  string          `json:"error,omitempty"`
	Result json.RawMessage `json:"result,omitempty"`
	Detail string          `json:"detail,omitempty"`
}

// Matches reports whether the verdict equals the expectation (results
// compared as JSON values).
func (v Verdict) Matches(e Expect) bool {
	return v.Valid == e.Valid && v.Error == e.Error && SameJSON(v.Result, e.Result)
}

// SameJSON reports whether a and b are the same JSON value (both empty
// counts as the same).
func SameJSON(a, b json.RawMessage) bool {
	if len(a) == 0 || len(b) == 0 {
		return len(a) == len(b)
	}
	var x, y any
	if json.Unmarshal(a, &x) != nil || json.Unmarshal(b, &y) != nil {
		return false
	}
	return reflect.DeepEqual(x, y)
}

// KeyFile is contracts/testkeys/keys.json (public parts are enough).
type KeyFile struct {
	Keys []struct {
		Name     string             `json:"name"`
		KeyID    string             `json:"keyid"`
		Public   string             `json:"public_key"`
		Purposes []contract.Purpose `json:"purposes"`
		Operator string             `json:"operator"`
		Lab      string             `json:"lab"`
		Issuer   string             `json:"issuer"`
	} `json:"keys"`
}

// Runner runs vectors against a key file.
type Runner struct {
	keys map[string]keys.TrustedKey
}

// NewRunner loads keys.json.
func NewRunner(keyFile string) (*Runner, error) {
	b, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}
	var kf KeyFile
	if err := json.Unmarshal(b, &kf); err != nil {
		return nil, err
	}
	r := &Runner{keys: map[string]keys.TrustedKey{}}
	for _, k := range kf.Keys {
		pub, err := keys.ParsePublicKey(k.Public)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", k.Name, err)
		}
		r.keys[k.Name] = keys.TrustedKey{KeyID: k.KeyID, Public: pub, Purposes: k.Purposes, Operator: k.Operator, Lab: k.Lab, Issuer: k.Issuer}
	}
	return r, nil
}

// Files lists all vector files under dir, sorted.
func Files(dir string) ([]string, error) {
	var out []string
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(p, ".json") && (strings.Contains(p, "/valid/") || strings.Contains(p, "/invalid/")) {
			out = append(out, p)
		}
		return nil
	})
	sort.Strings(out)
	return out, err
}

// Load reads one vector file.
func Load(path string) (*Vector, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var v Vector
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &v, nil
}

// Run executes one vector and returns the verdict.
func (r *Runner) Run(v *Vector) (Verdict, error) {
	ctx, err := r.context(v.Context)
	if err != nil {
		return Verdict{}, err
	}
	raw := []byte(v.InputRaw)
	var verr error
	var result any
	switch v.Contract {
	case "bot-catalogue":
		_, verr = bots.Parse(raw)
	case "bot-match":
		result, verr = bots.RunVector(raw, ctx.Now)
	case "geo-map":
		result, verr = geo.RunVector(raw)
	case "website-derive": // v0.5 (D36)
		result, verr = websites.RunDeriveVector(raw)
	case "website-status":
		result, verr = websites.RunStatusVector(raw)
	case "website-exception":
		result, verr = websites.RunExceptionVector(raw)
	case "website-visitor": // D36 amendment 2026-10-29
		result, verr = websites.RunVisitorVector(raw)
	case "waiting-page": // D37 (MVP-23 step 1)
		result, verr = waitingpage.RunVector(raw)
	case "body-limits": // D41
		result, verr = bodylimit.RunVector(raw)
	case "agent-block": // D42
		result, verr = agentapi.RunBlockVector(raw)
	case "cluster-record": // D105
		result, verr = cluster.RunVector(raw, ctx.Now)
	case "access-gate": // D56
		result, verr = access.RunVector(raw)
	case "crawler-policy": // D57
		result, verr = crawlers.RunVector(raw, ctx.Now)
	case "human-check": // MVP-12 v1_cut
		result, verr = humancheck.RunVector(raw, ctx.Now)
	case "storage-bounds": // D38
		result, verr = storage.RunVector(raw)
	case "ingress-order": // D31 amendment 2026-10-29
		result, verr = ingress.RunVector(raw)
	case "request-recheck": // D33 amendment 2026-10-29
		result, verr = monitoring.RunRecheckVector(raw)
	case "crowdsec-hub": // D39 (MVP-26)
		result, verr = crowdsec.RunVector(raw)
	case "rule-effect": // D73
		result, verr = rules.RunVector(raw)
	case "crowdsec-set":
		_, verr = crowdsec.ParseSet(raw)
	case "envelope":
		_, verr = verify.Signed(contract.Kind(v.Context.Kind), raw, ctx)
	case "signal", "feedback", "ack", "checkpoint", "rule-bundle", "withdrawal", "agent-report":
		_, verr = verify.Signed(contract.Kind(v.Contract), raw, ctx)
	case "agent-enrolment":
		_, verr = verify.AgentEnrolment(raw, ctx)
	case "submission", "stream", "events", "config/schild", "config/lab", "results", "log-tree", "peer-request", "host-report", "agent-ack":
		_, verr = verify.Document(verify.Doc(v.Contract), raw, ctx)
	case "seclang":
		_, verr = seclang.Validate(v.InputRaw, seclang.Options{MaxAction: v.Context.MaxAction})
	default:
		return Verdict{}, fmt.Errorf("unknown contract %q", v.Contract)
	}
	if verr == nil {
		vd := Verdict{Valid: true}
		if result != nil {
			b, err := jsonx.Marshal(result)
			if err != nil {
				return Verdict{}, err
			}
			vd.Result = b
		}
		return vd, nil
	}
	code := contract.CodeOf(verr)
	if code == "" {
		return Verdict{}, fmt.Errorf("non-contract error: %w", verr)
	}
	return Verdict{Valid: false, Error: string(code), Detail: verr.Error()}, nil
}

func (r *Runner) context(c Context) (*verify.Context, error) {
	now, err := msg.ParseTime(c.Now)
	if err != nil && c.Now != "" {
		return nil, fmt.Errorf("context.now: %w", err)
	}
	if c.Now == "" {
		now = time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	}
	ts := keys.NewTrustStore()
	for _, n := range c.Trust {
		k, ok := r.keys[n]
		if !ok {
			return nil, fmt.Errorf("context.trust: unknown key %q", n)
		}
		if err := ts.Add(k); err != nil {
			return nil, err
		}
	}
	seen := map[string]bool{}
	for _, id := range c.SeenIDs {
		seen[id] = true
	}
	revoked := map[string]bool{}
	for _, n := range c.Revoked {
		k, ok := r.keys[n]
		if !ok {
			return nil, fmt.Errorf("context.revoked: unknown key %q", n)
		}
		revoked[k.KeyID] = true
	}
	ctx := &verify.Context{
		Now:               now,
		Trust:             ts,
		Threshold:         c.Threshold,
		Channel:           c.Channel,
		Seen:              func(id string) bool { return seen[id] },
		ExpectedInReplyTo: c.ExpectedInReplyTo,
		Revoked:           func(keyid string) bool { return revoked[keyid] },
		Gateway:           c.Gateway,
	}
	if s := c.State; s != nil {
		ctx.State = verify.State{
			BundleVersion: s.BundleVersion, BundleDigest: s.BundleDigest,
			WithdrawalSeq: s.WithdrawalSeq, WithdrawalDigest: s.WithdrawalDigest,
			CheckpointSeq: s.CheckpointSeq, CheckpointDigest: s.CheckpointDigest,
		}
	}
	if len(c.SimulatedOperators) > 0 {
		sim := c.SimulatedOperators
		ctx.OperatorOf = func(k *keys.TrustedKey) string {
			if op, ok := sim[k.Lab]; ok {
				return op
			}
			return k.Operator
		}
	}
	return ctx, nil
}

// RunAll runs every vector under dir.
func (r *Runner) RunAll(dir string) ([]Verdict, []*Vector, error) {
	files, err := Files(dir)
	if err != nil {
		return nil, nil, err
	}
	var out []Verdict
	var vecs []*Vector
	for _, f := range files {
		v, err := Load(f)
		if err != nil {
			return nil, nil, err
		}
		vd, err := r.Run(v)
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %w", f, err)
		}
		rel, _ := filepath.Rel(dir, f)
		vd.File = filepath.ToSlash(rel)
		out = append(out, vd)
		vecs = append(vecs, v)
	}
	return out, vecs, nil
}
