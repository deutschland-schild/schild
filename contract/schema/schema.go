// Package schema embeds the JSON Schemas of contracts/ (draft 2020-12) and
// validates generic JSON values (from jsonx.Parse) against them.
//
// schema/files is a byte-for-byte copy of contracts/*.schema.json made by
// `make contracts-sync`; TestEmbeddedInSync fails when they drift.
package schema

import (
	"bytes"
	"embed"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/deutschland-schild/schild/contract"
)

//go:embed files
var files embed.FS

// BaseURL is the $id prefix of all contract schemas.
const BaseURL = "https://contracts.schild.invalid/v0/"

// Names of the top-level schemas (file name without .schema.json).
const (
	Envelope   = "envelope"
	Signal     = "signal"
	Feedback   = "feedback"
	Ack        = "ack"
	Submission = "submission"
	Checkpoint = "checkpoint"
	RuleBundle = "rule-bundle"
	Withdrawal = "withdrawal"
	Stream     = "stream"
	Events     = "events"
	Results    = "results"
	ConfigSite = "config/schild"
	ConfigLab  = "config/lab"
	commonName = "common"
	// v0.3 (host-check.md)
	HostReport     = "host-report"
	AgentReport    = "agent-report"
	AgentEnrolment = "agent-enrolment"
	AgentAck       = "agent-ack"
	// v0.5 (MVP-22, D35)
	BotCatalogue = "bot-catalogue"
	BotMatch     = "bot-match"
	GeoMap       = "geo-map"
	// v0.5 (D36): website model of the dashboards
	WebsiteDerive    = "website-derive"
	WebsiteStatus    = "website-status"
	WebsiteException = "website-exception"
	// D36 amendment (2026-10-29): visitors are browser requests.
	WebsiteVisitor = "website-visitor"
	// D37 (2026-10-29, MVP-23 step 1): the waiting page decision.
	WaitingPage = "waiting-page"
	// D38 (2026-10-29): storage bounds and log hygiene.
	StorageBounds = "storage-bounds"
	// Initiator decisions of 2026-10-29 evening (D31 and D33 amendments):
	// the ingress order rule and re-checked requests.
	IngressOrder   = "ingress-order"
	RequestRecheck = "request-recheck"
	// D41 and D42 (2026-10-30): body limits and agent block writes.
	BodyLimits = "body-limits"
	AgentBlock = "agent-block"
	// D56 (2026-11-02, MVP-14 step 1): the access lock decision.
	AccessGate = "access-gate"
	// D57 (2026-11-02, MVP-29): crawler control.
	CrawlerPolicy = "crawler-policy"
	// MVP-12 v1_cut: browser verification ("Kurze Prüfung") and Under Attack.
	HumanCheck = "human-check"
	// D103 (unreleased, MVP-27): whether a node of a group takes a record.
	ClusterRecord = "cluster-record"
)

var (
	once     sync.Once
	compiled map[string]*jsonschema.Schema
	initErr  error
)

// Files returns the embedded schema files (relative path -> bytes).
func Files() map[string][]byte {
	out := map[string][]byte{}
	_ = fs.WalkDir(files, "files", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, _ := files.ReadFile(p)
		out[strings.TrimPrefix(p, "files/")] = b
		return nil
	})
	return out
}

// Names lists all schema names.
func Names() []string {
	var n []string
	for p := range Files() {
		n = append(n, strings.TrimSuffix(p, ".schema.json"))
	}
	sort.Strings(n)
	return n
}

func load() {
	c := jsonschema.NewCompiler()
	c.DefaultDraft(jsonschema.Draft2020)
	for p, b := range Files() {
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
		if err != nil {
			initErr = fmt.Errorf("schema %s: %w", p, err)
			return
		}
		if err := c.AddResource(BaseURL+p, doc); err != nil {
			initErr = fmt.Errorf("schema %s: %w", p, err)
			return
		}
	}
	compiled = map[string]*jsonschema.Schema{}
	for _, n := range Names() {
		s, err := c.Compile(BaseURL + n + ".schema.json")
		if err != nil {
			initErr = fmt.Errorf("compile %s: %w", n, err)
			return
		}
		compiled[n] = s
	}
}

// Validate checks a generic JSON value against a named schema. Violations
// are *contract.Error with code schema.
func Validate(name string, v any) error {
	once.Do(load)
	if initErr != nil {
		return initErr
	}
	s, ok := compiled[name]
	if !ok {
		return fmt.Errorf("schema: unknown schema %q", name)
	}
	if err := s.Validate(v); err != nil {
		return contract.Errf(contract.CodeSchema, "%s: %s", name, oneLine(err)).WithPointer(instancePointer(err))
	}
	return nil
}

// Check compiles all schemas and reports the first error.
func Check() error {
	once.Do(load)
	return initErr
}

// instancePointer is the JSON pointer of the deepest failing place.
func instancePointer(err error) string {
	ve, ok := err.(*jsonschema.ValidationError)
	if !ok {
		return ""
	}
	for len(ve.Causes) > 0 {
		ve = ve.Causes[0]
	}
	if len(ve.InstanceLocation) == 0 {
		return "/"
	}
	return "/" + strings.Join(ve.InstanceLocation, "/")
}

func oneLine(err error) string {
	s := strings.Join(strings.Fields(err.Error()), " ")
	if len(s) > 600 {
		s = s[:600] + "..."
	}
	return s
}

// FileName maps a schema name to its relative file path.
func FileName(name string) string { return path.Clean(name + ".schema.json") }
