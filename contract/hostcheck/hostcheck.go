// Package hostcheck holds the v0.3 contract of the server check and the agent
// (MVP-11, contracts/host-check.md): the host report schild.host_report/0.1,
// the agent delivery payload, the enrolment request, the gateway ack and the
// checks for content a report must never carry (secrets, environment dumps,
// file bodies). The Python cross-check (contracts/tools/crosscheck.py)
// implements the same rules; `make contracts-test` compares both.
package hostcheck

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/msg"
)

// Schema identifiers.
const (
	SchemaReport      = "schild.host_report/0.1"
	SchemaAgentReport = "schild.agent_report/0.1"
	SchemaEnrolment   = "schild.agent_enrolment/0.1"
	SchemaAck         = "schild.agent_ack/0.1"
)

// EnrolmentPayloadType is the DSSE payload type of an enrolment request. It
// is not a trust-store kind: the envelope is signed by the new key itself.
const EnrolmentPayloadType = "application/vnd.schild.agent-enrolment.v0+json"

// Limits of a report (the schema enforces the counts as well).
const (
	MaxFindings  = 500
	MaxInventory = 2000
)

// Roles, statuses, severities and areas.
const (
	RoleGateway = "gateway"
	RoleAgent   = "agent"

	StatusOK         = "ok"
	StatusFinding    = "finding"
	StatusUnreadable = "unreadable"
)

// Severities in ascending order.
var Severities = []string{"info", "low", "medium", "high", "critical"}

// Areas in display order.
var Areas = []string{"distribution", "updates", "ports", "firewall", "ssh", "tls", "software", "logs"}

// Report is schild.host_report/0.1.
type Report struct {
	Schema    string          `json:"schema"`
	ReportID  string          `json:"report_id"`
	Host      Host            `json:"host"`
	Run       Run             `json:"run"`
	Findings  []Finding       `json:"findings"`
	Inventory []InventoryItem `json:"inventory"`
}

// Host identifies the checked host.
type Host struct {
	Hostname   string  `json:"hostname"`
	Role       string  `json:"role"`
	AgentKeyID *string `json:"agent_key_id"`
	OS         OS      `json:"os"`
}

// OS describes distribution, kernel and architecture.
type OS struct {
	ID                   string  `json:"id"`
	VersionID            string  `json:"version_id"`
	Name                 string  `json:"name"`
	Kernel               string  `json:"kernel"`
	Arch                 string  `json:"arch"`
	EOL                  *string `json:"eol"`
	ExtendedSupportUntil *string `json:"extended_support_until,omitempty"`
}

// Run describes one check run.
type Run struct {
	StartedAt     string `json:"started_at"`
	DurationMS    int64  `json:"duration_ms"`
	SchildVersion string `json:"schild_version"`
	EOLTable      string `json:"eol_table"`
	AsRoot        bool   `json:"as_root"`
}

// Finding is one check result.
type Finding struct {
	ID          string  `json:"id"`
	Area        string  `json:"area"`
	Subject     string  `json:"subject,omitempty"`
	Severity    string  `json:"severity"`
	Status      string  `json:"status"`
	Title       string  `json:"title"`
	Explanation string  `json:"explanation"`
	FixCommand  *string `json:"fix_command"`
	// FixConfig (v0.5, D38): a config file to write instead of a command,
	// rendered from a gateway-side template (FixTemplates); only with
	// status finding.
	FixConfig  *FixConfig  `json:"fix_config,omitempty"`
	Evidence   Evidence    `json:"evidence"`
	Unreadable *Unreadable `json:"unreadable,omitempty"`
}

// Evidence holds small typed facts, never free text or file contents.
type Evidence struct {
	Source           string   `json:"source,omitempty"`
	Path             string   `json:"path,omitempty"`
	Setting          string   `json:"setting,omitempty"`
	Value            *string  `json:"value,omitempty"`
	Expected         *string  `json:"expected,omitempty"`
	Port             int      `json:"port,omitempty"`
	Protocol         string   `json:"protocol,omitempty"`
	Address          string   `json:"address,omitempty"`
	Process          string   `json:"process,omitempty"`
	Package          string   `json:"package,omitempty"`
	InstalledVersion string   `json:"installed_version,omitempty"`
	CandidateVersion string   `json:"candidate_version,omitempty"`
	Count            *int64   `json:"count,omitempty"`
	Packages         []string `json:"packages,omitempty"`
	Date             string   `json:"date,omitempty"`
	NotAfter         string   `json:"not_after,omitempty"`
	DaysLeft         *int     `json:"days_left,omitempty"`
	Enabled          *bool    `json:"enabled,omitempty"`
	Policy           string   `json:"policy,omitempty"`
	WindowHours      int      `json:"window_hours,omitempty"`
	// v0.5 (D38, area logs).
	SizeBytes         *int64 `json:"size_bytes,omitempty"`
	GrowthBytesPerDay *int64 `json:"growth_bytes_per_day,omitempty"`
	FSPercent         *int   `json:"fs_percent,omitempty"`
	Mount             string `json:"mount,omitempty"`
}

// FixConfig is a config file a finding suggests (path and full content).
type FixConfig struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

// Unreadable explains why a check could not read safely ("nicht lesbar").
type Unreadable struct {
	Reason string `json:"reason"`
	Needs  string `json:"needs,omitempty"`
}

// InventoryItem is one package, runtime, server, database or app.
type InventoryItem struct {
	Kind    string  `json:"kind"`
	Name    string  `json:"name"`
	Version string  `json:"version"`
	EOL     *string `json:"eol"`
	Source  string  `json:"source"`
	Path    string  `json:"path,omitempty"`
	Parent  string  `json:"parent,omitempty"`
}

// AgentReport is the payload an agent signs (schild.agent_report/0.1).
type AgentReport struct {
	Schema   string `json:"schema"`
	Gateway  string `json:"gateway"`
	IssuedAt string `json:"issued_at"`
	Nonce    string `json:"nonce"`
	Report   Report `json:"report"`
}

// Enrolment is the payload of an enrolment request (schild.agent_enrolment/0.1).
type Enrolment struct {
	Schema    string `json:"schema"`
	Gateway   string `json:"gateway"`
	Code      string `json:"code"`
	KeyID     string `json:"keyid"`
	PublicKey string `json:"public_key"`
	Hostname  string `json:"hostname"`
	IssuedAt  string `json:"issued_at"`
	Nonce     string `json:"nonce"`
}

// Ack is the gateway's only answer to an agent (schild.agent_ack/0.1).
type Ack struct {
	Schema      string  `json:"schema"`
	Status      string  `json:"status"`
	Nonce       string  `json:"nonce"`
	ReceivedAt  string  `json:"received_at"`
	Error       *string `json:"error"`
	RetryAfterS int     `json:"retry_after_s,omitempty"`
}

// ForbiddenFields are key names that never appear in a host report, agent
// report or enrolment request, at any depth. Compared after
// msg.NormalizeFieldName (ASCII lower case without '-', '_' and '.').
var ForbiddenFields = []string{
	"env", "envs", "environ", "environment", "env_vars", "environment_variables",
	"password", "passwd", "passphrase", "secret", "secrets", "secret_key", "private_key", "privkey",
	"api_key", "apikey", "token", "tokens", "access_token", "auth_token", "bearer", "credential", "credentials",
	"cookie", "cookies", "session", "authorization",
	"content", "contents", "file_content", "file_contents", "file_body", "body", "raw", "raw_output",
	"output", "stdout", "stderr", "cmdline", "command_line", "argv", "config_file", "shadow",
}

var forbidden = func() map[string]bool {
	m := map[string]bool{}
	for _, f := range ForbiddenFields {
		m[msg.NormalizeFieldName(f)] = true
	}
	return m
}()

// IsForbiddenField reports whether a key name is never allowed in a report.
func IsForbiddenField(k string) bool { return forbidden[msg.NormalizeFieldName(k)] }

// Content detectors (host-check.md section 2). Both implementations apply
// them to every object key and every string value, at any depth.
var (
	// secretAssign runs on the ASCII-lower-cased string: a secret-looking
	// name directly followed by '=' and a printable character.
	secretAssign = regexp.MustCompile(`(password|passwd|secret|token|api_?key|access_?key|private_?key|credentials?)[a-z0-9_]*=[!-~]`)
	// envAssign runs on the original string; three or more matches are an
	// environment dump.
	envAssign = regexp.MustCompile("(^|[ ;\\t\\n\\x00])[A-Z_][A-Z0-9_]{1,63}=")
)

// pemMarkers are searched in the ASCII-lower-cased string: PEM armour lines
// (keys, certificates, any file body in PEM) and PuTTY key files.
var pemMarkers = []string{"-----begin ", "-----end ", "private key-----", "putty-user-key-file"}

// EnvDumpMin is the number of NAME= assignments in one string that count as
// an environment dump.
const EnvDumpMin = 3

// asciiLower lower-cases ASCII letters only (no Unicode case folding, so Go
// and Python agree byte for byte).
func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}

// ForbiddenContent returns a short reason when s looks like a secret, else "".
func ForbiddenContent(s string) string {
	l := asciiLower(s)
	for _, m := range pemMarkers {
		if strings.Contains(l, m) {
			return "pem"
		}
	}
	if secretAssign.MatchString(l) {
		return "secret assignment"
	}
	if len(envAssign.FindAllStringIndex(s, -1)) >= EnvDumpMin {
		return "environment dump"
	}
	return ""
}

// CheckForbidden runs the two passes in contract order: first every key name
// against ForbiddenFields (forbidden_field), then every key and string value
// against the content detectors (forbidden_content). Two passes keep the
// error code independent of map iteration order.
func CheckForbidden(v any) error {
	if err := walkKeys(v, ""); err != nil {
		return err
	}
	return walkContent(v, "")
}

// fixConfigAt matches the pointer of a finding's fix_config object in a
// host report or an agent report payload.
var fixConfigAt = regexp.MustCompile(`^(/report)?/findings/[0-9]+/fix_config$`)

func walkKeys(v any, at string) error {
	switch t := v.(type) {
	case map[string]any:
		for k, x := range t {
			// v0.5 (D38): fix_config.content is the one place a report
			// carries file content. It is never read from the host: it must
			// equal a gateway-side template (CheckReport), which is stricter
			// than the key net.
			if k == "content" && fixConfigAt.MatchString(at) {
				if err := walkKeys(x, at+"/"+k); err != nil {
					return err
				}
				continue
			}
			if IsForbiddenField(k) {
				return contract.Errf(contract.CodeForbiddenField, "field %q is never allowed in a host report", k).WithPointer(at + "/" + k)
			}
			if err := walkKeys(x, at+"/"+k); err != nil {
				return err
			}
		}
	case []any:
		for i, x := range t {
			if err := walkKeys(x, at+"/"+strconv.Itoa(i)); err != nil {
				return err
			}
		}
	}
	return nil
}

func walkContent(v any, at string) error {
	switch t := v.(type) {
	case string:
		if r := ForbiddenContent(t); r != "" {
			return contract.Errf(contract.CodeForbiddenContent, "value looks like a secret (%s)", r).WithPointer(at)
		}
	case map[string]any:
		for k, x := range t {
			if r := ForbiddenContent(k); r != "" {
				// The key itself is the secret: point at its parent.
				return contract.Errf(contract.CodeForbiddenContent, "key looks like a secret (%s)", r).WithPointer(at + "/*")
			}
			if err := walkContent(x, at+"/"+k); err != nil {
				return err
			}
		}
	case []any:
		for i, x := range t {
			if err := walkContent(x, at+"/"+strconv.Itoa(i)); err != nil {
				return err
			}
		}
	}
	return nil
}

// CheckReport runs the semantic checks of a schema-valid host report given
// as generic JSON: (id, subject) of findings is unique, then every
// fix_config is a rendering of a template of its finding id (v0.5, D38;
// both code schema).
func CheckReport(report map[string]any) error {
	if err := checkUnique(report); err != nil {
		return err
	}
	fs, _ := report["findings"].([]any)
	for i, f := range fs {
		m, _ := f.(map[string]any)
		fc, ok := m["fix_config"].(map[string]any)
		if !ok {
			continue
		}
		id, _ := m["id"].(string)
		p, _ := fc["path"].(string)
		c, _ := fc["content"].(string)
		if !FixConfigKnown(id, p, c) {
			return contract.Errf(contract.CodeSchema, "fix_config of %s is not a rendering of a gateway template", id).WithPointer("/findings/" + strconv.Itoa(i) + "/fix_config")
		}
	}
	return nil
}

func checkUnique(report map[string]any) error {
	seen := map[string]bool{}
	fs, _ := report["findings"].([]any)
	for _, f := range fs {
		m, _ := f.(map[string]any)
		id, _ := m["id"].(string)
		subj, _ := m["subject"].(string)
		k := id + "\x00" + subj
		if seen[k] {
			return contract.Errf(contract.CodeSchema, "finding %s (subject %q) appears twice", id, subj).WithPointer("/findings")
		}
		seen[k] = true
	}
	return nil
}
