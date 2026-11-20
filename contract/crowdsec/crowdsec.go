// Package crowdsec is the contract of the crowdsec rule repository of the
// gateway (D39, D73, contracts/crowdsec-hub.md): the conversion of public
// CrowdSec Hub rules from YAML to SecLang, the update of a rule set and which
// set loads at start. The effect of a rule and the state of the repository are
// contract/rules, as for every repository. Everything here is a pure function
// of its input: no network, no clock, no CrowdSec code.
// contracts/tools/crosscheck.py implements the same rules independently; the
// crowdsec-hub vectors keep both in step.
//
// Hub content is data. Nothing in it is ever executed, and no hub text reaches
// a SecRule except an operator argument or a selector, both checked here.
package crowdsec

import (
	"crypto/sha256"
	"encoding/binary"
	"regexp"

	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/rules"
)

// Schema is the name of the vector input schema.
const Schema = "crowdsec-hub"

// The states of the repository (contract/rules, D73).
const (
	StateOff    = rules.StateOff
	StateDetect = rules.StateDetect
	StateBlock  = rules.StateBlock
)

// Limits of one update. A breach of a set bound refuses the whole update.
const (
	MaxIndexBytes   = 32 << 20 // decompressed .index.json
	MaxRules        = 500      // selected rules in one index (today 206; D43)
	MaxContentBytes = 64 << 10 // decoded YAML of one rule
	MaxSetBytes     = 1 << 20  // SecLang text of all rules of a set (today 64 KiB; D43)
	MaxSetLines     = 2000     // SecRule lines of all rules of a set (today 487; D43)
	MaxGroups       = 8        // AND-groups of one hub rule; the stride of the ids
	MaxNodeDepth    = 8        // and/or nesting
	// MaxRegexInstructions bounds the compiled program of one regex. Go only:
	// see CheckRegexCost.
	MaxRegexInstructions = 4096
	// MinShrinkDivisor: a set with fewer than 1/2 of the rules of the image
	// snapshot is refused (a hollow index looks like a valid one, D43).
	MinShrinkDivisor = 2
	// ShrinkOff as Limits.ShrinkBase: no shrink check (a pin, D43).
	ShrinkOff = -1
	// MaxInputBytes of a crowdsec-hub vector.
	MaxInputBytes = 1 << 20
)

// Metadata caps (characters).
const (
	MaxLabelChars       = 128
	MaxDescriptionChars = 512
)

// Refusal codes of one rule: the rule is skipped and listed, the rest of the
// set loads.
const (
	SkipDigest         = "digest_mismatch"
	SkipDeprecated     = "deprecated"
	SkipBadName        = "bad_name"
	SkipNameMismatch   = "name_mismatch"
	SkipTooLong        = "rule_too_long"
	SkipYAML           = "yaml"
	SkipRawSecLang     = "raw_seclang"
	SkipExternalData   = "external_data"
	SkipUnknownKey     = "unknown_key"
	SkipNoRules        = "no_rules"
	SkipNodeShape      = "node_shape"
	SkipTooManyGroups  = "too_many_groups"
	SkipTooManyLines   = "too_many_lines"
	SkipTooManyVars    = "too_many_variables"
	SkipZone           = "unsupported_zone"
	SkipTransform      = "unsupported_transform"
	SkipMatch          = "unsupported_match"
	SkipMissingValue   = "missing_value"
	SkipValueChars     = "value_chars"
	SkipNotNumeric     = "not_numeric"
	SkipCountNoVar     = "count_without_variable"
	SkipSelector       = "selector"
	SkipHeadersNoName  = "headers_without_name"
	SkipForbiddenHdr   = "forbidden_header"
	SkipRegex          = "regex"
	SkipCatchAll       = "catch_all"
	SkipSubset         = "subset"
	SkipIDCollision    = "id_collision"
	SkipRegexCost      = "regex_cost"       // Go only (CheckRegexCost)
	SkipCompileFailed  = "compile_failed"   // gateway: Coraza refused this rule alone
	NoteRawBodyPartial = "raw_body_partial" // loaded, but sees only urlencoded and JSON bodies
)

// RuleRefusals lists every rule-level code in the order of the OpenAPI enum
// CrowdsecHubSkipCode.
var RuleRefusals = []string{SkipDigest, SkipDeprecated, SkipBadName, SkipNameMismatch, SkipTooLong, SkipYAML, SkipRawSecLang,
	SkipExternalData, SkipUnknownKey, SkipNoRules, SkipNodeShape, SkipTooManyGroups, SkipTooManyLines, SkipTooManyVars, SkipZone,
	SkipTransform, SkipMatch, SkipMissingValue, SkipValueChars, SkipNotNumeric, SkipCountNoVar, SkipSelector, SkipHeadersNoName,
	SkipForbiddenHdr, SkipRegex, SkipCatchAll, SkipSubset, SkipIDCollision, SkipRegexCost, SkipCompileFailed}

// Refusal codes of a whole update: the running set stays.
const (
	RefuseFetchFailed  = "fetch_failed"   // gateway: network error or deadline
	RefuseFetchStatus  = "fetch_status"   // gateway: HTTP status other than 200 or 304
	RefuseIndexSize    = "index_oversize" // above MaxIndexBytes
	RefuseMalformed    = "index_malformed"
	RefuseTooManyRules = "too_many_rules"
	RefuseSetTooLarge  = "set_too_large"
	RefuseEmpty        = "set_empty"
	RefuseShrink       = "shrink"
	RefuseCompile      = "compile_failed"  // gateway: the set did not compile
	RefuseCompileTime  = "compile_timeout" // gateway: not compiled within CompileTimeoutS
	RefuseCost         = "set_too_costly"  // gateway: the measured cost check (D43, CheckSetCost)
)

// UpdateRefusals lists every update-level code in the order of the OpenAPI
// enum CrowdsecHubRefusalCode.
var UpdateRefusals = []string{RefuseFetchFailed, RefuseFetchStatus, RefuseIndexSize, RefuseMalformed, RefuseTooManyRules,
	RefuseSetTooLarge, RefuseEmpty, RefuseShrink, RefuseCompile, RefuseCompileTime, RefuseCost}

// Bounds of the fetch and the build in the gateway (no vectors: time).
const (
	FetchTimeoutS   = 60
	ConnectTimeoutS = 10
	CompileTimeoutS = 30
	JitterPercent   = 10 // the interval is drawn from +-10 %
)

// IndexURL is the one public file of the hub; PinnedURLFormat takes a commit.
const (
	// Collection names the rules of the source.
	Collection      = "crowdsecurity/appsec-virtual-patching"
	IndexURL        = "https://raw.githubusercontent.com/crowdsecurity/hub/master/.index.json"
	PinnedURLFormat = "https://raw.githubusercontent.com/crowdsecurity/hub/%s/.index.json"
	UserAgent       = "schild"
	// TestURLEnv overrides the URL in non-release builds only (test lab).
	TestURLEnv = "SCHILD_CROWDSEC_HUB_URL"
	// Tag on every converted rule. It names the conversion, not the
	// repository: changing it would change every converted rule.
	Tag = "crowdsec_hub"
	// Licence shown with every rule.
	Licence = "MIT"
)

// idSlots: slots of MaxGroups ids each.
const idSlots = (contract.HubRuleIDMax - contract.HubRuleIDMin + 1) / MaxGroups

// BaseID returns the first SecRule id of a hub rule: a pure function of its
// name, the same on every gateway, in every image and after every update.
// Group g of the rule has the id BaseID(name) + g.
func BaseID(name string) int {
	h := sha256.Sum256([]byte("schild.crowdsec_hub.rule_id/1\n" + name))
	n := binary.BigEndian.Uint64(h[:8])
	return contract.HubRuleIDMin + int(n%idSlots)*MaxGroups
}

var (
	reSelected = regexp.MustCompile(`^crowdsecurity/vpatch-`)
	reName     = regexp.MustCompile(`^crowdsecurity/vpatch-[A-Za-z0-9._-]{1,128}$`)
	reVersion  = regexp.MustCompile(`^[0-9]{1,6}\.[0-9]{1,6}$`)
	reDigest   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	reCVE      = regexp.MustCompile(`^[Cc][Vv][Ee]\.(CVE-[0-9]{4}-[0-9]{4,8})$`)
	reCWE      = regexp.MustCompile(`^[Cc][Ww][Ee]\.(CWE-[0-9]{1,6})$`)
	reAttack   = regexp.MustCompile(`^[Aa][Tt][Tt][Aa][Cc][Kk]\.(T[0-9]{4}(\.[0-9]{3})?)$`)
)

// Selected reports whether a hub item belongs to the source: the vpatch rules
// of the crowdsecurity namespace that are members of Collection in the same
// index (D39). The collection is what a default CrowdSec install gets; the hub
// keeps rules out of it on purpose (a rule that hits every Brotli body, for
// example).
func Selected(name string, members map[string]bool) bool {
	return members[name] && reSelected.MatchString(name)
}
