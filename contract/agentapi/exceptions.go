package agentapi

import (
	"regexp"
	"strconv"
)

// Rule exceptions (D54, D73): an agent takes named rules of repository crs or
// crowdsec off one field of one page of one website. It names these things and
// never writes SecLang, so a token cannot switch the engine off or remove a
// rule for a whole gateway. Local rules get no exception: they are the
// operator's own file. The text comes from websites.RuleExceptionRule.
const (
	// MaxExceptions running on a gateway.
	MaxExceptions = 256
	// MaxExceptionRules in one exception.
	MaxExceptionRules = 16
	// MaxExceptionBody of a write.
	MaxExceptionBody = 2048
	// ExceptionIDMin..ExceptionIDMax: SecRule ids of agent exceptions, which
	// are also their public ids. Keep operator rules outside this range.
	ExceptionIDMin = 1900000
	ExceptionIDMax = 1999999
	// CRS detection rules, as waf.Analyze counts them.
	exceptionRuleMin = 910000
	exceptionRuleMax = 948999
	// Base ids of crowdsec rules (contract.HubRuleIDMin..Max).
	crowdsecRuleMin = 60000000
	crowdsecRuleMax = 99999999
)

// Repositories an exception may name.
const (
	ExceptionCRS      = "crs"
	ExceptionCrowdsec = "crowdsec"
)

// Refusals of createAgentException.
const (
	CodeExceptionCap     = "exception_cap"
	CodeUnknownRule      = "unknown_rule"
	CodeWebsiteNoHosts   = "website_without_hosts"
	CodeExceptionRefused = "exception_refused"
	// CodeNotSupported: repository local, whose rules are the operator's file.
	CodeNotSupported = "not_supported"
)

// ExceptionRequest is the body of createAgentException.
type ExceptionRequest struct {
	Website    string   `json:"website"`
	Path       string   `json:"path"`
	Target     string   `json:"target"`
	Repository string   `json:"repository"` // crs | crowdsec
	Rules      []string `json:"rules"`
	Reason     string   `json:"reason"`
}

// ExceptionRemoveRequest is the body of removeAgentException. Rules (D86)
// takes only those out, and the exception stays for the others.
type ExceptionRemoveRequest struct {
	Reason string   `json:"reason"`
	Rules  []string `json:"rules,omitempty"`
}

// ValidRuleList checks the rules of ExceptionRemoveRequest: absent, or 1 to
// MaxExceptionRules rule ids, each once.
func ValidRuleList(ids []string) bool {
	if ids == nil {
		return true
	}
	if len(ids) == 0 || len(ids) > MaxExceptionRules {
		return false
	}
	seen := map[string]bool{}
	for _, id := range ids {
		if !ruleIDRe.MatchString(id) || seen[id] {
			return false
		}
		seen[id] = true
	}
	return true
}

// Who set an exception (D84): an agent with its token, or the operator in the
// dashboard, where token_id and token_label are empty.
const (
	SetByAgent     = "agent"
	SetByDashboard = "dashboard"
)

// RuleException is one running exception.
type RuleException struct {
	ID         int      `json:"id"`
	Website    string   `json:"website"`
	Hosts      []string `json:"hosts"`
	Path       string   `json:"path"`
	Target     string   `json:"target"`
	Repository string   `json:"repository"`
	Rules      []string `json:"rules"`
	Reason     string   `json:"reason"`
	SetBy      string   `json:"set_by"` // agent | dashboard
	TokenID    string   `json:"token_id"`
	TokenLabel string   `json:"token_label"`
	Created    string   `json:"created"`
}

// ExceptionList is the answer of listAgentExceptions.
type ExceptionList struct {
	Items []RuleException `json:"items"`
	Max   int             `json:"max"`
}

var (
	exceptionPathRe = regexp.MustCompile(`^/[A-Za-z0-9._~/{}-]{0,255}$`)
	// exceptionTargetRe: one named value, * stands for one part of a name
	// between dots. A whole collection is no target.
	exceptionTargetRe = regexp.MustCompile(`^(?:ARGS|REQUEST_COOKIES|REQUEST_HEADERS):[A-Za-z0-9_.*\[\]-]{1,160}$`)
	exceptionNameRe   = regexp.MustCompile(`:.*[A-Za-z0-9_-]`)
)

// ValidException checks the shape of a request for repository crs or
// crowdsec; the caller refuses local with CodeNotSupported first. The reason
// has its own check.
func ValidException(r ExceptionRequest) bool {
	if r.Website == "" || !exceptionPathRe.MatchString(r.Path) || !exceptionTargetRe.MatchString(r.Target) {
		return false
	}
	if !exceptionNameRe.MatchString(r.Target) {
		return false // nothing but wildcards names every value
	}
	if len(r.Rules) == 0 || len(r.Rules) > MaxExceptionRules {
		return false
	}
	seen := map[string]bool{}
	for _, id := range r.Rules {
		if !ExceptionRuleID(r.Repository, id) || seen[id] {
			return false
		}
		seen[id] = true
	}
	return true
}

var ruleIDRe = regexp.MustCompile(`^[1-9][0-9]{0,8}$`)

// ExceptionRuleID reports whether an exception of repository may name rule
// id: a CRS detection rule, or the base id of a crowdsec rule.
func ExceptionRuleID(repository, id string) bool {
	if !ruleIDRe.MatchString(id) {
		return false
	}
	n, _ := strconv.Atoi(id)
	switch repository {
	case ExceptionCRS:
		return n >= exceptionRuleMin && n <= exceptionRuleMax
	case ExceptionCrowdsec:
		return n >= crowdsecRuleMin && n <= crowdsecRuleMax
	}
	return false
}
