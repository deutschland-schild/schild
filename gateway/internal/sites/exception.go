package sites

import (
	"errors"
	"strings"

	"github.com/deutschland-schild/schild/contract/requests"
	"github.com/deutschland-schild/schild/contract/websites"
)

// ErrUnknownWebsite: the id names no website of this gateway.
var ErrUnknownWebsite = errors.New("sites: unknown website")

// Exception returns the narrow local exception for a possible false
// positive of rule on path (and target) of one website (v0.5, D36): the
// SecLang snippet starts a chain with a Host condition of the website's
// hosts (scope website), so it never relaxes another app on this gateway;
// a website without hosts (default, _any) gets a gateway-wide snippet
// (scope gateway). id is a fresh local rule id. Schild never applies it
// (D32): the operator copies it into rules.d.
func (v *View) Exception(siteID, ruleID, path, target string, id int64) (requests.Exception, error) {
	w, ok := v.Website(siteID)
	if !ok {
		return requests.Exception{}, ErrUnknownWebsite
	}
	ex, err := websites.ExceptionSnippet(websites.ExceptionInput{SiteID: w.ID, Hosts: w.Hosts, RuleID: ruleID, Path: path, Target: target, ID: id})
	if err != nil {
		return requests.Exception{}, err
	}
	return requests.Exception{Language: "seclang", Scope: ex.Scope, File: exceptionFile(w.ID, ruleID), Snippet: ex.Snippet}, nil
}

// exceptionFile suggests rules.d/<website>-<rule>.conf (lower case, at
// most 64 characters of [a-z0-9._-]).
func exceptionFile(siteID, ruleID string) string {
	name := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '-':
			return r
		}
		return '_'
	}, strings.ToLower(siteID+"-"+ruleID))
	if len(name) > 64 {
		name = name[:64]
	}
	return "rules.d/" + name + ".conf"
}
