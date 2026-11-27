package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/deutschland-schild/schild/gateway/internal/auditlog"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	contractapi "github.com/deutschland-schild/schild/contract/agentapi"
	"github.com/deutschland-schild/schild/contract/crowdsec"
	"github.com/deutschland-schild/schild/contract/events"
	"github.com/deutschland-schild/schild/contract/msg"
	"github.com/deutschland-schild/schild/contract/rules"
	"github.com/deutschland-schild/schild/contract/websites"
	"github.com/deutschland-schild/schild/gateway/internal/agentapi"
	"github.com/deutschland-schild/schild/gateway/internal/dashboard"
	"github.com/deutschland-schild/schild/gateway/internal/eventlog"
	"github.com/deutschland-schild/schild/gateway/internal/store"
)

// ruleExceptionsKey is the store row of the rule exceptions agents set (D54, D73).
// They live in schild.db, next to the operator's rules.d, and never in a file
// of it. The row of v0.5 (integer CRS ids) is dropped when the store opens.
const ruleExceptionsKey = "rule_exceptions_v2"

// exceptionTargets are the SecRule ids an exception takes the target off: a
// CRS rule, or every group of a crowdsec rule as an id range (D73).
func exceptionTargets(x contractapi.RuleException) []string {
	if x.Repository != rules.RepoCrowdsec {
		return x.Rules
	}
	out := make([]string, len(x.Rules))
	for i, id := range x.Rules {
		n, _ := strconv.Atoi(id)
		out[i] = fmt.Sprintf("%d-%d", n, n+crowdsec.MaxGroups-1)
	}
	return out
}

func renderRuleExceptions(xs []contractapi.RuleException) (string, error) {
	var b strings.Builder
	for _, x := range xs {
		rule, err := websites.RuleExceptionRule(websites.RuleExceptionInput{Hosts: x.Hosts, Path: x.Path, Target: x.Target, Rules: exceptionTargets(x), ID: x.ID,
			SplitArgs: x.Repository == rules.RepoCrowdsec})
		if err != nil {
			return "", err
		}
		b.WriteString(rule)
	}
	return b.String(), nil
}

// loadRuleExceptions reads the stored exceptions at start and returns their text.
func (a *App) loadRuleExceptions(ctx context.Context) (string, error) {
	raw, err := a.Store.Get(ctx, ruleExceptionsKey)
	if errors.Is(err, store.ErrNotFound) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("rule exceptions: %w", err)
	}
	if err := json.Unmarshal(raw, &a.exceptions); err != nil {
		return "", fmt.Errorf("rule exceptions: %w", err)
	}
	// Stored before D84: only agents set exceptions.
	for i := range a.exceptions {
		if a.exceptions[i].SetBy == "" {
			a.exceptions[i].SetBy = contractapi.SetByAgent
		}
	}
	return renderRuleExceptions(a.exceptions)
}

func (a *App) listRuleExceptions(context.Context) []contractapi.RuleException {
	a.exceptionsMu.Lock()
	defer a.exceptionsMu.Unlock()
	return append([]contractapi.RuleException{}, a.exceptions...)
}

// applyRuleExceptions swaps the WAF, then stores. It runs under exceptionsMu. A
// build that fails leaves the running rules, a store that fails takes the swap back.
func (a *App) applyRuleExceptions(ctx context.Context, next []contractapi.RuleException, entries func(o auditlog.Origin) []auditlog.Entry) error {
	text, err := renderRuleExceptions(next)
	if err != nil {
		return &agentapi.ErrExceptionRefused{Code: contractapi.CodeExceptionRefused, Status: http.StatusConflict, Detail: err.Error()}
	}
	if _, err := a.Composer.SetExceptions(text); err != nil {
		a.log.Error("rule exception refused, the running rules stay", "err", err)
		return &agentapi.ErrExceptionRefused{Code: contractapi.CodeExceptionRefused, Status: http.StatusConflict, Detail: "The rules did not build, the running rules stay. An id in rules.d may overlap 1900000 to 1999999."}
	}
	raw, err := json.Marshal(next)
	if err == nil {
		err = a.putAudited(ctx, ruleExceptionsKey, raw, entries)
	}
	if err != nil {
		if old, rerr := renderRuleExceptions(a.exceptions); rerr == nil {
			_, _ = a.Composer.SetExceptions(old)
		}
		return err
	}
	a.exceptions = next
	return nil
}

// exceptionState is what rule_exception.set and rule_exception.remove record
// of an exception.
func exceptionState(x contractapi.RuleException) map[string]any {
	return map[string]any{"path": x.Path, "target": x.Target, "repository": x.Repository, "rules": x.Rules}
}

// exceptionEntry is the entry of an exception that is set or removed. The
// reason is the one the caller gave with the change.
func exceptionEntry(action string, x contractapi.RuleException, reason string, before, after any) func(o auditlog.Origin) []auditlog.Entry {
	return func(o auditlog.Origin) []auditlog.Entry {
		if o.Reason == "" {
			o.Reason = reason
		}
		return one(action, strconv.Itoa(x.ID), x.Website, before, after)(o)
	}
}

func freeExceptionID(xs []contractapi.RuleException) int {
	id := contractapi.ExceptionIDMin
	for slices.ContainsFunc(xs, func(x contractapi.RuleException) bool { return x.ID == id }) {
		id++
	}
	return id
}

// exceptionActor names who writes: an agent with its token, or the operator in
// the dashboard, which has none (D84).
func exceptionActor(tokenID string) string {
	if tokenID == "" {
		return contractapi.SetByDashboard
	}
	return contractapi.SetByAgent
}

func (a *App) createRuleException(ctx context.Context, req contractapi.ExceptionRequest, tokenID, label string) (contractapi.RuleException, error) {
	w, ok := a.Sites.View().Website(req.Website)
	if !ok {
		return contractapi.RuleException{}, &agentapi.ErrExceptionRefused{Code: "not_found", Status: http.StatusNotFound, Detail: "No website with this id, see schild_websites."}
	}
	if len(w.Hosts) == 0 {
		return contractapi.RuleException{}, &agentapi.ErrExceptionRefused{Code: contractapi.CodeWebsiteNoHosts, Status: http.StatusConflict, Detail: "This website has no hosts, an exception would hold for every website of the gateway."}
	}
	for _, id := range req.Rules {
		if !a.Repos.HasRule(req.Repository, id) {
			return contractapi.RuleException{}, &agentapi.ErrExceptionRefused{Code: contractapi.CodeUnknownRule, Status: http.StatusBadRequest,
				Detail: fmt.Sprintf("Rule %s of repository %s does not run on this gateway, see listAgentRules.", id, req.Repository)}
		}
	}
	slices.Sort(req.Rules)
	a.exceptionsMu.Lock()
	defer a.exceptionsMu.Unlock()
	for _, x := range a.exceptions {
		if x.Website == req.Website && x.Path == req.Path && x.Target == req.Target && x.Repository == req.Repository && slices.Equal(x.Rules, req.Rules) {
			return x, nil
		}
	}
	if len(a.exceptions) >= contractapi.MaxExceptions {
		return contractapi.RuleException{}, &agentapi.ErrExceptionRefused{Code: contractapi.CodeExceptionCap, Status: http.StatusConflict, Detail: fmt.Sprintf("This gateway keeps at most %d exceptions.", contractapi.MaxExceptions)}
	}
	now := time.Now().UTC()
	x := contractapi.RuleException{ID: freeExceptionID(a.exceptions), Website: w.ID, Hosts: w.Hosts, Path: req.Path, Target: req.Target, Repository: req.Repository,
		Rules: req.Rules, Reason: req.Reason, SetBy: exceptionActor(tokenID),
		TokenID: tokenID, TokenLabel: label, Created: now.Format(time.RFC3339)}
	if err := a.applyRuleExceptions(ctx, append(slices.Clone(a.exceptions), x), exceptionEntry("rule_exception.set", x, req.Reason, nil, exceptionState(x))); err != nil {
		return contractapi.RuleException{}, err
	}
	a.emitRuleException(events.RuleExceptionSet, now, x, req.Reason, tokenID, label, "rule exception set")
	return x, nil
}

// removeRuleException removes an exception, or with rules (D86) takes only
// those out: the exception stands with the others, its id, reason, author and
// time unchanged. Taking out every rule removes it. False for an unknown id or
// a rule the exception does not hold.
func (a *App) removeRuleException(ctx context.Context, id int, rules []string, reason, tokenID, label string) (bool, error) {
	a.exceptionsMu.Lock()
	defer a.exceptionsMu.Unlock()
	i := slices.IndexFunc(a.exceptions, func(x contractapi.RuleException) bool { return x.ID == id })
	if i < 0 {
		return false, nil
	}
	x := a.exceptions[i]
	for _, r := range rules {
		if !slices.Contains(x.Rules, r) {
			return false, nil
		}
	}
	next := slices.Clone(a.exceptions)
	gone := x
	var after any
	if left := slices.DeleteFunc(slices.Clone(x.Rules), func(r string) bool { return slices.Contains(rules, r) }); len(rules) > 0 && len(left) > 0 {
		next[i].Rules = left
		gone.Rules = slices.Sorted(slices.Values(rules))
		after = exceptionState(next[i])
	} else {
		next = slices.Delete(next, i, i+1)
	}
	if err := a.applyRuleExceptions(ctx, next, exceptionEntry("rule_exception.remove", x, reason, exceptionState(x), after)); err != nil {
		return false, err
	}
	a.emitRuleException(events.RuleExceptionRemoved, time.Now().UTC(), gone, reason, tokenID, label, "rule exception removed")
	return true, nil
}

// dashboardRefusal hands a refusal to the dashboard, which words it itself.
func dashboardRefusal(err error) error {
	var ref *agentapi.ErrExceptionRefused
	if errors.As(err, &ref) {
		return &dashboard.ExceptionRefused{Code: ref.Code, Status: ref.Status}
	}
	return err
}

func (a *App) emitRuleException(typ string, t time.Time, x contractapi.RuleException, reason, tokenID, label, summary string) {
	a.Events.EmitWithID(msg.NewID(), typ, t, events.RuleExceptionChange{ID: x.ID, Website: x.Website, Path: x.Path, Target: x.Target, Repository: x.Repository, Rules: x.Rules,
		Actor: exceptionActor(tokenID), TokenID: tokenID, TokenLabel: label, Reason: reason}, eventlog.Index{Summary: summary})
}
