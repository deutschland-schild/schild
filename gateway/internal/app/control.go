package app

import (
	"context"
	"errors"
	"log/slog"
	"reflect"
	"time"

	"github.com/deutschland-schild/schild/gateway/internal/auditlog"
	"github.com/deutschland-schild/schild/gateway/internal/control"
	"github.com/deutschland-schild/schild/gateway/internal/dashboard"
	"github.com/deutschland-schild/schild/gateway/internal/ruleset"
	"github.com/deutschland-schild/schild/gateway/internal/store"
)

// Control answers requests on the local control path (MVP-09 addendum,
// D38). The setup code goes back to the host command only; it is not
// logged.
//
// Every operation that changes something leaves an audit entry with the
// host account the command handed over as its actor (MVP-36,
// contracts/audit.md section 4). A change in schild.db and its entry are one
// transaction; a change outside of it (the rules that run, the drain) has
// its entry written before the answer.
func (a *App) Control(ctx context.Context, req control.Request) control.Response {
	actor := auditlog.CLI(req.HostUser)
	switch req.Op {
	case control.OpResetDashboard:
		code, res, err := a.resetDashboard(ctx, req.HostUser)
		if err != nil {
			a.log.Error("dashboard access reset failed", "err", err)
			return control.Response{Error: "reset failed: " + err.Error()}
		}
		return control.Response{OK: true, SetupCode: code, UsersRemoved: res.UsersRemoved, SessionsEnded: res.SessionsEnded}
	case control.OpSetupCode:
		// The same code as in the start log, for the host command only. It
		// gives nothing a reader of the log or `reset-password` would not get.
		if a.Store.HasUsers(ctx) {
			return control.Response{Error: "a dashboard password is already set, so there is no setup code. Lost the password? schild dashboard reset-password"}
		}
		code := a.Dashboard.FirstRunCode()
		if code == "" {
			return control.Response{Error: "the dashboard access was reset: the setup code was shown once by schild dashboard reset-password and schild keeps only its hash. Run schild dashboard reset-password again for a new code"}
		}
		// Who saw the code is noted before it leaves; the entry never holds
		// it. Without the entry the code is not shown.
		if err := a.Audit.Write(ctx, auditlog.Entry{Action: "password.setup_code_shown", Operation: "cli:dashboard setup-code", Actor: actor}); err != nil {
			a.log.Error("setup code not shown: audit entry not written", "err", err)
			return control.Response{Error: "the setup code is not shown, because the audit entry could not be written: " + err.Error()}
		}
		return control.Response{OK: true, SetupCode: code}
	case control.OpRulesSync:
		before := a.repositoryState(req.Repository)
		res, err := a.Repos.Sync(ctx, req.Repository)
		if err != nil {
			return control.Response{Error: err.Error()}
		}
		resp := control.Response{OK: true, RulesLoaded: res.Rules, Unchanged: res.Unchanged}
		if res.Unchanged {
			// The source holds what runs: nothing changed, no entry.
			return resp
		}
		// A sync that built a new set is a change also when the set has the
		// same name and as many rules as before: then the entry stands
		// without a difference, where the log would leave it out otherwise.
		e := auditlog.Entry{Action: "rule_repository.sync", Operation: "cli:rules sync", Actor: actor, Subject: req.Repository}
		if after := a.repositoryState(req.Repository); !reflect.DeepEqual(before, after) {
			e.Before, e.After = before, after
		}
		return a.auditStands(ctx, resp, e)
	case control.OpRulesReset:
		before := a.repositoryState(req.Repository)
		if err := a.Repos.Reset(ctx, req.Repository); err != nil {
			a.log.Error("rule repository reset failed", "repository", req.Repository, "err", err)
			return control.Response{Error: "reset failed: " + err.Error()}
		}
		v, _ := a.Repos.Repository(req.Repository)
		resp := control.Response{OK: true, RulesLoaded: v.Counts.Rules}
		if v.Crowdsec != nil {
			resp.SetSource = v.Crowdsec.SetSource
		}
		// The gateway ran the image's rules again and dropped the stored set:
		// the command has its entry also when the image's rules ran before.
		e := auditlog.Entry{Action: "rule_repository.reset", Operation: "cli:rules reset", Actor: actor, Subject: req.Repository}
		if after := repositoryState(v); !reflect.DeepEqual(before, after) {
			e.Before, e.After = before, after
		}
		return a.auditStands(ctx, resp, e)
	case control.OpDrain:
		if a.Cluster == nil {
			return control.Response{Error: "this gateway is no node of a group; stop it with systemctl stop schild"}
		}
		// The drain cannot fail and cannot be taken back, so its entry is
		// written first: without the entry the node stays in traffic.
		if err := a.Audit.Write(ctx, auditlog.Entry{Action: "cluster.drain", Operation: "cli:cluster drain", Actor: actor, Subject: a.Cluster.ID()}); err != nil {
			a.log.Error("drain refused: audit entry not written", "err", err)
			return control.Response{Error: "the node stays in traffic, because the audit entry could not be written: " + err.Error()}
		}
		a.Drain()
		return control.Response{OK: true}
	case control.OpAccessSet, control.OpAccessRemove, control.OpAccessList:
		// The code that stores the lock writes the entry in the transaction
		// of its change, from the origin in the context (auditlog.Origin).
		// `schild lock off` ends a maintenance mode too: one entry each.
		switch req.Op {
		case control.OpAccessSet:
			ctx = auditlog.WithOrigin(ctx, auditlog.Origin{Operation: "cli:lock on", Actor: actor})
		case control.OpAccessRemove:
			ctx = auditlog.WithOrigin(ctx, auditlog.Origin{Operation: "cli:lock off", Actor: actor})
		}
		return a.accessControl(ctx, req)
	default:
		return control.Response{Error: "unknown operation"}
	}
}

// auditStands writes the entry of a change that is made already and is no
// part of schild.db. When the entry cannot be written the answer is an
// error that says the change stands (contracts/audit.md section 4).
func (a *App) auditStands(ctx context.Context, resp control.Response, e auditlog.Entry) control.Response {
	if err := a.Audit.Write(ctx, e); err != nil {
		a.log.Error("audit entry not written, the change stands", "action", e.Action, "operation", e.Operation, "err", err)
		resp.OK, resp.Stands, resp.Error = false, true, "the audit entry could not be written: "+err.Error()
	}
	return resp
}

// repositoryState is what rule_repository.sync and rule_repository.reset
// record of a repository: the set it runs (crowdsec: image, stored, none)
// and how many rules are loaded.
func (a *App) repositoryState(id string) map[string]any {
	v, err := a.Repos.Repository(id)
	if err != nil {
		return nil
	}
	return repositoryState(v)
}

func repositoryState(v ruleset.RepositoryView) map[string]any {
	m := map[string]any{"rules_loaded": v.Counts.Rules}
	if v.Crowdsec != nil {
		m["set"] = v.Crowdsec.SetSource
	}
	return m
}

// ResetAuditEntry is the audit entry of `schild dashboard reset-password`:
// the users and the sessions that were removed, by their number. account is
// the host account as the command saw it. The setup code and its hash are
// no part of it. The numbers stand as removed, so a reset of an access
// without a user (it still replaces the setup code) has its entry too.
func ResetAuditEntry(account string, res store.AccessReset) auditlog.Entry {
	return auditlog.Entry{Action: "password.reset", Operation: "cli:dashboard reset-password", Actor: auditlog.CLI(account),
		Before: map[string]any{"users": res.UsersRemoved, "sessions": res.SessionsEnded}}
}

// resetDashboard is `schild dashboard reset-password` in the running
// gateway: the reset, its event and its audit entry in one transaction of
// schild.db, then the new setup code replaces the one in memory and the
// event goes to the live view. Sessions live in the store only, so every
// old session cookie is invalid at once.
//
// Only the store is called inside the transaction; what takes the lock of
// the dashboard's setup code follows after it (store.InTx).
func (a *App) resetDashboard(ctx context.Context, account string) (string, store.AccessReset, error) {
	var (
		code string
		row  *store.EventRow
		res  store.AccessReset
	)
	err := a.Audit.Tx(ctx, func(ctx context.Context, rec *auditlog.Rec) error {
		var err error
		code, row, res, err = dashboard.ResetAccess(ctx, a.Store, a.Config().NodeName, dashboard.ViaControlPath, account, time.Now().UTC())
		if err != nil {
			return err
		}
		rec.Add(ResetAuditEntry(account, res))
		return nil
	})
	if err != nil {
		return "", res, err
	}
	if !a.Dashboard.LoadPendingSetup(ctx) {
		return "", res, errors.New("the users and sessions are removed, but the new setup code could not be read back from the store; restart schild and use the code this command printed, or run it again")
	}
	if a.Events != nil && row != nil {
		a.Events.Bus().Publish(row)
	}
	a.log.Warn("dashboard access reset on the host: users and sessions removed, first-run setup needs the code shown to the host command",
		"users_removed", res.UsersRemoved, "sessions_ended", res.SessionsEnded)
	return code, res, nil
}

// ServeControl opens the control socket of dataDir for this gateway until
// ctx ends. The caller holds the gateway lock (control.Lock).
func (a *App) ServeControl(ctx context.Context, dataDir string) (*control.Server, error) {
	return control.Listen(ctx, dataDir, a.Control, a.log.With(slog.String("component", "control")))
}
