package app

import (
	"context"
	"log/slog"

	"github.com/deutschland-schild/schild/gateway/internal/control"
)

// Control answers requests on the local control path (MVP-09 addendum,
// D38). The setup code goes back to the host command only; it is not
// logged.
func (a *App) Control(ctx context.Context, req control.Request) control.Response {
	switch req.Op {
	case control.OpResetDashboard:
		code, res, err := a.Dashboard.ResetAccess(ctx, req.HostUser)
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
		return control.Response{OK: true, SetupCode: code}
	case control.OpRulesSync:
		res, err := a.Repos.Sync(ctx, req.Repository)
		if err != nil {
			return control.Response{Error: err.Error()}
		}
		return control.Response{OK: true, RulesLoaded: res.Rules, Unchanged: res.Unchanged}
	case control.OpRulesReset:
		if err := a.Repos.Reset(ctx, req.Repository); err != nil {
			a.log.Error("rule repository reset failed", "repository", req.Repository, "err", err)
			return control.Response{Error: "reset failed: " + err.Error()}
		}
		v, _ := a.Repos.Repository(req.Repository)
		resp := control.Response{OK: true, RulesLoaded: v.Counts.Rules}
		if v.Crowdsec != nil {
			resp.SetSource = v.Crowdsec.SetSource
		}
		return resp
	case control.OpIngressReload:
		res, err := a.ReloadIngress(req.Force)
		if err != nil {
			return control.Response{Error: err.Error(), Warnings: res.Warnings}
		}
		return control.Response{OK: true, Unchanged: res.Unchanged, Websites: res.Websites, Warnings: res.Warnings}
	case control.OpIngressLoad:
		res, err := a.LoadIngress([]byte(req.Caddyfile), req.Force)
		if err != nil {
			return control.Response{Error: err.Error(), Warnings: res.Warnings}
		}
		return control.Response{OK: true, Unchanged: res.Unchanged, Websites: res.Websites, Warnings: res.Warnings}
	case control.OpDrain:
		if a.Cluster == nil {
			return control.Response{Error: "this gateway is no node of a group; stop it with systemctl stop schild"}
		}
		a.Drain()
		return control.Response{OK: true}
	case control.OpAccessSet, control.OpAccessRemove, control.OpAccessList:
		return a.accessControl(ctx, req)
	default:
		return control.Response{Error: "unknown operation"}
	}
}

// ServeControl opens the control socket of dataDir for this gateway until
// ctx ends. The caller holds the gateway lock (control.Lock).
func (a *App) ServeControl(ctx context.Context, dataDir string) (*control.Server, error) {
	return control.Listen(ctx, dataDir, a.Control, a.log.With(slog.String("component", "control")))
}
