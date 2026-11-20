package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"time"

	"github.com/deutschland-schild/schild/gateway/internal/app"
	"github.com/deutschland-schild/schild/gateway/internal/control"
	"github.com/deutschland-schild/schild/gateway/internal/dashboard"
	"github.com/deutschland-schild/schild/gateway/internal/store"
)

const dashboardUsage = `schild dashboard setup-code [-config FILE] [-data DIR]

Host only. Prints the one-time setup code of the first start again, as long
as no dashboard password is set. It is the code from the start log
(setup_code); nothing is changed. Needs a running schild: the code lives in
its memory and a restart creates a new one.

schild dashboard reset-password [-config FILE] [-data DIR]

Host only (never reachable over HTTP, the dashboard or the agent API).
Removes every dashboard user and session and requires the first-run setup
again with a new one-time setup code. The code is printed here once; schild
keeps only its hash. Events, settings and blocks stay as they are. The
reset is recorded as the local event schild.dashboard.access_reset.v1.

While schild runs, the command goes through the gateway's local control path
(<data>/control/schild.sock), so open sessions end at once. While schild is
stopped, it writes the store directly. If schild runs but its control path
does not answer, nothing is changed.

Exit codes: 0 done, 1 error or refused, 2 usage.
`

func cmdDashboard(args []string) error {
	if len(args) == 0 || (args[0] != "reset-password" && args[0] != "setup-code") {
		fmt.Fprint(os.Stderr, dashboardUsage)
		os.Exit(2)
	}
	fs := flag.NewFlagSet("dashboard "+args[0], flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, dashboardUsage)
		fs.PrintDefaults()
	}
	cfgPath := fs.String("config", "", "schild.yaml (default $SCHILD_CONFIG or /etc/schild/schild.yaml)")
	data := fs.String("data", "", "data directory (default $SCHILD_DATA_DIR or storage.path)")
	if pos := parseInterleaved(fs, args[1:]); len(pos) > 0 {
		fs.Usage()
		os.Exit(2)
	}
	cfg, _, err := app.LoadConfig(*cfgPath)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if args[0] == "setup-code" {
		code, err := setupCode(ctx, app.DataDir(cfg, *data))
		if err != nil {
			return err
		}
		printSetupCode(os.Stdout, code, cfg.Listen.Dashboard)
		return nil
	}
	r, err := resetPassword(ctx, cfg.NodeName, app.DataDir(cfg, *data), hostUser(os.Getenv, currentUser))
	if err != nil {
		return err
	}
	printReset(os.Stdout, r)
	return nil
}

// setupCode asks the running gateway of the data directory dir for the
// setup code of its first start. It never writes.
func setupCode(ctx context.Context, dir string) (string, error) {
	resp, err := control.Call(ctx, dir, control.Request{Op: control.OpSetupCode})
	switch {
	case err == nil && resp.OK:
		return resp.SetupCode, nil
	case err == nil:
		return "", fmt.Errorf("dashboard setup-code: %s", resp.Error)
	case errors.Is(err, control.ErrUnavailable):
		return "", fmt.Errorf("dashboard setup-code: no running schild answers on %s (check -config, -data or SCHILD_DATA_DIR). "+
			"The setup code is created at every start while no password is set: start schild, then run this command again or look for setup_code in its log", control.SocketPath(dir))
	}
	return "", fmt.Errorf("dashboard setup-code: %w", err)
}

func printSetupCode(w io.Writer, code, listen string) {
	fmt.Fprintf(w, "one-time setup code: %s\n", code)
	fmt.Fprintf(w, "open %s (from your own machine: ssh -L, or your VPN) and set the dashboard password with it.\n", app.DashboardURL(listen))
	fmt.Fprintln(w, "the code is valid until a password is set or schild restarts.")
}

// resetResult is what `schild dashboard reset-password` did.
type resetResult struct {
	Via      string // dashboard.ViaHostCLI or dashboard.ViaControlPath
	Code     string
	Users    int
	Sessions int
}

// errGatewayUnreachable: the gateway holds the data directory, but its
// control path does not answer.
var errGatewayUnreachable = errors.New("dashboard reset-password: refused")

// resetPassword resets the dashboard access of the data directory dir:
// through the running gateway's control path when one answers, else
// directly in the store while holding the gateway lock. With a running
// gateway that does not answer it changes nothing.
func resetPassword(ctx context.Context, node, dir, hostUser string) (resetResult, error) {
	resp, err := control.Call(ctx, dir, control.Request{Op: control.OpResetDashboard, HostUser: hostUser})
	switch {
	case err == nil && resp.OK:
		return resetResult{Via: dashboard.ViaControlPath, Code: resp.SetupCode, Users: resp.UsersRemoved, Sessions: resp.SessionsEnded}, nil
	case err == nil:
		return resetResult{}, fmt.Errorf("dashboard reset-password: the running schild refused: %s", resp.Error)
	case !errors.Is(err, control.ErrUnavailable):
		return resetResult{}, fmt.Errorf("dashboard reset-password: %w (the reset may or may not have happened; run the command again)", err)
	}
	db := filepath.Join(dir, "schild.db")
	if _, err := os.Stat(db); err != nil {
		return resetResult{}, fmt.Errorf("dashboard reset-password: no store at %s (check -config, -data or SCHILD_DATA_DIR): %w", db, err)
	}
	release, err := control.Lock(dir)
	if errors.Is(err, control.ErrLocked) {
		return resetResult{}, fmt.Errorf("%w: schild is running (it holds %s), but its control path %s does not answer; nothing was changed. "+
			"Restart schild so it opens the control path, or stop schild and run this command again",
			errGatewayUnreachable, control.LockPath(dir), control.SocketPath(dir))
	}
	if err != nil {
		return resetResult{}, fmt.Errorf("dashboard reset-password: gateway lock: %w", err)
	}
	defer release()
	st, err := store.Open(db)
	if err != nil {
		return resetResult{}, err
	}
	defer st.Close()
	code, _, res, err := dashboard.ResetAccess(ctx, st, node, dashboard.ViaHostCLI, hostUser, time.Now().UTC())
	if err != nil {
		return resetResult{}, err
	}
	return resetResult{Via: dashboard.ViaHostCLI, Code: code, Users: res.UsersRemoved, Sessions: res.SessionsEnded}, nil
}

func printReset(w io.Writer, r resetResult) {
	how := "directly in the store (schild is stopped)"
	if r.Via == dashboard.ViaControlPath {
		how = "through the running schild (control path)"
	}
	fmt.Fprintf(w, "dashboard access reset %s: %d user(s) removed, %d session(s) ended\n", how, r.Users, r.Sessions)
	fmt.Fprintf(w, "one-time setup code: %s\n", r.Code)
	fmt.Fprintln(w, "shown only now, schild keeps only its hash. Open the dashboard and set a new password with this code.")
	fmt.Fprintln(w, "events, settings and blocks are unchanged; the reset is recorded as the event schild.dashboard.access_reset.v1.")
}

func currentUser() string {
	if u, err := user.Current(); err == nil {
		return u.Username
	}
	return ""
}

// hostUser is the host account that runs the command, for the audit event:
// the account behind sudo first. Names outside the contract pattern are
// left out.
func hostUser(getenv func(string) string, current func() string) string {
	for _, k := range []string{"SUDO_USER", "USER", "LOGNAME"} {
		if v := getenv(k); v != "" {
			return dashboard.HostUser(v)
		}
	}
	return dashboard.HostUser(current())
}
