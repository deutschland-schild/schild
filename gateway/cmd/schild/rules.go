package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/deutschland-schild/schild/contract/crowdsec"
	"github.com/deutschland-schild/schild/contract/rules"
	"github.com/deutschland-schild/schild/gateway/internal/app"
	"github.com/deutschland-schild/schild/gateway/internal/control"
	"github.com/deutschland-schild/schild/gateway/internal/store"
)

const rulesUsage = `schild rules sync local|crowdsec [-config FILE] [-data DIR]
schild rules reset crowdsec [-config FILE] [-data DIR]

Host only. The rule repositories of the gateway: crs (OWASP CRS), crowdsec
(CrowdSec Hub virtual patches) and local (the files of rules.local.dir).

sync local      loads the files again and runs them without a restart. The
                new set is compiled in full next to the running one, requests
                go on while it builds, and requests in flight end with the
                rules they started with. A file that does not build, or a rule
                id in the range of another repository, leaves the running rules
                in place and the command fails with the reason. SIGHUP to the
                gateway does the same, with the result in the log.
sync crowdsec   checks the CrowdSec Hub for new rules now.
reset crowdsec  goes back to the crowdsec rules of the image: drops the stored
                set and, while schild runs, runs the image's rules at once
                (recorded as schild.rule.repository_updated.v1, outcome reset).
                The state of the repository stays; updates go on afterwards.
                While schild is stopped it drops the stored set directly.

Every command but reset while stopped goes through the gateway's local control
path, so schild has to run. The dashboard and the agent API offer the same.

Exit codes: 0 done, 1 error or refused, 2 usage.
`

func cmdRules(args []string) error {
	if len(args) < 2 || !(args[0] == "sync" && (args[1] == rules.RepoLocal || args[1] == rules.RepoCrowdsec) || args[0] == "reset" && args[1] == rules.RepoCrowdsec) {
		fmt.Fprint(os.Stderr, rulesUsage)
		os.Exit(2)
	}
	op, repo := args[0], args[1]
	fs := flag.NewFlagSet("rules "+op, flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, rulesUsage)
		fs.PrintDefaults()
	}
	cfgPath := fs.String("config", "", "schild.yaml (default $SCHILD_CONFIG or /etc/schild/schild.yaml)")
	data := fs.String("data", "", "data directory (default $SCHILD_DATA_DIR or storage.path)")
	if pos := parseInterleaved(fs, args[2:]); len(pos) > 0 {
		fs.Usage()
		os.Exit(2)
	}
	cfg, _, err := app.LoadConfig(*cfgPath)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if op == "reset" {
		return resetCrowdsec(ctx, app.DataDir(cfg, *data), os.Stdout)
	}
	return syncRules(ctx, app.DataDir(cfg, *data), repo, os.Stdout)
}

// syncRules asks the running gateway of the data directory dir to sync a
// repository.
func syncRules(ctx context.Context, dir, repo string, w io.Writer) error {
	resp, err := control.Call(ctx, dir, control.Request{Op: control.OpRulesSync, Repository: repo})
	switch {
	case errors.Is(err, control.ErrUnavailable):
		return errors.New("rules sync: schild does not answer on its control path; nothing was changed, a stopped gateway loads its rules at its next start")
	case err != nil:
		return fmt.Errorf("rules sync: %w", err)
	case !resp.OK:
		return fmt.Errorf("rules sync: refused, the running rules stay: %s", resp.Error)
	case resp.Unchanged:
		fmt.Fprintf(w, "%s rules unchanged: %d rules\n", repo, resp.RulesLoaded)
	default:
		fmt.Fprintf(w, "%s rules synced: %d rules\n", repo, resp.RulesLoaded)
	}
	return nil
}

// resetCrowdsec resets the crowdsec rules of the data directory dir: through
// the running gateway's control path when one answers, else directly in the
// store while holding the gateway lock. With a running gateway that does not
// answer it changes nothing.
func resetCrowdsec(ctx context.Context, dir string, w io.Writer) error {
	resp, err := control.Call(ctx, dir, control.Request{Op: control.OpRulesReset, Repository: rules.RepoCrowdsec})
	switch {
	case err == nil && resp.OK:
		fmt.Fprintf(w, "crowdsec rules reset through the running schild: %d rules of set %s\n", resp.RulesLoaded, resp.SetSource)
		return nil
	case err == nil:
		return fmt.Errorf("rules reset: the running schild refused: %s", resp.Error)
	case !errors.Is(err, control.ErrUnavailable):
		return fmt.Errorf("rules reset: %w (the reset may or may not have happened; run the command again)", err)
	}
	db := filepath.Join(dir, "schild.db")
	if _, err := os.Stat(db); err != nil {
		return fmt.Errorf("rules reset: no store at %s (check -config, -data or SCHILD_DATA_DIR): %w", db, err)
	}
	release, err := control.Lock(dir)
	if errors.Is(err, control.ErrLocked) {
		return fmt.Errorf("rules reset: refused: schild is running (it holds %s), but its control path %s does not answer; nothing was changed",
			control.LockPath(dir), control.SocketPath(dir))
	}
	if err != nil {
		return fmt.Errorf("rules reset: gateway lock: %w", err)
	}
	defer release()
	st, err := store.Open(db)
	if err != nil {
		return err
	}
	defer st.Close()
	if err := st.Delete(ctx, crowdsec.StoreKey); err != nil {
		return err
	}
	fmt.Fprintln(w, "crowdsec rules reset directly in the store (schild is stopped): the next start runs the image's rules")
	return nil
}
