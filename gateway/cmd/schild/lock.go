package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/deutschland-schild/schild/contract/access"
	"github.com/deutschland-schild/schild/gateway/internal/app"
	"github.com/deutschland-schild/schild/gateway/internal/control"
)

const lockUsage = `schild lock on WEBSITE [-path PATH]... [-except PATH]...
                      [-address IP|CIDR]... [-own-networks] [-password-stdin] [-message TEXT]
schild lock off WEBSITE
schild lock status
       [-config FILE] [-data DIR]

Host only. The access lock of a website, for example when a known gap
has no patch yet. Without -path the whole website needs a way in: everyone
else gets a maintenance page (503), nothing of theirs reaches the app. With -path
only those paths are protected (repeat it; /wp-admin/* covers /wp-admin and
everything below).

Conditions, give at least one; every one given must hold:
  -password-stdin   a shared password, read as one line from stdin (8 to 128
                    characters); without it a stored password stays
  -address          an IP or a network (repeat it)
  -own-networks     every address of the allowlist
-address and -own-networks are one condition: either list is enough. With a
password as well, only those addresses get the login form.

-except keeps a path of a site lock reachable for everyone, for example a
payment webhook (the app is reachable there).

The lock is on until schild lock off, in force before the command returns
and survives a restart.
Every change ends all logins of the website. WEBSITE is the id the dashboard
shows (schild lock status lists the ones in force).

The command goes through the gateway's local control path, so schild has to
run.

Exit codes: 0 done, 1 error or refused, 2 usage.
`

type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

func cmdLock(args []string) error {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, lockUsage)
		os.Exit(2)
	}
	sub := args[0]
	fs := flag.NewFlagSet("lock "+sub, flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, lockUsage)
		fs.PrintDefaults()
	}
	cfgPath := fs.String("config", "", "schild.yaml (default $SCHILD_CONFIG or /etc/schild/schild.yaml)")
	data := fs.String("data", "", "data directory (default $SCHILD_DATA_DIR or storage.path)")
	var paths, except, addresses stringList
	fs.Var(&paths, "path", "protect only this path (repeatable)")
	fs.Var(&except, "except", "path of a site lock that stays reachable (repeatable)")
	fs.Var(&addresses, "address", "only this IP or network (repeatable)")
	own := fs.Bool("own-networks", false, "only the addresses of the allowlist")
	pwStdin := fs.Bool("password-stdin", false, "read the shared password as one line from stdin")
	message := fs.String("message", "", "text of the maintenance page")
	pos := parseInterleaved(fs, args[1:])
	req := control.Request{HostUser: hostAccount(os.Getenv, currentUser)}
	switch sub {
	case "on":
		if len(pos) != 1 {
			fs.Usage()
			os.Exit(2)
		}
		set := lockSpec(paths, except, addresses, *own, *message)
		if *pwStdin {
			pw, err := readPassword(os.Stdin)
			if err != nil {
				return err
			}
			set.Password = pw
		}
		req.Op, req.Website, req.Access = control.OpAccessSet, pos[0], set
	case "off":
		if len(pos) != 1 {
			fs.Usage()
			os.Exit(2)
		}
		req.Op, req.Website = control.OpAccessRemove, pos[0]
	case "status":
		if len(pos) != 0 {
			fs.Usage()
			os.Exit(2)
		}
		req.Op = control.OpAccessList
	default:
		fmt.Fprint(os.Stderr, lockUsage)
		os.Exit(2)
	}
	cfg, _, err := app.LoadConfig(*cfgPath)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	return lockCall(ctx, app.DataDir(cfg, *data), req, os.Stdout)
}

// lockSpec builds the protection of `schild lock on`.
func lockSpec(paths, except, addresses []string, own bool, message string) *control.AccessSet {
	set := &control.AccessSet{Scope: access.ScopeSite, Paths: paths, Except: except, Addresses: addresses, OwnNetworks: own, Message: message}
	if len(paths) > 0 {
		set.Scope = access.ScopePaths
	}
	return set
}

func readPassword(r io.Reader) (string, error) {
	line, err := bufio.NewReader(io.LimitReader(r, 4096)).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", fmt.Errorf("lock on: password: %w", err)
	}
	pw := strings.TrimRight(line, "\r\n")
	if len(pw) < access.MinPasswordLen || len(pw) > access.MaxPasswordLen {
		return "", errors.New("lock on: the password needs 8 to 128 characters")
	}
	return pw, nil
}

// lockCall sends one access operation to the running gateway of dir.
func lockCall(ctx context.Context, dir string, req control.Request, w io.Writer) error {
	resp, err := control.Call(ctx, dir, req)
	switch {
	case errors.Is(err, control.ErrUnavailable):
		return errors.New("lock: schild does not answer on its control path; nothing was changed")
	case err != nil:
		return fmt.Errorf("lock: %w", err)
	case !resp.OK:
		return fmt.Errorf("lock: refused, nothing changed: %s", resp.Error)
	}
	switch req.Op {
	case control.OpAccessSet:
		fmt.Fprintf(w, "access lock on for %s, every login of it ended\n", req.Website)
	case control.OpAccessRemove:
		if resp.Removed {
			fmt.Fprintf(w, "access lock off for %s\n", req.Website)
		} else {
			fmt.Fprintf(w, "%s had no access lock\n", req.Website)
		}
	}
	if len(resp.Access) == 0 {
		fmt.Fprintln(w, "no access lock in force")
		return nil
	}
	for _, x := range resp.Access {
		var from []string
		if len(x.Addresses) > 0 {
			from = append(from, "addresses "+strings.Join(x.Addresses, ","))
		}
		if x.OwnNetworks {
			from = append(from, "own networks")
		}
		var ways []string
		if x.Password {
			ways = append(ways, "password")
		}
		if len(from) > 0 {
			ways = append(ways, "from "+strings.Join(from, " or "))
		}
		what := "whole website"
		if x.Maintenance {
			what = "maintenance mode, whole website"
		}
		if x.Scope == access.ScopePaths {
			what = "paths " + strings.Join(x.Paths, ",")
		}
		fmt.Fprintf(w, "%s: %s, needs: %s", x.Website, what, strings.Join(ways, " and "))
		if len(x.Except) > 0 {
			fmt.Fprintf(w, ", except %s", strings.Join(x.Except, ","))
		}
		fmt.Fprintln(w)
	}
	return nil
}
