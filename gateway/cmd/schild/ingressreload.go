package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/deutschland-schild/schild/gateway/internal/app"
	"github.com/deutschland-schild/schild/gateway/internal/control"
)

const ingressReloadUsage = `schild ingress reload [-config FILE] [-data DIR] [-force]

Host only. The running gateway reads its Caddyfile again and puts it in force
without a restart: websites, backends, headers, TLS. Requests that run end with
the Caddyfile they started with; a WebSocket ends unless its reverse_proxy has
stream_close_delay. Counters, blocks and the state of a cluster stay.

Everything a start checks is checked first. A Caddyfile that schild refuses
leaves the running one in place, and the command fails with the reason. Also
refused, because it needs a restart: other listen addresses and another
certificate storage. schild.yaml is not read again, a list like
ingress.unprotected_sites is the one of the start.

-force loads a Caddyfile that did not change, for certificate files it names.

In a cluster the command acts on this node only: run it on every node.

Exit codes: 0 done or unchanged, 1 error or refused, 2 usage.
`

func cmdIngressReload(args []string) error {
	fs := flag.NewFlagSet("ingress reload", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), ingressReloadUsage)
		fs.PrintDefaults()
	}
	cfgPath := fs.String("config", "", "schild.yaml (default $SCHILD_CONFIG or /etc/schild/schild.yaml)")
	data := fs.String("data", "", "data directory (default $SCHILD_DATA_DIR or storage.path)")
	force := fs.Bool("force", false, "load the Caddyfile also when it did not change")
	_ = fs.Parse(args)
	cfg, _, err := app.LoadConfig(*cfgPath)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	return reloadIngress(ctx, app.DataDir(cfg, *data), *force, os.Stdout)
}

// reloadIngress asks the running gateway of the data directory dir.
func reloadIngress(ctx context.Context, dir string, force bool, w io.Writer) error {
	return callIngress(ctx, dir, "reload", control.Request{Op: control.OpIngressReload, Force: force}, w)
}

const ingressLoadUsage = `schild ingress load [-config FILE] [-data DIR] [-force] FILE|-

Host only. Sends a whole Caddyfile to the running gateway: FILE, or standard
input with "-". The gateway checks it as schild ingress reload does, writes it
to ingress.caddyfile and puts it in force without a restart. For a program
that builds the Caddyfile, such as the panel of a hoster.

A Caddyfile that schild refuses changes nothing: the running one stays, and
so does the file. The same refusals as schild ingress reload. Files that the
Caddyfile imports are not sent: they are read on this host, relative to
ingress.caddyfile. The user of schild needs write access to ingress.caddyfile
or its directory. At most 8 MiB.

In a cluster the command acts on this node only: run it on every node.

Exit codes: 0 done or unchanged, 1 error or refused, 2 usage.
`

func cmdIngressLoad(args []string) error {
	fs := flag.NewFlagSet("ingress load", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), ingressLoadUsage)
		fs.PrintDefaults()
	}
	cfgPath := fs.String("config", "", "schild.yaml (default $SCHILD_CONFIG or /etc/schild/schild.yaml)")
	data := fs.String("data", "", "data directory (default $SCHILD_DATA_DIR or storage.path)")
	force := fs.Bool("force", false, "load the Caddyfile also when it gives the config that runs")
	_ = fs.Parse(args)
	if fs.NArg() != 1 {
		fs.Usage()
		os.Exit(2)
	}
	var in io.Reader = os.Stdin
	if name := fs.Arg(0); name != "-" {
		f, err := os.Open(name)
		if err != nil {
			return fmt.Errorf("ingress load: %w", err)
		}
		defer f.Close()
		in = f
	}
	cfg, _, err := app.LoadConfig(*cfgPath)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	return loadIngress(ctx, app.DataDir(cfg, *data), in, *force, os.Stdout)
}

// loadIngress sends the Caddyfile of in to the running gateway of the data
// directory dir.
func loadIngress(ctx context.Context, dir string, in io.Reader, force bool, w io.Writer) error {
	text, err := io.ReadAll(io.LimitReader(in, app.MaxCaddyfile+1))
	if err != nil {
		return fmt.Errorf("ingress load: %w", err)
	}
	if len(text) > app.MaxCaddyfile {
		return fmt.Errorf("ingress load: the Caddyfile has more than %d bytes; nothing was changed", app.MaxCaddyfile)
	}
	return callIngress(ctx, dir, "load", control.Request{Op: control.OpIngressLoad, Force: force, Caddyfile: string(text)}, w)
}

func callIngress(ctx context.Context, dir, cmd string, req control.Request, w io.Writer) error {
	resp, err := control.Call(ctx, dir, req)
	switch {
	case errors.Is(err, control.ErrUnavailable) && cmd == "load":
		return errors.New("ingress load: schild does not answer on its control path; nothing was changed. For a stopped gateway, write the file yourself")
	case errors.Is(err, control.ErrUnavailable):
		return errors.New("ingress reload: schild does not answer on its control path; nothing was changed, a stopped gateway reads its Caddyfile at its next start")
	case err != nil:
		return fmt.Errorf("ingress %s: %w (it may or may not have happened; the log of the gateway says so)", cmd, err)
	}
	for _, m := range resp.Warnings {
		fmt.Fprintf(w, "  warning   %s\n", m)
	}
	switch {
	case !resp.OK:
		return fmt.Errorf("ingress %s: refused, the running Caddyfile stays: %s", cmd, resp.Error)
	case resp.Unchanged:
		fmt.Fprintf(w, "Caddyfile unchanged: %d websites\n", resp.Websites)
	case cmd == "load":
		fmt.Fprintf(w, "Caddyfile written and loaded: %d websites\n", resp.Websites)
	default:
		fmt.Fprintf(w, "Caddyfile reloaded: %d websites\n", resp.Websites)
	}
	return nil
}
