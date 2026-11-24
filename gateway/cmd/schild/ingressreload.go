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
	resp, err := control.Call(ctx, dir, control.Request{Op: control.OpIngressReload, Force: force})
	switch {
	case errors.Is(err, control.ErrUnavailable):
		return errors.New("ingress reload: schild does not answer on its control path; nothing was changed, a stopped gateway reads its Caddyfile at its next start")
	case err != nil:
		return fmt.Errorf("ingress reload: %w (it may or may not have happened; the log of the gateway says so)", err)
	}
	for _, m := range resp.Warnings {
		fmt.Fprintf(w, "  warning   %s\n", m)
	}
	switch {
	case !resp.OK:
		return fmt.Errorf("ingress reload: refused, the running Caddyfile stays: %s", resp.Error)
	case resp.Unchanged:
		fmt.Fprintf(w, "Caddyfile unchanged: %d websites\n", resp.Websites)
	default:
		fmt.Fprintf(w, "Caddyfile reloaded: %d websites\n", resp.Websites)
	}
	return nil
}
