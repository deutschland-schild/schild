package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/deutschland-schild/schild/contract/firewall"
	"github.com/deutschland-schild/schild/gateway/internal/app"
	"github.com/deutschland-schild/schild/gateway/internal/buildinfo"
	"github.com/deutschland-schild/schild/gateway/internal/cluster"
	"github.com/deutschland-schild/schild/gateway/internal/nftfw"
)

const firewallUsage = `schild firewall run [-api URL] [-token-file FILE]
schild firewall status
schild firewall off

Needs CAP_NET_ADMIN on the host's network (D87). run puts the address blocks of
schild into the host's firewall and keeps them in step: it asks the agent API
of the gateway for the blocks that run (a long poll, answered at once when a
block starts or is lifted) and keeps the nftables table "inet schild" holding
exactly these clients, each with its remaining time as the kernel timeout;
their traffic to the ports 80 and 443 (TCP and UDP) is dropped before it
reaches schild or a container. SSH and every other port stay as they are.
Blocks end in the kernel by themselves, also when this process stops; a clean
stop (SIGTERM) removes the table.

Like a CrowdSec firewall bouncer: the same image or binary as the gateway, as
its own container (network_mode host, cap_add NET_ADMIN) or systemd service.
On a balancer VM in front of a group of gateways: schild firewall run -group -data DIR.
The VM joins as an edge first (on a gateway: schild cluster invite -role edge; on the VM:
schild cluster join ADDRESS CODE -edge -name NAME -data DIR). It gets the block list and
nothing else, over the mesh, without a token.

On the gateway's own host it needs the agent API (agent_api.enabled) and a token of its own:
  schild token add --scope firewall:sync --expires 365d --label firewall
given as $SCHILD_FIREWALL_TOKEN or in -token-file.

status prints what the table holds, off removes the table at once.
`

func cmdFirewall(args []string) error {
	if len(args) == 0 || (args[0] != "run" && args[0] != "status" && args[0] != "off") {
		fmt.Fprint(os.Stderr, firewallUsage)
		os.Exit(2)
	}
	fs := flag.NewFlagSet("firewall "+args[0], flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, firewallUsage)
		fs.PrintDefaults()
	}
	api := fs.String("api", envOr("SCHILD_FIREWALL_API", "http://127.0.0.1:8789/agent/v0"), "agent API of the gateway ($SCHILD_FIREWALL_API)")
	tokenFile := fs.String("token-file", "", "file with the token of scope firewall:sync (default $SCHILD_FIREWALL_TOKEN)")
	group := fs.Bool("group", false, "an edge of a group: get the blocks from the gateways over the mesh, no token (needs -data)")
	data := fs.String("data", "", "with -group: data directory of the edge, as given to schild cluster join -edge")
	if pos := parseInterleaved(fs, args[1:]); len(pos) > 0 {
		fs.Usage()
		os.Exit(2)
	}
	k := nftfw.Kernel{}
	switch args[0] {
	case "off":
		if err := k.Remove(); err != nil {
			return err
		}
		fmt.Printf("table %s removed: no block of schild is in the firewall any more\n", firewall.Table)
		return nil
	case "status":
		held, err := k.Held()
		if err != nil {
			return fmt.Errorf("table %s: %w (is schild firewall run running?)", firewall.Table, err)
		}
		fmt.Printf("table %s holds %d clients (ports %s)\n", firewall.Table, len(held), firewall.Ports)
		for _, h := range held {
			fmt.Printf("  %-43s ends in %s\n", h.Client, h.Expires.Truncate(time.Second))
		}
		return nil
	}
	if *group {
		return runEdgeFirewall(k, *data)
	}
	token := strings.TrimSpace(os.Getenv("SCHILD_FIREWALL_TOKEN"))
	if *tokenFile != "" {
		b, err := os.ReadFile(*tokenFile)
		if err != nil {
			return err
		}
		token = strings.TrimSpace(string(b))
	}
	if token == "" {
		return errors.New("firewall run: no token; create one with schild token add --scope firewall:sync --expires 365d --label firewall and give it as SCHILD_FIREWALL_TOKEN")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	return nftfw.Run(ctx, k, nftfw.Config{API: strings.TrimRight(*api, "/"), Token: token, Version: buildinfo.String(), Log: log})
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// EdgeFirewallCall is how an edge asks its gateways for the blocks: the
// firewall sync of D87, over the mesh.
func EdgeFirewallCall(e *cluster.Edge) func(ctx context.Context, req firewall.SyncRequest) (firewall.SyncResponse, error) {
	return func(ctx context.Context, req firewall.SyncRequest) (firewall.SyncResponse, error) {
		var ans firewall.SyncResponse
		body, err := json.Marshal(req)
		if err != nil {
			return ans, err
		}
		raw, err := e.Ask(ctx, "firewall", body, 40*time.Second)
		if err != nil {
			return ans, err
		}
		return ans, json.Unmarshal(raw, &ans)
	}
}

// runEdgeFirewall is `schild firewall run -group` on a balancer VM: the
// table of D87, fed by the gateways of the group (MVP-27).
func runEdgeFirewall(k nftfw.Backend, data string) error {
	if data == "" {
		return errors.New("firewall run -group: -data DIR is required (the directory given to schild cluster join -edge)")
	}
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	e, err := cluster.OpenEdge(app.ClusterDir(data), log)
	if err != nil {
		return err
	}
	defer e.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	log.Info("firewall: edge of a group", "node", e.Name(), "id", e.ID())
	return nftfw.Run(ctx, k, nftfw.Config{API: "the gateways of the group", Version: buildinfo.String(), Log: log, Call: EdgeFirewallCall(e)})
}
