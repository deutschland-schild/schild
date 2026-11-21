package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"text/tabwriter"
	"time"

	"github.com/deutschland-schild/schild/contract/config"
	"github.com/deutschland-schild/schild/gateway/internal/app"
	"github.com/deutschland-schild/schild/gateway/internal/cluster"
)

const clusterUsage = `schild cluster init                    make this gateway the first node of a new group
schild cluster invite                  print a join code of this node (one use, valid one hour)
schild cluster join ADDRESS CODE       join the group of the node at ADDRESS (its cluster.listen) with its code
schild cluster status                  members, last contact, records held
schild cluster remove NODE             end the membership of a node (name or id); no member talks to it afterwards
Common flags: -config FILE, -data DIR

A group shares the address blocks of every node (MVP-27, first version). The
node's name is node_name, its address cluster.advertise or cluster.listen of
schild.yaml. After init or join, restart schild.`

// cmdCluster sets up and shows the group of this gateway on the host
// (MVP-27, D103). Like tokens, membership is never changed through the
// dashboard or an API.
func cmdCluster(args []string) error {
	return runCluster(args, os.Stdout, time.Now)
}

func runCluster(args []string, out io.Writer, now func() time.Time) error {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		fmt.Fprintln(out, clusterUsage)
		return nil
	}
	sub := args[0]
	fs := flag.NewFlagSet("cluster "+sub, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	cfgPath := fs.String("config", "", "schild.yaml")
	data := fs.String("data", "", "data directory")
	pos := parseInterleaved(fs, args[1:])
	cfg, _, err := app.LoadConfig(*cfgPath)
	if err != nil {
		return err
	}
	dir := app.ClusterDir(app.DataDir(cfg, *data))
	needAddress := func() error {
		if !cfg.Cluster.Enabled {
			return errors.New("cluster " + sub + ": set cluster.enabled and cluster.listen in schild.yaml first (the other nodes reach this node there)")
		}
		return nil
	}
	switch sub {
	case "init":
		if err := needAddress(); err != nil {
			return err
		}
		group, err := cluster.Init(dir, cfg.NodeName, cfg.Cluster.Address(), now)
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "Group %s created, %s is its first node (%s).\nRestart schild, then let the next node in:\n  schild cluster invite\n", group, cfg.NodeName, cfg.Cluster.Address())
	case "invite":
		code, expires, err := cluster.Invite(dir, now)
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "Join code, shown once, valid until %s for one node:\n\n  %s\n\nOn the new node (schild has to run here while it joins):\n  schild cluster join %s %s\n",
			expires.Local().Format("15:04"), code, cfg.Cluster.Address(), code)
	case "join":
		if len(pos) != 2 {
			return errors.New("cluster join: ADDRESS and CODE\n" + clusterUsage)
		}
		if err := needAddress(); err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		group, members, err := cluster.Join(ctx, dir, cfg.NodeName, cfg.Cluster.Address(), pos[0], pos[1], now)
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "%s joined group %s (%d nodes). Restart schild: it then takes the state of the group.\n", cfg.NodeName, group, members)
	case "remove":
		if len(pos) != 1 {
			return errors.New("cluster remove: NODE (name or id)\n" + clusterUsage)
		}
		e, err := cluster.Remove(dir, pos[0], now)
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "%s (%s) is no member any more. On that node: cluster.enabled false, and delete its cluster directory before it joins a group again.\n", e.Member.Name, e.ID)
	case "status":
		st, err := cluster.ReadStatus(dir, now)
		if err != nil {
			return err
		}
		printClusterStatus(out, st, cfg, now())
	default:
		return fmt.Errorf("cluster: unknown command %q\n%s", sub, clusterUsage)
	}
	return nil
}

func printClusterStatus(out io.Writer, st *cluster.Status, cfg *config.Site, now time.Time) {
	fmt.Fprintf(out, "Group %s\n", st.Group)
	running := !st.Seen.IsZero() && now.Sub(st.Seen) < 10*time.Second
	switch {
	case !cfg.Cluster.Enabled:
		fmt.Fprintln(out, "cluster.enabled is false: this gateway runs alone.")
	case !running:
		fmt.Fprintln(out, "The node does not run (no sign of it in the last 10 s): contact times below are its last.")
	}
	ago := func(t time.Time) string {
		if t.IsZero() {
			return "never"
		}
		return now.Sub(t).Round(time.Second).String() + " ago"
	}
	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "NODE\tROLE\tADDRESS\tSTATE\tASKED\tWAS ASKED\tBEHIND\tID")
	for _, m := range st.Members {
		state := "ok"
		switch {
		case m.Removed:
			state = "removed"
		case m.Self:
			state = "this node"
		case m.Error != "":
			state = "unreachable"
		case m.OutOK.IsZero() || now.Sub(m.OutOK) > 15*time.Second:
			state = "no contact"
		}
		asked, was, behind := ago(m.OutOK), ago(m.InOK), fmt.Sprint(m.Behind)
		if m.Self || m.Removed {
			asked, was, behind = "-", "-", "-"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", m.Member.Name, m.Member.Role, m.Member.Address, state, asked, was, behind, m.ID)
	}
	tw.Flush()
	for _, m := range st.Members {
		if m.Error != "" && !m.Removed {
			fmt.Fprintf(out, "%s: %s\n", m.Member.Name, m.Error)
		}
	}
	fmt.Fprintf(out, "Blocks of the group that run: %d\n", st.Records["blocks"])
	if running {
		fmt.Fprintf(out, "Since the start: %d records taken, %d refused, %d put off (clock or unknown origin), %d of a newer version unread\n",
			st.Counters["applied"], st.Counters["rejected"], st.Counters["deferred"], st.Counters["unread"])
	}
}
