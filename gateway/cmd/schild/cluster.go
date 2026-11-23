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
	"github.com/deutschland-schild/schild/gateway/internal/control"
)

const clusterUsage = `schild cluster secret                  print a new group secret for cluster.secret_file
schild cluster init                    make this gateway the first node of a new group
schild cluster invite [-role edge]     print a join code of this node (one use, valid one hour); -role edge
                                       admits a balancer VM that only enforces the block list
schild cluster join ADDRESS CODE -edge -name NAME -data DIR
                                       on a balancer VM: join as an edge, then schild firewall run -group -data DIR
schild cluster join ADDRESS CODE       join the group of the node at ADDRESS (its cluster.listen) with its code
schild cluster status                  members, last contact, records held
schild cluster remove NODE             end the membership of a node (name or id); no member talks to it afterwards
schild cluster drain                   take this node out of traffic and stop it: the readiness answer turns to
                                       503, it stops after cluster.drain.delay_s (as on systemctl stop)
Common flags: -config FILE, -data DIR

A group shares address blocks, the settings made in the dashboard, logins,
certificates, counts, events and requests between its gateways (MVP-27). The
node's name is cluster.name, with cluster.name_from_host its host name, else
node_name; its address is cluster.advertise or cluster.listen of schild.yaml.

Two ways into a group:
  by configuration  the same cluster.secret_file and cluster.peers on every node, deployed like the
                    rest of schild.yaml (Ansible, for example). A node lets itself in at its start;
                    init, invite and join are not needed.
  by hand           init on the first node, invite there, join on every other, then restart schild.`

// cmdCluster sets up and shows the group of this gateway on the host
// (MVP-27, D105). Like tokens, membership is never changed through the
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
	if sub == "secret" {
		secret, err := cluster.NewSecret()
		if err != nil {
			return err
		}
		fmt.Fprintln(out, secret)
		return nil
	}
	fs := flag.NewFlagSet("cluster "+sub, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	cfgPath := fs.String("config", "", "schild.yaml")
	data := fs.String("data", "", "data directory")
	role := fs.String("role", "gateway", "invite: gateway, or edge for a balancer VM that only enforces the block list")
	edge := fs.Bool("edge", false, "join: as an edge (a balancer VM; needs -name and -data, no schild.yaml)")
	name := fs.String("name", "", "join -edge: name of the edge")
	pos := parseInterleaved(fs, args[1:])
	if sub == "join" && *edge {
		// A balancer VM has no schild.yaml: name and directory come as flags.
		if len(pos) != 2 || *name == "" || *data == "" {
			return errors.New("cluster join -edge: ADDRESS, CODE, -name NAME and -data DIR\n" + clusterUsage)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		group, _, err := cluster.Join(ctx, app.ClusterDir(*data), *name, "", pos[0], pos[1], now)
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "%s joined group %s as an edge. Start the firewall:\n  schild firewall run -group -data %s\n", *name, group, *data)
		return nil
	}
	cfg, _, err := app.LoadConfig(*cfgPath)
	if err != nil {
		return err
	}
	dir := app.ClusterDir(app.DataDir(cfg, *data))
	needAddress := func() error {
		if cfg.Cluster.SecretFile != "" {
			return errors.New("cluster " + sub + ": this node is set up by cluster.secret_file; it lets itself into the group when schild starts")
		}
		if !cfg.Cluster.Enabled {
			return errors.New("cluster " + sub + ": set cluster.enabled and cluster.listen in schild.yaml first (the other nodes reach this node there)")
		}
		return nil
	}
	// The name of this node in its group (config.Site.MemberName).
	host, _ := os.Hostname()
	member := cfg.MemberName(host)
	switch sub {
	case "init":
		if err := needAddress(); err != nil {
			return err
		}
		group, err := cluster.Init(dir, member, cfg.Cluster.Address(), now)
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "Group %s created, %s is its first node (%s).\nRestart schild, then let the next node in:\n  schild cluster invite\n", group, member, cfg.Cluster.Address())
	case "invite":
		code, expires, err := cluster.InviteRole(dir, *role, now)
		if err != nil {
			return err
		}
		if *role == "edge" {
			fmt.Fprintf(out, "Join code for one edge (a balancer VM), shown once, valid until %s:\n\n  %s\n\nOn the VM (schild has to run here while it joins):\n  schild cluster join %s %s -edge -name NAME -data /var/lib/schild-edge\n  schild firewall run -group -data /var/lib/schild-edge\n",
				expires.Local().Format("15:04"), code, cfg.Cluster.Address(), code)
			return nil
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
		group, members, err := cluster.Join(ctx, dir, member, cfg.Cluster.Address(), pos[0], pos[1], now)
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "%s joined group %s (%d nodes). Restart schild: it then takes the state of the group.\n", member, group, members)
	case "remove":
		if len(pos) != 1 {
			return errors.New("cluster remove: NODE (name or id)\n" + clusterUsage)
		}
		e, err := cluster.Remove(dir, pos[0], now)
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "%s (%s) is no member any more. On that node: cluster.enabled false, and delete its cluster directory before it joins a group again.\n", e.Member.Name, e.ID)
	case "drain":
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		resp, err := control.Call(ctx, app.DataDir(cfg, *data), control.Request{Op: control.OpDrain})
		if err != nil {
			return fmt.Errorf("cluster drain: %w (does schild run here?)", err)
		}
		if !resp.OK {
			return errors.New("cluster drain: " + resp.Error)
		}
		fmt.Fprintf(out, "%s left traffic: /.schild/readyz answers 503. It stops in %s, running requests get %s to finish.\n", cfg.NodeName, cfg.Cluster.Drain.Delay(), cfg.Cluster.Drain.Grace())
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
		case m.Member.Role == "edge":
			// An edge asks one gateway at a time: here only when it asked this one.
			state = "asked elsewhere"
			if !m.InOK.IsZero() && now.Sub(m.InOK) < time.Minute {
				state = "ok"
			}
		case m.Error != "":
			state = "unreachable"
		case m.OutOK.IsZero() || now.Sub(m.OutOK) > 15*time.Second:
			state = "no contact"
		}
		asked, was, behind := ago(m.OutOK), ago(m.InOK), fmt.Sprint(m.Behind)
		if m.Self || m.Removed {
			asked, was, behind = "-", "-", "-"
		} else if m.Member.Role == "edge" {
			asked, behind = "-", "-"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", m.Member.Name, m.Member.Role, m.Member.Address, state, asked, was, behind, m.ID)
	}
	tw.Flush()
	for _, m := range st.Members {
		if m.Error != "" && !m.Removed {
			fmt.Fprintf(out, "%s: %s\n", m.Member.Name, m.Error)
		}
	}
	if !st.ClockOut.IsZero() && now.Sub(st.ClockOut) < 2*time.Minute {
		fmt.Fprintf(out, "Clock: this node left traffic (/.schild/readyz answers 503): its clock is a minute or more off the clocks of the other gateways, which agree with each other. It returns by itself when its clock is right (NTP).\n")
	}
	// A clock that is off: named from five seconds on, while the note of the
	// running node is fresh.
	for _, m := range st.Members {
		if m.Self || m.Removed || m.ClockAt.IsZero() || now.Sub(m.ClockAt) > 2*time.Minute {
			continue
		}
		d, word := m.Clock, "ahead of"
		if d < 0 {
			d, word = -d, "behind"
		}
		if d >= 5*time.Second {
			fmt.Fprintf(out, "Clock: %s is %s %s this node. The later change wins in a group and a record more than 60 s ahead is put off: set the clocks right (NTP).\n", m.Member.Name, d.Round(time.Second), word)
		}
	}
	fmt.Fprintf(out, "Blocks of the group that run: %d\n", st.Records["blocks"])
	fmt.Fprintf(out, "Shared: %d settings, %d lists of who passes, %d lists of who signs in\n", st.Records["settings"], st.Records["access"], st.Records["logins"])
	if st.Replaced > 0 {
		fmt.Fprintf(out, "At its first sync this node took %d values of the group in place of its own; the own ones are kept in cluster.db, table replaced.\n", st.Replaced)
	}
	if running {
		fmt.Fprintf(out, "Since the start: %d records taken, %d refused, %d put off (clock or unknown origin), %d of a newer version unread\n",
			st.Counters["applied"], st.Counters["rejected"], st.Counters["deferred"], st.Counters["unread"])
	}
}
