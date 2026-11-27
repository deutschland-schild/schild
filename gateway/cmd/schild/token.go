package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	contractapi "github.com/deutschland-schild/schild/contract/agentapi"
	"github.com/deutschland-schild/schild/gateway/internal/auditlog"
	"github.com/deutschland-schild/schild/gateway/internal/store"
)

var tokenUsage = func() string {
	var b strings.Builder
	b.WriteString("schild token add [--scope SCOPE] [--expires 90d] [--label TEXT]   create a token (shown once; agent:read and 90 days unless given)\n")
	for _, sc := range contractapi.Scopes {
		fmt.Fprintf(&b, "  %-17s %s\n", sc, contractapi.ScopeHelp[sc])
	}
	b.WriteString("  Every write scope needs --label: it names the token in the change history.\n")
	return b.String() + `schild token list                                                   tokens with id, scope, label, expiry
schild token revoke tok_<12 hex>                                    revoke a token at once
schild token log [tok_<12 hex>] [-n 50]                             recent agent API calls
Common flags: -config FILE, -data DIR`
}()

// cmdToken manages agent API tokens on the host (MVP-21, D33). Tokens are
// never created, listed or revoked through the dashboard or any API.
func cmdToken(args []string) error {
	return runToken(args, os.Stdout, time.Now)
}

func runToken(args []string, out io.Writer, now func() time.Time) error {
	if len(args) == 0 {
		return errors.New("token: add, list, revoke or log\n" + tokenUsage)
	}
	sub, rest := args[0], args[1:]
	fs := flag.NewFlagSet("token "+sub, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	cfgPath := fs.String("config", "", "schild.yaml")
	data := fs.String("data", "", "data directory")
	scope := fs.String("scope", contractapi.ScopeAgentRead, contractapi.ScopeList())
	expires := fs.String("expires", "90d", "lifetime in days, 1d to 365d")
	label := fs.String("label", "", "label, e.g. \"Claude Code Laptop\"")
	n := fs.Int("n", 50, "number of log entries")
	// Accept flags before and after a positional argument (revoke ID, log ID).
	var pos []string
	for len(rest) > 0 {
		if err := fs.Parse(rest); err != nil {
			return fmt.Errorf("token %s: %w\n%s", sub, err, tokenUsage)
		}
		rest = fs.Args()
		if len(rest) > 0 {
			pos = append(pos, rest[0])
			rest = rest[1:]
		}
	}
	st, al, err := openAudited(*cfgPath, *data)
	if err != nil {
		return err
	}
	defer st.Close()
	ctx := context.Background()
	switch sub {
	case "add":
		if !contractapi.ValidScope(*scope) {
			return fmt.Errorf("token add: scope %q: want one of %s", *scope, contractapi.ScopeList())
		}
		ttl, err := contractapi.ParseTTL(*expires)
		if err != nil {
			return fmt.Errorf("token add: %w", err)
		}
		lb := strings.TrimSpace(*label)
		if lb == "" && contractapi.NeedsLabel(*scope) {
			return errors.New("token add: --label is required for a write scope: it names the token in the change history")
		}
		if len(lb) > 64 {
			return errors.New("token add: label at most 64 characters")
		}
		for _, r := range lb {
			if r < 0x20 || r == 0x7f {
				return errors.New("token add: label must not contain control characters")
			}
		}
		tok := contractapi.NewToken()
		t := store.AgentToken{ID: contractapi.TokenID(tok), Hash: contractapi.HashToken(tok), Scope: *scope, Label: lb, Created: now().UTC(), Expires: now().UTC().Add(ttl)}
		// The token and its audit entry are one transaction. The entry names
		// the id, never the token or its hash.
		if err := al.Tx(ctx, func(ctx context.Context, rec *auditlog.Rec) error {
			if err := st.AddAgentToken(ctx, t); err != nil {
				return err
			}
			rec.Add(auditlog.Entry{Action: "token.add", Operation: "cli:token add", Actor: cliActor(), Subject: t.ID, After: tokenState(t)})
			return nil
		}); err != nil {
			return err
		}
		fmt.Fprintf(out, "%s\n\nid %s, scope %s, valid until %s.\nThe token is shown only now; schild stores its SHA-256 only. Revoke it with: schild token revoke %s\n",
			tok, t.ID, t.Scope, t.Expires.Format(time.RFC3339), t.ID)
		return nil
	case "list":
		ts, err := st.ListAgentTokens(ctx)
		if err != nil {
			return err
		}
		tw := tabwriter.NewWriter(out, 0, 2, 2, ' ', 0)
		fmt.Fprintln(tw, "ID\tSCOPE\tSTATE\tCREATED\tEXPIRES\tLABEL")
		for _, t := range ts {
			state := "active"
			switch {
			case !t.RevokedAt.IsZero():
				state = "revoked"
			case !now().Before(t.Expires):
				state = "expired"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", t.ID, t.Scope, state, t.Created.Format("2006-01-02"), t.Expires.Format("2006-01-02"), t.Label)
		}
		return tw.Flush()
	case "revoke":
		if len(pos) != 1 {
			return errors.New("token revoke tok_<12 hex>")
		}
		err := al.Tx(ctx, func(ctx context.Context, rec *auditlog.Rec) error {
			ts, err := st.ListAgentTokens(ctx)
			if err != nil {
				return err
			}
			if err := st.RevokeAgentToken(ctx, pos[0], now().UTC()); err != nil {
				return err
			}
			for _, t := range ts {
				if t.ID == pos[0] {
					rec.Add(auditlog.Entry{Action: "token.revoke", Operation: "cli:token revoke", Actor: cliActor(), Subject: t.ID, Before: tokenState(t)})
				}
			}
			return nil
		})
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return fmt.Errorf("token revoke: no active token %s", pos[0])
			}
			return err
		}
		fmt.Fprintf(out, "revoked %s; it is refused from the next request on\n", pos[0])
		return nil
	case "log":
		id := ""
		if len(pos) > 0 {
			id = pos[0]
		}
		calls, err := st.ListAgentCalls(ctx, id, max(1, min(*n, 1000)))
		if err != nil {
			return err
		}
		tw := tabwriter.NewWriter(out, 0, 2, 2, ' ', 0)
		fmt.Fprintln(tw, "TIME\tTOKEN\tOPERATION\tSTATUS\tCALLS\tROWS\tBYTES")
		for _, c := range calls {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%d\t%d\t%d\n", c.Time.UTC().Format(time.RFC3339), c.TokenID, c.Op, c.Status, max(1, c.Count), c.Rows, c.Bytes)
		}
		return tw.Flush()
	}
	return errors.New("token: add, list, revoke or log\n" + tokenUsage)
}

// tokenState is what an audit entry records of a token: never its hash.
func tokenState(t store.AgentToken) map[string]any {
	m := map[string]any{"scope": t.Scope, "expires": t.Expires.UTC().Format(time.RFC3339)}
	if t.Label != "" {
		m["label"] = t.Label
	}
	return m
}
