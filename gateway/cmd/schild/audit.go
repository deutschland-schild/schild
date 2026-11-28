package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"
	"unicode"
	"unicode/utf16"

	"github.com/deutschland-schild/schild/gateway/internal/app"
	"github.com/deutschland-schild/schild/gateway/internal/auditlog"
	"github.com/deutschland-schild/schild/gateway/internal/store"
)

const auditUsage = `schild audit [--website ID] [--token ID] [--action A] [--since 7d] [--json]
schild audit check
       [-config FILE] [-data DIR]

Host only. The audit log of this gateway: who changed what, when, through
which way (dashboard, agent API, a command on the host, the configuration,
schild itself) and what it was before. Newest first.

  --website ID   entries of one website
  --token ID     entries an agent token made (tok_<12 hex>)
  --action A     entries of one action, for example allowlist.add
  --since 7d     entries of the last days (7d) or hours (36h)
  --json         one entry per line as JSON, as the gateway stores it

Reads audit.db of the data directory and what waits in schild.db, also next
to a running schild; it writes nothing. A reason or a label in an entry is
text from outside: control characters in it are printed escaped.

check names the numbers missing between two kept entries of a log this node
wrote: an entry removed by hand, or written with a wrong clock. What
audit.keep_days deletes is the oldest part of a log and leaves no hole.

Exit codes: 0 done, 1 error or check found a hole, 2 usage.
`

// hostAccount is the host account that runs the command, as the command sees
// it: the account behind sudo first. A hint for the audit log, not a proof.
func hostAccount(getenv func(string) string, current func() string) string {
	for _, k := range []string{"SUDO_USER", "USER", "LOGNAME"} {
		if v := getenv(k); v != "" {
			return v
		}
	}
	return current()
}

// cliActor is the actor of the audit entries of this command.
func cliActor() auditlog.Actor { return auditlog.CLI(hostAccount(os.Getenv, currentUser)) }

// openAudited opens the store of a command that changes it, with the audit
// log that writes into its outbox (contracts/audit.md section 4): the change
// and its entry are one transaction, also while schild is stopped.
func openAudited(cfgPath, data string) (*store.Store, *auditlog.Log, error) {
	cfg, _, err := app.LoadConfig(cfgPath)
	if err != nil {
		return nil, nil, err
	}
	st, err := store.Open(filepath.Join(app.DataDir(cfg, data), "schild.db"))
	if err != nil {
		return nil, nil, err
	}
	return st, auditlog.ForStore(context.Background(), st, cfg.NodeName), nil
}

// usageError: the arguments do not fit; the command prints its usage and
// exits 2.
type usageError struct{ error }

func cmdAudit(args []string) error {
	err := runAudit(args, os.Stdout, time.Now)
	if errors.As(err, new(usageError)) {
		fmt.Fprintln(os.Stderr, "schild:", err)
		fmt.Fprint(os.Stderr, auditUsage)
		os.Exit(2)
	}
	return err
}

func runAudit(args []string, out io.Writer, now func() time.Time) error {
	fs := flag.NewFlagSet("audit", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	cfgPath := fs.String("config", "", "schild.yaml")
	data := fs.String("data", "", "data directory")
	website := fs.String("website", "", "entries of one website")
	token := fs.String("token", "", "entries of one agent token")
	action := fs.String("action", "", "entries of one action")
	since := fs.String("since", "", "entries of the last days or hours, e.g. 7d")
	asJSON := fs.Bool("json", false, "one entry per line as JSON")
	// Flags before and after the subcommand, as everywhere.
	var pos []string
	for rest := args; len(rest) > 0; {
		if err := fs.Parse(rest); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				fmt.Fprint(out, auditUsage)
				return nil
			}
			return usageError{fmt.Errorf("audit: %w", err)}
		}
		if rest = fs.Args(); len(rest) > 0 {
			pos = append(pos, rest[0])
			rest = rest[1:]
		}
	}
	check := len(pos) == 1 && pos[0] == "check"
	if len(pos) > 0 && !check {
		return usageError{fmt.Errorf("audit: unknown argument %q", pos[0])}
	}
	f := auditlog.Filter{Website: *website, Actor: *token, Action: *action}
	if *since != "" {
		d, err := parseSince(*since)
		if err != nil {
			return usageError{err}
		}
		f.From = now().UTC().Add(-d)
	}
	if check && (*website != "" || *token != "" || *action != "" || *since != "" || *asJSON) {
		return usageError{errors.New("audit check takes no filter")}
	}
	cfg, _, err := app.LoadConfig(*cfgPath)
	if err != nil {
		return err
	}
	dir := app.DataDir(cfg, *data)
	db := filepath.Join(dir, "schild.db")
	// A reading command never creates a store.
	if _, err := os.Stat(db); err != nil {
		return fmt.Errorf("audit: no store at %s (check -config, -data or SCHILD_DATA_DIR): %w", db, err)
	}
	st, err := store.Open(db)
	if err != nil {
		return err
	}
	defer st.Close()
	ctx := context.Background()
	l, err := auditlog.OpenRead(ctx, st, filepath.Join(dir, auditlog.FileName), cfg.NodeName)
	if err != nil {
		return fmt.Errorf("audit: %w", err)
	}
	defer l.Close()
	if check {
		return auditCheck(ctx, l, out)
	}
	return auditList(ctx, l, f, *asJSON, out)
}

// parseSince reads the age of --since: days (7d) or a duration of hours and
// minutes (36h).
func parseSince(s string) (time.Duration, error) {
	if n, err := strconv.Atoi(strings.TrimSuffix(s, "d")); err == nil && strings.HasSuffix(s, "d") && n > 0 && n <= 36500 {
		return time.Duration(n) * 24 * time.Hour, nil
	}
	if d, err := time.ParseDuration(s); err == nil && d > 0 {
		return d, nil
	}
	return 0, fmt.Errorf("audit: --since %q: want days or hours, for example 7d or 36h", s)
}

// auditList prints the entries of a filter, newest first: page by page, so
// a long log does not have to fit into memory as a whole.
func auditList(ctx context.Context, l *auditlog.Log, f auditlog.Filter, asJSON bool, out io.Writer) error {
	tw := tabwriter.NewWriter(out, 0, 2, 2, ' ', 0)
	if !asJSON {
		fmt.Fprintln(tw, "TIME\tWAY\tWHO\tACTION\tOBJECT\tWEBSITE\tCHANGE")
	}
	// A running schild moves entries from schild.db to audit.db while this
	// command reads the two one after the other, so an entry of the first
	// page may be met in both. It is printed once.
	first := map[string]bool{}
	for cursor := ""; ; {
		items, next, err := l.List(ctx, f, cursor, auditlog.MaxPage)
		if err != nil {
			return fmt.Errorf("audit: %w", err)
		}
		newestFirst(items)
		for _, e := range items {
			if id := auditStr(e, "id"); first[id] {
				continue
			} else if cursor == "" {
				first[id] = true
			}
			if asJSON {
				line, err := jsonLine(e)
				if err != nil {
					return fmt.Errorf("audit: %w", err)
				}
				if _, err := out.Write(line); err != nil {
					return err
				}
				continue
			}
			fmt.Fprintln(tw, strings.Join(auditColumns(e), "\t"))
		}
		if next == "" {
			break
		}
		cursor = next
	}
	if asJSON {
		return nil
	}
	return tw.Flush()
}

// newestFirst orders a page: by time as List does, and the entries of one
// second, which List leaves as it met them (what waits in schild.db comes
// oldest first), by their log and number. An entry has no finer time; of two
// entries of one log the higher number is the newer.
func newestFirst(items []map[string]any) {
	key := func(e map[string]any) (t, log string, n int64) {
		id := auditStr(e, "id")
		if k := strings.LastIndex(id, "-"); k >= 0 {
			log = id[:k]
			n, _ = strconv.ParseInt(id[k+1:], 10, 64)
		}
		return auditStr(e, "time"), log, n
	}
	sort.SliceStable(items, func(i, j int) bool {
		ta, la, na := key(items[i])
		tb, lb, nb := key(items[j])
		if ta != tb {
			return ta > tb
		}
		if la != lb {
			return la < lb
		}
		return na > nb
	})
}

// auditCheck names the holes of the logs this node wrote.
func auditCheck(ctx context.Context, l *auditlog.Log, out io.Writer) error {
	holes, err := l.Holes(ctx)
	if err != nil {
		return fmt.Errorf("audit check: %w", err)
	}
	if len(holes) == 0 {
		fmt.Fprintln(out, "no hole: the kept entries of every log this node wrote are numbered without a gap")
		return nil
	}
	var missing int64
	for _, h := range holes {
		n := h.To - h.From + 1
		missing += n
		if n == 1 {
			fmt.Fprintf(out, "log %s: entry %s-k-%d is missing\n", visible(h.Log), visible(h.Log), h.From)
		} else {
			fmt.Fprintf(out, "log %s: entries %s-k-%d to %s-k-%d are missing (%d)\n", visible(h.Log), visible(h.Log), h.From, visible(h.Log), h.To, n)
		}
	}
	fmt.Fprintln(out, "A missing number means an entry was removed by hand, or written with a wrong clock and deleted by its age before its neighbours.")
	word := "holes"
	if len(holes) == 1 {
		word = "hole"
	}
	return fmt.Errorf("audit check: %d %s, %d entries missing", len(holes), word, missing)
}

// visible returns s for a terminal: as it is when it is plain, else quoted
// with every control character, every character that shows nothing and every
// character that changes the direction of text escaped. Text of an entry
// (a reason, a label) comes from outside and is never printed raw.
func visible(s string) string {
	if s == "" {
		return `""`
	}
	q := strconv.Quote(s)
	if q[1:len(q)-1] == s && !strings.ContainsAny(s, " =") {
		return s
	}
	return q
}

func auditStr(m map[string]any, k string) string { s, _ := m[k].(string); return s }

func auditObj(m map[string]any, k string) map[string]any { o, _ := m[k].(map[string]any); return o }

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return visible(s)
}

// auditColumns is one entry as a line for a person: time, way, who, action,
// object, website and the changed fields in short.
func auditColumns(e map[string]any) []string {
	actor, subject := auditObj(e, "actor"), auditObj(e, "subject")
	who := ""
	switch auditStr(actor, "kind") {
	case auditlog.WayDashboard:
		who = auditStr(actor, "user")
		if s := auditStr(actor, "session"); s != "" {
			who = strings.TrimSpace(who + " (session " + s + ")")
		}
	case auditlog.WayAgent, auditlog.WayIntegration:
		who = strings.TrimSpace(auditStr(actor, "id") + " " + auditStr(actor, "label"))
		if b := auditStr(actor, "on_behalf_of"); b != "" {
			who += " for " + b
		}
	case auditlog.WayCLI:
		who = auditStr(actor, "account")
	default:
		who = auditStr(actor, "kind")
	}
	if a := auditStr(e, "address"); a != "" {
		who = strings.TrimSpace(who + " from " + a)
	}
	action := auditStr(e, "action")
	if auditStr(e, "result") == "refused" {
		action += " refused"
		if n := auditValue(e["count"]); e["count"] != nil && n != "1" {
			action += " x" + n
		}
	}
	object := auditStr(subject, "kind")
	if id := auditStr(subject, "id"); id != "" {
		object += " " + id
	}
	change := auditChange(auditObj(e, "change"))
	cause := auditObj(e, "cause")
	for _, k := range []string{"event", "incident"} {
		if v := auditStr(cause, k); v != "" {
			change = append(change, "because of "+k+" "+visible(v))
		}
	}
	if r := auditStr(e, "reason"); r != "" {
		change = append(change, "reason="+visible(r))
	}
	return []string{orDash(auditStr(e, "time")), orDash(auditStr(e, "operation")), orDash(who), orDash(action), orDash(object),
		orDash(auditStr(e, "website")), strings.Join(change, " ")}
}

// auditChange is the change of an entry in short: +field=value for an added
// field, -field=value for a removed one, field=before->after for a changed
// one. A field without a value says why it has none.
func auditChange(c map[string]any) []string {
	var out []string
	fields, _ := c["fields"].([]any)
	for _, x := range fields {
		f, _ := x.(map[string]any)
		name := visible(strings.TrimPrefix(auditStr(f, "field"), "/"))
		kind := auditStr(f, "change")
		_, hasB := f["before"]
		_, hasA := f["after"]
		added, removed := auditItems(f["added"]), auditItems(f["removed"])
		s := ""
		switch {
		case auditStr(f, "hidden") != "":
			s = name + " " + kind + " (not recorded: " + visible(auditStr(f, "hidden")) + ")"
		case added != "" || removed != "":
			s = name
			if added != "" {
				s += " +[" + added + "]"
			}
			if removed != "" {
				s += " -[" + removed + "]"
			}
			if more := auditValue(f["more"]); f["more"] != nil && more != "0" {
				s += " and " + more + " more"
			}
		case hasB && hasA:
			s = name + "=" + auditValue(f["before"]) + "->" + auditValue(f["after"])
		case hasA:
			s = "+" + name + "=" + auditValue(f["after"])
		case hasB:
			s = "-" + name + "=" + auditValue(f["before"])
		default:
			s = name + " " + kind
		}
		if cut, _ := f["cut"].(bool); cut {
			s += " (cut)"
		}
		out = append(out, s)
	}
	if n := auditValue(c["more_fields"]); c["more_fields"] != nil && n != "0" {
		out = append(out, "and "+n+" more fields")
	}
	return out
}

func auditItems(v any) string {
	xs, _ := v.([]any)
	parts := make([]string, 0, len(xs))
	for _, x := range xs {
		parts = append(parts, auditValue(x))
	}
	return strings.Join(parts, " ")
}

// auditValue is a recorded value for a terminal.
func auditValue(v any) string {
	switch x := v.(type) {
	case string:
		return visible(x)
	case json.Number:
		return x.String()
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(x)
	case nil:
		return "-"
	}
	b, _ := json.Marshal(v)
	return visible(string(b))
}

// jsonLine is an entry as one JSON line for a terminal or a pipe. JSON
// escapes the control characters below U+0020 itself; what else a terminal
// would act on or not show (U+007F to U+009F, direction marks, zero width
// characters) is written as \u escapes too, which reads back the same.
func jsonLine(e map[string]any) ([]byte, error) {
	var raw bytes.Buffer
	enc := json.NewEncoder(&raw)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(e); err != nil {
		return nil, err
	}
	var out bytes.Buffer
	for _, r := range strings.TrimRight(raw.String(), "\n") {
		if r < 0x7f || unicode.IsPrint(r) {
			out.WriteRune(r)
			continue
		}
		if r > 0xffff {
			hi, lo := utf16.EncodeRune(r)
			fmt.Fprintf(&out, `\u%04x\u%04x`, hi, lo)
			continue
		}
		fmt.Fprintf(&out, `\u%04x`, r)
	}
	out.WriteByte('\n')
	return out.Bytes(), nil
}
