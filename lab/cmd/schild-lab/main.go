// Command schild-lab is the Schild lab core (MVP-03) with its dashboard
// (MVP-10).
//
//	schild-lab [run] [-check]     run the lab (config: -config, $SCHILD_LAB_CONFIG, /etc/schild-lab/lab.yaml)
//	schild-lab preflight          D24 test key / test CA check (same as run -check): print, exit 1 on refusal
//	schild-lab check-config       validate lab.yaml and the key files
//	schild-lab keygen -out FILE -lab LAB [-keyid ID] [-purposes ack,rules,checkpoint] [-operator OP]
//	                              production signing key outside the repo (mode 0600)
//	schild-lab tls-keygen -out-dir DIR -host NAME[,NAME]   TLS key (0600) and CSR for the lab's ports
//	schild-lab health             container health check (GET /healthz on the metrics listener)
//	schild-lab user add -name N   add or reset a dashboard user (password on stdin; lab stopped)
//	schild-lab cosign ...         co-sign a bundle or withdrawal offline (see -h)
//	schild-lab export d2 [-from DAY] [-to DAY] [-data DIR]   D2: first-seen per pattern and site, lags (no IPs)
//	schild-lab export d2-merge FILE ...                       combine the D2 exports of several labs
//	schild-lab version
//
// Environment (contracts/conventions.md §5 plus):
//
//	SCHILD_LAB_DATA_DIR             overrides storage.path
//	SCHILD_LAB_THRESHOLD            operators needed to publish (default 3, floor 2)
//	SCHILD_LAB_SIMULATED_OPERATORS  "lab-x=sim-x,lab-y=sim-y" (profile test only;
//	                                independence through it caps rules at observe)
//	SCHILD_LAB_QUEUE_SYNC           os (default, fsync) | full (also flush the drive cache)
//	SCHILD_ALLOW_TEST_KEYS=1        test lab only: start despite test keys or the test CA (D24)
//	SCHILD_TEST_CA, SCHILD_LOG_LEVEL, SCHILD_LOG_FORMAT
//
//go:debug multipathtcp=0
package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/config"
	"github.com/deutschland-schild/schild/contract/dsse"
	"github.com/deutschland-schild/schild/contract/jsonx"
	"github.com/deutschland-schild/schild/contract/keys"
	"github.com/deutschland-schild/schild/contract/msg"
	"github.com/deutschland-schild/schild/contract/preflight"
	"github.com/deutschland-schild/schild/lab/internal/app"
	"github.com/deutschland-schild/schild/lab/internal/dashboard"
	"github.com/deutschland-schild/schild/lab/internal/feed"
	"github.com/deutschland-schild/schild/lab/internal/queue"
	"github.com/deutschland-schild/schild/lab/internal/store"
	"github.com/deutschland-schild/schild/relay/upstream"
)

var version = "0.1.0-alpha"

// devCommands are filled by dev.go in non-release builds.
var devCommands = map[string]func([]string) error{}

func main() {
	args := os.Args[1:]
	cmd := "run"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, args = args[0], args[1:]
	}
	var err error
	switch cmd {
	case "run":
		err = run(args)
	case "preflight":
		err = run(append([]string{"-check"}, args...))
	case "keygen":
		err = keygenCmd(args, os.Stdout)
	case "tls-keygen":
		err = tlsKeygenCmd(args, os.Stdout)
	case "check-config":
		err = checkConfig(args)
	case "health":
		err = healthCheck(args)
	case "user":
		err = userCmd(args)
	case "cosign":
		err = cosign(args, os.Stdin, os.Stdout)
	case "export":
		err = exportCmd(args, os.Stdout, os.Stderr)
	case "version":
		fmt.Println("schild-lab", version, "contracts", contract.Version, "release", keys.Release)
	default:
		if f, ok := devCommands[cmd]; ok {
			err = f(args)
			break
		}
		err = fmt.Errorf("unknown command %q (run, preflight, check-config, keygen, tls-keygen, health, user, cosign, export, version)", cmd)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "schild-lab:", err)
		os.Exit(1)
	}
}

func newLogger() *slog.Logger {
	var lvl slog.Level
	_ = lvl.UnmarshalText([]byte(envOr("SCHILD_LOG_LEVEL", "info")))
	opts := &slog.HandlerOptions{Level: lvl}
	var h slog.Handler = slog.NewJSONHandler(os.Stdout, opts)
	if os.Getenv("SCHILD_LOG_FORMAT") == "text" {
		h = slog.NewTextHandler(os.Stdout, opts)
	}
	return slog.New(h).With("component", "schild-lab")
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// Options reads the environment options.
func options(log *slog.Logger) (app.Options, error) {
	o := app.Options{DataDir: os.Getenv("SCHILD_LAB_DATA_DIR"), Log: log, QueueSync: queue.SyncMode(envOr("SCHILD_LAB_QUEUE_SYNC", "os"))}
	if v := os.Getenv("SCHILD_LAB_THRESHOLD"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < contract.MinIndependentOperatorsFloor {
			return o, fmt.Errorf("SCHILD_LAB_THRESHOLD must be an integer >= %d", contract.MinIndependentOperatorsFloor)
		}
		o.Threshold = n
	}
	if v := os.Getenv("SCHILD_LAB_SIMULATED_OPERATORS"); v != "" {
		o.Simulated = map[string]string{}
		for _, pair := range strings.Split(v, ",") {
			lab, op, ok := strings.Cut(strings.TrimSpace(pair), "=")
			if !ok || lab == "" || op == "" {
				return o, fmt.Errorf("SCHILD_LAB_SIMULATED_OPERATORS: want lab=operator pairs, got %q", pair)
			}
			o.Simulated[lab] = op
		}
	}
	return o, nil
}

func loadConfig(args []string, name string) (*config.LabConfig, *flag.FlagSet, error) {
	return loadConfigFlags(args, flag.NewFlagSet(name, flag.ContinueOnError))
}

func loadConfigFlags(args []string, fs *flag.FlagSet) (*config.LabConfig, *flag.FlagSet, error) {
	path := fs.String("config", "", "lab.yaml path (default $SCHILD_LAB_CONFIG or /etc/schild-lab/lab.yaml)")
	if err := fs.Parse(args); err != nil {
		return nil, nil, err
	}
	cfg, err := config.LoadLab(*path)
	return cfg, fs, err
}

func run(args []string) error {
	log := newLogger()
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	check := fs.Bool("check", false, "run the preflight (D24) only: print the result and exit")
	cfg, _, err := loadConfigFlags(args, fs)
	if err != nil {
		return err
	}
	pf := preflight.Lab(cfg)
	if *check {
		pf.Print(os.Stdout)
		return pf.Err()
	}
	if err := pf.Enforce(log); err != nil {
		return err
	}
	o, err := options(log)
	if err != nil {
		return err
	}
	a, err := app.New(cfg, o)
	if err != nil {
		return err
	}
	defer a.Close()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	log.Info("schild-lab starting", "lab", cfg.Identity.Lab, "operator", cfg.Identity.Operator, "profile", cfg.Profile,
		"channel", cfg.Channel, "release", keys.Release, "peers", len(cfg.Peers), "clients", len(cfg.Clients))
	return a.Serve(ctx)
}

func checkConfig(args []string) error {
	cfg, _, err := loadConfig(args, "check-config")
	if err != nil {
		return err
	}
	for _, k := range cfg.Keys {
		if _, err := keys.LoadSigner(k.KeyID, k.PrivateKeyFile); err != nil {
			return fmt.Errorf("key %s: %w", k.KeyID, err)
		}
	}
	if _, err := cfg.ClientTrustStore(); err != nil {
		return err
	}
	fmt.Printf("lab.yaml ok: lab %s, operator %s, %d clients, %d issuers, %d peers\n", cfg.Identity.Lab, cfg.Identity.Operator, len(cfg.Clients), len(cfg.Issuers), len(cfg.Peers))
	return nil
}

func healthCheck(args []string) error {
	cfg, _, err := loadConfig(args, "health")
	if err != nil {
		return err
	}
	addr := cfg.Listen.Metrics
	if i := strings.LastIndexByte(addr, ':'); i >= 0 && (addr[:i] == "" || addr[:i] == "0.0.0.0" || addr[:i] == "[::]") {
		addr = "127.0.0.1" + addr[i:]
	}
	c := &http.Client{Timeout: 3 * time.Second}
	resp, err := c.Get("http://" + addr + "/healthz")
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("healthz: %d", resp.StatusCode)
	}
	return nil
}

func userCmd(args []string) error {
	if len(args) == 0 || args[0] != "add" {
		return errors.New("usage: schild-lab user add -name NAME [-config lab.yaml] (password on stdin)")
	}
	fs := flag.NewFlagSet("user add", flag.ContinueOnError)
	path := fs.String("config", "", "lab.yaml path")
	name := fs.String("name", "", "user name (a-z 0-9 . - _)")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	cfg, err := config.LoadLab(*path)
	if err != nil {
		return err
	}
	dir := envOr("SCHILD_LAB_DATA_DIR", cfg.Storage.Path)
	db, err := store.Open(filepath.Join(dir, "store.db"))
	if err != nil {
		return fmt.Errorf("%w (stop the lab first)", err)
	}
	defer db.Close()
	pw, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && pw == "" {
		return errors.New("password expected on stdin")
	}
	a := dashboard.NewAuthStore(db)
	if err := a.SetPassword(*name, strings.TrimRight(pw, "\r\n")); err != nil {
		return err
	}
	fmt.Printf("user %s saved\n", *name)
	return nil
}

// cosign signs the payload of a bundle or withdrawal envelope with this
// lab's rules key, after showing what is signed.
func cosign(args []string, stdin io.Reader, stdout io.Writer) error {
	fs := flag.NewFlagSet("cosign", flag.ContinueOnError)
	keyFile := fs.String("key", "", "private key file of this lab (purpose rules)")
	keyID := fs.String("keyid", "", "key id of that key")
	in := fs.String("in", "-", "envelope file (- = stdin), or a lab feed URL with -from")
	from := fs.String("from", "", "fetch GET <url>/v0/collecting and pick -digest from it")
	digest := fs.String("digest", "", "payload digest to sign (required with -from)")
	post := fs.String("post", "", "deliver the signature to <url>/v0/signatures instead of printing it")
	yes := fs.Bool("yes", false, "I checked the summary and want to sign")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *keyFile == "" || *keyID == "" {
		return errors.New("cosign needs -key and -keyid")
	}
	signer, err := keys.LoadSigner(*keyID, *keyFile)
	if err != nil {
		return err
	}
	var raw []byte
	client, cerr := upstream.HTTPClient()
	if cerr != nil {
		return cerr
	}
	switch {
	case *from != "":
		resp, err := client.Get(strings.TrimRight(*from, "/") + "/v0/collecting")
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		var page struct {
			Items []struct {
				Digest   string          `json:"digest"`
				Envelope json.RawMessage `json:"envelope"`
			} `json:"items"`
		}
		if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&page); err != nil {
			return err
		}
		for _, it := range page.Items {
			if it.Digest == *digest {
				raw = it.Envelope
			}
		}
		if raw == nil {
			return fmt.Errorf("no collecting item with digest %s at %s", *digest, *from)
		}
	case *in == "-":
		raw, err = io.ReadAll(io.LimitReader(stdin, 2<<20))
	default:
		raw, err = os.ReadFile(*in)
	}
	if err != nil {
		return err
	}
	var env dsse.Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return fmt.Errorf("not a DSSE envelope: %w", err)
	}
	payload, err := env.DecodePayload()
	if err != nil {
		return err
	}
	var kind contract.Kind
	switch env.PayloadType {
	case contract.KindBundle.PayloadType():
		kind = contract.KindBundle
	case contract.KindWithdrawal.PayloadType():
		kind = contract.KindWithdrawal
	default:
		return fmt.Errorf("only bundles and withdrawals are co-signed, got %s", env.PayloadType)
	}
	summary, err := summarize(kind, payload)
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, summary)
	fmt.Fprintln(os.Stderr, "digest:", msg.Digest(payload))
	if !*yes {
		return errors.New("check the summary above, then run again with -yes to sign")
	}
	sig, err := signer.Sign(dsse.PAE(env.PayloadType, payload))
	if err != nil {
		return err
	}
	req := feed.SignatureRequest{Kind: string(kind), Digest: msg.Digest(payload), Signature: dsse.Signature{KeyID: *keyID, Sig: b64(sig)}}
	body, _ := json.Marshal(req)
	if *post == "" {
		fmt.Fprintln(stdout, string(body))
		return nil
	}
	resp, err := client.Post(strings.TrimRight(*post, "/")+"/v0/signatures", "application/json", strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("lab answered %d: %s", resp.StatusCode, out)
	}
	fmt.Fprintln(stdout, string(out))
	return nil
}

func summarize(kind contract.Kind, payload []byte) (string, error) {
	v, err := jsonx.ParseObject(payload)
	if err != nil {
		return "", err
	}
	switch kind {
	case contract.KindBundle:
		var b msg.Bundle
		if err := jsonx.Decode(v, &b); err != nil {
			return "", err
		}
		var sb strings.Builder
		fmt.Fprintf(&sb, "bundle %s version %d, issued %s, expires %s, %d rules:\n", b.BundleID, b.Version, b.IssuedAt, b.Expires, len(b.Rules))
		for _, r := range b.Rules {
			fmt.Fprintf(&sb, "  %s %s max %s (reproduced by %d operators, %d approval orgs)\n", r.RuleID, r.Class, r.MaxAction, r.Evidence.ReproducedOperators, r.Evidence.HumanApprovalOrgs)
		}
		return sb.String(), nil
	default:
		var w msg.Withdrawal
		if err := jsonx.Decode(v, &w); err != nil {
			return "", err
		}
		what := strings.Join(w.RuleIDs, ", ")
		if w.Scope == "all" {
			what = "ALL network rules (emergency stop)"
		}
		return fmt.Sprintf("withdrawal %s seq %d: %s up to bundle %d, reason %s", w.BundleID, w.Seq, what, w.UpToVersion, w.Reason), nil
	}
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
