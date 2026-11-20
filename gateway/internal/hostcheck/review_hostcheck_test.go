package hostcheck

// Independent review probes of the MVP-11 kill criteria "the check changes
// system state" and "a report leaks a secret" at unit level. The container
// probes on real distributions are in adversaries/host-check.
//
// The probes of the defects the review found (dnf writes, java perf data)
// run normally since the fixes; they fail if a defect comes back.

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// TestReviewCommandListIsReadOnly audits the fixed argv list: nothing that
// refreshes indexes, installs, or runs without its read-only flag.
func TestReviewCommandListIsReadOnly(t *testing.T) {
	bad := []string{"update", "makecache", "install", "remove", "upgrade", "reinstall", "clean", "autoremove", "--refresh", "-y", "--assumeyes", "rebuilddb", "--initdb", "reload", "restart", "flush", "-F", "-X", "add", "delete"}
	for _, c := range Commands {
		args := c.Argv[1:]
		for _, a := range args {
			if slices.Contains(bad, a) {
				t.Errorf("%s: argument %q", c.ID, a)
			}
		}
		switch c.Argv[0] {
		case "dnf", "yum":
			if !slices.Contains(args, "-C") {
				t.Errorf("%s: dnf/yum without -C (cache only)", c.ID)
			}
		case "apt-get":
			if !slices.Contains(args, "-s") {
				t.Errorf("%s: apt-get without -s", c.ID)
			}
		case "nft":
			if !slices.Equal(args, []string{"list", "ruleset"}) {
				t.Errorf("%s: nft %v", c.ID, args)
			}
		}
	}
	// The env refuses everything else, also a listed id with other argv.
	env := OSEnv{}
	if _, err := env.Run(context.Background(), Command{ID: "apt-list-upgradable", Argv: []string{"apt", "update"}}); err != ErrRefused {
		t.Fatalf("listed id with other argv: %v", err)
	}
}

// TestReviewJavaLeavesNoPerfData: `java -version` creates
// /tmp/hsperfdata_<user>/ (HotSpot perf data) and leaves the directory
// behind. The check runs it whenever Java is not found among the packages
// (tarball JDKs, Temurin/Oracle/Zulu packages whose names the package
// filter does not know). Repro on a real system:
// adversaries/host-check/readonly/readonly-distros.sh (debian-java image).
func TestReviewJavaLeavesNoPerfData(t *testing.T) {
	if !slices.Contains(CmdJavaVersion.Argv, "-XX:-UsePerfData") {
		t.Fatalf("java runs as %v: without -XX:-UsePerfData the JVM creates /tmp/hsperfdata_<user>/", CmdJavaVersion.Argv)
	}
}

// TestReviewDnfWritesLogsAndCaches: on RHEL-like hosts every dnf call run
// as root appends to /var/log/dnf.log, dnf.librepo.log, dnf.rpm.log and
// hawkey.log and may rewrite /var/cache/dnf/*.solv and expired_repos.json
// (-C only stops downloads); run as a normal user it creates a per-user
// cache under /var/tmp/dnf-<user>-*/; needs-restarting is a dnf plugin with
// the same writes; rpm as root updates the rpmdb's sqlite -shm file. Since
// the fix the check runs none of dnf, yum, needs-restarting; the package
// database and dnf's metadata cache are read by unprivileged commands only
// (the kernel refuses their writes), and the hawkey script switches off
// every write it would otherwise attempt. Repro of the original defect and
// proof of the fix on Rocky 9: adversaries/host-check/readonly/readonly-distros.sh.
func TestReviewDnfWritesLogsAndCaches(t *testing.T) {
	for _, c := range Commands {
		switch path.Base(c.Argv[0]) {
		case "dnf", "dnf5", "yum", "microdnf", "needs-restarting", "dnf-3", "yum-config-manager", "repoquery":
			t.Errorf("%s runs %s, which writes logs and caches", c.ID, c.Argv[0])
		case "rpm", "dpkg-query", "python3", "platform-python", "java", "node", "php":
			if !c.Unprivileged {
				t.Errorf("%s (%s) must run unprivileged", c.ID, c.Argv[0])
			}
		}
	}
	s := dnfUpdatesScript
	for _, want := range []string{`make_cache_dir=False`, `logfile="/dev/null"`, `load_system_repo(build_cache=False)`, `build_cache=False, load_filelists=False`} {
		if !strings.Contains(s, want) {
			t.Errorf("dnf script lacks %s", want)
		}
	}
	for _, bad := range []string{"open(p, \"w", "\"w\")", "\"a\")", "write_", ".save(", "makecache", "dnf.Base", "setup_loggers", "os.remove", "os.mkdir", "makedirs", "urlopen", "socket"} {
		if strings.Contains(s, bad) {
			t.Errorf("dnf script contains %q", bad)
		}
	}
	if strings.Count(s, "load_repo(") != 1 || strings.Count(s, "load_system_repo(") != 1 {
		t.Error("every repo load must be the build_cache=False one")
	}
}

// TestReviewCanariesNeverInReport plants secrets wherever a check reads
// (sshd config and sshd -T output, apt proxy credentials, nft comments, the
// journal, WordPress, Laravel .env, private keys next to certificates) and
// visitor addresses in the auth log, and requires that none of them shows
// up in the report while the planted things are seen (positive controls).
func TestReviewCanariesNeverInReport(t *testing.T) {
	src := "testdata/hosts/debian12"
	dir := t.TempDir()
	if err := os.CopyFS(dir, os.DirFS(src)); err != nil {
		t.Fatal(err)
	}
	put := func(rel, body string) {
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	app := func(rel string) string { b, _ := os.ReadFile(filepath.Join(dir, rel)); return string(b) }
	put("fs/etc/ssh/sshd_config.d/10-review.conf", "# deploy token=rvwcanary-a1\nAuthorizedKeysCommand /usr/local/bin/keys --token=rvwcanary-a2\nBanner /etc/issue.rvwcanary-a3\n")
	put("cmd/sshd-t.out", app("cmd/sshd-t.out")+"authorizedkeyscommand /usr/local/bin/keys --token=rvwcanary-a4\nbanner /etc/issue.rvwcanary-a5\n")
	put("fs/etc/apt/apt.conf.d/90proxy", "Acquire::http::Proxy \"http://deploy:rvwcanary-b1@proxy.local:3128\";\nAPT::Periodic::Unattended-Upgrade \"1\";\n")
	put("cmd/nft.out", app("cmd/nft.out")+"\ntable inet review {\n  chain input {\n    type filter hook input priority 0; policy accept;\n    tcp dport 8099 accept comment \"api key rvwcanary-c1\"\n  }\n}\n")
	put("cmd/journal-sshd.out", app("cmd/journal-sshd.out")+time.Now().UTC().Format("2006-01-02T15:04:05-0700")+" host sshd[1]: Failed password for rvwcanary-user from 198.51.100.77 port 4242 ssh2\n")
	put("fs/var/www/shop/wp-config.php", "<?php\ndefine('DB_PASSWORD', 'rvwcanary-d1');\ndefine('AUTH_KEY', 'rvwcanary-d2');\n")
	put("fs/var/www/shop/wp-content/plugins/rvw/rvw.php", "<?php\n/*\nPlugin Name: Review\nVersion: 1.2.3\n*/\ndefine('RVW_LICENSE', 'rvwcanary-d3');\n")
	put("fs/var/www/laravel/artisan", "#!/usr/bin/env php\n")
	put("fs/var/www/laravel/.env", "APP_KEY=base64:rvwcanary-e1\nDB_PASSWORD=rvwcanary-e2\n")
	put("fs/var/www/laravel/composer.lock", `{"packages":[{"name":"laravel/framework","version":"v10.48.4"}]}`)
	put("fs/etc/letsencrypt/live/shop.example/privkey.pem", "-----BEGIN PRIVATE KEY-----\nrvwcanary-f1\n-----END PRIVATE KEY-----\n")
	// A combined cert+key file under a name without "key".
	cert := app("fs/etc/letsencrypt/live/shop.example/cert.pem")
	put("fs/etc/haproxy/certs/shop.pem", cert+"# rvwcanary-f2\n-----BEGIN PRIVATE KEY-----\nrvwcanary-f3\n-----END PRIVATE KEY-----\n")

	env := &FixtureEnv{Dir: dir, Time: time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)}
	r := Run(context.Background(), env, Options{Role: "gateway", SchildVersion: "review", Apps: []string{"/var/www/shop", "/var/www/laravel"},
		CertGlobs: append([]string{"/etc/haproxy/certs/*.pem"}, DefaultCertGlobs...)})
	b, err := Marshal(r)
	if err != nil {
		t.Fatalf("report fails the contract: %v", err)
	}
	s := string(b)
	for _, bad := range []string{"rvwcanary", "198.51.100.77", "PRIVATE KEY", "BEGIN CERT"} {
		if strings.Contains(s, bad) {
			i := strings.Index(s, bad)
			t.Errorf("report carries %q: …%s…", bad, s[max(0, i-120):min(len(s), i+60)])
		}
	}
	for _, want := range []string{`"laravel"`, `"rvw"`, `"/etc/haproxy/certs/shop.pem"`, `"count":`} {
		if !strings.Contains(s, want) {
			t.Errorf("positive control %s missing", want)
		}
	}
	// Nothing in the fixture changed (the check only reads).
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			if fi, _ := d.Info(); fi.ModTime().After(time.Now().Add(time.Second)) {
				t.Errorf("%s modified", p)
			}
		}
		return nil
	})
}

// TestReviewOnlyTheReportStoreWrites is the code side of the read-only
// proof: the checks reach the host only through Env (read, list, stat,
// glob and the fixed commands). No file of the package but store.go (the
// report directory) calls a writing function of package os, os.OpenFile is
// only ever read-only, only env.go runs commands, and nothing opens a
// socket.
func TestReviewOnlyTheReportStoreWrites(t *testing.T) {
	writes := map[string]bool{"WriteFile": true, "Create": true, "CreateTemp": true, "Remove": true, "RemoveAll": true, "Mkdir": true,
		"MkdirAll": true, "MkdirTemp": true, "Rename": true, "Chmod": true, "Chown": true, "Lchown": true, "Chtimes": true,
		"Symlink": true, "Link": true, "Truncate": true, "Setenv": true, "Unsetenv": true, "Clearenv": true}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	n := 0
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		f, err := parser.ParseFile(fset, name, src, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		n++
		for _, imp := range f.Imports {
			switch p := strings.Trim(imp.Path.Value, `"`); {
			case p == "net" || p == "net/http" || p == "net/rpc" || strings.HasPrefix(p, "net/http/"):
				t.Errorf("%s imports %s: the check opens no connection", name, p)
			case p == "os/exec" && name != "env.go":
				t.Errorf("%s imports os/exec: commands run only through Env.Run", name)
			}
		}
		ast.Inspect(f, func(x ast.Node) bool {
			call, ok := x.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if id, ok := sel.X.(*ast.Ident); !ok || id.Name != "os" {
				return true
			}
			switch {
			case writes[sel.Sel.Name] && name != "store.go":
				t.Errorf("%s: os.%s outside the report store", fset.Position(call.Pos()), sel.Sel.Name)
			case sel.Sel.Name == "OpenFile" && len(call.Args) >= 2:
				flags := string(src[fset.Position(call.Args[1].Pos()).Offset:fset.Position(call.Args[1].End()).Offset])
				if !strings.Contains(flags, "O_RDONLY") || strings.ContainsAny(strings.NewReplacer("O_RDONLY", "", "O_NONBLOCK", "", "O_NOCTTY", "", "O_DIRECTORY", "").Replace(flags), "ABCDEFGHIJKLMNOPQRSTUVWXYZ") {
					t.Errorf("%s: os.OpenFile with %s", fset.Position(call.Pos()), flags)
				}
			}
			return true
		})
	}
	if n < 10 {
		t.Fatalf("only %d files parsed", n)
	}
}
