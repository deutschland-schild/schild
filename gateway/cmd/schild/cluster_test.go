//go:build !release

package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/gateway/internal/app"
	"github.com/deutschland-schild/schild/gateway/internal/cluster"
	"github.com/deutschland-schild/schild/gateway/internal/testport"
)

func clusterConfig(t *testing.T, name, listen string) (cfgPath, dataDir string) {
	t.Helper()
	dir := t.TempDir()
	dataDir = filepath.Join(dir, "data")
	cfgPath = filepath.Join(dir, "schild.yaml")
	yaml := fmt.Sprintf("config_version: 0\nnode_name: %s\nupstream: {url: \"http://127.0.0.1:8081\"}\nstorage: {path: %q}\n", name, dataDir)
	if listen != "" {
		yaml += fmt.Sprintf("cluster: {enabled: true, listen: %q}\n", listen)
	}
	if err := os.WriteFile(cfgPath, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	return cfgPath, dataDir
}

func clusterCmd(t *testing.T, cfg string, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	err := runCluster(append(args, "-config", cfg), &out, time.Now)
	return out.String(), err
}

func TestClusterCommands(t *testing.T) {
	addr1, addr2 := testport.Free(t), testport.Free(t)
	cfg1, data1 := clusterConfig(t, "web-1", addr1)
	cfg2, _ := clusterConfig(t, "web-2", addr2)

	if _, err := clusterCmd(t, cfg1, "status"); err == nil || !strings.Contains(err.Error(), "no group") {
		t.Fatalf("status before init: %v", err)
	}
	out, err := clusterCmd(t, cfg1, "init")
	if err != nil || !strings.Contains(out, "web-1 is its first node") {
		t.Fatalf("init: %q, %v", out, err)
	}
	if _, err := clusterCmd(t, cfg1, "init"); err == nil {
		t.Error("a second init was accepted")
	}
	// The node key is readable by its owner only.
	if fi, err := os.Stat(filepath.Join(app.ClusterDir(data1), "node.key")); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("node key: %v, mode %v", err, fi.Mode().Perm())
	}

	// web-1 runs, as schild would after the restart.
	node, err := cluster.Open(cluster.Options{Dir: app.ClusterDir(data1), Listen: addr1, Hold: 200 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = node.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-done; node.Close() })
	for node.Addr() == "" {
		time.Sleep(5 * time.Millisecond)
	}

	out, err = clusterCmd(t, cfg1, "invite")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`schild cluster join (\S+) (\S+)`).FindStringSubmatch(out)
	if m == nil || m[1] != addr1 {
		t.Fatalf("invite does not print the join command: %q", out)
	}
	if _, err := clusterCmd(t, cfg2, "join", addr1, "aaaaaaaaaaaaa-aaaaaaaaaaaaa-aaaaaaaaaaaaa-aaaaaaaaaaaaa"); err == nil {
		t.Error("a made-up code joined")
	}
	out, err = clusterCmd(t, cfg2, "join", m[1], m[2])
	if err != nil || !strings.Contains(out, "(2 nodes)") {
		t.Fatalf("join: %q, %v", out, err)
	}

	out, err = clusterCmd(t, cfg2, "status")
	if err != nil || !strings.Contains(out, "web-1") || !strings.Contains(out, "web-2") || !strings.Contains(out, "this node") {
		t.Fatalf("status on web-2: %q, %v", out, err)
	}
	out, err = clusterCmd(t, cfg1, "remove", "web-2")
	if err != nil || !strings.Contains(out, "no member any more") {
		t.Fatalf("remove: %q, %v", out, err)
	}
	out, _ = clusterCmd(t, cfg1, "status")
	if !regexp.MustCompile(`web-2\s+gateway\s+\S+\s+removed`).MatchString(out) {
		t.Errorf("status after the removal: %q", out)
	}
	if _, err := clusterCmd(t, cfg1, "remove", "web-2"); err == nil {
		t.Error("a removed node was removed again")
	}
}

func TestClusterCommandsNeedTheSection(t *testing.T) {
	cfg, _ := clusterConfig(t, "web-1", "")
	if _, err := clusterCmd(t, cfg, "init"); err == nil || !strings.Contains(err.Error(), "cluster.listen") {
		t.Errorf("init without the cluster section: %v", err)
	}
}
