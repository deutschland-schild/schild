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

func clusterConfig(t *testing.T, name, listen, secretFile string) (cfgPath, dataDir string) {
	t.Helper()
	dir := t.TempDir()
	dataDir = filepath.Join(dir, "data")
	cfgPath = filepath.Join(dir, "schild.yaml")
	yaml := fmt.Sprintf("config_version: 0\nnode_name: %s\nupstream: {url: \"http://127.0.0.1:8081\"}\nstorage: {path: %q}\n", name, dataDir)
	if listen != "" {
		yaml += fmt.Sprintf("cluster: {enabled: true, listen: %q, secret_file: %q}\n", listen, secretFile)
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

// runNode sets a node up from its secret, as schild does at its start, and
// runs it.
func runNode(t *testing.T, dataDir, name, listen string, secret []byte, peers []string) *cluster.Node {
	t.Helper()
	dir := app.ClusterDir(dataDir)
	if _, _, err := cluster.Configure(dir, name, listen, secret, nil); err != nil {
		t.Fatal(err)
	}
	node, err := cluster.Open(cluster.Options{Dir: dir, Listen: listen, Hold: 200 * time.Millisecond, Peers: peers})
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
	return node
}

func TestClusterCommands(t *testing.T) {
	var sec bytes.Buffer
	if err := runCluster([]string{"secret"}, &sec, time.Now); err != nil {
		t.Fatal(err)
	}
	secret := bytes.TrimSpace(sec.Bytes())
	secretFile := filepath.Join(t.TempDir(), "cluster.secret")
	if err := os.WriteFile(secretFile, secret, 0o600); err != nil {
		t.Fatal(err)
	}
	addr1, addr2 := testport.Free(t), testport.Free(t)
	cfg1, data1 := clusterConfig(t, "web-1", addr1, secretFile)
	cfg2, data2 := clusterConfig(t, "web-2", addr2, secretFile)

	if _, err := clusterCmd(t, cfg1, "status"); err == nil || !strings.Contains(err.Error(), "no group") {
		t.Fatalf("status before the first start: %v", err)
	}
	// Joining by code is gone: a group is set up by its secret file.
	for _, sub := range []string{"init", "invite", "join"} {
		if _, err := clusterCmd(t, cfg1, sub); err == nil || !strings.Contains(err.Error(), "unknown command") {
			t.Errorf("cluster %s: %v", sub, err)
		}
	}

	runNode(t, data1, "web-1", addr1, secret, nil)
	// The node key is readable by its owner only.
	if fi, err := os.Stat(filepath.Join(app.ClusterDir(data1), "node.key")); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("node key: %v, mode %v", err, fi.Mode().Perm())
	}
	two := runNode(t, data2, "web-2", addr2, secret, []string{addr1})
	deadline := time.Now().Add(10 * time.Second)
	for len(two.Reachable()) != 1 {
		if time.Now().After(deadline) {
			t.Fatal("web-2 did not find web-1")
		}
		time.Sleep(20 * time.Millisecond)
	}

	out, err := clusterCmd(t, cfg2, "status")
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

func TestClusterSecret(t *testing.T) {
	var out bytes.Buffer
	if err := runCluster([]string{"secret"}, &out, time.Now); err != nil || !regexp.MustCompile(`^[0-9a-f]{64}\n$`).MatchString(out.String()) {
		t.Fatalf("secret: %q, %v", out.String(), err)
	}
	var again bytes.Buffer
	_ = runCluster([]string{"secret"}, &again, time.Now)
	if again.String() == out.String() {
		t.Error("two secrets are the same")
	}
}
