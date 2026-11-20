//go:build unix

package hostcheck

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// TestOSEnvOpensOnlyRegularFiles: the check runs as root and reads below
// --app paths other users can write to. A FIFO planted there (or a link to
// one) must not block the run, and a link to a device node must not be
// opened; links to regular files still work (os-release, Let's Encrypt).
func TestOSEnvOpensOnlyRegularFiles(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "version.php")
	if err := os.WriteFile(file, []byte("<?php $wp_version = '6.6.1';"), 0o644); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o644); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	link := func(name, target string) string {
		p := filepath.Join(dir, name)
		if err := os.Symlink(target, p); err != nil {
			t.Fatal(err)
		}
		return p
	}
	fileLink := link("file-link", file)
	fifoLink := link("fifo-link", fifo)
	devLink := link("dev-link", os.DevNull)
	plugins := filepath.Join(dir, "plugins")
	if err := os.Mkdir(plugins, 0o755); err != nil {
		t.Fatal(err)
	}
	dirLink := link("plugins-link", plugins)

	env := OSEnv{}
	// Each call runs with a deadline: before the fix the FIFO blocked forever.
	within := func(name string, f func() error) error {
		t.Helper()
		done := make(chan error, 1)
		go func() { done <- f() }()
		select {
		case err := <-done:
			return err
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: blocked", name)
			return nil
		}
	}
	for _, p := range []string{file, fileLink} {
		var b []byte
		if err := within(p, func() (err error) { b, err = env.ReadFile(p, 1<<10); return }); err != nil || len(b) == 0 {
			t.Errorf("ReadFile(%s) = %q, %v", p, b, err)
		}
	}
	for _, p := range []string{fifo, fifoLink, devLink, plugins} {
		if err := within(p, func() error { _, err := env.ReadFile(p, 1<<10); return err }); err == nil {
			t.Errorf("ReadFile(%s): opened a file that is not regular", p)
		}
	}
	for _, p := range []string{plugins, dirLink} {
		if err := within(p, func() error { _, err := env.ReadDir(p); return err }); err != nil {
			t.Errorf("ReadDir(%s): %v", p, err)
		}
	}
	for _, p := range []string{fifo, fifoLink, file} {
		if err := within(p, func() error { _, err := env.ReadDir(p); return err }); err == nil {
			t.Errorf("ReadDir(%s): listed something that is no directory", p)
		}
	}
	// ReadDir keeps the order of os.ReadDir (sorted by name).
	for _, n := range []string{"b", "a", "c"} {
		if err := os.WriteFile(filepath.Join(plugins, n), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	es, err := env.ReadDir(plugins)
	if err != nil || len(es) != 3 || es[0].Name() != "a" || es[2].Name() != "c" {
		t.Fatalf("ReadDir order: %v %v", es, err)
	}
}
