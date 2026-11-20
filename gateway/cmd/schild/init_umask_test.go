//go:build unix

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// TestInitDirectoriesReadableUnderTightUmask: with umask 077 (a hardened
// root shell) the directories `schild init` creates are still 0755 and the
// file 0644, so the service user can read the config. A directory that
// existed before keeps its mode.
func TestInitDirectoriesReadableUnderTightUmask(t *testing.T) {
	old := syscall.Umask(0o077)
	defer syscall.Umask(old)

	base := t.TempDir()
	kept := filepath.Join(base, "kept")
	if err := os.Mkdir(kept, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(kept, "etc", "schild", "schild.yaml")
	if err := writeConfig(path, []byte("mode: observe\n"), false); err != nil {
		t.Fatal(err)
	}
	for p, want := range map[string]os.FileMode{
		kept:                                 0o700,
		filepath.Join(kept, "etc"):           0o755,
		filepath.Join(kept, "etc", "schild"): 0o755,
		path:                                 0o644,
	} {
		st, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if got := st.Mode().Perm(); got != want {
			t.Errorf("%s: mode %o, want %o", p, got, want)
		}
	}
}

// TestInitCaddyReadableUnderTightUmask: the Caddy swap writes its file the
// same way (0644 in 0755 directories under umask 077).
func TestInitCaddyReadableUnderTightUmask(t *testing.T) {
	old := syscall.Umask(0o077)
	defer syscall.Umask(old)

	o := swapInput(t, swapCaddyfileDone)
	o.Path = filepath.Join(filepath.Dir(o.Caddyfile), "etc", "schild", "schild.yaml")
	if err := runInitCaddy(&bytes.Buffer{}, o); err != nil {
		t.Fatal(err)
	}
	for p, want := range map[string]os.FileMode{filepath.Dir(filepath.Dir(o.Path)): 0o755, filepath.Dir(o.Path): 0o755, o.Path: 0o644} {
		st, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if got := st.Mode().Perm(); got != want {
			t.Errorf("%s: mode %o, want %o", p, got, want)
		}
	}
}
