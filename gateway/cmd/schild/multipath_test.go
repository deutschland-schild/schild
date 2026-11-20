package main

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Every binary that listens turns Multipath TCP off (defence in depth), and
// no code of its module or of the contract library turns it on again.
// schild-agent has no listener (main_test.go there checks that). The lab and
// the relay check themselves (multipath_test.go next to their main.go), so
// this module builds and tests without them.
func TestListenersDisableMultipathTCP(t *testing.T) {
	b, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	head, _, ok := strings.Cut(string(b), "\npackage main\n")
	if !ok || !strings.Contains(head, "//go:debug multipathtcp=0") {
		t.Fatal("main.go: no //go:debug multipathtcp=0 before the package clause")
	}
	for _, root := range []string{"../..", "../../../contract"} {
		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() && (d.Name() == "node_modules" || d.Name() == "ui") {
				return filepath.SkipDir
			}
			if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "multipath_test.go") {
				return nil
			}
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			if strings.Contains(string(b), "SetMultipathTCP(") {
				t.Errorf("%s calls SetMultipathTCP", p)
			}
			return nil
		})
		// The contract library lies next to the module in the repository; a
		// copy of the module alone is checked without it.
		if err != nil && !(errors.Is(err, fs.ErrNotExist) && root != "../..") {
			t.Fatal(err)
		}
	}
}
