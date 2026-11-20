package egress

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestScanTree(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, b []byte) {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("clean/queue.ndjson", []byte(`{"kind":"signal","origin":{"country":"DE"}}`+"\n"))
	// a canary inside binary data (as in a SQLite page)
	write("db/lab.sqlite", append(append(bytes.Repeat([]byte{0}, 100), []byte("x app-vm-canary-k4p8z2 y")...), 0, 1, 2))
	// a canary straddling the 1 MiB read boundary
	big := bytes.Repeat([]byte("a"), treeChunk-5)
	big = append(big, []byte("schild-canary-pkg-q7m3x9")...)
	write("log/big.bin", big)

	rep, err := ScanTree([]string{dir}, []string{"app-vm-canary-k4p8z2", "schild-canary-pkg-q7m3x9", "never-there", ""})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Files != 3 || rep.Canaries != 3 {
		t.Fatalf("files=%d canaries=%d, want 3/3", rep.Files, rep.Canaries)
	}
	if rep.OK() || len(rep.Findings) != 2 {
		t.Fatalf("findings %+v, want 2 (sqlite page, boundary)", rep.Findings)
	}
	if rep.Findings[0].Location != filepath.Join(dir, "db/lab.sqlite") || rep.Findings[1].Location != filepath.Join(dir, "log/big.bin") {
		t.Fatalf("locations %+v", rep.Findings)
	}

	clean, err := ScanTree([]string{filepath.Join(dir, "clean")}, []string{"app-vm-canary-k4p8z2"})
	if err != nil || !clean.OK() || clean.Files != 1 {
		t.Fatalf("clean dir: %+v %v", clean, err)
	}
}

func TestScanTreeMissingRootIsAFinding(t *testing.T) {
	rep, err := ScanTree([]string{filepath.Join(t.TempDir(), "absent")}, []string{"x"})
	if err != nil {
		t.Fatal(err)
	}
	if rep.OK() {
		t.Fatal("a root that cannot be read must not pass")
	}
}
