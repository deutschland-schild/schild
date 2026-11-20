package diskbudget

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/deutschland-schild/schild/gateway/internal/reqring"
)

// The MVP-22 request ring segments count as used bytes of the budget.
func TestUsedBytesCountsRequestRing(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, reqring.Dir), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, reqring.Dir, "seg-1.z"), make([]byte, 4096), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "schild.db"), make([]byte, 1000), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := UsedBytes(dir); got != 5096 {
		t.Fatalf("used %d", got)
	}
}
