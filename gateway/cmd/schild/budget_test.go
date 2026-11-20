package main

import (
	"errors"
	"testing"

	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/config"
	"github.com/deutschland-schild/schild/contract/storage"
	"github.com/deutschland-schild/schild/gateway/internal/diskbudget"
)

// TestPreflightStorageBudget: schild preflight and schild run refuse a
// budget larger than the file system of storage.path (D38).
func TestPreflightStorageBudget(t *testing.T) {
	good := writeStandalone(t, "(schild) {\n\tschild\n}\nhttp://shop.example.de:18080 {\n\timport schild\n\treverse_proxy 127.0.0.1:9\n}\n")
	data := t.TempDir()
	if err := cmdRun([]string{"-check", "-config", good, "-data", data}); err != nil {
		t.Fatalf("default budget refused: %v", err)
	}
	prev := budgetCheck
	t.Cleanup(func() { budgetCheck = prev })
	var gotWebsites int
	budgetCheck = func(cfg *config.Site, dir string, websites int) (diskbudget.Figures, error) {
		gotWebsites = websites
		// The audit's example: max_size_mb 100000 on a 20 GB disk.
		in := diskbudget.Input(cfg, websites)
		in.MaxSizeMB = 100000
		in.FSTotalBytes, in.FSAvailBytes = 20_000_000_000, 15_000_000_000
		return diskbudget.Figures{Path: dir, TotalBytes: in.FSTotalBytes, AvailBytes: in.FSAvailBytes, BudgetResult: storage.Budget(in)}, nil
	}
	for _, args := range [][]string{{"-check", "-config", good, "-data", data}, {"-config", good, "-data", data}} {
		err := cmdRun(args)
		var ce *contract.Error
		if !errors.As(err, &ce) || ce.Code != contract.CodeConfig || ce.Pointer != "/retention/max_size_mb" {
			t.Errorf("%v: %v", args, err)
		}
	}
	if gotWebsites != 1 {
		t.Errorf("websites %d, want 1", gotWebsites)
	}
}
