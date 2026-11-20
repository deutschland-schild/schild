//go:build !release

package app_test

import (
	"testing"
	"time"

	"github.com/deutschland-schild/schild/contract/storage"
	"github.com/deutschland-schild/schild/gateway/internal/apptest"
)

// TestStorageBudgetChecked: the running gateway checks the disk budget at
// start (D38) with the metrics.db bound of its websites.
func TestStorageBudgetChecked(t *testing.T) {
	h := apptest.New(t, apptest.Options{})
	deadline := time.Now().Add(5 * time.Second)
	for h.App.StorageBudget() == nil && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	f := h.App.StorageBudget()
	if f == nil {
		t.Fatal("no budget check after the start")
	}
	if f.TotalBytes <= 0 || f.BudgetBytes <= 0 || f.UsedBytes <= 0 || (f.Verdict != storage.BudgetOK && f.Verdict != storage.BudgetHint) {
		t.Errorf("%+v", f)
	}
	if h.App.Monitor != nil && f.MetricsBoundBytes == 0 {
		t.Error("metrics.db bound missing with monitoring on")
	}
}
