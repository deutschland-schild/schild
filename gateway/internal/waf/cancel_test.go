package waf

import (
	"strings"
	"testing"
)

func evalWithCancel(t *testing.T, inst *Instance, body string, onCheck func(int64, *Cancel)) (c *Cancel, cancelled bool, matched int) {
	t.Helper()
	var cc *Cancel
	tx, c := inst.newTransaction(func(n int64) {
		if onCheck != nil {
			onCheck(n, cc)
		}
	})
	cc = c
	if c == nil {
		t.Fatal("instance does not support cancellation")
	}
	defer func() {
		c.Finish()
		_ = tx.Close()
	}()
	r := browserReq("POST", "/contact", "application/x-www-form-urlencoded", body)
	func() {
		defer func() {
			if v := recover(); v != nil {
				if !IsCancelled(v) {
					panic(v)
				}
				cancelled = true
			}
		}()
		ProcessHeaders(tx, r, "203.0.113.7", 40000)
		if _, _, err := ReadBody(tx, r, DefaultLimits); err != nil {
			t.Fatal(err)
		}
		_, _ = tx.ProcessRequestBody()
	}()
	return c, cancelled, len(tx.MatchedRules())
}

func TestCancelStopsEvaluationAtNextCheckpoint(t *testing.T) {
	inst := crs(t)
	body := "msg=" + strings.Repeat("<script>alert(1)</script> union select ", 200)

	// Reference: the full evaluation passes many checkpoints and matches.
	full, cancelled, matched := evalWithCancel(t, inst, body, nil)
	if cancelled || matched == 0 || full.Checks() < 100 {
		t.Fatalf("reference evaluation: cancelled=%v matched=%d checks=%d", cancelled, matched, full.Checks())
	}

	// Cancel while checkpoint 50 runs (as another goroutine would): no
	// further checkpoint is passed, the evaluation stops right there.
	const at = 50
	var after int64
	c, cancelled, _ := evalWithCancel(t, inst, body, func(n int64, c *Cancel) {
		if n == at {
			c.Cancel()
		}
		if n > at {
			after++
		}
	})
	if !cancelled {
		t.Fatal("cancelled evaluation ran to the end")
	}
	if c.Checks() != at || after != 0 {
		t.Fatalf("evaluation went on after the cancel: %d checkpoints (cancel at %d), %d after", c.Checks(), at, after)
	}
}

func TestCancelAfterFinishIsHarmless(t *testing.T) {
	inst := crs(t)
	tx, c := inst.NewTransaction()
	c.Finish()
	if c.Cancel() {
		t.Fatal("Cancel after Finish reported a running evaluation")
	}
	r := browserReq("GET", "/?q=hello", "", "")
	ProcessHeaders(tx, r, "203.0.113.7", 40000) // must not panic
	_ = tx.Close()
}

func TestCancelIsPerTransaction(t *testing.T) {
	inst := crs(t)
	tx1, c1 := inst.NewTransaction()
	tx2, c2 := inst.NewTransaction()
	defer func() { c1.Finish(); _ = tx1.Close(); c2.Finish(); _ = tx2.Close() }()
	c1.Cancel()
	r := browserReq("GET", "/?q=hello", "", "")
	ProcessHeaders(tx2, r, "203.0.113.7", 40000) // other transaction unaffected
	if c2.Checks() == 0 {
		t.Fatal("second transaction has no checkpoints")
	}
	func() {
		defer func() {
			if v := recover(); !IsCancelled(v) {
				t.Fatalf("cancelled transaction did not stop: %v", v)
			}
		}()
		ProcessHeaders(tx1, r, "203.0.113.7", 40000)
	}()
}
