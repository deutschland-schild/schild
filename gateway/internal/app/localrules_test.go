//go:build !release

package app_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/deutschland-schild/schild/contract/bodylimit"
	"github.com/deutschland-schild/schild/gateway/internal/apptest"
	"github.com/deutschland-schild/schild/gateway/internal/control"
	"github.com/deutschland-schild/schild/gateway/internal/gate"
)

const (
	blockRule = `SecRule REQUEST_URI "@beginsWith /stop-here" "id:1000001,phase:1,deny,status:403,log"`
	// The exception of the fourth measurement: one rule, one path.
	whoamiException = `SecRule REQUEST_URI "@rx (?:^|/)whoami(?:$|[?])" "id:1000101,phase:1,pass,nolog,ctl:ruleRemoveById=932260"`
)

type rulesDir struct {
	t   *testing.T
	h   *apptest.Harness
	dir string
}

func newRules(t *testing.T) *rulesDir {
	t.Helper()
	h := apptest.New(t, apptest.Options{Mode: "autoblock"})
	dir := filepath.Join(h.Dir, "rules.d")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return &rulesDir{t, h, dir}
}

func (r *rulesDir) write(name, text string) {
	r.t.Helper()
	if err := os.WriteFile(filepath.Join(r.dir, name), []byte(text+"\n"), 0o600); err != nil {
		r.t.Fatal(err)
	}
}

func (r *rulesDir) status(path string) int {
	r.t.Helper()
	resp := r.h.Visit("GET", path, "203.0.113.9", "", "")
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

func (r *rulesDir) reload() control.Response {
	return r.h.App.Control(context.Background(), control.Request{Op: control.OpRulesSync, Repository: "local"})
}

func (r *rulesDir) count(result string) float64 {
	return testutil.ToFloat64(r.h.App.Metrics.LocalRulesReloads.WithLabelValues(result))
}

// The case of the measurement: an exception for one rule on one path, no restart.
func TestReloadTakesAnException(t *testing.T) {
	r := newRules(t)
	const whoami, attack = "/api/v1/users/whoami", "/?x=1%27%20OR%20%271%27%3D%271"
	if got := r.status(whoami); got != http.StatusForbidden {
		t.Fatalf("whoami before the exception: %d", got)
	}
	r.write("exceptions.conf", whoamiException)
	if resp := r.reload(); !resp.OK || resp.RulesLoaded != 1 || resp.Unchanged {
		t.Fatalf("%+v", resp)
	}
	if got := r.status(whoami); got != http.StatusOK {
		t.Fatalf("whoami after the exception: %d", got)
	}
	if got := r.status(attack); got != http.StatusForbidden {
		t.Fatalf("an attack elsewhere: %d", got)
	}
	if r.count(bodylimit.ReloadApplied) != 1 {
		t.Fatal("no count")
	}
}

func TestReloadAddsAndRemoves(t *testing.T) {
	r := newRules(t)
	if got := r.status("/stop-here"); got != http.StatusOK {
		t.Fatalf("before: %d", got)
	}
	r.write("block.conf", blockRule)
	if resp := r.reload(); !resp.OK {
		t.Fatalf("%+v", resp)
	}
	if got := r.status("/stop-here"); got != http.StatusForbidden {
		t.Fatalf("after: %d", got)
	}
	if err := os.Remove(filepath.Join(r.dir, "block.conf")); err != nil {
		t.Fatal(err)
	}
	if resp := r.reload(); !resp.OK || resp.RulesLoaded != 0 {
		t.Fatalf("%+v", resp)
	}
	if got := r.status("/stop-here"); got != http.StatusOK {
		t.Fatalf("removed: %d", got)
	}
}

// What follows the set follows the reload: the config version of the agent API
// and the rule list.
func TestReloadMovesWhatDependsOnTheSet(t *testing.T) {
	r := newRules(t)
	before := r.h.App.ConfigHash()
	r.write("a.conf", blockRule)
	if resp := r.reload(); !resp.OK {
		t.Fatalf("%+v", resp)
	}
	if r.h.App.ConfigHash() == before {
		t.Fatal("the config version stayed")
	}
	if !r.h.App.Repos.HasRule("local", "1000001") {
		t.Fatal("the rule list does not know the new rule")
	}
}

// Outside a cgroup no brake runs, and the gauge does not pretend it is calm.
func TestNoBrakeShowsInTheGauge(t *testing.T) {
	if _, err := os.Stat("/sys/fs/cgroup/memory.max"); err == nil {
		t.Skip("inside a cgroup")
	}
	r := newRules(t)
	deadline := time.Now().Add(10 * time.Second)
	for testutil.ToFloat64(r.h.App.Metrics.MemoryPressure) != bodylimit.PressureUnknown {
		if time.Now().After(deadline) {
			t.Fatal("the gauge says calm")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A file that does not build leaves the running set in place, whatever is wrong.
func TestReloadRefusesABadFile(t *testing.T) {
	for name, bad := range map[string]string{
		"syntax":         `SecRule REQUEST_URI "@nosuchoperator x" "id:1000002,deny"`,
		"cut off":        `SecRule REQUEST_URI "@beginsWith /x" "id:1000003,ph`,
		"network range":  `SecRule REQUEST_URI "@beginsWith /x" "id:7700001,phase:1,deny"`,
		"crs range":      `SecRule REQUEST_URI "@beginsWith /x" "id:942100,phase:1,deny"`,
		"crowdsec range": `SecRule REQUEST_URI "@beginsWith /x" "id:60000001,phase:1,deny"`,
		"same id twice":  blockRule,
		// D80: the backend would get an empty body.
		"engine off":      `SecRule REQUEST_URI "@beginsWith /hook" "id:1000004,phase:1,pass,nolog,ctl:ruleEngine=Off"`,
		"body access off": `SecRequestBodyAccess Off`,
		"include":         `Include /etc/schild/more.conf`,
	} {
		t.Run(name, func(t *testing.T) {
			r := newRules(t)
			r.write("a.conf", blockRule)
			if resp := r.reload(); !resp.OK {
				t.Fatalf("%+v", resp)
			}
			r.write("b.conf", bad)
			resp := r.reload()
			if resp.OK || resp.Error == "" {
				t.Fatalf("a bad file went through: %+v", resp)
			}
			if got := r.status("/stop-here"); got != http.StatusForbidden {
				t.Fatalf("the running set is gone: %d", got)
			}
			if r.count(bodylimit.ReloadRefused) != 1 {
				t.Fatal("no count")
			}
			if err := os.Remove(filepath.Join(r.dir, "b.conf")); err != nil {
				t.Fatal(err)
			}
			if resp := r.reload(); !resp.OK || !resp.Unchanged {
				t.Fatalf("after the fix: %+v", resp)
			}
		})
	}
}

// A volume that went away is not an empty directory.
func TestReloadRefusesAMissingDirectory(t *testing.T) {
	r := newRules(t)
	r.write("a.conf", blockRule)
	if resp := r.reload(); !resp.OK {
		t.Fatalf("%+v", resp)
	}
	if err := os.RemoveAll(r.dir); err != nil {
		t.Fatal(err)
	}
	if resp := r.reload(); resp.OK {
		t.Fatalf("%+v", resp)
	}
	if got := r.status("/stop-here"); got != http.StatusForbidden {
		t.Fatalf("the running set is gone: %d", got)
	}
}

func TestReloadUnchangedBuildsNothing(t *testing.T) {
	r := newRules(t)
	r.write("a.conf", blockRule)
	if resp := r.reload(); !resp.OK {
		t.Fatalf("%+v", resp)
	}
	before := r.h.App.Engine.Current()
	if resp := r.reload(); !resp.OK || !resp.Unchanged || resp.RulesLoaded != 1 {
		t.Fatalf("%+v", resp)
	}
	if r.h.App.Engine.Current() != before {
		t.Fatal("an unchanged set was built again")
	}
}

// Requests in flight and requests during the build see one set or the other, and
// never an error (B07).
func TestReloadDropsNoRequest(t *testing.T) {
	r := newRules(t)
	// Eight clients at once: a slow machine must not answer 503 for a full
	// evaluation queue, that is not what this test is about.
	r.h.App.Gate.SetEvalLimits(gate.EvalLimits{QueueWait: time.Minute})
	stop := make(chan struct{})
	var wg sync.WaitGroup
	var bad, n atomic.Int64
	var statuses sync.Map
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				resp := r.h.Visit("GET", "/stop-here", fmt.Sprintf("203.0.113.%d", i+1), "", "")
				_, _ = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				n.Add(1)
				if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusForbidden {
					bad.Add(1)
					statuses.Store(resp.StatusCode, true)
				}
			}
		}(i)
	}
	for i := 0; i < 6; i++ {
		if i%2 == 0 {
			r.write("a.conf", blockRule)
		} else if err := os.Remove(filepath.Join(r.dir, "a.conf")); err != nil {
			t.Fatal(err)
		}
		if resp := r.reload(); !resp.OK {
			t.Fatalf("%+v", resp)
		}
	}
	close(stop)
	wg.Wait()
	if n.Load() == 0 || bad.Load() != 0 {
		var got []int
		statuses.Range(func(k, _ any) bool { got = append(got, k.(int)); return true })
		t.Fatalf("%d requests, %d failed with status %v", n.Load(), bad.Load(), got)
	}
}

// Two reloads at once and a hub swap between build and commit: nothing is lost.
func TestReloadRebuildsAfterAnotherSwap(t *testing.T) {
	r := newRules(t)
	r.write("a.conf", blockRule)
	done := make(chan control.Response, 1)
	go func() { done <- r.reload() }()
	// A swap of another source while the build runs bumps the generation.
	for i := 0; i < 2; i++ {
		if _, err := r.h.App.Composer.SetExceptions(""); err != nil {
			t.Fatal(err)
		}
	}
	if resp := <-done; !resp.OK {
		t.Fatalf("%+v", resp)
	}
	if got := r.status("/stop-here"); got != http.StatusForbidden {
		t.Fatalf("the reload was lost: %d", got)
	}
	if !strings.Contains(r.h.App.Repos.LocalText(), "1000001") {
		t.Fatal("no local rules")
	}
}

func TestReloadOnSignal(t *testing.T) {
	r := newRules(t)
	r.write("a.conf", blockRule)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := make(chan os.Signal, 1)
	go r.h.App.ReloadOnSignal(ctx, c)
	c <- os.Interrupt // any value: the channel has only SIGHUP on it
	deadline := time.Now().Add(30 * time.Second)
	for r.count(bodylimit.ReloadApplied) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("no reload")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := r.status("/stop-here"); got != http.StatusForbidden {
		t.Fatalf("after the signal: %d", got)
	}
}
