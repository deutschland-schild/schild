//go:build !release

package app_test

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/gateway/internal/app"
	"github.com/deutschland-schild/schild/gateway/internal/apptest"
	"github.com/deutschland-schild/schild/gateway/internal/cluster"
	"github.com/deutschland-schild/schild/gateway/internal/reqring"
)

// TestTransferRateOfRequests measures how many requests a second one node
// takes over from another: web-1 gets requests handed straight into its
// request store at the rate SCHILD_TRANSFER_RATE names (no HTTP, no rules:
// the exchange alone), for SCHILD_TRANSFER_SECONDS (default 10), and the
// test counts what web-2 holds of them afterwards. A measurement, not a
// check: it runs only when the rate is set.
//
//	SCHILD_TRANSFER_RATE=20000 go test ./internal/app -run TestTransferRateOfRequests -v -timeout 600s
func TestTransferRateOfRequests(t *testing.T) {
	app.Parallel(t)
	rate, _ := strconv.Atoi(os.Getenv("SCHILD_TRANSFER_RATE"))
	if rate <= 0 {
		t.Skip("set SCHILD_TRANSFER_RATE to measure")
	}
	secs, _ := strconv.Atoi(os.Getenv("SCHILD_TRANSFER_SECONDS"))
	if secs <= 0 {
		secs = 10
	}
	a, b := pair(t)
	a.h.WaitFor("the nodes reach each other", func() bool { return a.h.App.Cluster.Synced() && b.h.App.Cluster.Synced() })
	time.Sleep(3 * time.Second)
	ra, rb := a.h.App.Requests, b.h.App.Requests
	a0, b0 := ra.Stats(), rb.Stats()
	uas := []string{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36", "curl/8.9.1"}
	total := rate * secs
	start := time.Now()
	for i := 0; i < total; i++ {
		// Paced in slices of a millisecond.
		if due := start.Add(time.Duration(i) * time.Second / time.Duration(rate)); i%64 == 0 {
			if d := time.Until(due); d > 0 {
				time.Sleep(d)
			}
		}
		e := reqring.Entry{T: time.Now().UnixMilli(), Client: netip.AddrFrom4([4]byte{203, 0, byte(113 + i%3), byte(i % 250)}), Site: "shop.example", Host: "shop.example",
			RawPath: "/produkte/" + strconv.Itoa(i%5000), Template: "/produkte/{n}", UA: uas[i%2], Status: 200, BytesOut: 5120, Country: [2]byte{'D', 'E'}}
		ra.Add(&e)
	}
	sent := time.Since(start)
	// Until web-2 holds no more for three seconds.
	last, since := int64(-1), time.Now()
	for time.Since(since) < 3*time.Second && time.Since(start) < time.Duration(secs+120)*time.Second {
		rb.Flush()
		if w := rb.Stats().Written; w != last {
			last, since = w, time.Now()
		}
		time.Sleep(100 * time.Millisecond)
	}
	ra.Flush()
	a1, b1 := ra.Stats(), rb.Stats()
	took := since.Sub(start)
	t.Logf("%d requests handed to web-1 in %.1f s (%.0f a second): web-1 wrote %d and dropped %d; web-2 holds %d of them (%d lacking) %.1f s after the first, dropped %d, sampled out %d; web-2 asked %d times",
		total, sent.Seconds(), float64(total)/sent.Seconds(), a1.Written-a0.Written, a1.Dropped-a0.Dropped, b1.Written-b0.Written, int64(total)-(b1.Written-b0.Written),
		took.Seconds(), b1.Dropped-b0.Dropped, b1.Sampled-b0.Sampled, b.h.App.DataAsks())
	t.Logf("web-1 sampled out %d; taken by web-2 in all (written and sampled out): %d of %d", a1.Sampled-a0.Sampled, b1.Written-b0.Written+b1.Sampled-b0.Sampled, total)
}

// TestIdleCostOfAGroup measures what a group costs with no visitor at all:
// N gateways in this process, set up by configuration, left alone for a
// while. It reports the CPU time and the allocations per node and minute.
// A measurement, not a check: it runs only when SCHILD_IDLE_NODES names the
// number of nodes (SCHILD_IDLE_SECONDS: how long, default 30).
//
//	SCHILD_IDLE_NODES=16 go test ./internal/app -run TestIdleCostOfAGroup -v -timeout 900s
func TestIdleCostOfAGroup(t *testing.T) {
	n, _ := strconv.Atoi(os.Getenv("SCHILD_IDLE_NODES"))
	if n < 2 {
		t.Skip("set SCHILD_IDLE_NODES to measure")
	}
	secs, _ := strconv.Atoi(os.Getenv("SCHILD_IDLE_SECONDS"))
	if secs <= 0 {
		secs = 30
	}
	secretFile := filepath.Join(t.TempDir(), "cluster.secret")
	secret, err := cluster.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(secretFile, []byte(secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	addrs := make([]string, n)
	for i := range addrs {
		addrs[i] = apptest.FreeAddr(t)
	}
	peers := `"` + strings.Join(addrs, `", "`) + `"`
	nodes := make([]*apptest.Harness, n)
	for i := range nodes {
		nodes[i] = apptest.New(t, apptest.Options{Extra: fmt.Sprintf("cluster: {enabled: true, listen: %q, secret_file: %q, peers: [%s]}\n", addrs[i], secretFile, peers)})
	}
	nodes[0].WaitFor("every node reaches every other", func() bool {
		for _, h := range nodes {
			if len(h.App.Cluster.Reachable()) != n-1 {
				return false
			}
		}
		return true
	})
	time.Sleep(25 * time.Second) // the first sync, its writes and the first rounds of every loop are through
	cpu := func() time.Duration {
		var ru syscall.Rusage
		_ = syscall.Getrusage(syscall.RUSAGE_SELF, &ru)
		return time.Duration(ru.Utime.Nano() + ru.Stime.Nano())
	}
	// SCHILD_IDLE_PROFILE: a CPU profile of the idle time alone.
	if p := os.Getenv("SCHILD_IDLE_PROFILE"); p != "" {
		f, err := os.Create(p)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		if err := pprof.StartCPUProfile(f); err != nil {
			t.Fatal(err)
		}
		defer pprof.StopCPUProfile()
	}
	var m0, m1 runtime.MemStats
	runtime.ReadMemStats(&m0)
	c0, t0 := cpu(), time.Now()
	time.Sleep(time.Duration(secs) * time.Second)
	c1, el := cpu(), time.Since(t0)
	runtime.ReadMemStats(&m1)
	used := float64(c1 - c0)
	t.Logf("idle group of %d nodes over %.0f s: %.2f CPU seconds per node and minute (%.2f %% of one core per node), %.1f MiB allocated per node and minute, %d allocations per node and second",
		n, el.Seconds(), used/float64(n)/el.Minutes()/float64(time.Second), 100*used/float64(n)/float64(el),
		float64(m1.TotalAlloc-m0.TotalAlloc)/float64(n)/el.Minutes()/(1<<20), int64(float64(m1.Mallocs-m0.Mallocs)/float64(n)/el.Seconds()))
}
