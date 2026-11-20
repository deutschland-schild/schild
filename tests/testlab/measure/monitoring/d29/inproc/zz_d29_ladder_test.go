//go:build !release

// TEST ONLY, measurement (D29 amendment, block duration per net class).
// Not part of the product: copied by run-inproc.sh into a scratch copy of
// gateway/internal/app (never into the repo's client module) and run
// there. It drives the real gate, behaviour engine, event log and store
// through apptest with a fake clock on the gate and the engine, so the
// whole ladder can be walked without waiting 8 days of real time.
//
// Env: D29_DIR (kept data directory), D29_GEO (d29 geo.mmdb), D29_OUT
// (JSON result file).
package app_test

import (
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/gateway/internal/apptest"
)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time  { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeClock) set(t time.Time) { c.mu.Lock(); c.t = t; c.mu.Unlock() }

const d29Extra = `behaviour:
  presets: [generic]
  preset_limits: "off"
  scenarios:
    waf_repeat: { mode: block }
  distributed:
    detectors:
      route_wave: { mode: "off" }
      account_wave: { mode: "off" }
      shape_wave: { mode: "off" }
      fingerprint_cluster: { mode: "off" }
      inconsistency: { mode: "off" }
`

type stepResult struct {
	NetClass    string `json:"net_class"`
	IP          string `json:"ip"`
	Offence     int    `json:"offence"`
	FakeTime    string `json:"fake_time"`
	Blocked     bool   `json:"blocked"`
	Status      int    `json:"status_after"`
	Level       int    `json:"level"`
	DurationS   int    `json:"duration_s"`
	Persisted   bool   `json:"persisted"`
	BlockNC     string `json:"block_net_class"`
	Note        string `json:"note,omitempty"`
	StatusOnEnd int    `json:"status_after_expiry"`
}

func d29Setup(t *testing.T, dir string) (*apptest.Harness, *fakeClock) {
	h := apptest.New(t, apptest.Options{Dir: dir, Standalone: true, Extra: d29Extra})
	geoSrc := os.Getenv("D29_GEO")
	b, err := os.ReadFile(geoSrc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "geo", "geo.mmdb"), b, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := h.App.Geo.Reload(); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := h.App.SetInstalledAt(ctx, time.Now().Add(-30*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	fc := &fakeClock{t: time.Now()}
	h.App.Gate.Now = fc.now
	h.App.Behaviour.Now = fc.now
	return h, fc
}

// offend sends two attack requests that match distinct CRS rules
// (waf_repeat: 2 distinct rules over 2 requests).
func offend(h *apptest.Harness, ip string) {
	h.Visit("GET", "/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E", ip, "", "")
	h.Visit("GET", "/item?id=1%27%20OR%20%271%27%3D%271%27%20--", ip, "", "")
}

func TestD29Ladder(t *testing.T) {
	dir := os.Getenv("D29_DIR")
	if dir == "" {
		t.Skip("D29_DIR not set")
	}
	_ = os.RemoveAll(dir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	h, fc := d29Setup(t, dir)
	h.Login()
	classes := []struct{ nc, ip string }{
		{"residential", "10.0.0.50"}, {"business", "10.2.0.50"}, {"education", "10.3.0.50"}, {"government", "10.4.0.50"},
		{"vpn", "10.20.0.50"}, {"proxy", "10.21.0.50"}, {"unknown", "10.25.0.50"}, {"unknown-unlisted", "172.16.0.50"},
		{"tor", "10.22.0.50"}, {"mobile", "10.23.0.50"}, {"cgnat", "10.24.0.50"}, {"cgnat-prefix", "100.64.0.50"},
		{"hosting", "10.1.0.50"},
	}
	var res []stepResult
	for _, c := range classes {
		for off := 1; off <= 6; off++ {
			offend(h, c.ip)
			st := h.Visit("GET", "/", c.ip, "", "").StatusCode
			bi, ok := h.App.Behaviour.ActiveBlock(netip.MustParseAddr(c.ip))
			r := stepResult{NetClass: c.nc, IP: c.ip, Offence: off, FakeTime: fc.now().UTC().Format(time.RFC3339), Blocked: ok, Status: st}
			if ok {
				r.Level, r.DurationS, r.Persisted, r.BlockNC = bi.Level, int(bi.Duration/time.Second), bi.Persisted, bi.NetClass
				// Just before the end: still blocked; just after: served.
				fc.set(bi.Until.Add(-2 * time.Second))
				if s := h.Visit("GET", "/", c.ip, "", "").StatusCode; s != 403 {
					r.Note = "not blocked 2 s before until"
				}
				fc.set(bi.Until.Add(time.Second))
				r.StatusOnEnd = h.Visit("GET", "/", c.ip, "", "").StatusCode
				fc.set(fc.now().Add(time.Minute)) // re-offend one minute after the end (within the 24 h memory)
			} else {
				fc.set(fc.now().Add(10 * time.Minute)) // past the 5 min cooldown
			}
			res = append(res, r)
		}
		// Ladder memory: an offence more than 24 h after the last block starts again at level 1.
		fc.set(fc.now().Add(25 * time.Hour))
		offend(h, c.ip)
		bi, ok := h.App.Behaviour.ActiveBlock(netip.MustParseAddr(c.ip))
		r := stepResult{NetClass: c.nc, IP: c.ip, Offence: 7, FakeTime: fc.now().UTC().Format(time.RFC3339), Blocked: ok, Note: "after 25 h gap"}
		if ok {
			r.Level, r.DurationS, r.Persisted, r.BlockNC = bi.Level, int(bi.Duration/time.Second), bi.Persisted, bi.NetClass
			if c.nc != "hosting" {
				fc.set(bi.Until.Add(time.Minute))
			}
		}
		res = append(res, r)
	}
	// The hosting client is now at level 1 again (after the gap). Walk it
	// up to the 7-day block once more so a kept block exists at the end,
	// and keep a residential one running (24 h, not kept).
	ip := "10.1.0.60"
	for off := 1; off <= 4; off++ {
		offend(h, ip)
		bi, _ := h.App.Behaviour.ActiveBlock(netip.MustParseAddr(ip))
		if off < 4 {
			fc.set(bi.Until.Add(time.Minute))
		}
	}
	h.Flush()
	h.App.FlushBlocks()
	b, _ := json.MarshalIndent(res, "", " ")
	if out := os.Getenv("D29_OUT"); out != "" {
		_ = os.WriteFile(out, b, 0o644)
	}
	t.Logf("fake clock at end %s", fc.now().UTC().Format(time.RFC3339))
	_ = h.Stop()
}
