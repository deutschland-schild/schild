// Package nftfw is `schild firewall run` (D87, the first step of MVP-15): a
// small process with CAP_NET_ADMIN, the same image or binary as the gateway,
// that asks the gateway's agent API for the blocks that run
// (syncAgentFirewall, a long poll with a token of scope firewall:sync) and
// keeps the nftables table "inet schild" in step: every blocked client's
// traffic to the ports 80 and 443 is dropped before it reaches schild or a
// container, until the block ends. Every element carries its remaining time
// as the kernel timeout, so no block outlives its end, also when this process
// dies. A clean stop removes the table. Like a CrowdSec firewall bouncer.
package nftfw

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/deutschland-schild/schild/contract/firewall"
)

// Element is one client with the time its block has left.
type Element struct {
	Client  string
	Timeout time.Duration
}

// Held is one client the table holds, with the time it has left.
type Held struct {
	Client  string
	Expires time.Duration
}

// Backend is the table: the kernel, or a fake in tests.
type Backend interface {
	Ensure() error
	Replace([]Element) error
	Held() ([]Held, error)
	Remove() error
}

// Config of a run.
type Config struct {
	// API is the agent API base, e.g. http://127.0.0.1:8789/agent/v0.
	API     string
	Token   string
	Version string
	Log     *slog.Logger
	// Client is the HTTP client (default: 70 s timeout, above firewall.Wait).
	Client *http.Client
	// Retry is the pause after a failed call (default 5 s).
	Retry time.Duration
	// Now is the clock (default time.Now).
	Now func() time.Time
}

// Elements turns the blocks that run at now into elements with timeouts.
func Elements(blocks []firewall.Block, now time.Time) []Element {
	out := make([]Element, 0, len(blocks))
	for _, b := range blocks {
		if left := b.Until.Sub(now); left >= time.Second {
			out = append(out, Element{Client: b.Client, Timeout: left})
		}
	}
	return out
}

// Run builds the table and keeps it in step until ctx ends; then it removes
// the table (a clean stop leaves nothing behind).
func Run(ctx context.Context, b Backend, cfg Config) error {
	if cfg.Client == nil {
		cfg.Client = &http.Client{Timeout: firewall.Wait + 20*time.Second}
	}
	if cfg.Retry <= 0 {
		cfg.Retry = 5 * time.Second
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.DiscardHandler)
	}
	if err := b.Ensure(); err != nil {
		return fmt.Errorf("build table %s: %w", firewall.Table, err)
	}
	cfg.Log.Info("firewall: table ready, asking the gateway for blocks", "table", firewall.Table, "ports", firewall.Ports, "api", cfg.API)
	defer func() {
		if err := b.Remove(); err != nil {
			cfg.Log.Error("firewall: table not removed at stop", "err", err)
			return
		}
		cfg.Log.Info("firewall: stopped, table removed", "table", firewall.Table)
	}()
	req := firewall.SyncRequest{Table: firewall.Table, Version: cfg.Version}
	failing := false
	for ctx.Err() == nil {
		start := cfg.Now()
		ans, err := call(ctx, cfg, req)
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			if !failing {
				cfg.Log.Warn("firewall: gateway not reachable, the table keeps what it holds (each block ends by itself)", "err", err)
			}
			failing = true
			sleep(ctx, cfg.Retry)
			continue
		}
		if failing {
			cfg.Log.Info("firewall: gateway reachable again")
			failing = false
		}
		if ans.Revision != req.Applied {
			req.Error = ""
			if err := apply(b, ans, cfg.Now()); err != nil {
				req.Error = firewall.OneLine(err.Error(), 300)
				cfg.Log.Error("firewall: blocks not applied", "err", err)
			} else {
				req.Applied = ans.Revision
				cfg.Log.Info("firewall: blocks applied", "blocks", len(ans.Blocks), "revision", ans.Revision)
			}
		}
		if held, err := b.Held(); err == nil {
			req.Held = len(held)
		}
		// A quick answer means a change: never more than one call a second.
		if d := cfg.Now().Sub(start); d < time.Second {
			sleep(ctx, time.Second-d)
		}
	}
	return nil
}

// apply puts the blocks into the table; a table that went away (a reload of
// the firewall) is built again once.
func apply(b Backend, ans firewall.SyncResponse, now time.Time) error {
	els := Elements(ans.Blocks, now)
	err := b.Replace(els)
	if err == nil {
		return nil
	}
	if e := b.Ensure(); e != nil {
		return errors.Join(err, e)
	}
	return b.Replace(els)
}

func call(ctx context.Context, cfg Config, req firewall.SyncRequest) (firewall.SyncResponse, error) {
	var ans firewall.SyncResponse
	body, _ := json.Marshal(req)
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.API+"/firewall/sync", bytes.NewReader(body))
	if err != nil {
		return ans, err
	}
	r.Header.Set("Authorization", "Bearer "+cfg.Token)
	r.Header.Set("Content-Type", "application/json")
	res, err := cfg.Client.Do(r)
	if err != nil {
		return ans, err
	}
	defer res.Body.Close()
	data, err := io.ReadAll(io.LimitReader(res.Body, 2<<20))
	if err != nil {
		return ans, err
	}
	if res.StatusCode != http.StatusOK {
		var p struct {
			Code   string `json:"code"`
			Detail string `json:"detail"`
		}
		_ = json.Unmarshal(data, &p)
		return ans, fmt.Errorf("agent API answered %d %s: %s", res.StatusCode, p.Code, firewall.OneLine(p.Detail, 200))
	}
	if err := json.Unmarshal(data, &ans); err != nil {
		return ans, fmt.Errorf("agent API answer: %w", err)
	}
	if !ans.Valid() {
		return firewall.SyncResponse{}, errors.New("agent API answer names something that is no client")
	}
	return ans, nil
}

func sleep(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}
