package app

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/deutschland-schild/schild/contract/events"
	"github.com/deutschland-schild/schild/gateway/internal/ratelog"
	"github.com/deutschland-schild/schild/gateway/internal/store"
)

// D29 amendment (2026-10-29): behaviour blocks over 24 h are kept in
// schild.db and restored at start. One writer goroutine keeps the order of
// puts and deletes; the engine never waits for the disk.

type blockOp struct {
	put *events.ActiveBlock
	// taken: the block of put is one this node took from its group.
	taken bool
	del   string
	flush chan struct{}
	// ended: the incident of a block the operator ended early is stored
	// as unblocked at endedAt. foreign: another node wrote the incident,
	// so the change is no news of this node (store.Foreign).
	ended   string
	endedAt time.Time
	foreign bool
}

func (a *App) startBlockWriter() {
	a.blockOps = make(chan blockOp, 4096)
	go func() {
		for op := range a.blockOps {
			if op.flush != nil {
				close(op.flush)
				continue
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			if op.foreign {
				ctx = store.Foreign(ctx)
			}
			var err error
			switch {
			case op.ended != "":
				if err = a.Store.MarkUnblocked(ctx, op.ended, op.endedAt, ""); errors.Is(err, store.ErrNotFound) {
					err = nil // already unblocked, deleted or never stored
				}
			case op.put != nil && op.taken:
				err = a.Store.PutTakenBlock(ctx, *op.put)
			case op.put != nil:
				err = a.Store.PutBlock(ctx, *op.put)
			default:
				err = a.Store.DeleteBlock(ctx, op.del)
			}
			cancel()
			if err != nil {
				ratelog.Error(a.log, "kept behaviour block not written", "err", err)
			}
		}
	}()
	a.Behaviour.Sink.Persist = func(ab events.ActiveBlock) { a.queueBlockOp(blockOp{put: &ab}) }
	a.Behaviour.Sink.PersistTaken = func(ab events.ActiveBlock) { a.queueBlockOp(blockOp{put: &ab, taken: true}) }
	a.Behaviour.Sink.Unpersist = func(k string) { a.queueBlockOp(blockOp{del: k}) }
	a.Behaviour.Sink.Ended = func(incident string, at time.Time) { a.queueBlockOp(blockOp{ended: incident, endedAt: at}) }
}

func (a *App) queueBlockOp(op blockOp) {
	select {
	case a.blockOps <- op:
	default:
		ratelog.Warn(a.log, "kept behaviour block queue full, write skipped (the block still runs in memory)")
	}
}

// FlushBlocks waits until every queued kept-block write is done (tests,
// shutdown).
func (a *App) FlushBlocks() {
	if a.blockOps == nil {
		return
	}
	done := make(chan struct{})
	a.blockOps <- blockOp{flush: done}
	<-done
}

// restoreBlocks reloads the kept blocks at start; ended and allowlisted
// ones are deleted.
func (a *App) restoreBlocks(ctx context.Context) {
	// A gateway that is in no group decided every block it keeps that does
	// not say who did (a row of a build before the mark); what it took from
	// a group it was in stays taken. A node of a group decides on the rows
	// that do not say once it read the records of its group
	// (resolveKeptBlocks).
	if !a.Config().Cluster.Enabled {
		if err := a.Store.OwnKeptBlocks(ctx); err != nil {
			a.log.Warn("kept behaviour blocks not marked as this gateway's own; should it join a group, it does not hand them over", "err", err)
		}
	}
	rows, err := a.Store.ListBlocks(ctx)
	if err != nil {
		a.log.Error("kept behaviour blocks not loaded", "err", err)
		return
	}
	now := time.Now()
	// The net class of a row sets its ladder (7 days only for hosting); it
	// is not trusted as stored but derived again from the geo data. A row
	// whose class no longer matches is dropped (D36 fix round 2,
	// re-measurement C: a residential address stored as hosting came back).
	keep := rows[:0:0]
	var drop []string
	for _, r := range rows {
		ip, err := netip.ParseAddr(r.ClientKey)
		if err != nil || a.Geo == nil || a.Geo.Lookup(ip).NetClass != r.NetClass {
			drop = append(drop, r.ClientKey)
			continue
		}
		keep = append(keep, r)
	}
	n, more := a.Behaviour.RestoreBlocks(keep, func(ip netip.Addr) bool { lvl, _ := a.Allow.Match(ip, now); return lvl != "" })
	drop = append(drop, more...)
	// Which of them another node decided: a node of a group writes only its
	// own decisions to its group. When the marks cannot be read, no kept
	// block counts as its own.
	taken, err := a.Store.TakenBlocks(ctx)
	if err != nil {
		a.log.Error("kept behaviour blocks: the marks of own decisions are not read; no kept block is handed to a group as this node's own", "err", err)
		taken = taken[:0]
		for _, r := range keep {
			taken = append(taken, r.ClientKey)
		}
	}
	a.Behaviour.TakenBlocks(taken)
	if d := len(rows) - len(keep); d > 0 {
		a.log.Info("kept behaviour blocks dropped: net class does not match the geo data", "blocks", d)
	}
	for _, k := range drop {
		_ = a.Store.DeleteBlock(ctx, k)
	}
	if n > 0 {
		a.log.Info("kept behaviour blocks restored", "blocks", n)
	}
}

// dropAllowlistedBlocks ends running blocks of addresses on the allowlist:
// the allowlist always wins, also over a kept 7-day block.
func (a *App) dropAllowlistedBlocks() {
	if a.Behaviour == nil || a.Allow == nil {
		return
	}
	now := time.Now()
	if n := a.Behaviour.DropBlocks(func(ip netip.Addr) bool { lvl, _ := a.Allow.Match(ip, now); return lvl != "" }); n > 0 {
		a.log.Info("behaviour blocks of allowlisted addresses ended", "blocks", n)
	}
}
