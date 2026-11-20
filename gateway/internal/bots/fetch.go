package bots

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/deutschland-schild/schild/contract/bots"
	"github.com/deutschland-schild/schild/contract/msg"
	"github.com/deutschland-schild/schild/gateway/internal/bots/rangesrc"
)

// Range fetch (bots.ranges_fetch, default on since D67): once a day the
// engine downloads the same lists the release snapshot was made from
// (rangesrc.Sources, each capped at rangesrc.MaxRangeBytes), checks the resulting
// catalogue with contract/bots.Parse and swaps in the new range tables
// (RangeInfo.source "fetch"). A list that fails keeps the last good
// snapshot. Nothing is written to disk; a restart starts from the release
// snapshot again.

const fetchUA = "schild-ranges/0.1"

func (e *Engine) fetchLoop(ctx context.Context) {
	// First fetch shortly after the start, then every day.
	t := time.NewTimer(time.Minute)
	if e.every < time.Minute {
		t.Reset(0)
	}
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		_ = e.FetchRanges(ctx)
		t.Reset(e.every)
	}
}

// FetchRanges fetches every range source the catalogue uses once and swaps
// in the sets that passed the contract check. It returns the first error
// (the other sources are still applied).
func (e *Engine) FetchRanges(ctx context.Context) error {
	now := e.now().UTC()
	old := e.state.Load()
	// Work on a copy of the catalogue ranges so the contract check sees a
	// complete catalogue.
	c := *e.cat
	c.Ranges = append([]bots.RangeSet(nil), e.cat.Ranges...)
	for i := range c.Ranges {
		t := &old.sets[i]
		c.Ranges[i].FetchedAt = msg.FormatTime(t.fetched)
	}
	got := map[int]bool{}
	var first error
	for i := range c.Ranges {
		src, ok := e.sourceOf(c.Ranges[i].ID)
		if !ok {
			continue
		}
		prefixes, err := rangesrc.FetchSource(ctx, e.client, src, fetchUA)
		if err != nil {
			if first == nil {
				first = err
			}
			continue
		}
		c.Ranges[i].Prefixes = prefixes
		c.Ranges[i].FetchedAt = msg.FormatTime(now)
		got[i] = true
	}
	if len(got) == 0 {
		return first
	}
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(&c); err != nil {
		return err
	}
	if _, err := bots.Parse(buf.Bytes()); err != nil {
		return fmt.Errorf("fetched ranges fail the contract check: %w", err)
	}
	st := &rangeState{sets: append([]rangeTable(nil), old.sets...)}
	for i := range got {
		t, err := buildTable(&c.Ranges[i], "fetch")
		if err != nil {
			return err
		}
		st.sets[i] = t
	}
	e.state.Store(st)
	return first
}

func (e *Engine) sourceOf(id string) (rangesrc.Source, bool) {
	for _, s := range e.sources {
		if s.ID == id {
			return s, true
		}
	}
	return rangesrc.Source{}, false
}
