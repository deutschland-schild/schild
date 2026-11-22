package app

import (
	"context"
	"time"

	"github.com/deutschland-schild/schild/gateway/internal/hub"
	"github.com/deutschland-schild/schild/gateway/internal/reqring"
)

// ConfigHash is the config version the agent API shows (tests).
func (a *App) ConfigHash() string {
	if p := a.configHash.Load(); p != nil {
		return *p
	}
	return ""
}

// GroupConfigVersion is the config version a node tells its group (tests).
var GroupConfigVersion = groupConfigVersion

// TakesForeignRequest reports whether this node would store a request a
// member of its group hands over (tests).
func (a *App) TakesForeignRequest(e *reqring.Entry) bool {
	return a.groupData != nil && a.groupData.takesRequest(e, time.Now())
}

// RequestsMissed counts requests of other nodes that were gone from their
// log before this node asked (tests).
func (a *App) RequestsMissed() uint64 {
	if a.groupData == nil {
		return 0
	}
	return a.groupData.requestsMissed.Load()
}

// SetHubShare puts another hub source in for the group (tests).
func (a *App) SetHubShare(h interface {
	SharedIndex() (hub.IndexInfo, []byte, bool)
	WantsIndex(hub.IndexInfo) bool
	TakeIndex(ctx context.Context, in hub.IndexInfo, gz []byte) error
}) {
	var x hubIndex = h
	a.hubShare.Store(&x)
}

// AgeHumanCheckKeys sets when the keys of the browser check were rotated
// (tests of the rotation).
func (a *App) AgeHumanCheckKeys(ctx context.Context, at time.Time) error {
	a.humanCheckMu.Lock()
	defer a.humanCheckMu.Unlock()
	next := a.HumanCheck.State().Clone()
	next.KeysRotatedAt = at
	if err := a.storeHumanCheck(ctx, next); err != nil {
		return err
	}
	a.HumanCheck.Store(next)
	return nil
}
