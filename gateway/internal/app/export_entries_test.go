//go:build !release

package app

import (
	"time"

	contract "github.com/deutschland-schild/schild/contract/cluster"
)

// NoteSharedEntry notes an entry of a key of the store as changed by another
// node, the way the handler of a record does, without a record: what a
// record leaves behind that lost against a later one before the loop of the
// shared things came to it.
func (a *App) NoteSharedEntry(key, entry string, v []byte) {
	t := a.genericThing(key)
	a.sharedMu.Lock()
	defer a.sharedMu.Unlock()
	if a.sharedPending[t.key()] == nil {
		a.sharedPending[t.key()] = map[string]pendingEntry{}
	}
	a.sharedPending[t.key()][entry] = pendingEntry{v: v, node: "web-x"}
}

// SharedEntryRecord returns the value and the origin of the record that is
// the state of an entry of a key of the store; "" when there is none.
func (a *App) SharedEntryRecord(key, entry string) (value, origin string) {
	rec, err := a.Cluster.Get(contract.ClassSettings, contract.EntryID(key, entry))
	if err != nil || rec == nil || rec.Deleted {
		return "", ""
	}
	v, err := contract.DecodeValue(rec)
	if err != nil {
		return "", ""
	}
	b, _ := v.Bytes()
	return string(b), rec.Origin
}

// SetFirstKeysTimes shortens how long a node keeps the first keys of the
// browser check back, and returns how to undo it.
func SetFirstKeysTimes(settle, wait time.Duration) (undo func()) {
	a, b := firstKeysSettle, firstKeysWait
	firstKeysSettle, firstKeysWait = settle, wait
	return func() { firstKeysSettle, firstKeysWait = a, b }
}
