//go:build !release

package cluster

import "encoding/json"

// Take hands records to the node as the answer of a member that is asked
// for everything does (Resync): a test sets the order in which records
// arrive with it. A release build has no such hook.
func (n *Node) Take(raws ...json.RawMessage) (applied int, err error) {
	n.retake.Add(1)
	defer n.retake.Add(-1)
	return n.take(raws, nil)
}
