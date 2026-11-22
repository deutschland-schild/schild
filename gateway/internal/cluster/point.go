package cluster

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"sort"
	"time"
)

// A point names what a node holds, so two nodes can tell whether they speak
// of the same state before they compare what is in force on them (the state
// fingerprint of the app). Two nodes that look at different moments while a
// change travels hold different records; their hashes of the state differ
// then, and that says nothing. Points are no secret and say nothing about
// content: they are hashes of record ids, origins and sequence numbers.

// VectorPoint is the point of everything the node has seen: a hash of its
// sync vector. Nodes with equal vectors saw the same records.
func (n *Node) VectorPoint() (string, error) {
	vec, err := n.vectorNow()
	if err != nil {
		return "", err
	}
	origins := make([]string, 0, len(vec))
	for o := range vec {
		origins = append(origins, o)
	}
	sort.Strings(origins)
	h := sha256.New()
	var b [8]byte
	for _, o := range origins {
		h.Write([]byte(o))
		binary.BigEndian.PutUint64(b[:], vec[o])
		h.Write(b[:])
	}
	return hex.EncodeToString(h.Sum(nil)[:6]), nil
}

// ClassPoint is the point of one class: a hash over the records that are
// its state at now (each as id, origin and sequence number; tombstones
// count, records that ended do not). Two nodes with the same point of a
// class hold the same records of it.
func (n *Node) ClassPoint(class string, now time.Time) (string, error) {
	rows, err := n.db.Query(`SELECT id, origin, seq FROM records WHERE class = ? AND state = ? AND (expires_ms = 0 OR expires_ms > ?) ORDER BY id`,
		class, stateWinner, now.UnixMilli())
	if err != nil {
		return "", err
	}
	defer rows.Close()
	h := sha256.New()
	var b [8]byte
	for rows.Next() {
		var id, origin string
		var seq int64
		if err := rows.Scan(&id, &origin, &seq); err != nil {
			return "", err
		}
		h.Write([]byte(id))
		h.Write([]byte{0})
		h.Write([]byte(origin))
		binary.BigEndian.PutUint64(b[:], uint64(seq))
		h.Write(b[:])
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)[:6]), nil
}

// Taking reports whether the node is taking records right now: they are in
// its store, and the handlers that tell the app have not all run. What the
// app holds is then not yet what the records say.
func (n *Node) Taking() bool { return n.taking.Load() > 0 }
