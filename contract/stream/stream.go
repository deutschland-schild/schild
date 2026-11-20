// Package stream implements the relay stream of contracts/stream.md: SSE
// framing (WHATWG HTML §9.2), event ids for Last-Event-ID resume, event
// priorities and freeze detection via signed checkpoints.
package stream

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/jsonx"
)

// Event types on the relay stream.
const (
	TypeCheckpoint = "schild.dist.checkpoint.v1"
	TypeBundle     = "schild.dist.bundle.v1"
	TypeWithdrawal = "schild.dist.withdrawal.v1"
	TypeHeartbeat  = "schild.dist.heartbeat.v1"
)

// Timing and buffering of the stream (concept 20 §3.4/3.5).
const (
	HeartbeatInterval  = 15 * time.Second  // relay -> client, carries the newest checkpoint
	CheckpointInterval = 60 * time.Second  // lab re-signs its checkpoint
	FreezeAfter        = 180 * time.Second // no fresher checkpoint: relay is frozen, switch
	CrossCheckInterval = 15 * time.Minute  // fetch the checkpoint from a second source
	ClientBuffer       = 256               // events buffered per client before disconnect
	RetryMS            = 3000              // SSE retry hint
	ContentType        = "text/event-stream"
	Path               = "/v0/stream"
	BundlePathPrefix   = "/v0/bundles/"
	CheckpointPath     = "/v0/checkpoint"
)

// Priority orders events: lower is sent first (withdrawal > bundle > checkpoint > heartbeat).
func Priority(eventType string) int {
	switch eventType {
	case TypeWithdrawal:
		return 0
	case TypeBundle:
		return 1
	case TypeCheckpoint:
		return 2
	case TypeHeartbeat:
		return 3
	}
	return 9
}

// Event is one stream event (the SSE data line).
type Event struct {
	Type       string          `json:"type"`
	ID         string          `json:"id"`
	Envelope   json.RawMessage `json:"envelope,omitempty"`
	Ref        *Ref            `json:"ref,omitempty"`
	Relay      *Relay          `json:"relay,omitempty"`
	Checkpoint json.RawMessage `json:"checkpoint,omitempty"`
}

// Ref points at a bundle too large to inline.
type Ref struct {
	BundleID string `json:"bundle_id"`
	Version  uint64 `json:"version"`
	URLPath  string `json:"url_path"`
	SHA256   string `json:"sha256"`
	Size     int    `json:"size"`
}

// BundleURLPath returns the static path of a bundle envelope on relays and labs.
func BundleURLPath(bundleID string, version uint64) string {
	return fmt.Sprintf("%s%s/%d.json", BundlePathPrefix, bundleID, version)
}

// Relay identifies the sending relay in heartbeats (informational, unsigned).
type Relay struct {
	ID   string `json:"id"`
	Time string `json:"time"`
}

// FormatID renders "<epoch>-<seq>". The epoch is random per relay start, so
// a Last-Event-ID from another relay or an earlier run is unknown and leads
// to a full resync (stream.md).
func FormatID(epoch string, seq uint64) string { return epoch + "-" + strconv.FormatUint(seq, 10) }

// ParseID splits an event id.
func ParseID(id string) (epoch string, seq uint64, err error) {
	i := strings.LastIndexByte(id, '-')
	if i <= 0 || i > 16 || i == len(id)-1 || len(id)-i-1 > 19 {
		return "", 0, fmt.Errorf("stream: bad event id %q", id)
	}
	epoch = id[:i]
	for _, c := range epoch {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9') {
			return "", 0, fmt.Errorf("stream: bad epoch in %q", id)
		}
	}
	seq, err = strconv.ParseUint(id[i+1:], 10, 64)
	if err != nil {
		return "", 0, fmt.Errorf("stream: bad seq in %q", id)
	}
	return epoch, seq, nil
}

// Marshal renders the event as one JSON line.
func (e *Event) Marshal() ([]byte, error) {
	b, err := jsonx.Marshal(e)
	if err != nil {
		return nil, err
	}
	if len(b) > contract.MaxStreamEventBytes {
		return nil, contract.Errf(contract.CodeOversize, "stream event %d bytes", len(b))
	}
	return b, nil
}

// WriteEvent writes one SSE frame: id, event and a single data line.
func WriteEvent(w io.Writer, e *Event) error {
	b, err := e.Marshal()
	if err != nil {
		return err
	}
	if strings.ContainsAny(e.ID, "\r\n\x00") || strings.ContainsAny(e.Type, "\r\n") {
		return errors.New("stream: id/type with line breaks")
	}
	_, err = fmt.Fprintf(w, "id: %s\nevent: %s\ndata: %s\n\n", e.ID, e.Type, b)
	return err
}

// WriteRetry writes the SSE retry hint.
func WriteRetry(w io.Writer, ms int) error {
	_, err := fmt.Fprintf(w, "retry: %d\n\n", ms)
	return err
}

// WriteComment writes an SSE comment (keep-alive for proxies).
func WriteComment(w io.Writer, text string) error {
	_, err := fmt.Fprintf(w, ": %s\n\n", strings.ReplaceAll(text, "\n", " "))
	return err
}

// Frame is one dispatched SSE message.
type Frame struct {
	ID    string // last event id after this frame (may be inherited)
	Event string
	Data  string
	Retry int // -1 if absent
}

// Reader parses an SSE stream.
type Reader struct {
	sc     *bufio.Scanner
	lastID string
}

// NewReader returns a reader with a line limit of MaxStreamEventBytes+64.
func NewReader(r io.Reader) *Reader {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 4096), contract.MaxStreamEventBytes+64)
	sc.Split(scanLines)
	return &Reader{sc: sc}
}

// scanLines splits on \n, \r\n or \r.
func scanLines(data []byte, atEOF bool) (int, []byte, error) {
	for i, c := range data {
		if c == '\n' {
			return i + 1, data[:i], nil
		}
		if c == '\r' {
			if i+1 < len(data) {
				if data[i+1] == '\n' {
					return i + 2, data[:i], nil
				}
				return i + 1, data[:i], nil
			}
			if atEOF {
				return i + 1, data[:i], nil
			}
			return 0, nil, nil // need more data to decide on \r\n
		}
	}
	if atEOF && len(data) > 0 {
		return len(data), data, nil
	}
	return 0, nil, nil
}

// Next returns the next dispatched frame, or io.EOF. The data of one frame
// is bounded by MaxStreamEventBytes (one event is one data line, stream.md):
// a relay that sends data lines without ever ending the frame gets an
// oversize error instead of growing the reader's memory. The error ends the
// stream; the caller reconnects or switches the relay.
func (r *Reader) Next() (*Frame, error) {
	var data []string
	hasData := false
	size := 0 // bytes of the joined data plus one
	event := ""
	retry := -1
	for r.sc.Scan() {
		line := r.sc.Text()
		if line == "" {
			joined := strings.Join(data, "\n")
			if !hasData || joined == "" {
				// WHATWG: an empty data buffer dispatches nothing.
				data, hasData, event, retry, size = nil, false, "", -1, 0
				continue
			}
			return &Frame{ID: r.lastID, Event: event, Data: joined, Retry: retry}, nil
		}
		if strings.HasPrefix(line, ":") {
			continue
		}
		field, value, _ := strings.Cut(line, ":")
		value = strings.TrimPrefix(value, " ")
		switch field {
		case "event":
			event = value
		case "data":
			// Every line counts at least one byte (its line feed in the
			// joined data), so empty data lines are bounded as well.
			if size += len(value) + 1; size > contract.MaxStreamEventBytes+1 {
				return nil, contract.Errf(contract.CodeOversize, "stream frame data above %d bytes", contract.MaxStreamEventBytes)
			}
			data = append(data, value)
			hasData = true
		case "id":
			if !strings.ContainsRune(value, 0) {
				r.lastID = value
			}
		case "retry":
			if n, err := strconv.Atoi(value); err == nil && n >= 0 {
				retry = n
			}
		}
	}
	if err := r.sc.Err(); err != nil {
		return nil, err
	}
	return nil, io.EOF
}

// LastEventID returns the id to send as Last-Event-ID on reconnect.
func (r *Reader) LastEventID() string { return r.lastID }

// Freshness detects a frozen relay: the newest verified checkpoint must not
// be older than FreezeAfter.
type Freshness struct {
	mu     sync.Mutex
	newest time.Time
	after  time.Duration
}

// NewFreshness returns a tracker; after <= 0 uses FreezeAfter.
func NewFreshness(after time.Duration) *Freshness {
	if after <= 0 {
		after = FreezeAfter
	}
	return &Freshness{after: after}
}

// Observe records the issued_at of a verified checkpoint.
func (f *Freshness) Observe(issuedAt time.Time) {
	f.mu.Lock()
	if issuedAt.After(f.newest) {
		f.newest = issuedAt
	}
	f.mu.Unlock()
}

// Frozen reports whether no fresh checkpoint arrived in time.
func (f *Freshness) Frozen(now time.Time) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.newest.IsZero() || now.Sub(f.newest) > f.after
}
