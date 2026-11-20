package eventlog

import (
	"log/slog"
	"os"
	"path/filepath"
	"sync"

	"github.com/deutschland-schild/schild/gateway/internal/ratelog"
	"github.com/deutschland-schild/schild/gateway/internal/store"
)

// NDJSONMirror appends every written local event to <dir>/events.ndjson, one
// CloudEvent per line, so the test lab's evaluator can read them
// (SCHILD_EVENTS_NDJSON_DIR).
//
// TEST LAB / EVALUATION ONLY: the file holds full visitor IPs like the local
// event store, but retention (raw_ip_days, events_days) does not rewrite
// it. Writing stops at maxBytes; release builds never enable it.
type NDJSONMirror struct {
	mu       sync.Mutex
	events   *os.File
	written  int64
	maxBytes int64
	log      *slog.Logger
}

// OpenNDJSONMirror opens (appends to) the file in dir.
func OpenNDJSONMirror(dir string, maxBytes int64, log *slog.Logger) (*NDJSONMirror, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	fh, err := os.OpenFile(filepath.Join(dir, "events.ndjson"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	m := &NDJSONMirror{events: fh, maxBytes: maxBytes, log: log}
	if st, err := fh.Stat(); err == nil {
		m.written = st.Size()
	}
	return m, nil
}

// Write implements Mirror.
func (m *NDJSONMirror) Write(rows []*store.EventRow) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range rows {
		m.line(r.Body)
	}
}

func (m *NDJSONMirror) line(body []byte) {
	if m.events == nil || m.written+int64(len(body))+1 > m.maxBytes {
		return
	}
	n, err := m.events.Write(append(append([]byte{}, body...), '\n'))
	m.written += int64(n)
	if err != nil && m.log != nil {
		ratelog.Warn(m.log, "event mirror write failed", "file", m.events.Name(), "err", err)
	}
}

// Close closes the file.
func (m *NDJSONMirror) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.events != nil {
		_ = m.events.Close()
	}
}
