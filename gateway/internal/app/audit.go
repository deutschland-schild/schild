package app

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/deutschland-schild/schild/contract/config"
	"github.com/deutschland-schild/schild/gateway/internal/auditlog"
)

// openAudit opens the audit log of this gateway (MVP-36): audit.db in the
// data directory, a file of its own outside retention.max_size_mb and the
// disk budget. It never keeps the gateway from starting because of its
// size; a file that cannot be read is kept under another name and a new log
// starts (auditlog.Open).
func (a *App) openAudit(ctx context.Context, cfg *config.Site) error {
	stream, err := auditStream(cfg.Audit.Stream)
	if err != nil {
		// The copy never holds the gateway back: said once, and the log
		// itself is written.
		a.log.Error("audit.stream cannot be opened: the audit log is written, the copy is not", "stream", cfg.Audit.Stream, "err", err)
	}
	a.auditStream = stream
	l, err := auditlog.Open(ctx, a.Store, filepath.Join(a.dataDir, auditlog.FileName), auditlog.Options{
		Node:     a.eventNode(cfg),
		KeepDays: func() int64 { return a.Config().Audit.Days() },
		Stream:   stream,
		Log:      a.log,
		Now:      a.opts.Now,
	})
	if err != nil {
		return fmt.Errorf("open audit log in %s: %w", a.dataDir, err)
	}
	a.Audit = l
	return nil
}

// auditStream opens the copy of the audit log: stdout, or a file that is
// appended to (mode 0600: an entry holds addresses and names).
func auditStream(target string) (io.Writer, error) {
	switch target {
	case "":
		return nil, nil
	case "stdout":
		return os.Stdout, nil
	}
	return os.OpenFile(target, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
}

// closeAudit closes the audit log and the file of its copy.
func (a *App) closeAudit() {
	_ = a.Audit.Close()
	if c, ok := a.auditStream.(io.Closer); ok && a.auditStream != io.Writer(os.Stdout) {
		_ = c.Close()
	}
}

// retainAudit deletes the audit entries that are past their age
// (audit.keep_days; contracts/audit.md section 6).
func (a *App) retainAudit(ctx context.Context) {
	n, err := a.Audit.Retain(ctx)
	if err != nil {
		a.log.Error("audit log retention", "err", err)
		return
	}
	if n > 0 {
		a.log.Info("audit log: entries past audit.keep_days deleted", "deleted", n)
	}
}
