package waf

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"

	"github.com/corazawaf/coraza/v3/debuglog"
	"github.com/corazawaf/coraza/v3/experimental"
	"github.com/corazawaf/coraza/v3/types"
)

// ErrCancelled is the panic value that stops a cancelled evaluation. Callers
// of Instance.NewTransaction run the phases with a recover (the gate does)
// and treat the transaction as uninspected.
var ErrCancelled = errors.New("waf: evaluation cancelled")

// Cancel stops one transaction's rule evaluation at the next rule or the next
// argument a rule looks at. Coraza has no cancellation of its own and keeps
// evaluating every rule of a phase; without this an evaluation that ran out
// of its time budget kept burning CPU and memory in the background
// (MVP-19 measurement, finding 1).
//
// Mechanism: Coraza asks the transaction's debug logger for a Debug event
// before every phase, every rule, every variable and every argument it
// evaluates. Each transaction gets its own logger bound to its Cancel; once
// cancelled, that logger panics with ErrCancelled. The state is atomic, so
// cancelling from another goroutine is race free.
type Cancel struct {
	state atomic.Int32 // 0 running, 1 cancelled, 2 finished (never panics again)
	// checks counts the checkpoints passed (tests only use it).
	checks atomic.Int64
	// onCheck runs at every checkpoint (tests only).
	onCheck func(n int64)
}

const (
	cancelRunning int32 = iota
	cancelRequested
	cancelFinished
)

// Cancel requests the stop. It reports whether the evaluation was still
// running (false after Finish).
func (c *Cancel) Cancel() bool {
	if c == nil {
		return false
	}
	return c.state.CompareAndSwap(cancelRunning, cancelRequested)
}

// Finish disarms the checkpoints. Call it once the goroutine that evaluated
// the transaction has stopped and before Close (Coraza logs from Close).
func (c *Cancel) Finish() {
	if c != nil {
		c.state.Store(cancelFinished)
	}
}

// Cancelled reports whether Cancel was called before Finish.
func (c *Cancel) Cancelled() bool { return c != nil && c.state.Load() == cancelRequested }

// Checks returns the number of checkpoints passed so far.
func (c *Cancel) Checks() int64 {
	if c == nil {
		return 0
	}
	return c.checks.Load()
}

func (c *Cancel) check() {
	if c == nil || c.state.Load() == cancelFinished {
		return
	}
	n := c.checks.Add(1)
	if c.onCheck != nil {
		c.onCheck(n)
	}
	if c.state.Load() == cancelRequested {
		panic(ErrCancelled)
	}
}

// IsCancelled reports whether a recovered panic value is the cancellation.
func IsCancelled(v any) bool {
	err, ok := v.(error)
	return ok && errors.Is(err, ErrCancelled)
}

// cancelRegistry hands a Cancel to the logger Coraza derives for a new
// transaction (Coraza calls Logger.With(tx_id) inside NewTransaction).
type cancelRegistry struct{ m sync.Map } // tx id -> *Cancel

// NewTransaction starts a transaction whose evaluation can be cancelled.
func (inst *Instance) NewTransaction() (types.Transaction, *Cancel) {
	return inst.newTransaction(nil)
}

func (inst *Instance) newTransaction(onCheck func(int64)) (types.Transaction, *Cancel) {
	c := &Cancel{onCheck: onCheck}
	wo, ok := inst.WAF.(experimental.WAFWithOptions)
	if !ok || inst.cancels == nil {
		return inst.WAF.NewTransaction(), nil
	}
	var b [12]byte
	_, _ = rand.Read(b[:])
	id := "sx" + hex.EncodeToString(b[:])
	inst.cancels.m.Store(id, c)
	tx := wo.NewTransactionWithOptions(experimental.Options{ID: id})
	inst.cancels.m.Delete(id)
	return tx, c
}

// cancelLogger is the WAF's debug logger. It forwards to inner (no output
// unless SecDebugLog is configured) and, when bound to a transaction,
// checks that transaction's Cancel before every Debug and Trace event.
type cancelLogger struct {
	inner debuglog.Logger
	reg   *cancelRegistry
	c     *Cancel
}

func (l cancelLogger) WithOutput(w io.Writer) debuglog.Logger {
	l.inner = l.inner.WithOutput(w)
	return l
}

func (l cancelLogger) WithLevel(lvl debuglog.Level) debuglog.Logger {
	l.inner = l.inner.WithLevel(lvl)
	return l
}

func (l cancelLogger) With(fs ...debuglog.ContextField) debuglog.Logger {
	l.inner = l.inner.With(fs...)
	if l.c == nil && l.reg != nil {
		for _, f := range fs {
			fc := &fieldCapture{}
			f(fc)
			if fc.key == "tx_id" {
				if v, ok := l.reg.m.Load(fc.val); ok {
					l.c = v.(*Cancel)
				}
			}
		}
	}
	return l
}

func (l cancelLogger) Trace() debuglog.Event { l.c.check(); return l.inner.Trace() }
func (l cancelLogger) Debug() debuglog.Event { l.c.check(); return l.inner.Debug() }
func (l cancelLogger) Info() debuglog.Event  { return l.inner.Info() }
func (l cancelLogger) Warn() debuglog.Event  { return l.inner.Warn() }
func (l cancelLogger) Error() debuglog.Event { return l.inner.Error() }

// fieldCapture reads one context field (key and string value).
type fieldCapture struct{ key, val string }

func (f *fieldCapture) Msg(string) {}
func (f *fieldCapture) Str(k, v string) debuglog.Event {
	f.key, f.val = k, v
	return f
}
func (f *fieldCapture) Err(error) debuglog.Event                     { return f }
func (f *fieldCapture) Bool(string, bool) debuglog.Event             { return f }
func (f *fieldCapture) Int(string, int) debuglog.Event               { return f }
func (f *fieldCapture) Uint(string, uint) debuglog.Event             { return f }
func (f *fieldCapture) Stringer(string, fmt.Stringer) debuglog.Event { return f }
func (f *fieldCapture) IsEnabled() bool                              { return true }
