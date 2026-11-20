package dashboard

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/deutschland-schild/schild/contract/events"
	"github.com/deutschland-schild/schild/gateway/internal/eventlog"
	"github.com/deutschland-schild/schild/gateway/internal/store"
)

// Ways a dashboard access reset reached the store (events.AccessReset.Via).
const (
	ViaHostCLI     = "host_cli"
	ViaControlPath = "control_path"
)

var hostUserRE = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

// HostUser returns name when it is a valid host account name for the audit
// event (events.schema.json), else "".
func HostUser(name string) string {
	if hostUserRE.MatchString(name) {
		return name
	}
	return ""
}

func normalizeSetupCode(code string) string { return strings.ToUpper(strings.TrimSpace(code)) }

// HashSetupCode is the stored form of a one-time setup code.
func HashSetupCode(code string) []byte {
	sum := sha256.Sum256([]byte(normalizeSetupCode(code)))
	return sum[:]
}

// ResetAccess is `schild dashboard reset-password` (MVP-09 addendum, D38) on
// the store: it removes every dashboard user and session, stores the hash of
// a new one-time setup code and writes the audit event
// schild.dashboard.access_reset.v1 in the same transaction. It returns the
// code (to be shown once, never logged or stored in plain) and the written
// event. Events, settings and blocks are not touched.
func ResetAccess(ctx context.Context, st *store.Store, node, via, hostUser string, now time.Time) (string, *store.EventRow, store.AccessReset, error) {
	if via != ViaHostCLI && via != ViaControlPath {
		return "", nil, store.AccessReset{}, fmt.Errorf("dashboard: unknown reset path %q", via)
	}
	code := NewSetupCode()
	var row *store.EventRow
	res, err := st.ResetDashboardAccess(ctx, HashSetupCode(code), now, func(r store.AccessReset) (*store.EventRow, error) {
		ev := events.New(events.DashboardAccessReset, node, now, events.AccessReset{
			Via: via, UsersRemoved: r.UsersRemoved, SessionsEnded: r.SessionsEnded, HostUser: HostUser(hostUser)})
		if err := ev.Validate(); err != nil {
			return nil, fmt.Errorf("dashboard: audit event: %w", err)
		}
		var err error
		row, err = eventlog.RowOf(ev, now, eventlog.Index{Summary: "dashboard access reset (" + via + ")"})
		return row, err
	})
	if err != nil {
		return "", nil, res, err
	}
	return code, row, res, nil
}

// ResetAccess runs the reset inside the running gateway (control path): the
// store as in ResetAccess, then the new setup code replaces the one in
// memory, and the audit event goes to the live view. Sessions live in the
// store only, so every old session cookie is invalid at once.
func (s *Server) ResetAccess(ctx context.Context, hostUser string) (string, store.AccessReset, error) {
	node := ""
	if s.Config != nil {
		if c := s.Config(); c != nil {
			node = c.NodeName
		}
	}
	code, row, res, err := ResetAccess(ctx, s.St, node, ViaControlPath, hostUser, s.now())
	if err != nil {
		return "", res, err
	}
	s.setPendingSetup(HashSetupCode(code))
	if s.Events != nil {
		s.Events.Bus().Publish(row)
	}
	if s.Log != nil {
		s.Log.Warn("dashboard access reset on the host: users and sessions removed, first-run setup needs the code shown to the host command",
			"users_removed", res.UsersRemoved, "sessions_ended", res.SessionsEnded)
	}
	return code, res, nil
}

// LoadPendingSetup takes over a setup code hash left by a reset while schild
// was stopped. It reports whether one was pending.
func (s *Server) LoadPendingSetup(ctx context.Context) bool {
	h := s.St.PendingSetupHash(ctx)
	if h == nil {
		return false
	}
	s.setPendingSetup(h)
	return true
}

func (s *Server) setPendingSetup(h []byte) {
	s.setupMu.Lock()
	defer s.setupMu.Unlock()
	s.setupHash = h
	s.SetupCode = ""
}

// setupCodeOK checks a first-run setup code: the hash of a reset code when
// one is pending, else the code from the server log.
func (s *Server) setupCodeOK(code string) bool {
	s.setupMu.Lock()
	defer s.setupMu.Unlock()
	if s.setupHash != nil {
		return subtle.ConstantTimeCompare(HashSetupCode(code), s.setupHash) == 1
	}
	return s.SetupCode != "" && subtle.ConstantTimeCompare([]byte(normalizeSetupCode(code)), []byte(s.SetupCode)) == 1
}

// setupDone ends the one-time code after the first password is set.
// FirstRunCode is the setup code of the first start while it is still
// valid: empty once a password is set or a reset replaced it by a hash.
func (s *Server) FirstRunCode() string {
	s.setupMu.Lock()
	defer s.setupMu.Unlock()
	if s.setupHash != nil {
		return ""
	}
	return s.SetupCode
}

func (s *Server) setupDone(ctx context.Context) error {
	s.setupMu.Lock()
	s.setupHash = nil
	s.SetupCode = ""
	s.setupMu.Unlock()
	if err := s.St.ClearPendingSetup(ctx); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	return nil
}
