// Package control is the local control path of a running schild gateway
// (MVP-09 addendum, D38): a unix socket under the data directory that only
// the owner of the gateway process (and root) can reach, plus an exclusive
// lock file that tells host commands whether a gateway uses the data
// directory right now.
//
//	<data>/gateway.lock          held (flock) by `schild run` while it runs
//	<data>/control/              0700
//	<data>/control/schild.sock   0600, one JSON request and one JSON answer per connection
//
// The control path is never reachable over the network, the dashboard or the
// agent API. Its operations are the dashboard access reset of
// `schild dashboard reset-password`, the sync and reset of a rule repository
// of `schild rules sync` and `schild rules reset` (D43, D46, D73) and the
// access lock of `schild lock` (D56).
package control

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// OpResetDashboard removes the dashboard users and sessions and returns a new
// one-time setup code.
const OpResetDashboard = "dashboard_reset_password"

// OpDrain takes a node of a group out of traffic and stops it (`schild
// cluster drain`, MVP-27): the readiness answer turns to 503 at once, the
// gateway stops after cluster.drain.delay_s like on SIGTERM.
const OpDrain = "cluster_drain"

// OpSetupCode returns the first-run setup code again while no dashboard
// password is set (`schild dashboard setup-code`). It changes nothing.
const OpSetupCode = "dashboard_setup_code"

// OpRulesSync loads what a rule repository's source has now (local: rules.d,
// crowdsec: the hub) and swaps the WAF without a restart.
const OpRulesSync = "rules_sync"

// OpRulesReset goes back to the rules of the image (crowdsec only).
const OpRulesReset = "rules_reset"

// OpAccessSet, OpAccessRemove and OpAccessList are `schild lock on`, `off`
// and `status` (D56): the access lock of a website, also when the
// dashboard is not reachable.
const (
	OpAccessSet    = "access_set"
	OpAccessRemove = "access_remove"
	OpAccessList   = "access_list"
)

// AccessSet is the protection `schild lock on` sets. An empty Password keeps
// the stored one.
type AccessSet struct {
	Scope       string   `json:"scope"`
	Paths       []string `json:"paths,omitempty"`
	Except      []string `json:"except,omitempty"`
	Password    string   `json:"password,omitempty"`
	Addresses   []string `json:"addresses,omitempty"`
	OwnNetworks bool     `json:"own_networks"`
	Message     string   `json:"message,omitempty"`
}

// AccessInfo is one protection in force, as `schild lock status` shows it.
type AccessInfo struct {
	Website     string   `json:"website"`
	Scope       string   `json:"scope"`
	Paths       []string `json:"paths,omitempty"`
	Except      []string `json:"except,omitempty"`
	Password    bool     `json:"password"`
	Addresses   []string `json:"addresses,omitempty"`
	OwnNetworks bool     `json:"own_networks"`
	// Maintenance: this line is the maintenance mode of the website (D98),
	// not a protection.
	Maintenance bool `json:"maintenance,omitempty"`
}

// ErrLocked means another process holds the gateway lock of the data
// directory (a running gateway or a host command that writes the store).
var ErrLocked = errors.New("control: data directory is locked by another schild process")

// ErrUnavailable means no gateway answers on the control socket.
var ErrUnavailable = errors.New("control: no gateway answers on the control path")

// Request is one control request.
type Request struct {
	Op       string `json:"op"`
	HostUser string `json:"host_user,omitempty"`
	// Website and Access: the access lock operations (D56).
	Website string     `json:"website,omitempty"`
	Access  *AccessSet `json:"access,omitempty"`
	// Repository: the rule operations (D73).
	Repository string `json:"repository,omitempty"`
}

// Response is the answer. SetupCode is only ever sent back over the socket
// to the host command that asked; the gateway neither logs nor stores it in
// plain.
type Response struct {
	OK            bool   `json:"ok"`
	Error         string `json:"error,omitempty"`
	SetupCode     string `json:"setup_code,omitempty"`
	UsersRemoved  int    `json:"users_removed"`
	SessionsEnded int    `json:"sessions_ended"`
	SetSource     string `json:"set_source,omitempty"`
	RulesLoaded   int    `json:"rules_loaded,omitempty"`
	// Unchanged: the source holds what runs, nothing was built.
	Unchanged bool `json:"unchanged,omitempty"`
	// Access: the protections in force after an access operation (D56).
	Access []AccessInfo `json:"access,omitempty"`
	// Removed: access_remove ended a protection.
	Removed bool `json:"removed,omitempty"`
}

// Handler answers one request.
type Handler func(ctx context.Context, req Request) Response

// LockPath is the gateway lock file of dataDir.
func LockPath(dataDir string) string { return filepath.Join(dataDir, "gateway.lock") }

// SocketPath is the control socket of dataDir.
func SocketPath(dataDir string) string { return filepath.Join(dataDir, "control", "schild.sock") }

// Lock takes the gateway lock of dataDir without waiting. It returns
// ErrLocked when another process holds it. The lock ends with release or
// when the process exits.
func Lock(dataDir string) (release func(), err error) {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, err
	}
	return lockFile(LockPath(dataDir))
}

const (
	// maxRequest bounds one request line. The largest is access_set with
	// every list of the access lock at its contract maximum (32 paths and
	// 16 exceptions of up to 255 bytes, 64 addresses): about 16 KiB.
	maxRequest = 64 << 10
	// maxAnswer bounds one answer line. access_list holds every protection
	// in force, up to about 16 KiB per website.
	maxAnswer = 8 << 20
	ioTimeout = 30 * time.Second
)

// Server serves the control socket.
type Server struct {
	ln   net.Listener
	path string
	h    Handler
	log  *slog.Logger
	once sync.Once
	wg   sync.WaitGroup
}

// Listen opens the control socket of dataDir and serves h until ctx ends or
// Close is called. Call it only while holding the gateway lock: a leftover
// socket file from an earlier run is removed.
func Listen(ctx context.Context, dataDir string, h Handler, log *slog.Logger) (*Server, error) {
	dir := filepath.Dir(SocketPath(dataDir))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, err
	}
	path := SocketPath(dataDir)
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		ln.Close()
		return nil, err
	}
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	s := &Server{ln: ln, path: path, h: h, log: log}
	s.wg.Add(1)
	go s.serve(ctx)
	go func() {
		<-ctx.Done()
		s.Close()
	}()
	return s, nil
}

// Path returns the socket path.
func (s *Server) Path() string { return s.path }

// Close stops accepting, waits for running requests and removes the socket.
func (s *Server) Close() {
	s.once.Do(func() {
		_ = s.ln.Close()
		s.wg.Wait()
		_ = os.Remove(s.path)
	})
}

func (s *Server) serve(ctx context.Context) {
	defer s.wg.Done()
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handle(ctx, c)
		}()
	}
}

func (s *Server) handle(ctx context.Context, c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(ioTimeout))
	line, err := bufio.NewReader(io.LimitReader(c, maxRequest)).ReadBytes('\n')
	if err != nil && !(errors.Is(err, io.EOF) && len(line) > 0) {
		return
	}
	var req Request
	var resp Response
	if err := json.Unmarshal(line, &req); err != nil {
		resp = Response{Error: "invalid request"}
	} else {
		rctx, cancel := context.WithTimeout(ctx, ioTimeout)
		resp = s.h(rctx, req)
		cancel()
	}
	// Op only: never the answer, which may hold a setup code.
	s.log.Info("control request", "op", req.Op, "ok", resp.OK)
	b, _ := json.Marshal(resp)
	_, _ = c.Write(append(b, '\n'))
}

// Call sends req to the gateway of dataDir. It returns ErrUnavailable when
// nothing listens on the socket.
func Call(ctx context.Context, dataDir string, req Request) (Response, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, "unix", SocketPath(dataDir))
	if err != nil {
		return Response{}, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(ioTimeout + 5*time.Second))
	b, _ := json.Marshal(req)
	if _, err := c.Write(append(b, '\n')); err != nil {
		return Response{}, err
	}
	line, err := bufio.NewReader(io.LimitReader(c, maxAnswer)).ReadBytes('\n')
	if err != nil && !(errors.Is(err, io.EOF) && len(line) > 0) {
		return Response{}, fmt.Errorf("control: no answer from the gateway: %w", err)
	}
	var resp Response
	if err := json.Unmarshal(line, &resp); err != nil {
		return Response{}, fmt.Errorf("control: unreadable answer: %w", err)
	}
	return resp, nil
}
