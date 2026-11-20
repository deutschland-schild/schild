// Package upstream subscribes to the SSE stream of a lab feed or another relay
// (GET /v0/stream) with Last-Event-ID resume, reconnects with exponential
// backoff and full jitter, and fetches bundles sent by reference.
//
// Nothing here trusts the upstream: events are only checked against the
// stream schema. Signatures are verified by clients (and by labs that follow
// peers); a relay can only delay or withhold.
package upstream

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/jsonx"
	"github.com/deutschland-schild/schild/contract/schema"
	"github.com/deutschland-schild/schild/contract/stream"
)

// HeaderName carries the subscriber's id (relay or lab id, never an address).
const HeaderName = "X-Schild-Relay"

// Event is one validated upstream event.
type Event struct {
	Upstream string // base URL of the upstream
	Event    stream.Event
	Raw      []byte // the JSON data line
}

// Subscriber follows one upstream.
type Subscriber struct {
	Base   string // e.g. https://lab-a:7444
	Client *http.Client
	// Name is sent as X-Schild-Relay so a lab can list its subscribers.
	Name    string
	OnEvent func(Event)
	OnState func(connected bool)
	// Authorize, if set, is called on every stream request before it is
	// sent. Peer labs use it to sign the subscription with Schild-Peer-Auth
	// so the upstream lab can tell them apart from relays (contracts v0.2).
	Authorize func(*http.Request) error
	Log       *slog.Logger
	MinDelay  time.Duration // default 1 s
	MaxDelay  time.Duration // default 60 s
	// IdleTimeout reconnects when nothing (not even a comment) arrives for
	// this long (default 45 s, three missed heartbeats).
	IdleTimeout time.Duration

	mu        sync.Mutex
	lastID    string
	connected bool
	since     time.Time
	events    uint64
}

// Status of a subscriber.
type Status struct {
	Base      string
	Connected bool
	Since     time.Time
	LastID    string
	Events    uint64
}

// Status returns the current status.
func (s *Subscriber) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	return Status{Base: s.Base, Connected: s.connected, Since: s.since, LastID: s.lastID, Events: s.events}
}

func (s *Subscriber) setConnected(v bool) {
	s.mu.Lock()
	changed := s.connected != v
	s.connected = v
	if v {
		s.since = time.Now()
	}
	s.mu.Unlock()
	if changed && s.OnState != nil {
		s.OnState(v)
	}
}

// Run follows the upstream until ctx ends.
func (s *Subscriber) Run(ctx context.Context) {
	minD, maxD := s.MinDelay, s.MaxDelay
	if minD <= 0 {
		minD = time.Second
	}
	if maxD <= 0 {
		maxD = 60 * time.Second
	}
	attempt := 0
	for ctx.Err() == nil {
		got, err := s.once(ctx)
		s.setConnected(false)
		if ctx.Err() != nil {
			return
		}
		if got {
			attempt = 0
		}
		if err != nil && s.Log != nil {
			s.Log.Warn("upstream stream ended", "upstream", s.Base, "err", err)
		}
		// Full jitter: uniform in [0, min(max, min*2^attempt)].
		ceil := minD << min(attempt, 16)
		if ceil > maxD || ceil <= 0 {
			ceil = maxD
		}
		d := time.Duration(rand.Int64N(int64(ceil))) + minD/2
		attempt++
		select {
		case <-ctx.Done():
			return
		case <-time.After(d):
		}
	}
}

// once runs one connection; got reports whether at least one event arrived.
func (s *Subscriber) once(ctx context.Context) (bool, error) {
	idle := s.IdleTimeout
	if idle <= 0 {
		idle = 45 * time.Second
	}
	cctx, cancel := context.WithCancel(ctx)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodGet, strings.TrimRight(s.Base, "/")+stream.Path, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Accept", stream.ContentType)
	if s.Name != "" {
		req.Header.Set(HeaderName, s.Name)
	}
	s.mu.Lock()
	if s.lastID != "" {
		req.Header.Set("Last-Event-ID", s.lastID)
	}
	s.mu.Unlock()
	if s.Authorize != nil {
		if err := s.Authorize(req); err != nil {
			return false, err
		}
	}
	resp, err := s.Client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("status %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, stream.ContentType) {
		return false, fmt.Errorf("content type %q", ct)
	}
	s.setConnected(true)
	// Watchdog: any byte resets it (comments included).
	activity := make(chan struct{}, 1)
	go func() {
		t := time.NewTimer(idle)
		defer t.Stop()
		for {
			select {
			case <-cctx.Done():
				return
			case <-activity:
				if !t.Stop() {
					select {
					case <-t.C:
					default:
					}
				}
				t.Reset(idle)
			case <-t.C:
				cancel()
				return
			}
		}
	}()
	rd := stream.NewReader(&activityReader{r: resp.Body, ch: activity})
	got := false
	for {
		f, err := rd.Next()
		if err != nil {
			if errors.Is(err, io.EOF) {
				err = errors.New("upstream closed the stream")
			}
			return got, err
		}
		ev, raw, err := Parse(f.Data)
		if err != nil {
			if s.Log != nil {
				s.Log.Warn("upstream event rejected", "upstream", s.Base, "err", err)
			}
			continue
		}
		got = true
		s.mu.Lock()
		s.lastID = rd.LastEventID()
		s.events++
		s.mu.Unlock()
		if s.OnEvent != nil {
			s.OnEvent(Event{Upstream: s.Base, Event: *ev, Raw: raw})
		}
	}
}

type activityReader struct {
	r  io.Reader
	ch chan struct{}
}

func (a *activityReader) Read(p []byte) (int, error) {
	n, err := a.r.Read(p)
	if n > 0 {
		select {
		case a.ch <- struct{}{}:
		default:
		}
	}
	return n, err
}

// Parse checks one SSE data line against the stream schema (strict JSON,
// size, schema) and decodes it. Signatures are not checked here.
func Parse(data string) (*stream.Event, []byte, error) {
	raw := []byte(data)
	if len(raw) > contract.MaxStreamEventBytes {
		return nil, nil, contract.Errf(contract.CodeOversize, "event %d bytes", len(raw))
	}
	v, err := jsonx.ParseObject(raw)
	if err != nil {
		return nil, nil, contract.Errf(contract.CodeMalformed, "%v", err)
	}
	if err := schema.Validate(schema.Stream, v); err != nil {
		return nil, nil, err
	}
	// Strictness is established above (jsonx + schema); decode with
	// encoding/json so the embedded envelopes keep their exact bytes.
	var ev stream.Event
	if err := json.Unmarshal(raw, &ev); err != nil {
		return nil, nil, contract.Errf(contract.CodeSchema, "%v", err)
	}
	return &ev, raw, nil
}

// Fetch downloads a referenced bundle envelope and checks size and sha256.
func Fetch(ctx context.Context, c *http.Client, base string, ref *stream.Ref) ([]byte, error) {
	if !strings.HasPrefix(ref.URLPath, stream.BundlePathPrefix) {
		return nil, fmt.Errorf("upstream: bad ref path %q", ref.URLPath)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(base, "/")+ref.URLPath, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("upstream: %s: status %d", ref.URLPath, resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, int64(contract.LimitsFor(contract.KindBundle).MaxEnvelopeBytes)+1))
	if err != nil {
		return nil, err
	}
	if len(b) != ref.Size {
		return nil, fmt.Errorf("upstream: %s: %d bytes, ref says %d", ref.URLPath, len(b), ref.Size)
	}
	if got := SHA256(b); got != ref.SHA256 {
		return nil, fmt.Errorf("upstream: %s: sha256 mismatch", ref.URLPath)
	}
	return b, nil
}

// SHA256 returns "sha256:<hex>".
func SHA256(b []byte) string {
	h := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(h[:])
}

// HTTPClient returns a client for upstream connections: no environment
// proxy, no redirects, TLS 1.2+, the test CA from SCHILD_TEST_CA if set, and
// no overall timeout (streams are long-lived; the idle watchdog ends dead
// ones).
func HTTPClient() (*http.Client, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if p := os.Getenv("SCHILD_TEST_CA"); p != "" {
		pem, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("SCHILD_TEST_CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("SCHILD_TEST_CA: no certificates")
		}
		tlsCfg.RootCAs = pool
	}
	tr := &http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSClientConfig:       tlsCfg,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		MaxIdleConnsPerHost:   4,
		IdleConnTimeout:       90 * time.Second,
		ForceAttemptHTTP2:     true,
	}
	return &http.Client{
		Transport:     tr,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}, nil
}
