// Package transport makes the client -> lab path pluggable (decision E1):
// HTTPS with a per-site key now, OHTTP (RFC 9458) from v1. The network is
// never in the request path: callers run transports from a background queue,
// never while a visitor waits.
package transport

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/jsonx"
	"github.com/deutschland-schild/schild/contract/msg"
)

// SubmitPath is the lab ingest endpoint.
const SubmitPath = "/v0/submit"

// Header names.
const (
	HeaderAuthorization = "Authorization"
	ContentTypeJSON     = "application/json"
)

// MaxRetryAfter caps the Retry-After header of an answer without an ack. It
// equals the largest control.retry_after_ms of a signed ack (ack.schema.json),
// so an unsigned header never delays a lab longer than a signed ack could.
const MaxRetryAfter = 10 * time.Minute

// Lab is a destination.
type Lab struct {
	ID       string
	Endpoint string // https://host:port
}

// Response is the raw lab answer. The caller verifies AckEnvelope with
// verify.Signed(contract.KindAck, ...) and ExpectedInReplyTo = request_id.
type Response struct {
	Status      int
	AckEnvelope []byte
	RetryAfter  time.Duration // from Retry-After when the lab sent no ack
}

// Transport delivers one submission to one lab.
type Transport interface {
	Name() string
	Submit(ctx context.Context, lab Lab, sub *msg.Submission, authorization string) (*Response, error)
}

// Errors classify failures for the client's retry logic.
var (
	ErrRefused   = errors.New("transport: connection refused")
	ErrTimeout   = errors.New("transport: timeout")
	ErrNotV1Yet  = errors.New("transport: OHTTP is not implemented before v1")
	ErrBadStatus = errors.New("transport: unexpected status")
)

// HTTPS is the prototype transport: POST /v0/submit with a JSON body.
type HTTPS struct {
	Client *http.Client
}

// NewHTTPS returns a transport with conservative timeouts. tlsConfig may be
// set on the returned client's transport by the caller (test CA in the lab).
func NewHTTPS(timeout time.Duration) *HTTPS {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &HTTPS{Client: &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy:                 nil, // never through an environment proxy: payloads go only to configured labs
			MaxIdleConnsPerHost:   4,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   timeout,
			ResponseHeaderTimeout: timeout,
			ForceAttemptHTTP2:     true,
			TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

// Name implements Transport.
func (*HTTPS) Name() string { return "https" }

// Submit implements Transport.
func (h *HTTPS) Submit(ctx context.Context, lab Lab, sub *msg.Submission, authorization string) (*Response, error) {
	if !endpointAllowed(lab.Endpoint) {
		return nil, fmt.Errorf("transport: lab %s: endpoint must be https", lab.ID)
	}
	body, err := jsonx.Marshal(sub)
	if err != nil {
		return nil, err
	}
	if len(body) > contract.MaxSubmissionBytes {
		return nil, contract.Errf(contract.CodeOversize, "submission %d bytes", len(body))
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(lab.Endpoint, "/")+SubmitPath, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", ContentTypeJSON)
	if authorization != "" {
		req.Header.Set(HeaderAuthorization, authorization)
	}
	resp, err := h.Client.Do(req)
	if err != nil {
		return nil, Classify(err)
	}
	defer resp.Body.Close()
	ack, err := io.ReadAll(io.LimitReader(resp.Body, int64(contract.LimitsFor(contract.KindAck).MaxEnvelopeBytes)+1))
	if err != nil {
		return nil, Classify(err)
	}
	out := &Response{Status: resp.StatusCode}
	out.RetryAfter = parseRetryAfter(resp.Header.Get("Retry-After"))
	switch resp.StatusCode {
	case http.StatusOK, http.StatusAccepted, http.StatusTooManyRequests, http.StatusServiceUnavailable:
		if len(ack) > 0 && ack[0] == '{' {
			out.AckEnvelope = ack
		}
		return out, nil
	}
	return out, fmt.Errorf("%w: %d", ErrBadStatus, resp.StatusCode)
}

// endpointAllowed accepts https URLs and, for local tests, plain http to the
// IPv4 loopback address. The URL is parsed, so "http://127.0.0.1.example" or
// "http://127.0.0.1@lab.example" do not pass as loopback, and userinfo
// (credentials in the URL) is refused.
func endpointAllowed(endpoint string) bool {
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" || u.User != nil {
		return false
	}
	switch u.Scheme {
	case "https":
		return true
	case "http":
		return u.Hostname() == "127.0.0.1"
	}
	return false
}

// parseRetryAfter reads the delay-seconds form of Retry-After (RFC 9110,
// section 10.2.3: a non-negative decimal integer), capped at MaxRetryAfter.
// Anything else (an HTTP date, a sign, a fraction) yields 0.
func parseRetryAfter(v string) time.Duration {
	if v == "" || len(v) > 9 || strings.TrimLeft(v, "0123456789") != "" {
		return 0
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0
	}
	return min(time.Duration(n)*time.Second, MaxRetryAfter)
}

// Classify maps network errors to ErrRefused or ErrTimeout where possible.
func Classify(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return fmt.Errorf("%w: %v", ErrRefused, err)
	}
	var ne net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout()) {
		return fmt.Errorf("%w: %v", ErrTimeout, err)
	}
	return err
}

// OHTTP is the v1 transport (RFC 9458, relay of another operator than the
// lab). Stub: the interface is fixed now so the client can switch later.
type OHTTP struct {
	RelayURL  string
	KeyConfig []byte
}

// Name implements Transport.
func (*OHTTP) Name() string { return "ohttp" }

// Submit implements Transport (not implemented before v1).
func (*OHTTP) Submit(context.Context, Lab, *msg.Submission, string) (*Response, error) {
	return nil, ErrNotV1Yet
}
