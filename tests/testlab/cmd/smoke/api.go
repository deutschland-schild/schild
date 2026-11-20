package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// apiClient talks to one dashboard API (/api/v0) with a session cookie and the
// CSRF token. Cookies are handled by hand: the dashboards mark them Secure
// (plain HTTP inside the test lab is not localhost), which Go's cookie jar
// would never send back over http.
type apiClient struct {
	name   string
	base   string // e.g. http://lab-a:8789
	cookie string // name=value
	csrf   string
	user   string
	hc     *http.Client
}

func newAPI(name, base string) *apiClient {
	return &apiClient{name: name, base: strings.TrimRight(base, "/"), hc: &http.Client{Timeout: 30 * time.Second}}
}

// apiError is a non-expected HTTP status with the problem body.
type apiError struct {
	Status int
	Body   string
}

func (e *apiError) Error() string { return fmt.Sprintf("HTTP %d: %s", e.Status, trunc(e.Body, 400)) }

func trunc(s string, n int) string {
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

// do sends a JSON request below /api/v0 and decodes the answer into out.
// want lists accepted status codes (default 200/201/204).
func (a *apiClient) do(method, path string, body, out any, want ...int) (int, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, a.base+"/api/v0"+path, rd)
	if err != nil {
		return 0, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	if a.cookie != "" {
		req.Header.Set("Cookie", a.cookie)
	}
	if a.csrf != "" && method != http.MethodGet {
		req.Header.Set("X-CSRF-Token", a.csrf)
	}
	resp, err := a.hc.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	for _, c := range resp.Cookies() {
		if c.Value != "" && (strings.HasPrefix(c.Name, "schild_")) {
			a.cookie = c.Name + "=" + c.Value
		}
	}
	if len(want) == 0 {
		want = []int{200, 201, 204}
	}
	ok := false
	for _, w := range want {
		ok = ok || resp.StatusCode == w
	}
	if !ok {
		return resp.StatusCode, &apiError{resp.StatusCode, string(raw)}
	}
	if out != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			return resp.StatusCode, fmt.Errorf("%s %s: decode: %w: %s", method, path, err, trunc(string(raw), 300))
		}
	}
	return resp.StatusCode, nil
}

type session struct {
	Authenticated bool   `json:"authenticated"`
	FirstRun      bool   `json:"first_run"`
	User          string `json:"user"`
	CSRFToken     string `json:"csrf_token"`
	Via           string `json:"via"`
}

// loginLab logs a named user into a lab dashboard.
func (a *apiClient) loginLab(user, password string) error {
	var s session
	if _, err := a.do("POST", "/auth/login", map[string]string{"user": user, "password": password}, &s); err != nil {
		return fmt.Errorf("%s: login %s: %w", a.name, user, err)
	}
	if !s.Authenticated || s.CSRFToken == "" {
		return fmt.Errorf("%s: login %s: no session", a.name, user)
	}
	a.csrf, a.user = s.CSRFToken, user
	return nil
}

// loginClient sets the first password with the setup code from the server
// log (first run) or logs in.
func (a *apiClient) loginClient(setupCode, password string) error {
	var s session
	if _, err := a.do("GET", "/auth/session", nil, &s); err != nil {
		return fmt.Errorf("%s: session: %w", a.name, err)
	}
	if s.FirstRun {
		if setupCode == "" {
			return fmt.Errorf("%s: first run but no setup code (SMOKE_SETUP_CODE_*)", a.name)
		}
		if _, err := a.do("POST", "/auth/setup", map[string]string{"setup_code": setupCode, "password": password}, &s); err != nil {
			return fmt.Errorf("%s: setup: %w", a.name, err)
		}
	} else if _, err := a.do("POST", "/auth/login", map[string]string{"password": password}, &s); err != nil {
		return fmt.Errorf("%s: login: %w", a.name, err)
	}
	if !s.Authenticated || s.CSRFToken == "" {
		return fmt.Errorf("%s: no session after login", a.name)
	}
	a.csrf, a.user = s.CSRFToken, "admin"
	return nil
}

// eventually polls f until it returns true, an error or the timeout passes.
func eventually(ctx context.Context, timeout, every time.Duration, what string, f func() (bool, error)) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var last error
	for {
		ok, err := f()
		if ok && err == nil {
			return nil
		}
		if err != nil {
			last = err
		}
		select {
		case <-ctx.Done():
			if last != nil {
				return fmt.Errorf("%s: not within %s (last error: %v)", what, timeout, last)
			}
			return fmt.Errorf("%s: not within %s", what, timeout)
		case <-time.After(every):
		}
	}
}

// tlsClient trusts the test CA (SCHILD_TEST_CA) for the labs' TLS ports.
func tlsClient() (*http.Client, error) {
	pool := x509.NewCertPool()
	path := os.Getenv("SCHILD_TEST_CA")
	if path == "" {
		return nil, errors.New("SCHILD_TEST_CA is not set")
	}
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if !pool.AppendCertsFromPEM(pem) {
		return nil, errors.New("no certificate in SCHILD_TEST_CA")
	}
	return &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}}, nil
}
