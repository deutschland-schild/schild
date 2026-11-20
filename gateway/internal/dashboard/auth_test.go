//go:build !release

package dashboard_test

import (
	"bufio"
	"context"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/gateway/internal/apptest"
	"github.com/deutschland-schild/schild/gateway/internal/dashboard"
)

// TestLoginLimitHoldsInParallel: the 5 attempts per address and 15 minutes
// hold for attempts sent at once. Each attempt is counted before its
// password check, so the requests cannot all pass the limit while the first
// checks still run.
func TestLoginLimitHoldsInParallel(t *testing.T) {
	h := apptest.New(t, apptest.Options{})
	h.Login() // a successful attempt gives its attempt back
	const n = 20
	codes := make(chan int, n)
	var wg sync.WaitGroup
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := http.Post(h.Dash.URL+"/api/v0/auth/login", "application/json", strings.NewReader(`{"password":"wrong-password"}`))
			if err != nil {
				t.Error(err)
				return
			}
			resp.Body.Close()
			codes <- resp.StatusCode
		}()
	}
	wg.Wait()
	close(codes)
	got := map[int]int{}
	for c := range codes {
		got[c]++
	}
	if got[401] != 5 || got[429] != n-5 {
		t.Fatalf("parallel wrong passwords: %v, want 5x 401 and %dx 429", got, n-5)
	}
	resp, err := http.Post(h.Dash.URL+"/api/v0/auth/login", "application/json", strings.NewReader(`{"password":"`+h.Password+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 429 {
		t.Fatalf("right password with no attempt left: %d", resp.StatusCode)
	}
}

// TestPasswordGuessesBehindASession: a session does not give unlimited
// guesses at the password through the password change; the budget is the
// session's own.
func TestPasswordGuessesBehindASession(t *testing.T) {
	h := apptest.New(t, apptest.Options{Mode: "observe"})
	h.Login()
	for i := range 5 {
		if code, b := h.API("POST", "/auth/password", map[string]string{"current_password": "wrong-password", "new_password": "neues-langes-passwort"}); code != 401 {
			t.Fatalf("wrong current password %d: %d %s", i, code, b)
		}
	}
	if code, _ := h.API("POST", "/auth/password", map[string]string{"current_password": h.Password, "new_password": "neues-langes-passwort"}); code != 429 {
		t.Fatalf("sixth guess: %d", code)
	}
	// A fresh login (its own session) is not affected by the guesses.
	h.Login()
	if code, b := h.API("POST", "/auth/password", map[string]string{"current_password": h.Password, "new_password": "neues-langes-passwort"}); code != 204 {
		t.Fatalf("password change in a fresh session: %d %s", code, b)
	}
}

// TestEventStreamEndsWithSession: a logout (and so a password change or a
// reset on the host) also ends an event stream that is already open.
func TestEventStreamEndsWithSession(t *testing.T) {
	h := apptest.New(t, apptest.Options{Mode: "observe"})
	dashboard.SetStreamCheck(h.App.Dashboard, 50*time.Millisecond)
	h.Login()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", h.Dash.URL+"/api/v0/events/stream", nil)
	resp, err := h.Client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("stream: %d", resp.StatusCode)
	}
	ended := make(chan struct{})
	go func() {
		sc := bufio.NewScanner(resp.Body)
		for sc.Scan() {
		}
		close(ended)
	}()
	select {
	case <-ended:
		t.Fatal("stream ended before the logout")
	case <-time.After(300 * time.Millisecond):
	}
	if code, b := h.API("POST", "/auth/logout", nil); code != 204 {
		t.Fatalf("logout: %d %s", code, b)
	}
	select {
	case <-ended:
	case <-ctx.Done():
		t.Fatal("stream still open after the logout")
	}
}

// TestMonitoringStreamEndsWithSession: the live monitoring stream ends with
// the session too, like the event stream.
func TestMonitoringStreamEndsWithSession(t *testing.T) {
	h := apptest.New(t, apptest.Options{Mode: "observe"})
	dashboard.SetStreamCheck(h.App.Dashboard, 50*time.Millisecond)
	h.Login()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", h.Dash.URL+"/api/v0/monitoring/stream", nil)
	resp, err := h.Client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("stream: %d", resp.StatusCode)
	}
	ended := make(chan struct{})
	go func() {
		sc := bufio.NewScanner(resp.Body)
		sc.Buffer(make([]byte, 64<<10), 4<<20)
		for sc.Scan() {
		}
		close(ended)
	}()
	select {
	case <-ended:
		t.Fatal("stream ended before the logout")
	case <-time.After(300 * time.Millisecond):
	}
	if code, b := h.API("POST", "/auth/logout", nil); code != 204 {
		t.Fatalf("logout: %d %s", code, b)
	}
	select {
	case <-ended:
	case <-time.After(3 * time.Second):
		t.Fatal("monitoring stream still open after the logout")
	}
}
