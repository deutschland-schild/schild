package control

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
)

func shortDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("", "ctl")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return d
}

func TestLockExclusive(t *testing.T) {
	dir := shortDir(t)
	release, err := Lock(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Lock(dir); !errors.Is(err, ErrLocked) {
		t.Fatalf("second lock: %v, want ErrLocked", err)
	}
	release()
	r2, err := Lock(dir)
	if err != nil {
		t.Fatalf("lock after release: %v", err)
	}
	r2()
}

func TestCallAndClose(t *testing.T) {
	dir := shortDir(t)
	if _, err := Call(context.Background(), dir, Request{Op: OpResetDashboard}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("without server: %v", err)
	}
	// A leftover socket file from a crashed run is replaced.
	if err := os.MkdirAll(dir+"/control", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(SocketPath(dir), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s, err := Listen(ctx, dir, func(_ context.Context, r Request) Response {
		if r.Op != OpResetDashboard {
			return Response{Error: "unknown operation"}
		}
		return Response{OK: true, SetupCode: "ABCD-EFGH-JKLM", UsersRemoved: 1, SessionsEnded: 2}
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for p, want := range map[string]os.FileMode{dir + "/control": 0o700, SocketPath(dir): 0o600} {
		fi, err := os.Stat(p)
		if err != nil || fi.Mode().Perm() != want {
			t.Fatalf("%s: %v (%v), want %v", p, fi.Mode().Perm(), err, want)
		}
	}
	resp, err := Call(context.Background(), dir, Request{Op: OpResetDashboard, HostUser: "deploy"})
	if err != nil || !resp.OK || resp.SetupCode != "ABCD-EFGH-JKLM" || resp.SessionsEnded != 2 {
		t.Fatalf("%+v %v", resp, err)
	}
	if resp, _ := Call(context.Background(), dir, Request{Op: "other"}); resp.OK {
		t.Fatal("unknown op answered OK")
	}
	cancel()
	s.Close()
	if _, err := os.Stat(SocketPath(dir)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("socket left after close: %v", err)
	}
	if _, err := Call(context.Background(), dir, Request{Op: OpResetDashboard}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("after close: %v", err)
	}
}

// TestLargeAccessRoundTrip: an access lock with every list at its contract
// maximum (32 paths and 16 exceptions of 255 bytes, 64 addresses) fits into
// a request, and the protections of many websites into an answer.
func TestLargeAccessRoundTrip(t *testing.T) {
	dir := shortDir(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s, err := Listen(ctx, dir, func(_ context.Context, r Request) Response {
		if r.Access == nil {
			return Response{Error: "no access"}
		}
		var out []AccessInfo
		for i := range 100 {
			out = append(out, AccessInfo{Website: fmt.Sprintf("site-%d.example", i), Scope: r.Access.Scope, Paths: r.Access.Paths,
				Except: r.Access.Except, Addresses: r.Access.Addresses, Password: true})
		}
		return Response{OK: true, Access: out}
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	long := "/" + strings.Repeat("a", 250)
	set := &AccessSet{Scope: "paths", Message: strings.Repeat("m", 500), Password: strings.Repeat("p", 128)}
	for i := range 32 {
		set.Paths = append(set.Paths, fmt.Sprintf("%s%04d", long, i))
	}
	for i := range 16 {
		set.Except = append(set.Except, fmt.Sprintf("%s%04d", long, i))
	}
	for i := range 64 {
		set.Addresses = append(set.Addresses, fmt.Sprintf("2001:db8:ffff:ffff:ffff:ffff:ffff:%x/128", i))
	}
	resp, err := Call(context.Background(), dir, Request{Op: OpAccessSet, Website: "shop.example", Access: set})
	if err != nil || !resp.OK || len(resp.Access) != 100 || len(resp.Access[99].Paths) != 32 || resp.Access[99].Paths[31] != set.Paths[31] {
		t.Fatalf("large access_set: ok=%v %q err=%v", resp.OK, resp.Error, err)
	}
}
