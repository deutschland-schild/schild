package memlimit

import (
	"errors"
	"testing"
)

func files(m map[string]string) func(string) ([]byte, error) {
	return func(p string) ([]byte, error) {
		if v, ok := m[p]; ok {
			return []byte(v), nil
		}
		return nil, errors.New("missing")
	}
}

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func pct(n int64) int64 { return int64(float64(n) * Share) }

// TestOf (MVP-19 fix round 3): 80 % of the total, but always at least
// 256 MiB headroom to it, and at least half of a tiny total.
func TestOf(t *testing.T) {
	const mib = int64(1) << 20
	cases := []struct {
		total, limit int64
		rule         string
	}{
		{4096 * mib, pct(4096 * mib), RuleShare}, // 3276 MiB, 820 MiB headroom
		{2048 * mib, pct(2048 * mib), RuleShare}, // 1638 MiB, 410 MiB headroom
		{1280 * mib, 1024 * mib, RuleShare},      // 80 % = total - 256 MiB exactly
		{1024 * mib, 768 * mib, RuleHeadroom},    // was 819 MiB (0.2 GiB headroom)
		{768 * mib, 512 * mib, RuleHeadroom},     // 256 MiB headroom
		{512 * mib, 256 * mib, RuleHeadroom},     // headroom and floor meet
		{384 * mib, 192 * mib, RuleFloor},        // half of a tiny limit
		{128 * mib, 64 * mib, RuleFloor},         // never zero or negative
		{64 << 30, pct(64 << 30), RuleShare},     // big machine: 80 %
	}
	for _, tc := range cases {
		l, rule := Of(tc.total)
		if l != tc.limit || rule != tc.rule {
			t.Errorf("Of(%d MiB) = %d MiB %s, want %d MiB %s", tc.total/mib, l/mib, rule, tc.limit/mib, tc.rule)
		}
		if l <= 0 || l > tc.total {
			t.Errorf("Of(%d MiB) = %d out of range", tc.total/mib, l)
		}
		if tc.total >= 512*mib && tc.total-l < Headroom {
			t.Errorf("Of(%d MiB) leaves %d MiB headroom", tc.total/mib, (tc.total-l)/mib)
		}
	}
}

func TestDerive(t *testing.T) {
	const gib = int64(1) << 30
	cases := []struct {
		name   string
		env    map[string]string
		files  map[string]string
		limit  int64
		source string
	}{
		{"GOMEMLIMIT wins", map[string]string{"GOMEMLIMIT": "3000MiB"}, map[string]string{"/sys/fs/cgroup/memory.max": "4294967296\n"}, 3000 << 20, SourceEnv},
		{"cgroup v2", nil, map[string]string{"/sys/fs/cgroup/memory.max": "4294967296\n", "/proc/meminfo": "MemTotal: 16000000 kB\n"}, pct(4 * gib), SourceCgroup},
		{"cgroup v2 without limit falls back to RAM", nil, map[string]string{"/sys/fs/cgroup/memory.max": "max\n", "/proc/meminfo": "MemTotal:        2048000 kB\nMemFree: 1 kB\n"}, pct(2048000 << 10), SourceRAM},
		{"cgroup v1", nil, map[string]string{"/sys/fs/cgroup/memory/memory.limit_in_bytes": "2147483648"}, pct(2 * gib), SourceCgroup},
		{"cgroup 1 GiB keeps 256 MiB headroom", nil, map[string]string{"/sys/fs/cgroup/memory.max": "1073741824\n"}, 768 << 20, SourceCgroup},
		{"GOMEMLIMIT wins over a small cgroup", map[string]string{"GOMEMLIMIT": "700MiB"}, map[string]string{"/sys/fs/cgroup/memory.max": "1073741824\n"}, 3000 << 20, SourceEnv},
		{"cgroup v1 unlimited", nil, map[string]string{"/sys/fs/cgroup/memory/memory.limit_in_bytes": "9223372036854771712"}, 0, SourceNone},
		{"nothing readable", nil, nil, 0, SourceNone},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := Derive(env(tc.env), files(tc.files), 3000<<20)
			if r.Limit != tc.limit || r.Source != tc.source {
				t.Fatalf("got %d %s, want %d %s", r.Limit, r.Source, tc.limit, tc.source)
			}
		})
	}
}

func TestWithoutOutside(t *testing.T) {
	const gib = int64(1) << 30
	for _, c := range []struct{ limit, sock, want int64 }{
		{2 * gib, 0, 2 * gib},
		{2 * gib, gib / 2, 3 * gib / 2},
		{2 * gib, 3 * gib, gib}, // never below half
	} {
		if got := WithoutOutside(c.limit, c.sock); got != c.want {
			t.Errorf("%d - %d: %d, want %d", c.limit, c.sock, got, c.want)
		}
	}
}

func TestReadStat(t *testing.T) {
	file := func(s string) func(string) ([]byte, error) {
		return func(string) ([]byte, error) { return []byte(s), nil }
	}
	s, ok := readStat(file("anon 5\nfile 700\nsock 4096\nfile_dirty 10\nfile_writeback 20\nfile_mapped 9\n"))
	if !ok || s != (Stat{Anon: 5, Sock: 4096, Dirty: 10, Writeback: 20}) {
		t.Fatalf("%+v %v", s, ok)
	}
	if s.Held() != 4131 || s.Outside() != 4126 {
		t.Fatalf("clean page cache must not count: %d %d", s.Held(), s.Outside())
	}
	if _, ok := readStat(file("sockets 4096\n")); ok {
		t.Fatal("no known line, still a value")
	}
	if _, ok := readStat(file("sock many\n")); ok {
		t.Fatal("a broken line, still a value")
	}
	if _, ok := readStat(func(string) ([]byte, error) { return nil, errors.New("gone") }); ok {
		t.Fatal("no file, still a value")
	}
}

// Everything the kernel holds on to counts (D46). The reclaimable part of the slab
// counts too: it is the inodes of open sockets, and it still stood at the kill.
func TestReadStatCountsKernelMemory(t *testing.T) {
	file := func(name string) ([]byte, error) {
		return []byte("anon 1\nsock 2\nslab_reclaimable 4\nslab_unreclaimable 8\nslab 12\nkernel_stack 16\npagetables 32\nshmem 64\nfile_dirty 128\nfile_writeback 256\n" +
			"file 9000\nactive_file 5000\ninactive_file 4000\nfile_mapped 700\npercpu 60\n"), nil
	}
	s, ok := readStat(file)
	if !ok {
		t.Fatal("no stat")
	}
	if want := (Stat{Anon: 1, Sock: 2, Slab: 12, KernelStack: 16, PageTables: 32, Shmem: 64, Dirty: 128, Writeback: 256}); s != want {
		t.Fatalf("%+v", s)
	}
	if s.Held() != 511 || s.Outside() != 510 {
		t.Fatalf("held %d outside %d", s.Held(), s.Outside())
	}
}

// The brake needs the limit where the kernel kills: a cgroup, with or without an
// operator's GOMEMLIMIT.
func TestBrake(t *testing.T) {
	for _, c := range []struct {
		r    Result
		want bool
	}{
		{Result{Source: SourceCgroup, Total: 1 << 30}, true},
		{Result{Source: SourceEnv, Total: 1 << 30}, true},
		{Result{Source: SourceEnv}, false},
		{Result{Source: SourceRAM, Total: 1 << 30}, false},
		{Result{Source: SourceNone}, false},
	} {
		if c.r.Brake() != c.want {
			t.Errorf("%+v", c.r)
		}
		f := Follower{Result: c.r, read: func(string) ([]byte, error) { return []byte("anon 1\n"), nil }, set: func(int64) {}}
		if _, ok := f.Follow(); ok != c.want {
			t.Errorf("follow %+v", c.r)
		}
	}
}

func TestDeriveKeepsTheCgroupBesideGOMEMLIMIT(t *testing.T) {
	env := func(string) string { return "1638MiB" }
	files := func(name string) ([]byte, error) {
		if name == "/sys/fs/cgroup/memory.max" {
			return []byte("2147483648\n"), nil
		}
		return nil, errors.New("gone")
	}
	r := Derive(env, files, 1638<<20)
	if r.Source != SourceEnv || r.Limit != 1638<<20 || r.Total != 2<<30 || !r.Brake() {
		t.Fatalf("%+v", r)
	}
	r = Derive(env, func(string) ([]byte, error) { return []byte("max\n"), nil }, 1638<<20)
	if r.Total != 0 || r.Brake() {
		t.Fatalf("no limit of a cgroup: %+v", r)
	}
}

// An operator's GOMEMLIMIT is the ceiling of the move, and comes back when the
// sockets are empty again.
func TestFollowerMovesGOMEMLIMIT(t *testing.T) {
	stat := "anon 1\nsock 0\n"
	var set []int64
	f := Follower{Result: Result{Source: SourceEnv, Limit: 1 << 30, Total: 2 << 30},
		read: func(string) ([]byte, error) { return []byte(stat), nil }, set: func(n int64) { set = append(set, n) }}
	f.Follow()
	stat = "anon 1\nsock 268435456\n"
	f.Follow()
	stat = "anon 1\nsock 0\n"
	f.Follow()
	if len(set) != 3 || set[0] != 1<<30 || set[1] != 3<<28 || set[2] != 1<<30 {
		t.Fatalf("%v", set)
	}
}

// GOMEMLIMIT=off leaves no limit to move, and 0 would mean no heap at all.
func TestFollowerWithoutALimit(t *testing.T) {
	f := Follower{Result: Result{Source: SourceEnv, Total: 2 << 30},
		read: func(string) ([]byte, error) { return []byte("anon 1\nsock 268435456\n"), nil },
		set:  func(n int64) { t.Fatalf("limit set to %d", n) }}
	if _, ok := f.Follow(); !ok {
		t.Fatal("the brake runs")
	}
}

func TestEvalBudget(t *testing.T) {
	if b := EvalBudget(Result{Limit: 3 << 30}, 1); b != 3<<29 {
		t.Fatalf("half of the limit: %d", b)
	}
	if b := EvalBudget(Result{Limit: 64 << 20}, 1); b != 64<<20 {
		t.Fatalf("floor: %d", b)
	}
	if b := EvalBudget(Result{}, 7); b != 7 {
		t.Fatalf("no limit: %d", b)
	}
}
