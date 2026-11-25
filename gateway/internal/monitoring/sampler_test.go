package monitoring

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fixtureRoot writes a small /proc and /sys tree of a container with
// network_mode host (TEST ONLY values).
func fixtureRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	files := map[string]string{
		".dockerenv":   "",
		"proc/stat":    "cpu  1000 0 500 8000 100 0 0 10 0 0\ncpu0 500 0 250 4000 50 0 0 5 0 0\ncpu1 500 0 250 4000 50 0 0 5 0 0\nintr 1\n",
		"proc/loadavg": "0.50 0.40 0.30 1/200 1234\n",
		"proc/meminfo": "MemTotal:       16000000 kB\nMemFree:         2000000 kB\nMemAvailable:    6000000 kB\nCached:          3000000 kB\nSwapTotal:       2000000 kB\nSwapFree:        2000000 kB\n",
		"proc/vmstat":  "pswpin 100\noom_kill 2\n",
		"proc/uptime":  "86400.00 1000.00\n",
		"proc/self/mountinfo": "24 1 8:1 / / rw,relatime - ext4 /dev/sda1 rw\n25 24 0:22 / /proc rw - proc proc rw\n" +
			"30 24 8:16 / /var/lib/docker rw,relatime - ext4 /dev/sdb rw\n",
		"proc/self/cgroup": "0::/system.slice/docker-abc.scope\n",
		"proc/self/stat":   "1 (schild) S 0 1 1 0 -1 4194560 100 0 0 0 200 100 0 0 20 0 12 0 100 100000000 5000 18446744073709551615\n",
		"proc/diskstats":   "   8       1 sda1 100 0 2000 50 200 0 4000 100 0 300 150 0 0 0 0\n   8      16 sdb 10 0 200 5 20 0 400 10 0 30 15 0 0 0 0\n",
		"proc/net/dev": "Inter-|   Receive                                                |  Transmit\n face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n" +
			"    lo: 1000 10 0 0 0 0 0 0 1000 10 0 0 0 0 0 0\n  eth0: 100000 1000 0 0 0 0 0 0 200000 2000 0 0 0 0 0 0\ndocker0: 5000 50 0 0 0 0 0 0 5000 50 0 0 0 0 0 0\n",
		"proc/net/tcp": "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
			"   0: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1\n" +
			"   1: 0100007F:0050 0200007F:C000 01 00000000:00000000 00:00000000 00000000     0        0 2\n" +
			"   2: 0100007F:0050 0200007F:C001 06 00000000:00000000 00:00000000 00000000     0        0 3\n",
		"proc/net/tcp6":    "  sl  local_address remote st\n",
		"proc/net/netstat": "TcpExt: SyncookiesSent ListenOverflows ListenDrops\nTcpExt: 0 0 5\n",
		"proc/net/snmp":    "Tcp: RtoAlgorithm RetransSegs\nTcp: 1 40\n",
		"proc/sys/net/netfilter/nf_conntrack_count":                  "2000\n",
		"proc/sys/net/netfilter/nf_conntrack_max":                    "262144\n",
		"proc/sys/fs/file-nr":                                        "9000 0 1048576\n",
		"sys/fs/cgroup/cgroup.controllers":                           "cpu memory\n",
		"sys/fs/cgroup/system.slice/docker-abc.scope/cpu.max":        "200000 100000\n",
		"sys/fs/cgroup/system.slice/docker-abc.scope/cpu.stat":       "usage_usec 1000000\nnr_periods 100\nnr_throttled 0\n",
		"sys/fs/cgroup/system.slice/docker-abc.scope/memory.current": "200000000\n",
		"sys/fs/cgroup/system.slice/docker-abc.scope/memory.max":     "1000000000\n",
		"sys/fs/cgroup/system.slice/docker-abc.scope/memory.events":  "oom 0\noom_kill 0\n",
		"etc/os-release": "PRETTY_NAME=\"Ubuntu 24.04.1 LTS\"\n",
	}
	for p, c := range files {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, d := range []string{"var/lib/docker", "proc/self/fd/0", "proc/self/fd/1"} {
		_ = os.MkdirAll(filepath.Join(root, d), 0o755)
	}
	return root
}

func bump(t *testing.T, root, p, from, to string) {
	t.Helper()
	full := filepath.Join(root, p)
	b, _ := os.ReadFile(full)
	if err := os.WriteFile(full, []byte(strings.Replace(string(b), from, to, 1)), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestSamplerReadsProcAndSaysWhatIsVisible(t *testing.T) {
	root := fixtureRoot(t)
	s := newSampler(SamplerConfig{Root: root, Linux: true, Host: true, Started: time.Now()})
	t0 := time.Unix(1_800_000_000, 0)
	first := s.take(t0)
	if first.snap.CPU == nil || first.snap.CPU.Cores != 2 {
		t.Fatalf("cpu %+v", first.snap.CPU)
	}
	// Ten seconds later: 300 of 1000 jiffies busy, 10 kB/s in, 20 kB/s out.
	bump(t, root, "proc/stat", "cpu  1000 0 500 8000 100", "cpu  1200 0 600 8700 100")
	bump(t, root, "proc/net/dev", "eth0: 100000 1000", "eth0: 200000 1100")
	bump(t, root, "proc/net/dev", "200000 2000 0 0 0 0 0 0\ndocker0", "400000 2200 0 0 0 0 0 0\ndocker0")
	bump(t, root, "proc/net/netstat", "TcpExt: 0 0 5", "TcpExt: 0 0 7")
	bump(t, root, "sys/fs/cgroup/system.slice/docker-abc.scope/cpu.stat", "usage_usec 1000000", "usage_usec 3000000")
	s2 := s.take(t0.Add(10 * time.Second))
	snap := s2.snap
	if u := snap.CPU.Usage; u < 0.299 || u > 0.301 {
		t.Errorf("cpu usage %.3f, want 0.3", u)
	}
	if snap.Memory.TotalBytes != 16000000*1024 || snap.Memory.AvailableBytes != 6000000*1024 || *snap.Memory.OOMKills24h != 0 {
		t.Errorf("memory %+v", snap.Memory)
	}
	if len(snap.Interfaces) != 1 || snap.Interfaces[0].Name != "eth0" || snap.Interfaces[0].RxBytesPerS != 10000 || snap.Interfaces[0].TxBytesPerS != 20000 {
		t.Errorf("interfaces %+v (lo and docker0 must be hidden)", snap.Interfaces)
	}
	if snap.TCP.Listen == nil || *snap.TCP.Listen != 1 || snap.TCP.Established != 1 || snap.TCP.TimeWait != 1 || *snap.TCP.ListenDropsPerS != 0.2 {
		t.Errorf("tcp %+v", snap.TCP)
	}
	if snap.Conntrack == nil || snap.Conntrack.Count != 2000 || snap.Files.Open != 9000 {
		t.Errorf("conntrack %+v files %+v", snap.Conntrack, snap.Files)
	}
	e := snap.Environment
	if !e.Container || e.Cgroup != "v2" || e.NetNamespace != "host" || e.OSFamily != "linux" {
		t.Errorf("environment %+v", e)
	}
	if c := snap.Container; c == nil || *c.CPULimitCores != 2 || c.CPUUsage < 0.099 || c.CPUUsage > 0.101 || *c.MemoryLimitBytes != 1e9 {
		t.Errorf("container %+v", snap.Container)
	}
	if len(snap.Mounts) != 2 || snap.Mounts[0].Mount != "/" || snap.Mounts[1].Mount != "/var/lib/docker" {
		t.Errorf("mounts %+v", snap.Mounts)
	}
	// In a container os-release is the image's: the name is the kernel's.
	if snap.OS == nil || snap.OS.Name == "" || snap.OS.Name == "Ubuntu 24.04.1 LTS" || snap.OS.Source != "uname" {
		t.Errorf("os %+v", snap.OS)
	}
	for _, p := range []string{".dockerenv", "proc/self/cgroup"} {
		if err := os.Remove(filepath.Join(root, p)); err != nil {
			t.Fatal(err)
		}
	}
	if o := s.take(t0.Add(20 * time.Second)).snap.OS; o == nil || o.Name != "Ubuntu 24.04.1 LTS" {
		t.Errorf("os on the host itself %+v", o)
	}
	if s2.now.Disk == nil || s2.now.CPUUsage == nil || *s2.now.Cores != 2 {
		t.Errorf("server now %+v", s2.now)
	}
	snap.GeneratedAt = ts(time.Now())
	b, _ := json.Marshal(snap)
	validate(t, "ServerSnapshot", b)
}

func TestSamplerWithoutProc(t *testing.T) {
	s := newSampler(SamplerConfig{Root: t.TempDir(), Linux: false, Host: true, Started: time.Now()})
	snap := s.take(time.Now()).snap
	if snap.CPU != nil || snap.Memory != nil || snap.Environment.OSFamily != "other" {
		t.Errorf("not linux: %+v", snap)
	}
	areas := map[string]string{}
	for _, u := range snap.Unavailable {
		areas[u.Area] = u.Reason
	}
	if areas["cpu"] != "not_linux" || areas["tcp"] != "not_linux" {
		t.Errorf("unavailable %+v", snap.Unavailable)
	}
	b, _ := json.Marshal(snap)
	validate(t, "ServerSnapshot", b)
}

func writeFile(t *testing.T, root, p, c string) {
	t.Helper()
	full := filepath.Join(root, p)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(c), 0o644); err != nil {
		t.Fatal(err)
	}
}

// With many sockets the sampler takes the totals of sockstat and never
// reads /proc/net/tcp (MVP-21 measurement finding 6: 50000 sockets took
// 56-61 ms per sample, over the 50 ms budget).
func TestSamplerTCPManySocketsUsesSockstat(t *testing.T) {
	root := fixtureRoot(t)
	writeFile(t, root, "proc/net/sockstat", "sockets: used 50100\nTCP: inuse 30000 orphan 3 tw 200 alloc 30010 mem 900\nUDP: inuse 4 mem 1\n")
	writeFile(t, root, "proc/net/sockstat6", "TCP6: inuse 20005\nUDP6: inuse 1\n")
	// A /proc/net/tcp that must not be read: a directory fails any read.
	_ = os.Remove(filepath.Join(root, "proc/net/tcp"))
	_ = os.MkdirAll(filepath.Join(root, "proc/net/tcp/x"), 0o755)
	s := newSampler(SamplerConfig{Root: root, Linux: true, Host: true, Started: time.Now()})
	tcp := s.take(time.Now()).snap.TCP
	if tcp == nil || tcp.Source != "sockstat" || tcp.Listen != nil || tcp.Established != 50005 || tcp.TimeWait != 200 || tcp.InUse == nil || *tcp.InUse != 50005 || *tcp.Orphan != 3 {
		t.Fatalf("tcp %+v", tcp)
	}
	// listen null = unknown (D36 amendment), valid on the wire.
	if b, _ := json.Marshal(tcp); !strings.Contains(string(b), `"listen":null`) {
		t.Fatalf("listen not null: %s", b)
	} else {
		validate(t, "TCPSnapshot", b)
	}
	// Few sockets: per-state scan of /proc/net/tcp.
	root = fixtureRoot(t)
	writeFile(t, root, "proc/net/sockstat", "TCP: inuse 2 orphan 0 tw 1 alloc 3 mem 1\n")
	s = newSampler(SamplerConfig{Root: root, Linux: true, Host: true, Started: time.Now()})
	tcp = s.take(time.Now()).snap.TCP
	if tcp.Source != "proc" || tcp.Listen == nil || *tcp.Listen != 1 || tcp.Established != 1 || tcp.TimeWait != 1 {
		t.Fatalf("tcp %+v", tcp)
	}
}

// Just under the old switch (19800 sockets) the scan cost about 0.35 % of
// a core (D36 measurement A.3.6): the sampler now takes sockstat above
// procTCPMax and whenever the measured cost per socket predicts more than
// procTCPBudget, so the scan stays under 0.2 % of a core at every count.
func TestSamplerTCPScanBounded(t *testing.T) {
	root := fixtureRoot(t)
	writeFile(t, root, "proc/net/sockstat", "TCP: inuse 19800 orphan 0 tw 0 alloc 19800 mem 900\n")
	s := newSampler(SamplerConfig{Root: root, Linux: true, Host: true, Started: time.Now()})
	if tcp := s.take(time.Now()).snap.TCP; tcp.Source != "sockstat" {
		t.Fatalf("19800 sockets: source %s", tcp.Source)
	}
	if procTCPMax*2500*time.Nanosecond > procTCPBudget+3*time.Millisecond {
		t.Fatalf("procTCPMax %d at 2.5 µs per socket exceeds the budget", procTCPMax)
	}
	// Under the threshold, but the last scans were slow: sockstat.
	writeFile(t, root, "proc/net/sockstat", "TCP: inuse 4000 orphan 0 tw 0 alloc 4000 mem 900\n")
	s.p.tcpNsPerSocket = 5000 // 5 µs: 4000 sockets would take 20 ms
	if tcp := s.take(time.Now()).snap.TCP; tcp.Source != "sockstat" {
		t.Fatalf("slow scan: source %s", tcp.Source)
	}
	s.p.tcpNsPerSocket = 1000
	if tcp := s.take(time.Now()).snap.TCP; tcp.Source != "proc" {
		t.Fatalf("fast scan: source %s", tcp.Source)
	}
}

func TestTCPStateField(t *testing.T) {
	l := []byte("   1: 0100007F:0050 0200007F:C000 01 00000000:00000000 00:00000000 00000000     0        0 2\n")
	if f := string(tcpStateField(l)); f != "01" {
		t.Fatalf("got %q", f)
	}
	if tcpStateField([]byte("  0: a b\n")) != nil {
		t.Fatal("short line")
	}
}

// A container on its own bridge network: lo, eth0 (a veth end whose peer is
// on the host) and the tunnel stubs a loaded module creates in every
// namespace. Before, more than two interfaces counted as host (MVP-21
// measurement finding 8).
func TestSamplerNetNamespace(t *testing.T) {
	dev := func(names ...string) string {
		out := "Inter-|   Receive |  Transmit\n face |bytes packets|bytes packets\n"
		for _, n := range names {
			out += "  " + n + ": 100 1 0 0 0 0 0 0 100 1 0 0 0 0 0 0\n"
		}
		return out
	}
	link := func(root, name, idx, iflink string) {
		writeFile(t, root, "sys/class/net/"+name+"/ifindex", idx+"\n")
		writeFile(t, root, "sys/class/net/"+name+"/iflink", iflink+"\n")
	}
	stubs := []string{"lo", "eth0", "gre0", "gretap0", "erspan0", "ip_vti0", "ip6_vti0", "sit0", "ip6tnl0", "ip6gre0", "tunl0"}
	cases := []struct {
		name  string
		setup func(root string)
		want  string
		shown []string
	}{
		{"own bridge with tunnel stubs", func(root string) {
			writeFile(t, root, "proc/net/dev", dev(stubs...))
			link(root, "eth0", "27", "28")
		}, "own", []string{"eth0"}},
		{"host network, docker host", func(root string) {
			writeFile(t, root, "proc/net/dev", dev("lo", "ens3", "docker0", "veth12ab", "sit0"))
		}, "host", []string{"ens3"}},
		{"host network, no bridges", func(root string) {
			writeFile(t, root, "proc/net/dev", dev("lo", "ens3", "ens4", "gre0"))
			link(root, "ens3", "2", "2")
			link(root, "ens4", "3", "3")
		}, "host", []string{"ens3", "ens4"}},
		{"own namespace, two networks", func(root string) {
			writeFile(t, root, "proc/net/dev", dev("lo", "eth0", "eth1"))
			link(root, "eth0", "10", "11")
			link(root, "eth1", "12", "13")
		}, "own", []string{"eth0", "eth1"}},
		{"no sysfs, one interface", func(root string) {
			writeFile(t, root, "proc/net/dev", dev("lo", "eth0", "sit0", "tunl0"))
		}, "own", []string{"eth0"}},
		{"no sysfs, two interfaces", func(root string) {
			writeFile(t, root, "proc/net/dev", dev("lo", "eth0", "eth1"))
		}, "unknown", []string{"eth0", "eth1"}},
	}
	for _, c := range cases {
		root := fixtureRoot(t)
		c.setup(root)
		s := newSampler(SamplerConfig{Root: root, Linux: true, Host: true, Started: time.Now()})
		t0 := time.Unix(1_800_000_000, 0)
		s.take(t0)
		snap := s.take(t0.Add(10 * time.Second)).snap
		if snap.Environment.NetNamespace != c.want {
			t.Errorf("%s: net_namespace %q, want %q", c.name, snap.Environment.NetNamespace, c.want)
		}
		var shown []string
		for _, i := range snap.Interfaces {
			shown = append(shown, i.Name)
		}
		if strings.Join(shown, ",") != strings.Join(c.shown, ",") {
			t.Errorf("%s: interfaces %v, want %v", c.name, shown, c.shown)
		}
		hidden := false
		for _, u := range snap.Unavailable {
			hidden = hidden || u.Area == "conntrack" && u.Reason == "container_hidden"
		}
		if (c.want == "own") != (hidden && snap.Conntrack == nil) {
			t.Errorf("%s: conntrack %+v, container_hidden %v", c.name, snap.Conntrack, hidden)
		}
	}
}

// In a container the overlay root and a volume on the same disk have two
// device numbers and one file system: it is shown once, as "/".
func TestOverlayRootAndVolumeOnOneDiskAreOneMount(t *testing.T) {
	const gib = int64(1) << 30
	const info = "1563 1278 0:139 / / rw,relatime - overlay overlay rw,upperdir=/u\n" +
		"1572 1563 8:1 /docker/volumes/a/_data /data/caddy rw,relatime - ext4 /dev/sda1 rw\n" +
		"1575 1563 8:1 /docker/containers/c/hosts /etc/hosts rw,relatime - ext4 /dev/sda1 rw\n" +
		"1576 1563 8:16 / /srv/data rw,relatime - ext4 /dev/sdb rw\n" +
		"1577 1563 8:1 /docker/volumes/b/_data /var/lib/schild rw,relatime - ext4 /dev/sda1 rw\n"
	disk := fsStat{blocks: 40 * gib / 4096, bfree: 9 * gib / 4096, bavail: 8 * gib / 4096, bsize: 4096, files: 1000, ffree: 800}
	// The same model of disk with other content.
	other := disk
	other.bfree, other.bavail, other.ffree = disk.bfree-1, disk.bavail-1, disk.ffree-1

	setup := func(cfg SamplerConfig) (*sampler, string, map[string]fsStat) {
		root := fixtureRoot(t)
		if err := os.WriteFile(filepath.Join(root, "proc/self/mountinfo"), []byte(info), 0o644); err != nil {
			t.Fatal(err)
		}
		cfg.Root, cfg.Linux, cfg.Host, cfg.Started, cfg.StoragePath = root, true, true, time.Now(), "/var/lib/schild"
		st := map[string]fsStat{"/": disk, "/data/caddy": disk, "/srv/data": other}
		s := newSampler(cfg)
		s.statfs = func(p string) (fsStat, error) {
			rel, err := filepath.Rel(root, p)
			if err != nil {
				return fsStat{}, err
			}
			v, ok := st[filepath.Join("/", rel)]
			if !ok {
				return fsStat{}, os.ErrNotExist
			}
			return v, nil
		}
		return s, root, st
	}
	points := func(o *sample) string {
		var l []string
		for _, m := range o.snap.Mounts {
			l = append(l, m.Mount)
		}
		return strings.Join(l, " ")
	}
	t0 := time.Unix(1_800_000_000, 0)

	s, root, st := setup(SamplerConfig{})
	if got := points(s.take(t0)); got != "/ /srv/data" {
		t.Fatalf("mounts %q, want one for the shared disk and the second disk", got)
	}
	// The root shows the disk's I/O, which the overlay itself has not.
	bump(t, root, "proc/diskstats", "sda1 100 0 2000", "sda1 110 0 4000")
	// Writes between two calls: the mount does not come back.
	busy := disk
	busy.bfree--
	st["/data/caddy"] = busy
	second := s.take(t0.Add(10 * time.Second))
	if got := points(second); got != "/ /srv/data" {
		t.Errorf("mounts after a write %q", got)
	}
	if m := second.snap.Mounts[0]; m.Device != "sda1" || m.ReadBytesPerS == nil || *m.ReadBytesPerS != 2000*512/10 {
		t.Errorf("root %+v, want the I/O of sda1", m)
	}

	// A write between the first two calls of all: the next try tells.
	s, _, _ = setup(SamplerConfig{})
	inner, calls := s.statfs, 0
	s.statfs = func(p string) (fsStat, error) {
		v, err := inner(p)
		if calls++; calls == 1 {
			v.bfree++
		}
		return v, err
	}
	if got := points(s.take(t0)); got != "/ /srv/data" {
		t.Errorf("mounts with a write in between %q", got)
	}

	// A volume on a disk of its own stays, also one of the same size.
	s, _, st = setup(SamplerConfig{})
	st["/data/caddy"] = other
	if got := points(s.take(t0)); got != "/ /data/caddy /srv/data" {
		t.Errorf("mounts with a volume on another disk %q", got)
	}

	// Under load the values never match again, and the mount stays away: near
	// each other in every sample, or far apart in two samples in a row only.
	s, _, st = setup(SamplerConfig{})
	s.take(t0)
	near, far := disk, disk
	near.bfree -= 64 << 20 / disk.bsize
	far.bfree -= 1 << 30 / disk.bsize
	for i, v := range []fsStat{near, near, near, near, near, far, far, near, far, far, disk, far, far} {
		st["/data/caddy"] = v
		if got := points(s.take(t0.Add(time.Duration(i+1) * 10 * time.Second))); got != "/ /srv/data" {
			t.Fatalf("mounts under load, sample %d: %q", i, got)
		}
	}

	// Another disk that was equal once, by chance or as a copy, comes back
	// with the third sample in a row that is far apart, and stays.
	resized := disk
	resized.blocks++
	for name, v := range map[string]fsStat{"free space": far, "size": resized} {
		s, _, st = setup(SamplerConfig{})
		s.take(t0)
		st["/data/caddy"] = v
		for i, want := range []string{"/ /srv/data", "/ /srv/data", "/ /data/caddy /srv/data", "/ /data/caddy /srv/data"} {
			if got := points(s.take(t0.Add(time.Duration(i+1) * 10 * time.Second))); got != want {
				t.Errorf("%s apart, sample %d: mounts %q, want %q", name, i, got, want)
			}
		}
	}

	// The operator's own list is not changed.
	s, _, _ = setup(SamplerConfig{Mounts: []string{"/", "/data/caddy"}})
	if got := points(s.take(t0)); got != "/ /data/caddy" {
		t.Errorf("configured mounts %q", got)
	}
}
