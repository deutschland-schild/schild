package monitoring

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"runtime/metrics"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	cm "github.com/deutschland-schild/schild/contract/monitoring"
)

// The host sampler reads /proc and /sys every 10 s (spec MVP-21 server).
// Every area that cannot be read is null with an Unavailable entry; a
// failing read never stops the sampler. Paths are relative to Root so tests
// run against fixture trees.

// SamplerConfig configures the host sampler.
type SamplerConfig struct {
	// Root of /proc and /sys ("/" in production).
	Root string
	// Linux: /proc is there (runtime.GOOS == "linux" unless a test sets it).
	Linux bool
	// Host: monitoring.host (false: only the process is sampled).
	Host       bool
	Mounts     []string
	Interfaces []string
	// StoragePath is always shown as a mount (the file system of schild.db).
	StoragePath string
	Started     time.Time
	Version     string
	// OS returns the latest local MVP-11 host report's OS (nil: uname only).
	OS func() *HostOS
}

// Budget of one sample (spec: at most 50 ms CPU).
const samplerBudget = 50 * time.Millisecond

type cpuTimes struct{ user, nice, system, idle, iowait, irq, softirq, steal float64 }

func (c cpuTimes) total() float64 {
	return c.user + c.nice + c.system + c.idle + c.iowait + c.irq + c.softirq + c.steal
}

type ifCounters struct{ rxB, rxP, rxE, rxD, txB, txP, txE, txD float64 }
type diskCounters struct{ rdSect, wrSect, reads, writes, ioMS float64 }

// prev keeps the counters of the last sample for rates.
type prev struct {
	at      time.Time
	cpu     cpuTimes
	cores   []cpuTimes
	ifs     map[string]ifCounters
	disks   map[string]diskCounters
	pswpin  float64
	oomHist []oomPoint
	drops   float64
	retrans float64
	procCPU float64
	// tcpNsPerSocket: smoothed cost of the last /proc/net/tcp scans.
	tcpNsPerSocket float64
	cgUsage        float64
	cgThrot        float64
	cgPeriod       float64
	ok             bool
}

type oomPoint struct {
	at time.Time
	n  float64
}

// objectSample is one mount, device or interface of a sample.
type objectSample struct {
	object, kind string
	gauges       map[string]float64
	counters     map[string]float64
}

// sample is one host sample.
type sample struct {
	at       time.Time
	snap     ServerSnapshot
	now      cm.ServerNow
	gauges   map[string]float64
	counters map[string]float64 // delta over the interval
	objects  []objectSample
	took     time.Duration
	// swapIn in bytes per second (-1 unknown), for the swap_active hint.
	swapIn float64
}

type sampler struct {
	cfg  SamplerConfig
	p    prev
	mets []metrics.Sample
	// statfs is replaced in tests.
	statfs func(string) (fsStat, error)
	// rootOn: block mounts found to be the file system under an overlay root,
	// each with the number of samples in a row that spoke against it.
	rootOn map[rootPair]int
}

func newSampler(cfg SamplerConfig) *sampler {
	if cfg.Root == "" {
		cfg.Root = "/"
	}
	s := &sampler{cfg: cfg, statfs: statfs, rootOn: map[rootPair]int{}}
	s.mets = []metrics.Sample{{Name: "/memory/classes/heap/objects:bytes"}, {Name: "/sched/goroutines:goroutines"}, {Name: "/gc/pauses:seconds"}}
	return s
}

func (s *sampler) path(p string) string { return filepath.Join(s.cfg.Root, p) }

func (s *sampler) read(p string) ([]byte, error) {
	b, err := os.ReadFile(s.path(p))
	if err != nil {
		return nil, err
	}
	return b, nil
}

func reasonOf(err error) string {
	if os.IsPermission(err) {
		return "no_permission"
	}
	return "not_present"
}

func f64(s string) float64 {
	v, _ := strconv.ParseFloat(s, 64)
	return v
}

func ptr[T any](v T) *T { return &v }

// take reads one sample at now; internals are filled by the caller.
func (s *sampler) take(now time.Time) *sample {
	t0 := time.Now()
	out := &sample{at: now, gauges: map[string]float64{}, counters: map[string]float64{}, swapIn: -1}
	snap := &out.snap
	snap.GeneratedAt = ts(now)
	snap.SampledAt = ptr(ts(now))
	snap.IntervalS = cm.SampleInterval
	snap.Mounts = []MountSnapshot{}
	snap.Interfaces = []InterfaceSnapshot{}
	snap.Unavailable = []Unavailable{}
	snap.Schild = SchildInternals{EventQueueCapacity: 1, EvalSlotsMax: 1}
	dt := 0.0
	if s.p.ok {
		dt = now.Sub(s.p.at).Seconds()
	}
	unav := func(area, reason string) { snap.Unavailable = append(snap.Unavailable, Unavailable{area, reason}) }
	host := s.cfg.Linux && s.cfg.Host
	scope := "process"
	if host {
		scope = "host"
	}
	snap.Environment = Environment{OSFamily: "other", Cgroup: "none", NetNamespace: "unknown"}
	if s.cfg.Linux {
		snap.Environment.OSFamily = "linux"
		s.environment(&snap.Environment)
	}
	reason := "not_linux"
	if s.cfg.Linux {
		reason = "host_off"
	}
	nowS := &out.now
	nowS.SampledAt = ts(now)
	nowS.Scope = scope
	if host {
		s.cpu(out, dt, unav)
		s.memory(out, now, unav)
		s.mounts(out, dt, unav)
		s.network(out, dt, unav)
		s.tcp(out, dt, unav)
		s.conntrackFiles(out, unav)
		s.container(out, dt)
		if b, err := s.read("proc/uptime"); err == nil {
			if f := strings.Fields(string(b)); len(f) > 0 {
				u := int64(f64(f[0]))
				snap.UptimeS = &u
				nowS.UptimeS = &u
			}
		}
	} else {
		for _, a := range []string{"cpu", "memory", "load", "mounts", "disk_io", "interfaces", "tcp", "conntrack", "files"} {
			unav(a, reason)
		}
		if !s.cfg.Linux {
			unav("container", "not_linux")
		}
	}
	s.process(out, dt)
	s.os(snap, unav)
	s.p.at = now
	s.p.ok = true
	out.took = time.Since(t0)
	return out
}

func (s *sampler) environment(e *Environment) {
	if _, err := os.Stat(s.path(".dockerenv")); err == nil {
		e.Container = true
	}
	if _, err := os.Stat(s.path("run/.containerenv")); err == nil {
		e.Container = true
	}
	if _, err := os.Stat(s.path("sys/fs/cgroup/cgroup.controllers")); err == nil {
		e.Cgroup = "v2"
	} else if _, err := os.Stat(s.path("sys/fs/cgroup/cpu")); err == nil {
		e.Cgroup = "v1"
	}
	if b, err := s.read("proc/self/cgroup"); err == nil {
		for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
			parts := strings.SplitN(l, ":", 3)
			if len(parts) == 3 && parts[2] != "/" && parts[2] != "" && (strings.Contains(parts[2], "docker") || strings.Contains(parts[2], "containerd") || strings.Contains(parts[2], "libpod") || strings.Contains(parts[2], "kubepods")) {
				e.Container = true
			}
		}
	}
	if b, err := s.read("proc/self/mountinfo"); err == nil && bytes.Contains(b, []byte("lxcfs")) && bytes.Contains(b, []byte("/proc/meminfo")) {
		e.LXCFS = true
	}
	if !e.Container {
		e.NetNamespace = "host"
		return
	}
	e.NetNamespace = s.netNamespace()
}

// tunnelStubs are the fallback devices the kernel creates in every network
// namespace once a tunnel module is loaded (gre0, sit0, ...); they say
// nothing about the namespace and are never shown.
var tunnelStubs = map[string]bool{"gre0": true, "gretap0": true, "erspan0": true, "ip_vti0": true, "ip6_vti0": true, "sit0": true,
	"ip6tnl0": true, "ip6gre0": true, "tunl0": true, "ip6erspan0": true}

func isTunnelStub(name string) bool { return tunnelStubs[name] }

// netNamespace tells whether schild in a container sees the host's network
// (network_mode host) or its own namespace. Container bridges or veth host
// ends mean host. Otherwise every remaining interface (without lo and the
// tunnel stubs) is checked in /sys/class/net: a veth, macvlan or ipvlan end
// inside a container links to a device elsewhere (iflink != ifindex), a
// physical or virtual NIC of the host links to itself. Without sysfs a
// single remaining interface means own; anything else is unknown (MVP-21
// measurement finding 8: tunnel stubs were counted as host interfaces).
func (s *sampler) netNamespace() string {
	var rest []string
	for _, n := range s.ifNames() {
		if n == "lo" || isTunnelStub(n) {
			continue
		}
		if strings.HasPrefix(n, "docker") || strings.HasPrefix(n, "br-") || strings.HasPrefix(n, "veth") || strings.HasPrefix(n, "cni") {
			return "host"
		}
		rest = append(rest, n)
	}
	if len(rest) == 0 {
		return "unknown"
	}
	linked, self, unknown := 0, 0, 0
	for _, n := range rest {
		if !validObject(n) || strings.Contains(n, "/") || n == "." || n == ".." {
			unknown++
			continue
		}
		idx, err1 := s.read("sys/class/net/" + n + "/ifindex")
		link, err2 := s.read("sys/class/net/" + n + "/iflink")
		if err1 != nil || err2 != nil {
			unknown++
			continue
		}
		if strings.TrimSpace(string(idx)) == strings.TrimSpace(string(link)) {
			self++
		} else {
			linked++
		}
	}
	switch {
	case self > 0:
		return "host"
	case linked > 0 && unknown == 0:
		return "own"
	case unknown == 1 && len(rest) == 1:
		return "own"
	}
	return "unknown"
}

// ---------------------------------------------------------------- CPU, load

func parseCPU(f []string) cpuTimes {
	g := func(i int) float64 {
		if i < len(f) {
			return f64(f[i])
		}
		return 0
	}
	return cpuTimes{g(1), g(2), g(3), g(4), g(5), g(6), g(7), g(8)}
}

func ratio(a, b float64) float64 {
	if b <= 0 {
		return 0
	}
	return clamp01(a / b)
}

func clamp01(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

func (s *sampler) cpu(out *sample, dt float64, unav func(string, string)) {
	b, err := s.read("proc/stat")
	if err != nil {
		unav("cpu", reasonOf(err))
		return
	}
	var total cpuTimes
	var cores []cpuTimes
	for _, l := range strings.Split(string(b), "\n") {
		f := strings.Fields(l)
		if len(f) < 5 {
			continue
		}
		if f[0] == "cpu" {
			total = parseCPU(f)
		} else if strings.HasPrefix(f[0], "cpu") {
			cores = append(cores, parseCPU(f))
		}
	}
	n := len(cores)
	if n == 0 {
		n = 1
	}
	snapScope := "host"
	if out.snap.Environment.LXCFS {
		snapScope = "container"
	}
	c := &CPUSnapshot{Scope: snapScope, Cores: n}
	if s.p.ok && s.p.cpu.total() > 0 {
		p := s.p.cpu
		d := total.total() - p.total()
		idle := (total.idle - p.idle) + (total.iowait - p.iowait)
		c.Usage = ratio(d-idle, d)
		c.User = ratio(total.user+total.nice-p.user-p.nice, d)
		c.System = ratio(total.system+total.irq+total.softirq-p.system-p.irq-p.softirq, d)
		c.IOWait = ratio(total.iowait-p.iowait, d)
		c.Steal = ratio(total.steal-p.steal, d)
		if len(s.p.cores) == len(cores) {
			c.PerCore = make([]float64, len(cores))
			for i, x := range cores {
				q := s.p.cores[i]
				dd := x.total() - q.total()
				c.PerCore[i] = ratio(dd-((x.idle-q.idle)+(x.iowait-q.iowait)), dd)
			}
		}
		out.gauges["server.cpu_usage"] = c.Usage
		out.gauges["server.cpu_iowait"] = c.IOWait
		out.gauges["server.cpu_steal"] = c.Steal
		out.now.CPUUsage = ptr(c.Usage)
	}
	s.p.cpu, s.p.cores = total, cores
	out.now.Cores = ptr(n)
	if lb, err := s.read("proc/loadavg"); err == nil {
		if f := strings.Fields(string(lb)); len(f) >= 3 {
			c.Load1, c.Load5, c.Load15 = ptr(f64(f[0])), ptr(f64(f[1])), ptr(f64(f[2]))
			out.gauges["server.load1"], out.gauges["server.load5"], out.gauges["server.load15"] = *c.Load1, *c.Load5, *c.Load15
			out.now.Load1 = c.Load1
		}
	} else {
		unav("load", reasonOf(err))
	}
	out.snap.CPU = c
	_ = dt
}

// ---------------------------------------------------------------- memory

func (s *sampler) memory(out *sample, now time.Time, unav func(string, string)) {
	b, err := s.read("proc/meminfo")
	if err != nil {
		unav("memory", reasonOf(err))
		return
	}
	kv := map[string]int64{}
	for _, l := range strings.Split(string(b), "\n") {
		k, v, ok := strings.Cut(l, ":")
		if !ok {
			continue
		}
		f := strings.Fields(v)
		if len(f) == 0 {
			continue
		}
		n, _ := strconv.ParseInt(f[0], 10, 64)
		if len(f) > 1 && f[1] == "kB" {
			n *= 1024
		}
		kv[k] = n
	}
	total := kv["MemTotal"]
	avail, ok := kv["MemAvailable"]
	if !ok {
		avail = kv["MemFree"] + kv["Cached"] + kv["Buffers"]
	}
	scope := "host"
	if out.snap.Environment.LXCFS {
		scope = "container"
	}
	m := &MemorySnapshot{Scope: scope, TotalBytes: total, AvailableBytes: avail, UsedBytes: total - avail, CachedBytes: kv["Cached"],
		SwapTotalBytes: kv["SwapTotal"], SwapUsedBytes: kv["SwapTotal"] - kv["SwapFree"]}
	if vb, err := s.read("proc/vmstat"); err == nil {
		for _, l := range strings.Split(string(vb), "\n") {
			if v, ok := strings.CutPrefix(l, "pswpin "); ok {
				n := f64(v)
				if s.p.ok && s.p.pswpin > 0 {
					if dt := now.Sub(s.p.at).Seconds(); dt > 0 {
						out.swapIn = nonNeg(n-s.p.pswpin) * float64(os.Getpagesize()) / dt
					}
				}
				s.p.pswpin = n
			}
			if strings.HasPrefix(l, "oom_kill ") {
				n := f64(strings.TrimPrefix(l, "oom_kill "))
				s.p.oomHist = append(s.p.oomHist, oomPoint{now, n})
				for len(s.p.oomHist) > 1 && now.Sub(s.p.oomHist[0].at) > 24*time.Hour {
					s.p.oomHist = s.p.oomHist[1:]
				}
				k := int64(n - s.p.oomHist[0].n)
				m.OOMKills24h = &k
			}
		}
	}
	out.snap.Memory = m
	out.gauges["server.memory_used"] = float64(m.UsedBytes)
	out.gauges["server.memory_available"] = float64(m.AvailableBytes)
	out.gauges["server.swap_used"] = float64(m.SwapUsedBytes)
	out.now.MemoryUsedRatio = ptr(ratio(float64(m.UsedBytes), float64(total)))
	out.now.MemoryAvailableBytes = ptr(avail)
	out.now.SwapUsedBytes = ptr(m.SwapUsedBytes)
}

// ---------------------------------------------------------------- disks

var blockFS = map[string]bool{"ext2": true, "ext3": true, "ext4": true, "xfs": true, "btrfs": true, "zfs": true, "f2fs": true, "vfat": true}

type mountInfo struct{ point, device, fs, major string }

func unescapeMount(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	r := strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`)
	return r.Replace(s)
}

func (s *sampler) mountList() ([]mountInfo, error) {
	b, err := s.read("proc/self/mountinfo")
	if err != nil {
		return nil, err
	}
	var all []mountInfo
	for _, l := range strings.Split(string(b), "\n") {
		pre, post, ok := strings.Cut(l, " - ")
		if !ok {
			continue
		}
		f := strings.Fields(pre)
		g := strings.Fields(post)
		if len(f) < 5 || len(g) < 2 {
			continue
		}
		all = append(all, mountInfo{point: unescapeMount(f[4]), device: g[1], fs: g[0], major: f[2]})
	}
	return all, nil
}

// chosenMounts: monitoring.mounts, else one block file system per device
// (max 16), plus the storage path's file system.
func (s *sampler) chosenMounts(all []mountInfo) []mountInfo {
	var out []mountInfo
	seen := map[string]bool{}
	if len(s.cfg.Mounts) > 0 {
		for _, want := range s.cfg.Mounts {
			for _, m := range all {
				if m.point == want {
					out = append(out, m)
					break
				}
			}
		}
		return out
	}
	for _, m := range all {
		if !blockFS[m.fs] && m.point != "/" || seen[m.major] {
			continue
		}
		if !blockFS[m.fs] && !strings.HasPrefix(m.device, "/dev/") && m.fs != "overlay" {
			continue
		}
		seen[m.major] = true
		out = append(out, m)
		if len(out) == 16 {
			break
		}
	}
	if sp := s.cfg.StoragePath; sp != "" && len(out) < 16 {
		best := mountInfo{}
		for _, m := range all {
			if (strings.HasPrefix(sp, m.point) || m.point == "/") && len(m.point) > len(best.point) {
				best = m
			}
		}
		if best.point != "" && !seen[best.major] {
			out = append(out, best)
		}
	}
	return out
}

// rootPair names an overlay root and a block mount by their device numbers.
type rootPair struct{ root, mount string }

const (
	// overlayTries: how often a sample compares when the file system changed
	// between its two calls.
	overlayTries = 3
	// overlayApart: free bytes further apart than this are not explained by
	// writes between two calls (measured on one machine with six writers: at
	// most 16 MiB).
	overlayApart = 256 << 20
	// overlayApartFor: samples in a row that have to be apart before an
	// answer is taken back.
	overlayApartFor = 3
)

// foldOverlayRoot: in a container "/" is an overlay with a device number of
// its own, but its statfs is that of the file system it lies on. A volume on
// the same disk is then the same disk once more, so it is left out and the
// root takes its device (the overlay has none, and with it no disk I/O).
// Mounts named in monitoring.mounts stay as they are.
func (s *sampler) foldOverlayRoot(in []mountInfo) []mountInfo {
	root := -1
	for i, m := range in {
		if m.point == "/" && m.fs == "overlay" {
			root = i
		}
	}
	if root < 0 || len(s.cfg.Mounts) > 0 {
		return in
	}
	var out []mountInfo
	device := ""
	for i, m := range in {
		if i != root && blockFS[m.fs] && s.sameFS(in[root], m) {
			if device == "" {
				device = m.device
			}
			continue
		}
		out = append(out, m)
	}
	if device != "" {
		for i := range out {
			if out[i].point == "/" {
				out[i].device = device
			}
		}
	}
	return out
}

// sameFS: both mounts report the same sizes and the same free blocks and
// inodes, to the last one. The answer yes is kept, so that a file system
// under heavy writes does not come and go between samples, and is taken back
// when the two drift apart: a disk taken for another one would never show.
// The fsid does not tell: overlayfs has its own since Linux 6.6.
func (s *sampler) sameFS(root, m mountInfo) bool {
	k := rootPair{root.major, m.major}
	against, kept := s.rootOn[k]
	apart := true
	for range overlayTries {
		a, err := s.statfs(s.path(root.point))
		if err != nil {
			return kept
		}
		b, err := s.statfs(s.path(m.point))
		if err != nil {
			return kept
		}
		if a == b {
			s.rootOn[k] = 0
			return true
		}
		if !a.apart(b) {
			apart = false
		}
	}
	switch {
	case !kept:
		return false
	case !apart:
		s.rootOn[k] = 0
	case against+1 < overlayApartFor:
		s.rootOn[k] = against + 1
	default:
		delete(s.rootOn, k)
		return false
	}
	return true
}

// apart: the two differ by more than writes between two calls explain.
func (a fsStat) apart(b fsStat) bool {
	if a.blocks != b.blocks || a.bsize != b.bsize {
		return true
	}
	d := (a.bfree - b.bfree) * a.bsize
	return d > overlayApart || d < -overlayApart
}

func (s *sampler) mounts(out *sample, dt float64, unav func(string, string)) {
	all, err := s.mountList()
	if err != nil {
		unav("mounts", reasonOf(err))
		return
	}
	stats := s.diskstats(dt, unav)
	var fullest *cm.DiskNow
	for _, m := range s.foldOverlayRoot(s.chosenMounts(all)) {
		st, err := s.statfs(s.path(m.point))
		if err != nil {
			continue
		}
		size := st.blocks * st.bsize
		avail := st.bavail * st.bsize
		used := size - st.bfree*st.bsize
		ms := MountSnapshot{Mount: m.point, FSType: sanitizeFS(m.fs), SizeBytes: size, UsedBytes: used, AvailBytes: avail}
		if used+avail > 0 {
			ms.UsedRatio = clamp01(float64(used) / float64(used+avail))
		}
		if st.files > 0 {
			ms.InodesTotal = st.files
			ms.InodesUsed = st.files - st.ffree
		}
		dev := strings.TrimPrefix(m.device, "/dev/")
		if validObject(dev) {
			ms.Device = dev
		}
		if d, ok := stats[dev]; ok && dt > 0 {
			ms.ReadBytesPerS, ms.WriteBytesPerS = ptr(d.rdSect*512/dt), ptr(d.wrSect*512/dt)
			ms.ReadsPerS, ms.WritesPerS, ms.Busy = ptr(d.reads/dt), ptr(d.writes/dt), ptr(clamp01(d.ioMS/1000/dt))
			out.objects = append(out.objects, objectSample{object: dev, kind: "device",
				gauges:   map[string]float64{"server.disk_busy": *ms.Busy},
				counters: map[string]float64{"server.disk_read_bytes": d.rdSect * 512, "server.disk_write_bytes": d.wrSect * 512}})
		}
		if !validObject(m.point) {
			continue
		}
		out.snap.Mounts = append(out.snap.Mounts, ms)
		inodeRatio := 0.0
		if ms.InodesTotal > 0 {
			inodeRatio = float64(ms.InodesUsed) / float64(ms.InodesTotal)
		}
		out.objects = append(out.objects, objectSample{object: m.point, kind: "mount", gauges: map[string]float64{
			"server.disk_used": float64(used), "server.disk_used_ratio": ms.UsedRatio, "server.disk_inodes_used_ratio": inodeRatio}})
		r := max(ms.UsedRatio, inodeRatio)
		if fullest == nil || r > fullest.UsedRatio {
			fullest = &cm.DiskNow{Mount: m.point, UsedRatio: r}
		}
	}
	out.now.Disk = fullest
}

func sanitizeFS(s string) string {
	b := []byte(strings.ToLower(s))
	for i, c := range b {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-') {
			b[i] = '_'
		}
	}
	if len(b) > 32 {
		b = b[:32]
	}
	if len(b) == 0 {
		return "unknown"
	}
	return string(b)
}

// validObject: the MetricObject pattern.
func validObject(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("_.:@/-", c) >= 0) {
			return false
		}
	}
	return true
}

// diskstats returns the deltas per device since the last sample.
func (s *sampler) diskstats(dt float64, unav func(string, string)) map[string]diskCounters {
	b, err := s.read("proc/diskstats")
	if err != nil {
		unav("disk_io", reasonOf(err))
		return nil
	}
	cur := map[string]diskCounters{}
	for _, l := range strings.Split(string(b), "\n") {
		f := strings.Fields(l)
		if len(f) < 13 {
			continue
		}
		cur[f[2]] = diskCounters{reads: f64(f[3]), rdSect: f64(f[5]), writes: f64(f[7]), wrSect: f64(f[9]), ioMS: f64(f[12])}
	}
	delta := map[string]diskCounters{}
	if s.p.disks != nil && dt > 0 {
		for k, c := range cur {
			if p, ok := s.p.disks[k]; ok {
				delta[k] = diskCounters{rdSect: nonNeg(c.rdSect - p.rdSect), wrSect: nonNeg(c.wrSect - p.wrSect), reads: nonNeg(c.reads - p.reads), writes: nonNeg(c.writes - p.writes), ioMS: nonNeg(c.ioMS - p.ioMS)}
			}
		}
	}
	s.p.disks = cur
	return delta
}

func nonNeg(v float64) float64 {
	if v < 0 {
		return 0
	}
	return v
}

// ---------------------------------------------------------------- network

var virtualIf = []string{"veth", "docker", "br-", "cni", "flannel", "cali", "virbr", "vxlan", "tun", "tap"}

func (s *sampler) ifNames() []string {
	b, err := s.read("proc/net/dev")
	if err != nil {
		return nil
	}
	var out []string
	for _, l := range strings.Split(string(b), "\n") {
		if k, _, ok := strings.Cut(l, ":"); ok && !strings.Contains(k, "|") {
			out = append(out, strings.TrimSpace(k))
		}
	}
	return out
}

func (s *sampler) shownIf(name string) bool {
	if len(s.cfg.Interfaces) > 0 {
		for _, x := range s.cfg.Interfaces {
			if x == name {
				return true
			}
		}
		return false
	}
	if name == "lo" || isTunnelStub(name) {
		return false
	}
	for _, p := range virtualIf {
		if strings.HasPrefix(name, p) {
			return false
		}
	}
	return true
}

func (s *sampler) network(out *sample, dt float64, unav func(string, string)) {
	b, err := s.read("proc/net/dev")
	if err != nil {
		unav("interfaces", reasonOf(err))
		return
	}
	cur := map[string]ifCounters{}
	var names []string
	for _, l := range strings.Split(string(b), "\n") {
		k, v, ok := strings.Cut(l, ":")
		if !ok || strings.Contains(k, "|") {
			continue
		}
		name := strings.TrimSpace(k)
		f := strings.Fields(v)
		if len(f) < 16 || !s.shownIf(name) || !validObject(name) {
			continue
		}
		cur[name] = ifCounters{f64(f[0]), f64(f[1]), f64(f[2]), f64(f[3]), f64(f[8]), f64(f[9]), f64(f[10]), f64(f[11])}
		names = append(names, name)
	}
	sort.Strings(names)
	if len(names) > 16 {
		names = names[:16]
	}
	var rx, tx float64
	have := false
	for _, n := range names {
		c := cur[n]
		p, ok := s.p.ifs[n]
		if !ok || dt <= 0 {
			continue
		}
		d := ifCounters{nonNeg(c.rxB - p.rxB), nonNeg(c.rxP - p.rxP), nonNeg(c.rxE - p.rxE), nonNeg(c.rxD - p.rxD), nonNeg(c.txB - p.txB), nonNeg(c.txP - p.txP), nonNeg(c.txE - p.txE), nonNeg(c.txD - p.txD)}
		out.snap.Interfaces = append(out.snap.Interfaces, InterfaceSnapshot{Name: n, RxBytesPerS: d.rxB / dt, TxBytesPerS: d.txB / dt, RxPacketsPerS: d.rxP / dt, TxPacketsPerS: d.txP / dt,
			ErrorsPerS: (d.rxE + d.txE) / dt, DropsPerS: (d.rxD + d.txD) / dt})
		out.objects = append(out.objects, objectSample{object: n, kind: "interface", counters: map[string]float64{
			"server.net_rx_bytes": d.rxB, "server.net_tx_bytes": d.txB, "server.net_errors": d.rxE + d.txE, "server.net_drops": d.rxD + d.txD}})
		rx += d.rxB / dt
		tx += d.txB / dt
		have = true
	}
	s.p.ifs = cur
	if have {
		out.now.NetRxBytesPerS, out.now.NetTxBytesPerS = ptr(rx), ptr(tx)
	}
}

// ---------------------------------------------------------------- TCP

// TCP states of /proc/net/tcp (hex) -> index into the counts of tcp().
var tcpStates = map[string]int{"01": 0, "02": 1, "03": 2, "04": 3, "05": 3, "06": 4, "08": 5, "09": 6, "0B": 7, "0A": 8}

// procTCPMax: above this many sockets (sockstat) the per-state scan of
// /proc/net/tcp{,6} is skipped. The kernel formats every line, about
// 1.7-2.5 µs per socket: 50000 lines took 56-61 ms (MVP-21 measurement
// finding 6), 19800 lines 34-50 ms, about 0.35 % of a core at one sample
// per 10 s (D36 measurement A.3.6). Background load must stay under 0.2 %
// of a core (20 ms per 10 s); 5000 sockets keep the scan near 10 ms even
// at the slow end.
const procTCPMax = 5000

// procTCPLines caps the lines one scan reads (without sockstat totals the
// scan is the only source).
const procTCPLines = 20000

// procTCPBudget: the scan is also skipped when the cost per socket of the
// last scans predicts more than this (a slow or busy machine).
const procTCPBudget = 10 * time.Millisecond

// sockstat holds the TCP totals of /proc/net/sockstat and sockstat6.
type sockstat struct {
	inuse, orphan, tw int64
	ok                bool
}

func (s *sampler) sockstat() sockstat {
	var st sockstat
	for _, f := range []struct{ file, prefix string }{{"proc/net/sockstat", "TCP:"}, {"proc/net/sockstat6", "TCP6:"}} {
		b, err := s.read(f.file)
		if err != nil {
			continue
		}
		for _, l := range strings.Split(string(b), "\n") {
			if !strings.HasPrefix(l, f.prefix) {
				continue
			}
			st.ok = true
			fl := strings.Fields(l)
			for i := 1; i+1 < len(fl); i += 2 {
				n, _ := strconv.ParseInt(fl[i+1], 10, 64)
				switch fl[i] {
				case "inuse":
					st.inuse += n
				case "orphan":
					st.orphan += n
				case "tw":
					st.tw += n
				}
			}
		}
	}
	return st
}

// tcpStateField returns the 4th whitespace-separated field (st) of a
// /proc/net/tcp line without allocating.
func tcpStateField(l []byte) []byte {
	field := 0
	i := 0
	for i < len(l) {
		for i < len(l) && (l[i] == ' ' || l[i] == '\t') {
			i++
		}
		j := i
		for j < len(l) && l[j] != ' ' && l[j] != '\t' && l[j] != '\n' {
			j++
		}
		if j == i {
			return nil
		}
		if field == 3 {
			return l[i:j]
		}
		field++
		i = j
	}
	return nil
}

// scanProcTCP counts sockets per state; false when no file could be read.
// It keeps the cost per socket for scanWorth.
func (s *sampler) scanProcTCP(counts *[9]int64) bool {
	t0 := time.Now()
	ok := false
	lines := 0
	defer func() {
		if lines >= 100 {
			ns := float64(time.Since(t0).Nanoseconds()) / float64(lines)
			if s.p.tcpNsPerSocket == 0 {
				s.p.tcpNsPerSocket = ns
			} else {
				s.p.tcpNsPerSocket = 0.7*s.p.tcpNsPerSocket + 0.3*ns
			}
		}
	}()
	for _, f := range []string{"proc/net/tcp", "proc/net/tcp6"} {
		fh, err := os.Open(s.path(f))
		if err != nil {
			continue
		}
		ok = true
		r := bufio.NewReaderSize(fh, 64<<10)
		first := true
		for lines <= procTCPLines {
			l, err := r.ReadSlice('\n')
			if len(l) > 0 && !first {
				lines++
				if st := tcpStateField(l); len(st) == 2 {
					if i, ok := tcpStates[string(st)]; ok {
						counts[i]++
					}
				}
			}
			first = false
			if err != nil {
				break
			}
		}
		fh.Close()
	}
	return ok
}

// scanWorth reports whether the per-state scan fits: at most procTCPMax
// sockets and a predicted cost within procTCPBudget.
func (s *sampler) scanWorth(ss sockstat) bool {
	if !ss.ok {
		return true // no totals: the scan is the only source
	}
	n := ss.inuse + ss.tw
	if n > procTCPMax {
		return false
	}
	return s.p.tcpNsPerSocket == 0 || time.Duration(float64(n)*s.p.tcpNsPerSocket) <= procTCPBudget
}

func (s *sampler) tcp(out *sample, dt float64, unav func(string, string)) {
	t := &TCPSnapshot{Source: "proc"}
	var counts [9]int64
	ss := s.sockstat()
	// The cheap totals first: with many sockets the state scan is skipped.
	scanned := false
	if s.scanWorth(ss) {
		scanned = s.scanProcTCP(&counts)
	}
	if !scanned {
		if !ss.ok {
			unav("tcp", "not_present")
			return
		}
		t.Source = "sockstat"
		t.InUse, t.Orphan = ptr(ss.inuse), ptr(ss.orphan)
		counts = [9]int64{}
		counts[0], counts[4] = ss.inuse, ss.tw
	}
	t.Established, t.SynSent, t.SynRecv, t.FinWait, t.TimeWait, t.CloseWait, t.LastAck, t.Closing = counts[0], counts[1], counts[2], counts[3], counts[4], counts[5], counts[6], counts[7]
	if scanned {
		// D36 amendment: sockstat has no listen count; null, never 0.
		t.Listen = ptr(counts[8])
	}
	drops, retrans := s.netstatValue("proc/net/netstat", "TcpExt:", "ListenDrops"), s.netstatValue("proc/net/snmp", "Tcp:", "RetransSegs")
	if drops >= 0 && s.p.ok && dt > 0 && s.p.drops >= 0 {
		d := nonNeg(drops - s.p.drops)
		t.ListenDropsPerS = ptr(d / dt)
		out.counters["server.tcp_listen_drops"] = d
	}
	if retrans >= 0 && s.p.ok && dt > 0 && s.p.retrans >= 0 {
		d := nonNeg(retrans - s.p.retrans)
		t.RetransPerS = ptr(d / dt)
		out.counters["server.tcp_retransmits"] = d
	}
	s.p.drops, s.p.retrans = drops, retrans
	out.snap.TCP = t
	out.gauges["server.tcp_established"] = float64(t.Established)
	out.gauges["server.tcp_syn_recv"] = float64(t.SynRecv)
	out.gauges["server.tcp_time_wait"] = float64(t.TimeWait)
	out.gauges["server.tcp_close_wait"] = float64(t.CloseWait)
}

// netstatValue reads a "Prefix: names" / "Prefix: values" pair (-1 if absent).
func (s *sampler) netstatValue(file, prefix, name string) float64 {
	b, err := s.read(file)
	if err != nil {
		return -1
	}
	var hdr []string
	for _, l := range strings.Split(string(b), "\n") {
		if !strings.HasPrefix(l, prefix) {
			continue
		}
		f := strings.Fields(l)
		if hdr == nil {
			hdr = f
			continue
		}
		for i, h := range hdr {
			if h == name && i < len(f) {
				return f64(f[i])
			}
		}
		return -1
	}
	return -1
}

func (s *sampler) conntrackFiles(out *sample, unav func(string, string)) {
	cb, err1 := s.read("proc/sys/net/netfilter/nf_conntrack_count")
	mb, err2 := s.read("proc/sys/net/netfilter/nf_conntrack_max")
	switch {
	case out.snap.Environment.Container && out.snap.Environment.NetNamespace == "own":
		// The count of an own namespace is not the server's table (spec
		// MVP-21 containers): say so instead of showing 0 of the global max.
		unav("conntrack", "container_hidden")
	case err1 == nil && err2 == nil:
		c := &Conntrack{Count: int64(f64(strings.TrimSpace(string(cb)))), Max: int64(f64(strings.TrimSpace(string(mb))))}
		if c.Max > 0 {
			out.snap.Conntrack = c
			out.gauges["server.conntrack_used_ratio"] = ratio(float64(c.Count), float64(c.Max))
		}
	case out.snap.Environment.Container && out.snap.Environment.NetNamespace != "host":
		unav("conntrack", "container_hidden")
	default:
		e := err1
		if e == nil {
			e = err2
		}
		unav("conntrack", reasonOf(e))
	}
	if b, err := s.read("proc/sys/fs/file-nr"); err == nil {
		if f := strings.Fields(string(b)); len(f) >= 3 {
			fl := &Files{Open: int64(f64(f[0])), Max: int64(f64(f[2]))}
			if fl.Max > 0 {
				out.snap.Files = fl
				out.gauges["server.files_open_ratio"] = ratio(float64(fl.Open), float64(fl.Max))
			}
		}
	} else {
		unav("files", reasonOf(err))
	}
}

// ---------------------------------------------------------------- cgroup v2

func (s *sampler) container(out *sample, dt float64) {
	env := out.snap.Environment
	if !env.Container {
		return
	}
	if env.Cgroup != "v2" {
		out.snap.Unavailable = append(out.snap.Unavailable, Unavailable{"container", "cgroup_v1"})
		return
	}
	dir := "sys/fs/cgroup"
	if b, err := s.read("proc/self/cgroup"); err == nil {
		for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
			if p, ok := strings.CutPrefix(l, "0::"); ok && p != "/" {
				if _, err := os.Stat(s.path(filepath.Join(dir, p))); err == nil {
					dir = filepath.Join(dir, p)
				}
			}
		}
	}
	c := &ContainerSnapshot{}
	cores := float64(len(s.p.cores))
	if cores == 0 {
		cores = float64(runtime.NumCPU())
	}
	if b, err := s.read(filepath.Join(dir, "cpu.max")); err == nil {
		if f := strings.Fields(string(b)); len(f) == 2 && f[0] != "max" {
			if p := f64(f[1]); p > 0 {
				c.CPULimitCores = ptr(f64(f[0]) / p)
			}
		}
	}
	if b, err := s.read(filepath.Join(dir, "cpu.stat")); err == nil {
		var usage, throt, periods float64
		for _, l := range strings.Split(string(b), "\n") {
			f := strings.Fields(l)
			if len(f) != 2 {
				continue
			}
			switch f[0] {
			case "usage_usec":
				usage = f64(f[1])
			case "nr_throttled":
				throt = f64(f[1])
			case "nr_periods":
				periods = f64(f[1])
			}
		}
		if s.p.ok && dt > 0 && s.p.cgUsage > 0 {
			limit := cores
			if c.CPULimitCores != nil {
				limit = *c.CPULimitCores
			}
			c.CPUUsage = ratio((usage-s.p.cgUsage)/1e6/dt, limit)
			c.CPUThrottled = ratio(throt-s.p.cgThrot, periods-s.p.cgPeriod)
			out.gauges["container.cpu_usage"] = c.CPUUsage
			out.gauges["container.cpu_throttled"] = c.CPUThrottled
		}
		s.p.cgUsage, s.p.cgThrot, s.p.cgPeriod = usage, throt, periods
	}
	if b, err := s.read(filepath.Join(dir, "memory.current")); err == nil {
		c.MemoryUsedBytes = int64(f64(strings.TrimSpace(string(b))))
		out.gauges["container.memory_used"] = float64(c.MemoryUsedBytes)
	}
	if b, err := s.read(filepath.Join(dir, "memory.max")); err == nil {
		if v := strings.TrimSpace(string(b)); v != "max" {
			c.MemoryLimitBytes = ptr(int64(f64(v)))
		}
	}
	if b, err := s.read(filepath.Join(dir, "memory.events")); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			if v, ok := strings.CutPrefix(l, "oom_kill "); ok {
				c.OOMKills = int64(f64(v))
			}
		}
	}
	out.snap.Container = c
}

// ---------------------------------------------------------------- process

func (s *sampler) process(out *sample, dt float64) {
	p := &out.snap.Process
	p.StartedAt = ts(s.cfg.Started)
	p.Version = trimTo(s.cfg.Version, 64)
	metrics.Read(s.mets)
	if v := s.mets[0].Value; v.Kind() == metrics.KindUint64 {
		p.HeapBytes = int64(v.Uint64())
	}
	if v := s.mets[1].Value; v.Kind() == metrics.KindUint64 {
		p.Goroutines = int64(v.Uint64())
	}
	if v := s.mets[2].Value; v.Kind() == metrics.KindFloat64Histogram {
		p.GCPauseP99MS = histQuantile(v.Float64Histogram(), 0.99) * 1000
	}
	cores := float64(runtime.NumCPU())
	var cpuSec float64
	if s.cfg.Linux {
		if b, err := s.read("proc/self/stat"); err == nil {
			if i := bytes.LastIndexByte(b, ')'); i > 0 {
				f := strings.Fields(string(b[i+2:]))
				if len(f) > 21 {
					cpuSec = (f64(f[11]) + f64(f[12])) / 100
					p.Threads = int64(f64(f[17]))
					p.RSSBytes = int64(f64(f[21])) * int64(os.Getpagesize())
				}
			}
		}
		if es, err := os.ReadDir(s.path("proc/self/fd")); err == nil {
			p.OpenFiles = int64(len(es))
		}
	} else {
		var ru unix.Rusage
		if unix.Getrusage(unix.RUSAGE_SELF, &ru) == nil {
			cpuSec = float64(ru.Utime.Sec) + float64(ru.Utime.Usec)/1e6 + float64(ru.Stime.Sec) + float64(ru.Stime.Usec)/1e6
			p.RSSBytes = int64(ru.Maxrss) // bytes on macOS
		}
		p.Threads = int64(runtime.GOMAXPROCS(0))
	}
	var rl unix.Rlimit
	if unix.Getrlimit(unix.RLIMIT_NOFILE, &rl) == nil {
		p.OpenFilesLimit = int64(rl.Cur)
	}
	if s.p.ok && dt > 0 && s.p.procCPU > 0 {
		p.CPUUsage = ratio((cpuSec-s.p.procCPU)/dt, cores)
	}
	s.p.procCPU = cpuSec
	out.gauges["process.cpu_usage"] = p.CPUUsage
	out.gauges["process.rss"] = float64(p.RSSBytes)
	out.gauges["process.heap"] = float64(p.HeapBytes)
	out.gauges["process.goroutines"] = float64(p.Goroutines)
	out.gauges["process.gc_pause_p99"] = p.GCPauseP99MS
	out.gauges["process.open_files"] = float64(p.OpenFiles)
	if !s.cfg.Linux || !s.cfg.Host {
		out.now.CPUUsage = ptr(p.CPUUsage)
	}
}

func histQuantile(h *metrics.Float64Histogram, q float64) float64 {
	var total uint64
	for _, c := range h.Counts {
		total += c
	}
	if total == 0 {
		return 0
	}
	target := uint64(q * float64(total))
	var cum uint64
	for i, c := range h.Counts {
		cum += c
		if cum >= target {
			b := h.Buckets[i+1]
			if b > 1e9 {
				b = h.Buckets[i]
			}
			return b
		}
	}
	return 0
}

// ---------------------------------------------------------------- OS

func (s *sampler) os(snap *ServerSnapshot, unav func(string, string)) {
	if s.cfg.OS != nil {
		if o := s.cfg.OS(); o != nil {
			snap.OS = o
			return
		}
	}
	var u unix.Utsname
	if err := unix.Uname(&u); err != nil {
		unav("os", "not_present")
		return
	}
	name := unix.ByteSliceToString(u.Sysname[:])
	// In a container os-release names the image ("Distroless"), not the server: the kernel's name stays.
	if s.cfg.Linux && !snap.Environment.Container {
		if b, err := s.read("etc/os-release"); err == nil {
			for _, l := range strings.Split(string(b), "\n") {
				if v, ok := strings.CutPrefix(l, "PRETTY_NAME="); ok {
					name = strings.Trim(v, `"`)
				}
			}
		}
	}
	snap.OS = &HostOS{Source: "uname", Name: trimTo(name, 128), Kernel: trimTo(unix.ByteSliceToString(u.Release[:]), 64), Arch: trimTo(runtime.GOARCH, 16)}
}

func trimTo(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

type fsStat struct{ blocks, bfree, bavail, bsize, files, ffree int64 }

func statfs(p string) (fsStat, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(p, &st); err != nil {
		return fsStat{}, err
	}
	return fsStat{int64(st.Blocks), int64(st.Bfree), int64(st.Bavail), int64(st.Bsize), int64(st.Files), int64(st.Ffree)}, nil //nolint:unconvert // field types differ per OS
}
