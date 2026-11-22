// Command tool carries the three helpers of the MVP-27 hardening measurement.
// Standard library only; it imports nothing of schild and runs on 127.0.0.1.
//
//	tool backend -listen 127.0.0.1:P
//	    the application behind the gateways: 200 "ok" to everything
//	tool load -targets P1,P2,P3 -rps N -duration S [...] -out FILE
//	    open-loop load over several gateways with latency per request
//	tool proxy -control 127.0.0.1:P
//	    a TCP proxy between the nodes of a group that can hold, delay and
//	    refuse the bytes of one direction between two nodes
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: tool backend|load|proxy ...")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "backend":
		backend(os.Args[2:])
	case "load":
		load(os.Args[2:])
	case "proxy":
		proxy(os.Args[2:])
	default:
		fmt.Fprintln(os.Stderr, "unknown command")
		os.Exit(2)
	}
}

// ---------------------------------------------------------------- backend

func backend(args []string) {
	fs := flag.NewFlagSet("backend", flag.ExitOnError)
	listen := fs.String("listen", "127.0.0.1:19190", "address")
	fs.Parse(args)
	body := []byte("ok\n")
	srv := &http.Server{Addr: *listen, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Length", "3")
		w.Write(body)
	})}
	if err := srv.ListenAndServe(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// ---------------------------------------------------------------- load

type sample struct {
	target int
	status int // 0: no answer
	ms     float32
	at     float32 // seconds since the start
}

type job struct {
	seq   int
	sched time.Time
}

func quantile(sorted []float32, q float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	i := int(q*float64(len(sorted))+0.5) - 1
	if i < 0 {
		i = 0
	}
	if i >= len(sorted) {
		i = len(sorted) - 1
	}
	return float64(sorted[i])
}

func summarise(ms []float32) map[string]any {
	sort.Slice(ms, func(i, j int) bool { return ms[i] < ms[j] })
	if len(ms) == 0 {
		return map[string]any{"n": 0}
	}
	r := func(v float64) float64 { return float64(int(v*1000+0.5)) / 1000 }
	return map[string]any{"n": len(ms), "p50": r(quantile(ms, 0.50)), "p90": r(quantile(ms, 0.90)), "p99": r(quantile(ms, 0.99)),
		"p999": r(quantile(ms, 0.999)), "max": r(float64(ms[len(ms)-1])), "min": r(float64(ms[0]))}
}

func load(args []string) {
	fs := flag.NewFlagSet("load", flag.ExitOnError)
	targets := fs.String("targets", "", "comma list of proxy ports")
	rps := fs.Float64("rps", 100, "requests a second over all targets")
	duration := fs.Float64("duration", 10, "seconds")
	conns := fs.Int("conns", 16, "connections per target")
	seed := fs.Int64("seed", 27, "seed of the client addresses")
	ips := fs.Int("ips", 500, "client addresses per target (sticky) or in all (spread)")
	ipnet := fs.String("ipnet", "10.27", "first two bytes of the client addresses")
	spread := fs.Bool("spread", false, "every client address goes to every target in turn (round robin); default: an address stays on one target")
	prefix := fs.String("path", "/ld", "path prefix; the path is PREFIX/t<target>/<0..63>")
	fixedPath := fs.String("fixed-path", "", "use exactly this path for every request")
	host := fs.String("host", "shop.example", "Host header")
	attackEvery := fs.Int("attack-every", 0, "every n-th request carries an XSS probe in its query")
	health := fs.Bool("health", false, "act as a balancer: follow /.schild/readyz every 200 ms and send nothing new to a target that is not ready")
	perIP := fs.Bool("per-ip", false, "report the answers per client address")
	out := fs.String("out", "", "result file (JSON); default stdout")
	fs.Parse(args)

	var ports []int
	for _, p := range strings.Split(*targets, ",") {
		n, err := strconv.Atoi(strings.TrimSpace(p))
		if err != nil {
			fmt.Fprintln(os.Stderr, "bad target", p)
			os.Exit(2)
		}
		ports = append(ports, n)
	}
	nt := len(ports)
	clients := make([]*http.Client, nt)
	for i := range ports {
		tr := &http.Transport{MaxConnsPerHost: *conns, MaxIdleConnsPerHost: *conns, IdleConnTimeout: 30 * time.Second,
			DisableCompression: true, ResponseHeaderTimeout: 10 * time.Second,
			DialContext: (&net.Dialer{Timeout: 2 * time.Second}).DialContext}
		clients[i] = &http.Client{Transport: tr, Timeout: 10 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	up := make([]atomic.Bool, nt)
	for i := range up {
		up[i].Store(true)
	}
	stop := make(chan struct{})
	if *health {
		hc := &http.Client{Timeout: 500 * time.Millisecond, Transport: &http.Transport{DisableKeepAlives: true}}
		for i := range ports {
			go func(i int) {
				for {
					select {
					case <-stop:
						return
					default:
					}
					ok := false
					resp, err := hc.Get(fmt.Sprintf("http://127.0.0.1:%d/.schild/readyz", ports[i]))
					if err == nil {
						io.Copy(io.Discard, resp.Body)
						resp.Body.Close()
						ok = resp.StatusCode == 200
					}
					if !ok && up[i].Load() {
						// as a balancer: no connection is kept to a node that is out
						clients[i].Transport.(*http.Transport).CloseIdleConnections()
					}
					up[i].Store(ok)
					time.Sleep(200 * time.Millisecond)
				}
			}(i)
		}
		time.Sleep(450 * time.Millisecond)
	}

	total := int(*rps * *duration)
	queues := make([]chan job, nt)
	for i := range queues {
		queues[i] = make(chan job, 1<<16)
	}
	var mu sync.Mutex
	samples := make([]sample, 0, total)
	ipOK := map[string]int{}
	var lateMax atomic.Int64
	var skipped atomic.Int64
	start := time.Now()
	var wg sync.WaitGroup
	rng := rand.New(rand.NewSource(*seed))
	// the address of every request is fixed before the run, from the seed
	addrIdx := make([]int32, total)
	for i := range addrIdx {
		addrIdx[i] = int32(rng.Intn(*ips))
	}
	ipOf := func(target, k int) string {
		if *spread {
			return fmt.Sprintf("%s.%d.%d", *ipnet, 200+k/250, k%250+1)
		}
		return fmt.Sprintf("%s.%d.%d", *ipnet, target*12+k/250, k%250+1)
	}
	worker := func(t int) {
		defer wg.Done()
		local := make([]sample, 0, total/(nt**conns)+16)
		localIP := map[string]int{}
		for j := range queues[t] {
			if lag := time.Since(j.sched).Milliseconds(); lag > lateMax.Load() {
				lateMax.Store(lag)
			}
			ip := ipOf(t, int(addrIdx[j.seq]))
			path := *fixedPath
			if path == "" {
				path = fmt.Sprintf("%s/t%d/%d", *prefix, t, j.seq%64)
			}
			if *attackEvery > 0 && j.seq%*attackEvery == 0 {
				path += "?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"
			}
			req, _ := http.NewRequest("GET", fmt.Sprintf("http://127.0.0.1:%d%s", ports[t], path), nil)
			req.Host = *host
			req.Header.Set("User-Agent", "Mozilla/5.0 (measure MVP-27 hardening)")
			req.Header.Set("X-Forwarded-For", ip)
			t0 := time.Now()
			st := 0
			resp, err := clients[t].Do(req)
			if err == nil {
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				st = resp.StatusCode
			}
			local = append(local, sample{t, st, float32(time.Since(t0).Seconds() * 1000), float32(t0.Sub(start).Seconds())})
			if *perIP && st == 200 {
				localIP[ip]++
			}
		}
		mu.Lock()
		samples = append(samples, local...)
		for k, v := range localIP {
			ipOK[k] += v
		}
		mu.Unlock()
	}
	for t := 0; t < nt; t++ {
		for c := 0; c < *conns; c++ {
			wg.Add(1)
			go worker(t)
		}
	}
	gap := time.Duration(float64(time.Second) / *rps)
	for i := 0; i < total; i++ {
		due := start.Add(time.Duration(i) * gap)
		if d := time.Until(due); d > 0 {
			time.Sleep(d)
		}
		t := i % nt
		if *health && !up[t].Load() {
			found := false
			for k := 1; k < nt; k++ {
				if up[(t+k)%nt].Load() {
					t, found = (t+k)%nt, true
					break
				}
			}
			if !found {
				skipped.Add(1)
				continue
			}
		}
		select {
		case queues[t] <- job{i, due}:
		default:
			skipped.Add(1)
		}
	}
	for _, q := range queues {
		close(q)
	}
	wg.Wait()
	close(stop)
	elapsed := time.Since(start).Seconds()

	type per struct {
		Status map[string]int `json:"status"`
		Lat    map[string]any `json:"latency_ms"`
	}
	res := map[string]any{"targets": ports, "rps_asked": *rps, "duration_s": elapsed, "sent": len(samples),
		"rps_achieved": float64(len(samples)) / elapsed, "skipped": skipped.Load(), "max_queue_lag_ms": lateMax.Load(), "seed": *seed}
	all := make([]float32, 0, len(samples))
	status := map[string]int{}
	perT := make([]per, nt)
	latT := make([][]float32, nt)
	for i := range perT {
		perT[i].Status = map[string]int{}
	}
	secs := int(elapsed) + 2
	timeline := make([][]int, nt) // per target and second: answered, failed
	for i := range timeline {
		timeline[i] = make([]int, 2*secs)
	}
	var failures []map[string]any
	for _, s := range samples {
		k := strconv.Itoa(s.status)
		status[k]++
		perT[s.target].Status[k]++
		sec := int(s.at)
		if sec >= secs {
			sec = secs - 1
		}
		if s.status == 0 {
			timeline[s.target][2*sec+1]++
			if len(failures) < 50 {
				failures = append(failures, map[string]any{"target": ports[s.target], "at_s": s.at, "ms": s.ms})
			}
		} else {
			timeline[s.target][2*sec]++
			all = append(all, s.ms)
			latT[s.target] = append(latT[s.target], s.ms)
		}
	}
	for i := range perT {
		perT[i].Lat = summarise(latT[i])
	}
	res["status"], res["latency_ms"], res["per_target"], res["failed"] = status, summarise(all), perT, status["0"]
	res["timeline_answered_failed"], res["first_failures"] = timeline, failures
	if *perIP {
		res["ok_per_ip"] = ipOK
	}
	b, _ := json.Marshal(res)
	if *out == "" {
		os.Stdout.Write(append(b, '\n'))
	} else if err := os.WriteFile(*out, b, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// ---------------------------------------------------------------- proxy

// A rule says what happens to the bytes that travel from node From to node
// To, whoever opened the connection. "*" stands for every node.
type rule struct {
	From    string `json:"from"`
	To      string `json:"to"`
	Block   bool   `json:"block"`    // bytes are held (not lost) until the rule ends, new connections wait
	Refuse  bool   `json:"refuse"`   // connections opened by From to To are closed at once
	DelayMS int    `json:"delay_ms"` // every chunk arrives that much later
}

type link struct {
	Listen int    `json:"listen"`
	Target int    `json:"target"`
	Node   string `json:"node"`
}

type fault struct {
	mu      sync.RWMutex
	rules   []rule
	pids    map[int]string
	conns   map[*pconn]struct{}
	opened  map[string]int
	bytes   map[string]int64
	unknown int
	log     []string
}

type pconn struct {
	from, to string
	a, b     net.Conn
	once     sync.Once
}

func (c *pconn) close() {
	c.once.Do(func() {
		c.a.Close()
		if c.b != nil {
			c.b.Close()
		}
	})
}

func (f *fault) match(from, to string) (r rule) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	for _, x := range f.rules {
		if (x.From == "*" || x.From == from) && (x.To == "*" || x.To == to) {
			r.Block = r.Block || x.Block
			r.Refuse = r.Refuse || x.Refuse
			if x.DelayMS > r.DelayMS {
				r.DelayMS = x.DelayMS
			}
		}
	}
	return r
}

func (f *fault) note(format string, a ...any) {
	f.mu.Lock()
	f.log = append(f.log, time.Now().UTC().Format("15:04:05.000 ")+fmt.Sprintf(format, a...))
	if len(f.log) > 400 {
		f.log = f.log[len(f.log)-400:]
	}
	f.mu.Unlock()
}

var netstatLine = regexp.MustCompile(`^tcp4\s+\d+\s+\d+\s+(\S+)\s+(\S+)\s+.*?:(\d+)\s+[0-9a-f]{5}\s`)

// pidOf answers the process that holds the other end of a loopback
// connection, from netstat (no root needed for the pid column).
func pidOf(srcPort, dstPort int) int {
	want1, want2 := fmt.Sprintf("127.0.0.1.%d", srcPort), fmt.Sprintf("127.0.0.1.%d", dstPort)
	for try := 0; try < 3; try++ {
		out, err := exec.Command("netstat", "-anv", "-p", "tcp").Output()
		if err == nil {
			sc := bufio.NewScanner(strings.NewReader(string(out)))
			sc.Buffer(make([]byte, 1<<16), 1<<20)
			for sc.Scan() {
				m := netstatLine.FindStringSubmatch(sc.Text())
				if m != nil && m[1] == want1 && m[2] == want2 {
					pid, _ := strconv.Atoi(m[3])
					return pid
				}
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	return 0
}

type chunk struct {
	data []byte
	at   time.Time
	eof  bool
}

// pump carries the bytes of one direction; from and to name the nodes the
// bytes travel between.
func (f *fault) pump(c *pconn, in, out net.Conn, from, to string, done *sync.WaitGroup) {
	defer done.Done()
	q := make(chan chunk, 512)
	go func() {
		for {
			buf := make([]byte, 16<<10)
			n, err := in.Read(buf)
			if n > 0 {
				q <- chunk{data: buf[:n], at: time.Now()}
			}
			if err != nil {
				q <- chunk{eof: true, at: time.Now()}
				close(q)
				return
			}
		}
	}()
	key := from + ">" + to
	for ch := range q {
		for {
			r := f.match(from, to)
			if r.Block {
				time.Sleep(5 * time.Millisecond)
				continue
			}
			if wait := time.Until(ch.at.Add(time.Duration(r.DelayMS) * time.Millisecond)); wait > 0 {
				if wait > 5*time.Millisecond {
					wait = 5 * time.Millisecond
				}
				time.Sleep(wait)
				continue
			}
			break
		}
		if ch.eof {
			if t, ok := out.(*net.TCPConn); ok {
				t.CloseWrite()
			}
			break
		}
		if _, err := out.Write(ch.data); err != nil {
			c.close()
			break
		}
		f.mu.Lock()
		f.bytes[key] += int64(len(ch.data))
		f.mu.Unlock()
	}
	for range q { // let the reader end
	}
}

func (f *fault) serve(l link, ln net.Listener) {
	for {
		a, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			src := a.RemoteAddr().(*net.TCPAddr).Port
			pid := pidOf(src, l.Listen)
			f.mu.Lock()
			from := f.pids[pid]
			if from == "" {
				from = "?"
				f.unknown++
			}
			f.opened[from+">"+l.Node]++
			c := &pconn{from: from, to: l.Node, a: a}
			f.conns[c] = struct{}{}
			f.mu.Unlock()
			defer func() {
				c.close()
				f.mu.Lock()
				delete(f.conns, c)
				f.mu.Unlock()
			}()
			if f.match(from, l.Node).Refuse {
				f.note("refused %s>%s", from, l.Node)
				return
			}
			// a connection whose first packet would be lost: wait until the way is open or the caller gives up
			waited := false
			for f.match(from, l.Node).Block {
				waited = true
				time.Sleep(10 * time.Millisecond)
				if f.match(from, l.Node).Refuse {
					return
				}
			}
			if waited {
				f.note("held connection %s>%s goes on", from, l.Node)
			}
			b, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", l.Target), 2*time.Second)
			if err != nil {
				return
			}
			c.b = b
			var wg sync.WaitGroup
			wg.Add(2)
			go f.pump(c, a, b, from, l.Node, &wg)
			go f.pump(c, b, a, l.Node, from, &wg)
			wg.Wait()
		}()
	}
}

func proxy(args []string) {
	fs := flag.NewFlagSet("proxy", flag.ExitOnError)
	control := fs.String("control", "127.0.0.1:19191", "control address")
	fs.Parse(args)
	f := &fault{pids: map[int]string{}, conns: map[*pconn]struct{}{}, opened: map[string]int{}, bytes: map[string]int64{}}
	listening := map[int]bool{}
	mux := http.NewServeMux()
	mux.HandleFunc("/links", func(w http.ResponseWriter, r *http.Request) {
		var ls []link
		if json.NewDecoder(r.Body).Decode(&ls) != nil {
			http.Error(w, "bad", 400)
			return
		}
		for _, l := range ls {
			if listening[l.Listen] {
				continue
			}
			ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", l.Listen))
			if err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
			listening[l.Listen] = true
			go f.serve(l, ln)
		}
		w.Write([]byte("{}"))
	})
	mux.HandleFunc("/pids", func(w http.ResponseWriter, r *http.Request) {
		var m map[string]string
		if json.NewDecoder(r.Body).Decode(&m) != nil {
			http.Error(w, "bad", 400)
			return
		}
		p := map[int]string{}
		for k, v := range m {
			n, _ := strconv.Atoi(k)
			p[n] = v
		}
		f.mu.Lock()
		f.pids = p
		f.mu.Unlock()
		w.Write([]byte("{}"))
	})
	mux.HandleFunc("/rules", func(w http.ResponseWriter, r *http.Request) {
		var rs []rule
		if json.NewDecoder(r.Body).Decode(&rs) != nil {
			http.Error(w, "bad", 400)
			return
		}
		f.mu.Lock()
		f.rules = rs
		var kill []*pconn
		for c := range f.conns {
			for _, x := range rs {
				if x.Refuse && (x.From == "*" || x.From == c.from) && (x.To == "*" || x.To == c.to) {
					kill = append(kill, c)
				}
			}
		}
		f.mu.Unlock()
		for _, c := range kill {
			c.close()
		}
		b, _ := json.Marshal(rs)
		f.note("rules %s", b)
		w.Write([]byte("{}"))
	})
	mux.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
		f.mu.RLock()
		open := map[string]int{}
		for c := range f.conns {
			open[c.from+">"+c.to]++
		}
		b, _ := json.Marshal(map[string]any{"open": open, "opened": f.opened, "bytes": f.bytes, "unknown_callers": f.unknown, "log": f.log, "rules": f.rules})
		f.mu.RUnlock()
		w.Write(b)
	})
	if err := http.ListenAndServe(*control, mux); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
