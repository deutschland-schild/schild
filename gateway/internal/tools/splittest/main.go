// Command splittest runs the tests of one package as several processes side
// by side. It is for a package whose tests wait for real time and cannot all
// run in parallel inside one process (internal/app: issue #57).
//
//	go run ./internal/tools/splittest [-procs N] [-batch M] [-only sequential|parallel] [-pkg ./internal/app] [flags of go test]
//
// The flags of go test are passed on: those of the build (-race, -tags) to
// the one build of the test binary, the others (-short, -run, -v, -timeout)
// to every run of it.
//
// How the tests are split:
//
//   - The binary lists its tests (-test.list). That list is the only source
//     of names: a test is run because the binary holds it, so a new test
//     takes part without anybody doing anything.
//   - A test whose function calls Parallel (t.Parallel, app.Parallel) is a
//     parallel test, every other one is sequential. This is read from the
//     source of the package. A name the source does not explain counts as
//     sequential, which is the safe side.
//   - The sequential tests wait in one queue. N processes work at it: each
//     takes the next test, runs it in a process of its own and comes back.
//     No table of times is needed for the balance, and a test is taken
//     exactly once because it is taken from a queue.
//   - Then the parallel tests run, as go test runs them, in processes of at
//     most M tests (-batch, default 32), one process after the other. They
//     start when the queue is empty, so a sequential test still never meets
//     the parallel ones (see the package comment of apptest). The batches
//     bound the memory: a process keeps memory of every test it ran, and
//     one process for the 112 parallel tests of internal/app held 11 GiB
//     under the race detector, on a runner with 16.
//
// With -only the tool runs one of the two kinds. The Makefile uses it: the
// parallel tests run next to the other packages of the module, the
// sequential ones when those ended. Among the sequential tests are the ones
// that measure (a count in a window of real time, an upper bound for a
// duration); they failed when the other packages took the CPU.
//
// What the log shows while it runs, one line each on stderr, unbuffered: a
// sequential test that starts, every test that ends (result, process,
// duration), the start and the end of the parallel phase, and every 30 s
// the tests that run now. So the log of a run that was cancelled names the
// tests that were running. The output of a process is kept and printed in
// one piece when the process failed (with -v: always).
//
// The limit of go test (-timeout) holds for the package as a whole and
// counts from the first test, not from the build: every process gets what
// is left of it, and a test that is still running then ends with the stacks
// of its goroutines. A process that does not end by itself 15 s later gets
// SIGQUIT (stacks again), and is killed 10 s after that. The same happens
// when this tool is interrupted. A child of a test that keeps the output
// open does not hold the tool: it stops reading 10 s after the test binary
// ended.
//
// Every process gets a block of ports of its own (testport,
// SCHILD_TESTPORT_BLOCK): two processes never draw the same port, and none
// draws a port of a test binary that go test runs at the same time.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// buildFlags are the flags of go test that change the build; true: the flag
// takes a value. Every other flag belongs to the test binary.
var buildFlags = map[string]bool{
	"race": false, "msan": false, "asan": false, "cover": false, "trimpath": false, "a": false, "x": false,
	"tags": true, "ldflags": true, "gcflags": true, "asmflags": true, "covermode": true, "coverpkg": true, "mod": true,
}

// boolFlags are the flags of a test binary that take no value.
var boolFlags = map[string]bool{"short": true, "v": true, "failfast": true, "benchmem": true, "fullpath": true}

type options struct {
	procs   int
	batch   int    // parallel tests per process at most; 0: all in one
	only    string // "", sequential or parallel: the tests to run
	pkg     string
	timeout time.Duration
	verbose bool
	build   []string // for go test -c and go list
	run     []string // for the test binary, as -test.x
	runExpr string   // -run, applied to the list of names
}

func parseArgs(args []string) (options, error) {
	o := options{procs: 4, batch: 32, pkg: "./internal/app", timeout: 10 * time.Minute}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "-") {
			return o, fmt.Errorf("unexpected argument %q: the package is given with -pkg", a)
		}
		name, value, hasValue := strings.Cut(strings.TrimLeft(a, "-"), "=")
		name = strings.TrimPrefix(name, "test.")
		next := func() (string, error) {
			if hasValue {
				return value, nil
			}
			if i+1 >= len(args) {
				return "", fmt.Errorf("flag -%s needs a value", name)
			}
			i++
			return args[i], nil
		}
		switch takesValue, isBuild := buildFlags[name]; {
		case name == "procs":
			v, err := next()
			if err != nil {
				return o, err
			}
			// testport keeps 16 blocks of ports for the processes of a
			// runner; one is for the parallel tests.
			if o.procs, err = strconv.Atoi(v); err != nil || o.procs < 1 || o.procs > 15 {
				return o, fmt.Errorf("-procs %q: want a number from 1 to 15", v)
			}
		case name == "batch":
			v, err := next()
			if err != nil {
				return o, err
			}
			if o.batch, err = strconv.Atoi(v); err != nil || o.batch < 0 {
				return o, fmt.Errorf("-batch %q: want a number from 0", v)
			}
		case name == "only":
			v, err := next()
			if err != nil {
				return o, err
			}
			if v != "sequential" && v != "parallel" {
				return o, fmt.Errorf("-only %q: want sequential or parallel", v)
			}
			o.only = v
		case name == "pkg":
			v, err := next()
			if err != nil {
				return o, err
			}
			o.pkg = v
		case name == "timeout":
			v, err := next()
			if err != nil {
				return o, err
			}
			if o.timeout, err = time.ParseDuration(v); err != nil {
				return o, fmt.Errorf("-timeout %q: %v", v, err)
			}
		case name == "run":
			v, err := next()
			if err != nil {
				return o, err
			}
			o.runExpr = v
		case name == "v" && !hasValue:
			o.verbose = true
		case isBuild && !takesValue:
			o.build = append(o.build, a)
		case isBuild:
			v, err := next()
			if err != nil {
				return o, err
			}
			o.build = append(o.build, "-"+name+"="+v)
		case boolFlags[name] && !hasValue:
			o.run = append(o.run, "-test."+name)
		default:
			v, err := next()
			if err != nil {
				return o, err
			}
			o.run = append(o.run, "-test."+name+"="+v)
		}
	}
	return o, nil
}

func main() {
	o, err := parseArgs(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "splittest:", err)
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ok, err := run(ctx, o)
	if err != nil {
		fmt.Fprintln(os.Stderr, "splittest:", err)
		os.Exit(2)
	}
	if !ok {
		os.Exit(1)
	}
}

type goPackage struct {
	Dir, ImportPath           string
	TestGoFiles, XTestGoFiles []string
}

func run(ctx context.Context, o options) (bool, error) {
	out, err := goCmd(ctx, append(append([]string{"list", "-json"}, o.build...), o.pkg)...)
	if err != nil {
		return false, err
	}
	var pkg goPackage
	if err := json.Unmarshal(out, &pkg); err != nil {
		return false, fmt.Errorf("go list %s: %v (one package is expected)", o.pkg, err)
	}
	tmp, err := os.MkdirTemp("", "splittest-")
	if err != nil {
		return false, err
	}
	defer os.RemoveAll(tmp)
	bin := filepath.Join(tmp, "pkg.test")
	buildBegan := time.Now()
	progress("building the test binary of %s", pkg.ImportPath)
	if _, err := goCmd(ctx, append(append([]string{"test", "-c", "-o", bin}, o.build...), o.pkg)...); err != nil {
		return false, err
	}
	if _, err := os.Stat(bin); err != nil {
		fmt.Printf("?   \t%s\t[no test files]\n", pkg.ImportPath)
		return true, nil
	}

	names, err := listTests(ctx, bin, pkg.Dir, o.runExpr)
	if err != nil {
		return false, err
	}
	callers, err := parallelTests(pkg)
	if err != nil {
		return false, err
	}
	var sequential, parallel []string
	for _, n := range names {
		if callers[n] {
			parallel = append(parallel, n)
		} else {
			sequential = append(sequential, n)
		}
	}
	switch o.only {
	case "sequential":
		parallel, names = nil, sequential
	case "parallel":
		sequential, names = nil, parallel
	}
	procs := min(o.procs, max(1, len(sequential)))
	progress("built in %s. %d tests: %d sequential in %d processes, then %d parallel; limit %s from now",
		time.Since(buildBegan).Round(time.Second), len(names), len(sequential), procs, len(parallel), o.timeout)

	r := &runner{o: o, bin: bin, dir: pkg.Dir, start: time.Now(), finished: map[string]result{}, running: map[string]running{}, peak: map[string]int64{}}
	if o.timeout > 0 {
		// The test binaries end by themselves at the limit; this is for one
		// that does not.
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, r.start.Add(o.timeout+15*time.Second))
		defer cancel()
	}
	watchDone := make(chan struct{})
	defer close(watchDone)
	go r.watch(ctx, watchDone)
	// Phase 1: the queue of the sequential tests.
	queue := make(chan string)
	busy := make([]time.Duration, procs)
	var wg sync.WaitGroup
	for w := 0; w < procs; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for name := range queue {
				busy[w] += r.process(ctx, w, fmt.Sprintf("process %d", w+1), name, []string{name})
			}
		}()
	}
	for _, name := range sequential {
		queue <- name
	}
	close(queue)
	wg.Wait()
	seqWall := time.Since(r.start)
	// Phase 2: the parallel tests, in one process.
	var parWall time.Duration
	batches := split(parallel, o.batch)
	if len(parallel) > 0 {
		if len(sequential) > 0 {
			progress("the sequential tests ended after %s", seqWall.Round(time.Second))
		}
		progress("the %d parallel tests start, in %d processes one after the other", len(parallel), len(batches))
		for i, b := range batches {
			process := fmt.Sprintf("parallel %d of %d", i+1, len(batches))
			parWall += r.process(ctx, procs, process, fmt.Sprintf("%d parallel tests", len(b)), b)
		}
		progress("the parallel tests ended after %s", parWall.Round(time.Second))
	}

	var missing []string
	var seqSum, parSum float64
	for _, n := range names {
		res, done := r.finished[n]
		if !done {
			missing = append(missing, n)
		}
		if callers[n] {
			parSum += res.seconds
		} else {
			seqSum += res.seconds
		}
	}
	if len(missing) > 0 {
		r.failed = true
		fmt.Printf("--- %d tests did not finish: %s\n", len(missing), strings.Join(missing, " "))
		progress("FAIL: %d tests did not finish", len(missing))
	}
	var b []string
	for _, d := range busy {
		b = append(b, d.Round(time.Second).String())
	}
	what := map[string]string{"": "", "sequential": ", the sequential tests", "parallel": ", the parallel tests"}[o.only]
	if len(sequential) > 0 {
		fmt.Printf("    sequential: %d tests of %.0fs together in %s; the processes worked %s\n", len(sequential), seqSum, seqWall.Round(time.Second), strings.Join(b, ", "))
	}
	if len(parallel) > 0 {
		fmt.Printf("    parallel:   %d tests of %.0fs together in %s, in %d processes one after the other\n", len(parallel), parSum, parWall.Round(time.Second), len(batches))
	}
	fmt.Printf("    memory:     %d MiB at most in a process of a sequential test, %d MiB in a process of parallel tests\n", r.peak["sequential"], r.peak["parallel"])
	slow := append([]string(nil), names...)
	sort.SliceStable(slow, func(i, j int) bool { return r.finished[slow[i]].seconds > r.finished[slow[j]].seconds })
	var top []string
	for _, n := range slow[:min(5, len(slow))] {
		top = append(top, fmt.Sprintf("%s %.0fs", n, r.finished[n].seconds))
	}
	fmt.Printf("    slowest:    %s\n", strings.Join(top, ", "))
	total := time.Since(r.start).Seconds()
	if r.failed {
		fmt.Printf("FAIL\t%s%s\t%.3fs\n", pkg.ImportPath, what, total)
		return false, nil
	}
	fmt.Printf("ok  \t%s%s\t%.3fs\n", pkg.ImportPath, what, total)
	return true, nil
}

// split deals names out to as few lists as hold at most size each (size 0:
// one list). The lists are of about the same length, and neighbours in the
// order of the names go to different lists.
func split(names []string, size int) [][]string {
	if len(names) == 0 {
		return nil
	}
	n := 1
	if size > 0 {
		n = (len(names) + size - 1) / size
	}
	out := make([][]string, n)
	for i, name := range names {
		out[i%n] = append(out[i%n], name)
	}
	return out
}

func goCmd(ctx context.Context, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "go", args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("go %s: %v\n%s", strings.Join(args, " "), err, stderr.String())
	}
	return out, nil
}

// listTests asks the binary for what it runs: tests, fuzz targets (their
// seeds run as tests) and examples, no benchmarks.
func listTests(ctx context.Context, bin, dir, expr string) ([]string, error) {
	if expr == "" {
		expr = ".*"
	}
	cmd := exec.CommandContext(ctx, bin, "-test.list", expr)
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("list of tests: %v", err)
	}
	var names []string
	seen := map[string]bool{}
	for _, l := range strings.Split(string(out), "\n") {
		l = strings.TrimSpace(l)
		if !regexp.MustCompile(`^(Test|Fuzz|Example)\w*$`).MatchString(l) || seen[l] {
			continue
		}
		seen[l] = true
		names = append(names, l)
	}
	sort.Strings(names)
	return names, nil
}

// parallelTests are the test functions of the package that call Parallel
// themselves (not in a subtest).
func parallelTests(pkg goPackage) (map[string]bool, error) {
	out := map[string]bool{}
	fset := token.NewFileSet()
	for _, f := range append(append([]string(nil), pkg.TestGoFiles...), pkg.XTestGoFiles...) {
		file, err := parser.ParseFile(fset, filepath.Join(pkg.Dir, f), nil, parser.SkipObjectResolution)
		if err != nil {
			return nil, err
		}
		for _, d := range file.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || fn.Body == nil {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.FuncLit:
					return false // a subtest or a goroutine
				case *ast.CallExpr:
					switch f := x.Fun.(type) {
					case *ast.Ident:
						out[fn.Name.Name] = out[fn.Name.Name] || f.Name == "Parallel"
					case *ast.SelectorExpr:
						out[fn.Name.Name] = out[fn.Name.Name] || f.Sel.Name == "Parallel"
					}
				}
				return true
			})
		}
	}
	return out, nil
}

type result struct{ seconds float64 }

// running is a test a process works at now.
type running struct {
	process string
	since   time.Time
}

type runner struct {
	o        options
	bin, dir string
	start    time.Time

	mu       sync.Mutex // the output and what follows
	failed   bool
	finished map[string]result
	running  map[string]running
	// overLimit: the limit of the package passed before a process started.
	overLimit bool
	// peak is the largest memory a process of a kind held (resident set, in
	// MiB), by "sequential" and "parallel".
	peak map[string]int64
}

// residentMiB is the largest resident set of a process that ended. The
// kernel counts it in KiB on Linux and in bytes on macOS.
func residentMiB(st *os.ProcessState) int64 {
	ru, ok := st.SysUsage().(*syscall.Rusage)
	if !ok || ru == nil {
		return 0
	}
	if runtime.GOOS == "darwin" {
		return int64(ru.Maxrss) >> 20
	}
	return int64(ru.Maxrss) >> 10
}

// progress writes one line of the run to stderr, at once.
func progress(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "splittest: "+format+"\n", a...)
}

// runningNow names the tests that run, the oldest first. r.mu is held.
func (r *runner) runningNow() string {
	var names []string
	for n := range r.running {
		names = append(names, n)
	}
	sort.Slice(names, func(i, j int) bool { return r.running[names[i]].since.Before(r.running[names[j]].since) })
	for i, n := range names {
		names[i] = fmt.Sprintf("%s (%s, %s)", n, r.running[n].process, time.Since(r.running[n].since).Round(time.Second))
	}
	if len(names) == 0 {
		return "no test"
	}
	return strings.Join(names, ", ")
}

// watch says every 30 s which tests run, and once when the run is
// interrupted or passed its limit.
func (r *runner) watch(ctx context.Context, done <-chan struct{}) {
	tick := time.NewTicker(30 * time.Second)
	defer tick.Stop()
	stop := ctx.Done()
	for {
		select {
		case <-done:
			return
		case <-tick.C:
			r.mu.Lock()
			progress("after %s, running: %s", time.Since(r.start).Round(time.Second), r.runningNow())
			r.mu.Unlock()
		case <-stop:
			stop = nil
			why := "interrupted"
			if errors.Is(context.Cause(ctx), context.DeadlineExceeded) {
				why = fmt.Sprintf("the limit of %s is over and a process did not end by itself", r.o.timeout)
			}
			r.mu.Lock()
			r.failed = true
			progress("FAIL: %s after %s. Running: %s. The processes get SIGQUIT and print their stacks", why, time.Since(r.start).Round(time.Second), r.runningNow())
			r.mu.Unlock()
		}
	}
}

var (
	// Lines of a test binary with -test.v about a test function (no
	// subtest: its name has a slash, and its result line is indented).
	startedLine  = regexp.MustCompile(`^=== (?:RUN|CONT) +(\w+)$`)
	pausedLine   = regexp.MustCompile(`^=== PAUSE (\w+)$`)
	finishedLine = regexp.MustCompile(`^--- (PASS|FAIL|SKIP): (\w+) \(([0-9.]+)s\)$`)
)

// output keeps what a process writes and follows its tests line by line.
type output struct {
	r        *runner
	process  string
	announce bool // say when a test starts (the sequential ones)
	all      bytes.Buffer
	line     []byte
}

func (o *output) Write(p []byte) (int, error) {
	o.r.mu.Lock()
	defer o.r.mu.Unlock()
	o.all.Write(p)
	for _, c := range p {
		if c != '\n' {
			o.line = append(o.line, c)
			continue
		}
		o.read(string(o.line))
		o.line = o.line[:0]
	}
	return len(p), nil
}

func (o *output) read(line string) {
	r := o.r
	if m := startedLine.FindStringSubmatch(line); m != nil {
		if _, known := r.running[m[1]]; !known {
			r.running[m[1]] = running{process: o.process, since: time.Now()}
			if o.announce {
				progress("start %s (%s)", m[1], o.process)
			}
		}
	} else if m := pausedLine.FindStringSubmatch(line); m != nil {
		delete(r.running, m[1])
	} else if m := finishedLine.FindStringSubmatch(line); m != nil {
		delete(r.running, m[2])
		sec, _ := strconv.ParseFloat(m[3], 64)
		r.finished[m[2]] = result{seconds: sec}
		word := map[string]string{"PASS": "ok  ", "FAIL": "FAIL", "SKIP": "skip"}[m[1]]
		progress("%s  %s (%s) %ss", word, m[2], o.process, m[3])
	}
}

// process runs the named tests in one process and returns how long it ran.
// slot numbers its block of ports; what names the tests in a message.
func (r *runner) process(ctx context.Context, slot int, process, what string, names []string) time.Duration {
	left := r.o.timeout - time.Since(r.start)
	if ctx.Err() != nil || (r.o.timeout > 0 && left < time.Second) {
		r.mu.Lock()
		defer r.mu.Unlock()
		if !r.overLimit {
			msg := fmt.Sprintf("the limit of %s for the package is over or the run was interrupted, the tests left are not started (first: %s)", r.o.timeout, what)
			fmt.Printf("--- FAIL: %s\n", msg)
			progress("FAIL: %s", msg)
		}
		r.failed, r.overLimit = true, true
		return 0
	}
	args := []string{"-test.v", "-test.run=^(" + strings.Join(names, "|") + ")$"}
	if r.o.timeout > 0 {
		args = append(args, "-test.timeout="+left.Round(time.Second).String())
	} else {
		args = append(args, "-test.timeout=0")
	}
	args = append(args, r.o.run...)
	cmd := exec.CommandContext(ctx, r.bin, args...)
	cmd.Dir = r.dir
	// The ports of a process: a block of its own (testport).
	cmd.Env = append(os.Environ(), "SCHILD_TESTPORT_BLOCK="+strconv.Itoa(slot))
	// A test binary that passed its limit prints the stacks and exits by
	// itself. One that did not, or an interrupt of this tool: SIGQUIT, so
	// the Go runtime prints the stacks, and a kill 10 s later. The same 10 s
	// bound the wait for the output when a child of a test keeps it open.
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGQUIT) }
	cmd.WaitDelay = 10 * time.Second
	out := &output{r: r, process: process, announce: len(names) == 1}
	cmd.Stdout, cmd.Stderr = out, out
	began := time.Now()
	err := cmd.Run()
	took := time.Since(began)

	r.mu.Lock()
	defer r.mu.Unlock()
	if cmd.ProcessState != nil {
		kind := "sequential"
		if strings.HasPrefix(process, "parallel") {
			kind = "parallel"
		}
		r.peak[kind] = max(r.peak[kind], residentMiB(cmd.ProcessState))
	}
	var cut []string // tests of this process that did not end
	for n, t := range r.running {
		if t.process == process {
			cut = append(cut, n)
			delete(r.running, n)
		}
	}
	sort.Strings(cut)
	if errors.Is(err, exec.ErrWaitDelay) && cmd.ProcessState != nil && cmd.ProcessState.Success() {
		// The tests passed; something they started still holds the output.
		progress("note: %s ended, but a process it started kept its output open for 10 s more", what)
		err = nil
	}
	switch {
	case err != nil:
		r.failed = true
		var exit *exec.ExitError
		if !errors.As(err, &exit) {
			out.all.WriteString(err.Error() + "\n")
		}
		during := ""
		if len(cut) > 0 {
			during = " while running " + strings.Join(cut, ", ")
		}
		progress("FAIL: the process of %s (%s) ended after %s with %v%s; its output follows on stdout", what, process, took.Round(time.Millisecond), err, during)
		fmt.Printf("--- FAIL: %s (%s) after %s: %v%s. Its output:\n%s--- end of the output of %s (%s)\n", what, process, took.Round(time.Millisecond), err, during, out.all.String(), what, process)
	case r.o.verbose:
		fmt.Printf("%s", out.all.String())
	}
	return took
}
