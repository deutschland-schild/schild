// Command splittest runs the tests of one package as several processes side
// by side. It is for a package whose tests wait for real time and cannot all
// run in parallel inside one process (internal/app: issue #57).
//
//	go run ./internal/tools/splittest [-procs N] [-pkg ./internal/app] [flags of go test]
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
//   - Then one process runs all parallel tests, as go test does. It starts
//     when the queue is empty, so a sequential test still never meets the
//     parallel ones (see the package comment of apptest).
//
// The output of a process is kept and printed in one piece when the process
// failed (with -v: always). The limit of go test (-timeout) holds for the
// package as a whole: every process gets what is left of it, and the test
// that is still running then ends with the stacks of its goroutines.
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
	pkg     string
	timeout time.Duration
	verbose bool
	build   []string // for go test -c and go list
	run     []string // for the test binary, as -test.x
	runExpr string   // -run, applied to the list of names
}

func parseArgs(args []string) (options, error) {
	o := options{procs: 4, pkg: "./internal/app", timeout: 10 * time.Minute}
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
	procs := min(o.procs, max(1, len(sequential)))
	fmt.Printf("=== %s: %d tests, %d sequential in %d processes, then %d parallel in one process (limit %s)\n",
		pkg.ImportPath, len(names), len(sequential), procs, len(parallel), o.timeout)

	r := &runner{o: o, bin: bin, dir: pkg.Dir, start: time.Now(), finished: map[string]result{}}
	// Phase 1: the queue of the sequential tests.
	queue := make(chan string)
	busy := make([]time.Duration, procs)
	var wg sync.WaitGroup
	for w := 0; w < procs; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for name := range queue {
				busy[w] += r.process(ctx, w, fmt.Sprintf("%s (process %d of %d)", name, w+1, procs), []string{name})
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
	if len(parallel) > 0 {
		parWall = r.process(ctx, procs, fmt.Sprintf("the %d parallel tests", len(parallel)), parallel)
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
	}
	var b []string
	for _, d := range busy {
		b = append(b, d.Round(time.Second).String())
	}
	fmt.Printf("    sequential: %d tests of %.0fs together in %s; the processes worked %s\n", len(sequential), seqSum, seqWall.Round(time.Second), strings.Join(b, ", "))
	fmt.Printf("    parallel:   %d tests of %.0fs together in %s\n", len(parallel), parSum, parWall.Round(time.Second))
	slow := append([]string(nil), names...)
	sort.SliceStable(slow, func(i, j int) bool { return r.finished[slow[i]].seconds > r.finished[slow[j]].seconds })
	var top []string
	for _, n := range slow[:min(5, len(slow))] {
		top = append(top, fmt.Sprintf("%s %.0fs", n, r.finished[n].seconds))
	}
	fmt.Printf("    slowest:    %s\n", strings.Join(top, ", "))
	total := time.Since(r.start).Seconds()
	if r.failed {
		fmt.Printf("FAIL\t%s\t%.3fs\n", pkg.ImportPath, total)
		return false, nil
	}
	fmt.Printf("ok  \t%s\t%.3fs\n", pkg.ImportPath, total)
	return true, nil
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

type runner struct {
	o        options
	bin, dir string
	start    time.Time

	mu     sync.Mutex // the output and what follows
	failed bool
	// overLimit: the limit of the package passed before a process started.
	overLimit bool
	finished  map[string]result
}

var finishedLine = regexp.MustCompile(`(?m)^--- (?:PASS|FAIL|SKIP): (\S+) \(([0-9.]+)s\)$`)

// process runs the named tests in one process and returns how long it ran.
func (r *runner) process(ctx context.Context, slot int, what string, names []string) time.Duration {
	left := r.o.timeout - time.Since(r.start)
	if r.o.timeout > 0 && left < time.Second {
		r.mu.Lock()
		defer r.mu.Unlock()
		if !r.overLimit {
			fmt.Printf("--- FAIL: the limit of %s for the package is over, the tests left are not started (first: %s)\n", r.o.timeout, what)
		}
		r.failed, r.overLimit = true, true
		return 0
	}
	args := []string{"-test.v", "-test.timeout=" + left.Round(time.Second).String(), "-test.run=^(" + strings.Join(names, "|") + ")$"}
	args = append(args, r.o.run...)
	cmd := exec.CommandContext(ctx, r.bin, args...)
	cmd.Dir = r.dir
	// The ports of a process: a block of its own (testport).
	cmd.Env = append(os.Environ(), "SCHILD_TESTPORT_BLOCK="+strconv.Itoa(slot))
	// A test binary that passed its limit prints the stacks and exits; the
	// kill is for an interrupt of this tool.
	cmd.WaitDelay = 10 * time.Second
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	began := time.Now()
	err := cmd.Run()
	took := time.Since(began)

	r.mu.Lock()
	defer r.mu.Unlock()
	for _, m := range finishedLine.FindAllStringSubmatch(out.String(), -1) {
		s, _ := strconv.ParseFloat(m[2], 64)
		r.finished[m[1]] = result{seconds: s}
	}
	switch {
	case err != nil:
		r.failed = true
		var exit *exec.ExitError
		if !errors.As(err, &exit) {
			out.WriteString(err.Error() + "\n")
		}
		fmt.Printf("--- FAIL: %s after %s: %v. Its output:\n%s--- end of the output of %s\n", what, took.Round(time.Millisecond), err, out.String(), what)
	case r.o.verbose:
		fmt.Printf("%s", out.String())
	}
	return took
}
