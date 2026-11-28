package dashboard

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/deutschland-schild/schild/contract/audit"
)

// MVP-36 (contracts/audit.md section 2): the list of actions is compared
// with the routes the dashboard registers, not with the API document alone.
// Every route with POST, PUT, PATCH or DELETE names its operation with s.op,
// and every such operation is in an action or in not_audited with its
// reason; every dashboard operation of the catalogue is a route.
func TestEveryWritingRouteIsInTheAuditCatalogue(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil || len(files) == 0 {
		t.Fatal("no source files", err)
	}
	route := regexp.MustCompile(`(?:\ba|mux\.HandleFunc|mux\.Handle)\("(POST|PUT|PATCH|DELETE) "\+apiPrefix\+"([^"]*)",\s*(.*)\)\s*$`)
	named := regexp.MustCompile(`^s\.op\("([A-Za-z]+)", s\.[A-Za-z]+\)$`)
	routes := map[string]string{}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(string(raw), "\n") {
			m := route.FindStringSubmatch(strings.TrimSpace(line))
			if m == nil {
				continue
			}
			op := named.FindStringSubmatch(m[3])
			if op == nil {
				t.Errorf("%s: %s %s is registered without s.op: a writing route names its operation", f, m[1], m[2])
				continue
			}
			routes["dashboard:"+op[1]] = m[1] + " " + m[2]
		}
	}
	if len(routes) < 40 {
		t.Fatalf("found %d writing routes, the scan misses most of them", len(routes))
	}
	listed := map[string]bool{}
	for _, a := range audit.Actions.Actions {
		for _, op := range a.Operations {
			if strings.HasPrefix(op, "dashboard:") {
				listed[op] = true
			}
		}
	}
	for _, o := range audit.Actions.NotAudited {
		if strings.HasPrefix(o.Operation, "dashboard:") {
			if listed[o.Operation] {
				t.Errorf("%s is in an action and in not_audited", o.Operation)
			}
			if o.Reason == "" {
				t.Errorf("%s is not audited without a reason", o.Operation)
			}
			listed[o.Operation] = true
		}
	}
	for op, r := range routes {
		if !listed[op] {
			t.Errorf("%s (%s) changes something and is neither in an action nor in not_audited", op, r)
		}
	}
	for op := range listed {
		if _, ok := routes[op]; !ok {
			t.Errorf("the catalogue names %s, which is no writing route of the dashboard", op)
		}
	}
	// The routes the API document does not name are served all the same.
	for _, o := range audit.Actions.Undocumented {
		if r, ok := routes[o.Operation]; !ok || !strings.HasSuffix(o.Route, strings.SplitN(r, " ", 2)[1]) {
			t.Errorf("undocumented %s (%s) is no route: have %q", o.Operation, o.Route, r)
		}
	}
}
