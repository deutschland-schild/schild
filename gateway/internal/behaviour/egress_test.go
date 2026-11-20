package behaviour

import (
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// Nothing in this package can send anything: no network client, no
// transport (MVP-17 must: everything local).
func TestNoEgressImports(t *testing.T) {
	files, _ := filepath.Glob("*.go")
	forbidden := []string{"net/http", "net/rpc", "net/smtp", "crypto/tls", "/transport", "/rules", "/hosts"}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		af, err := parser.ParseFile(token.NewFileSet(), f, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, im := range af.Imports {
			p, _ := strconv.Unquote(im.Path.Value)
			for _, bad := range forbidden {
				if p == bad || strings.HasSuffix(p, bad) || p == "net" {
					t.Errorf("%s imports %s", f, p)
				}
			}
		}
	}
}
