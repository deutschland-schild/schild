package app_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/deutschland-schild/schild/gateway/internal/app"
)

// D80 at a start: with an operator rule that takes the request body away the
// gateway does not come up, and the error names the directive.
func TestStartRefusesRulesThatTakeTheBodyAway(t *testing.T) {
	for _, rule := range []string{
		`SecRuleEngine Off`,
		`SecRule REQUEST_URI "@beginsWith /hook" "id:1000004,phase:1,pass,nolog,ctl:requestBodyAccess=Off"`,
		`Include /etc/schild/more.conf`,
	} {
		dir := t.TempDir()
		rules := filepath.Join(dir, "rules.d")
		if err := os.MkdirAll(rules, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(rules, "a.conf"), []byte(rule+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		yaml := fmt.Sprintf("config_version: 0\nmode: observe\nnode_name: start\nupstream: { url: \"http://127.0.0.1:9\" }\nstorage: { path: %q }\nrules:\n  crowdsec: { auto_update: false }\n  local: { dir: %q }\n", filepath.Join(dir, "data"), rules)
		p := filepath.Join(dir, "schild.yaml")
		if err := os.WriteFile(p, []byte(yaml), 0o600); err != nil {
			t.Fatal(err)
		}
		a, err := app.New(context.Background(), app.Options{ConfigPath: p, NoListeners: true})
		if err == nil || !strings.Contains(err.Error(), "not allowed in operator rules") {
			t.Errorf("%s: started, err = %v", rule, err)
		}
		_ = a
	}
}
