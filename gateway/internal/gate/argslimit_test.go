package gate

import (
	"fmt"
	"strings"
	"testing"

	"github.com/deutschland-schild/schild/gateway/internal/decide"
	"github.com/deutschland-schild/schild/gateway/internal/waf"
)

// A JSON body that passes the gate's structural scan but exceeds Coraza's
// SecArgumentsLimit must be rejected in every mode (M1): Coraza >= 3.8 drops
// the arguments beyond the limit, so they were never inspected.
func TestArgumentsLimitInEveryMode(t *testing.T) {
	inst, err := waf.Build(waf.Config{CRS: true, ParanoiaLevel: 1, AnomalyThreshold: 5, ArgsLimit: 20})
	if err != nil {
		t.Fatal(err)
	}
	parts := make([]string, 30) // 31 JSON tokens: below the gate's 2*Args = 200
	for i := range parts {
		parts[i] = fmt.Sprint(i)
	}
	body := "[" + strings.Join(parts, ",") + "]"
	for _, mode := range []string{decide.ModeObserve, decide.ModeAutoblock} {
		e := newEnv(t, mode)
		e.g.Engine.Swap(inst)
		if r := e.do(t, "POST", "/api/items", "application/json", body, nil); r.StatusCode != 400 {
			t.Errorf("%s: got %d want 400", mode, r.StatusCode)
		}
		if e.hits.Load() != 0 {
			t.Fatalf("%s: %d uninspected requests reached the backend", mode, e.hits.Load())
		}
		// Within Coraza's limit the request passes.
		if r := e.do(t, "POST", "/api/items", "application/json", "[1,2,3]", nil); r.StatusCode != 200 {
			t.Fatalf("%s: small array got %d", mode, r.StatusCode)
		}
	}
}
