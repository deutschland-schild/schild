package gate

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v3"

	"github.com/deutschland-schild/schild/gateway/internal/decide"
	"github.com/deutschland-schild/schild/gateway/internal/waf"
)

// D80, the net behind the refusal at build: with a WAF whose engine or body
// access is off the client gets 503 and the backend sees nothing, instead of
// a request with an empty body.
func TestNoRequestWithAnEmptyBodyReachesTheBackend(t *testing.T) {
	for _, directives := range []string{"SecRuleEngine Off", "SecRuleEngine DetectionOnly\nSecRequestBodyAccess Off"} {
		e := newEnv(t, decide.ModeObserve)
		inst, err := waf.Build(waf.Config{})
		if err != nil {
			t.Fatal(err)
		}
		// waf.Build refuses these directives; only a bug could bring them in.
		if inst.WAF, err = coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(directives)); err != nil {
			t.Fatal(err)
		}
		e.g.Engine.Swap(inst)
		before := e.hits.Load()
		r := httptest.NewRequest("POST", "/hook", strings.NewReader("a=1"))
		r.RemoteAddr = net.JoinHostPort("203.0.113.9", "40000")
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		e.g.Handler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { e.hits.Add(1) })).ServeHTTP(w, r)
		if w.Code != http.StatusServiceUnavailable || e.hits.Load() != before {
			t.Errorf("%q: status %d, backend hits %d", directives, w.Code, e.hits.Load()-before)
		}
		// Without a body nothing is lost, the request goes on.
		g := httptest.NewRequest("GET", "/hook", nil)
		g.RemoteAddr = net.JoinHostPort("203.0.113.9", "40000")
		w = httptest.NewRecorder()
		e.g.Handler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { e.hits.Add(1) })).ServeHTTP(w, g)
		if w.Code != http.StatusOK || e.hits.Load() != before+1 {
			t.Errorf("%q: GET status %d, backend hits %d", directives, w.Code, e.hits.Load()-before)
		}
	}
}
