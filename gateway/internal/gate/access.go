package gate

import (
	"net/http"

	"github.com/deutschland-schild/schild/contract/access"
	"github.com/deutschland-schild/schild/gateway/internal/accesslock"
	"github.com/deutschland-schild/schild/gateway/internal/decide"
)

// accessSource names the access lock in the sources of a decision.
const accessSource = "access"

// accessStop applies the access lock of the request's website (D56) and
// reports whether it answered the request: the login form at
// accesslock.LoginPath, or the maintenance, login or "Kein Zugriff" page.
// Like a rate limit the answer is no incident and its event is sampled. A
// request that passes loses the session cookie before the WAF and the app.
func (g *Gate) accessStop(w http.ResponseWriter, r *http.Request, ri *reqInfo) bool {
	website := g.reqSite(r, ri)
	// Maintenance mode first (D98): it closes the whole website, the login
	// form included, for everyone outside the own networks.
	if v, stopped := g.Access.CheckMaintenance(r, website, ri.client.IP, ri.allow != ""); stopped {
		ri.stopped = true
		g.drain(w, r, ri)
		ri.status = v.Status
		ri.decision = decide.Output{Outcome: decide.Blocked, Status: v.Status, Sources: []string{accessSource + ":" + v.Answer}}
		accesslock.Write(w, r, v, "", ri.start)
		g.finish(r, ri)
		return true
	}
	if r.URL.Path == accesslock.LoginPath {
		// The login reads its small form itself (at most 4 KiB).
		ri.stopped = true
		ri.status = g.Access.Login(w, r, website, ri.client.IP, ri.allow != "", ri.start)
		ri.decision = decide.Output{Outcome: decide.Passed, Status: ri.status, Sources: []string{accessSource + ":login"}}
		g.finish(r, ri)
		return true
	}
	v, ok := g.Access.Check(r, website, ri.client.IP, ri.allow != "", ri.start)
	if !ok {
		return false
	}
	if v.Answer == access.AnswerPass {
		if v.Entry.Protection.Password {
			accesslock.StripCookie(r)
		}
		return false
	}
	ri.stopped = true
	g.drain(w, r, ri)
	ri.status = v.Status
	ri.decision = decide.Output{Outcome: decide.Blocked, Status: v.Status, Sources: []string{accessSource + ":" + v.Answer}}
	accesslock.Write(w, r, v, "", ri.start)
	g.finish(r, ri)
	return true
}
