package caddymod

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// hetznerAPI is a stand-in for the DNS part of the Hetzner Cloud API, written
// after https://docs.hetzner.cloud/cloud.spec.json (2026-11-25): the two
// actions add_records and remove_records of an RRSet, and the list of
// actions. Every other call is an error and noted, so a test sees when the
// module does more than it should. It holds what it is told, and serve makes
// the same zones answer over DNS.
type hetznerAPI struct {
	token string

	mu      sync.Mutex
	zones   map[string]map[string]*mockRRSet // zone -> "name/TYPE"
	actions map[int]string                   // id -> status once it was asked for
	fail    []int                            // answers of the next calls
	failAll int                              // answer of every call, 0 = none
	calls   []string                         // "POST /zones/..."
	refused []string                         // what a real API would have refused
	seen    []string                         // values that were ever added
	names   map[string]bool                  // names asked for over DNS
}

type mockRRSet struct {
	ttl       *int
	protected bool
	values    []string
}

func newHetznerAPI(token string, zones ...string) *hetznerAPI {
	h := &hetznerAPI{token: token, zones: map[string]map[string]*mockRRSet{}, actions: map[int]string{}, names: map[string]bool{}}
	for _, z := range zones {
		// What a zone holds besides the challenge; change protected, as in
		// issue 14 of caddy-dns/hetzner.
		h.zones[z] = map[string]*mockRRSet{
			"@/MX":  {protected: true, values: []string{"10 mail." + z + "."}},
			"@/TXT": {protected: true, values: []string{`"v=spf1 -all"`}},
			"www/A": {values: []string{"192.0.2.10"}},
		}
	}
	return h
}

// snapshot is every RRSet with its values.
func (h *hetznerAPI) snapshot() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []string
	for z, sets := range h.zones {
		for k, s := range sets {
			out = append(out, fmt.Sprintf("%s %s %v", z, k, s.values))
		}
	}
	slices.Sort(out)
	return strings.Join(out, "\n")
}

func (h *hetznerAPI) state() (calls, refused, seen []string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return slices.Clone(h.calls), slices.Clone(h.refused), slices.Clone(h.seen)
}

// asked reports whether name was asked for over DNS.
func (h *hetznerAPI) asked(name string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.names[name]
}

func (h *hetznerAPI) set(f func()) {
	h.mu.Lock()
	defer h.mu.Unlock()
	f()
}

func (h *hetznerAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	defer h.mu.Unlock()
	path := strings.TrimPrefix(r.URL.Path, "/v1")
	h.calls = append(h.calls, r.Method+" "+path)
	refuse := func(status int, code, msg string) {
		h.refused = append(h.refused, fmt.Sprintf("%s %s: %s %s", r.Method, path, code, msg))
		apiError(w, status, code, msg)
	}
	if r.Header.Get("Authorization") != "Bearer "+h.token {
		refuse(401, "unauthorized", "unable to authenticate")
		return
	}
	code := h.failAll
	if code == 0 && len(h.fail) > 0 {
		code, h.fail = h.fail[0], h.fail[1:]
	}
	switch code {
	case 0:
	case 429:
		apiError(w, code, "rate_limit_exceeded", "limit of requests reached")
		return
	default:
		apiError(w, code, "service_error", "planned failure")
		return
	}
	if r.Method == http.MethodGet && path == "/actions" {
		h.listActions(w, r)
		return
	}
	// /zones/{zone}/rrsets/{name}/{type}/actions/{action}
	p := strings.Split(strings.Trim(path, "/"), "/")
	if r.Method != http.MethodPost || len(p) != 7 || p[0] != "zones" || p[2] != "rrsets" || p[5] != "actions" {
		refuse(404, "not_found", "not in the mock")
		return
	}
	h.change(w, r, refuse, p[1], p[3]+"/"+p[4], p[6])
}

func (h *hetznerAPI) change(w http.ResponseWriter, r *http.Request, refuse func(int, string, string), zone, key, action string) {
	var body struct {
		TTL     *int `json:"ttl"`
		Records []struct {
			Value   string `json:"value"`
			Comment string `json:"comment"`
		} `json:"records"`
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		refuse(422, "invalid_input", err.Error())
		return
	}
	sets := h.zones[zone]
	if sets == nil {
		refuse(404, "not_found", "zone not found")
		return
	}
	if len(body.Records) < 1 || len(body.Records) > 50 {
		refuse(422, "invalid_input", "1 to 50 records")
		return
	}
	var values []string
	for _, rec := range body.Records {
		if slices.Contains(values, rec.Value) {
			refuse(422, "invalid_input", "records must be distinct")
			return
		}
		if strings.HasSuffix(key, "/TXT") && (len(rec.Value) < 2 || rec.Value[0] != '"' || rec.Value[len(rec.Value)-1] != '"') {
			refuse(422, "invalid_input", "TXT values are quoted")
			return
		}
		values = append(values, rec.Value)
	}
	s := sets[key]
	if s != nil && s.protected {
		refuse(422, "protected", "RRSet(s) is/are change protected")
		return
	}
	switch action {
	case "add_records":
		if body.TTL != nil && (*body.TTL < 60 || s != nil && s.ttl != nil && *s.ttl != *body.TTL) {
			refuse(422, "invalid_input", "ttl")
			return
		}
		if s == nil {
			s = &mockRRSet{ttl: body.TTL}
			sets[key] = s
		}
		for _, v := range values {
			if slices.Contains(s.values, v) {
				refuse(422, "invalid_input", "record exists")
				return
			}
			s.values = append(s.values, v)
			h.seen = append(h.seen, zone+" "+key+" "+v)
		}
	case "remove_records":
		if s == nil {
			refuse(404, "not_found", "rrset not found")
			return
		}
		s.values = slices.DeleteFunc(s.values, func(v string) bool { return slices.Contains(values, v) })
		if len(s.values) == 0 {
			delete(sets, key)
		}
	default:
		refuse(404, "not_found", "action not in the mock")
		return
	}
	// The action is running in this answer and done when it is asked for.
	id := len(h.actions) + 1
	h.actions[id] = "success"
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(201)
	_ = json.NewEncoder(w).Encode(map[string]any{"action": actionJSON(id, action, "running")})
}

func (h *hetznerAPI) listActions(w http.ResponseWriter, r *http.Request) {
	list := []any{}
	for _, s := range r.URL.Query()["id"] {
		id, _ := strconv.Atoi(s)
		if st, ok := h.actions[id]; ok {
			list = append(list, actionJSON(id, "change", st))
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"actions": list, "meta": map[string]any{"pagination": map[string]any{
		"page": 1, "per_page": 25, "previous_page": nil, "next_page": nil, "last_page": 1, "total_entries": len(list)}}})
}

func actionJSON(id int, command, status string) map[string]any {
	a := map[string]any{"id": id, "command": command, "status": status, "progress": 0, "started": "2026-11-25T10:00:00Z",
		"finished": nil, "resources": []any{}, "error": nil}
	if status != "running" {
		a["progress"], a["finished"] = 100, "2026-11-25T10:00:01Z"
	}
	if status == "error" {
		a["error"] = map[string]any{"code": "action_failed", "message": "planned failure"}
	}
	return a
}

func apiError(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"code": code, "message": msg, "details": nil}})
}

// intercept sends what the module sends to api.hetzner.cloud to the mock. The
// module has the address built in and uses http.DefaultTransport. A request
// to any other host that is not this machine fails, so no test reaches the
// network.
func (h *hetznerAPI) intercept(t *testing.T) {
	t.Helper()
	srv := httptest.NewServer(h)
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	orig := http.DefaultTransport
	http.DefaultTransport = roundTripper(func(r *http.Request) (*http.Response, error) {
		switch host := r.URL.Hostname(); {
		case host == "api.hetzner.cloud" && r.URL.Scheme == "https":
			r = r.Clone(r.Context())
			r.URL.Scheme, r.URL.Host = "http", u.Host
		case host != "127.0.0.1" && host != "localhost" && host != "::1":
			return nil, errors.New("test: no request to " + host)
		}
		return orig.RoundTrip(r)
	})
	t.Cleanup(func() {
		http.DefaultTransport = orig
		srv.Close()
	})
}

type roundTripper func(*http.Request) (*http.Response, error)

func (f roundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// serveDNS answers for the zones of the mock and for others (zones that are
// not at Hetzner), UDP and TCP on one loopback port, as a resolver would: a
// CNAME with what it points to.
func (h *hetznerAPI) serveDNS(t *testing.T, others []string, cnames map[string]string) (addr string) {
	t.Helper()
	zoneOf := func(name string) string {
		h.mu.Lock()
		defer h.mu.Unlock()
		best := ""
		for _, z := range others {
			if dns.IsSubDomain(z+".", name) && len(z) > len(best) {
				best = z
			}
		}
		for z := range h.zones {
			if dns.IsSubDomain(z+".", name) && len(z) > len(best) {
				best = z
			}
		}
		return best
	}
	soa := func(z string) dns.RR {
		rr, _ := dns.NewRR(z + ". 60 IN SOA ns1." + z + ". hostmaster." + z + ". 1 3600 600 86400 60")
		return rr
	}
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(q)
		m.RecursionAvailable = true
		name, typ := strings.ToLower(q.Question[0].Name), q.Question[0].Qtype
		h.set(func() { h.names[strings.TrimSuffix(name, ".")] = true })
		for range 4 {
			target, ok := cnames[strings.TrimSuffix(name, ".")]
			if !ok {
				break
			}
			m.Answer = append(m.Answer, &dns.CNAME{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 1}, Target: target + "."})
			name = target + "."
		}
		z := zoneOf(name)
		if z == "" {
			m.Rcode = dns.RcodeNameError
			_ = w.WriteMsg(m)
			return
		}
		switch {
		case typ == dns.TypeSOA && name == z+".":
			m.Answer = append(m.Answer, soa(z))
		case typ == dns.TypeTXT:
			h.mu.Lock()
			if s := h.zones[z][strings.TrimSuffix(name, "."+z+".")+"/TXT"]; s != nil {
				for _, v := range s.values {
					m.Answer = append(m.Answer, &dns.TXT{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 1}, Txt: []string{strings.Trim(v, `"`)}})
				}
			}
			h.mu.Unlock()
		}
		if len(m.Answer) == 0 {
			m.Ns = []dns.RR{soa(z)}
		}
		_ = w.WriteMsg(m)
	})
	addr = freePort(t)
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []*dns.Server{{PacketConn: pc, Handler: handler}, {Listener: l, Handler: handler}} {
		started := make(chan struct{})
		s.NotifyStartedFunc = func() { close(started) }
		go func() { _ = s.ActivateAndServe() }()
		select {
		case <-started:
		case <-time.After(5 * time.Second):
			t.Fatal("DNS server did not start")
		}
		t.Cleanup(func() { _ = s.Shutdown() })
	}
	return addr
}

func drain(r io.ReadCloser) string {
	b, _ := io.ReadAll(r)
	r.Close()
	return string(b)
}
