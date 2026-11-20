package monitoring

import (
	"hash/maphash"
	"math"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	cm "github.com/deutschland-schild/schild/contract/monitoring"

	"golang.org/x/net/publicsuffix"

	"github.com/deutschland-schild/schild/gateway/internal/bots"
	"github.com/deutschland-schild/schild/gateway/internal/pathtpl"
	"github.com/deutschland-schild/schild/gateway/internal/reqring"
	"github.com/deutschland-schild/schild/gateway/internal/sites"
)

// Class is what schild did with a request (disjoint, spec MVP-21 counting).
type Class uint8

const (
	Forwarded Class = iota
	BlockedWAF
	BlockedBehaviour
	RateLimited
	RejectedLimit
	Challenged
	FailTimeout
	FailBusy
	FailNotReady
	FailPanic
	FailBodyBusy // D41: refused by the body limits with a 503
	// BlockedCrawler (D57): 403 from the crawler policy of the website.
	BlockedCrawler
)

// Req is one finished request as the gate saw it. The gate fills it on its
// stack and passes a pointer; Record keeps no reference to it.
type Req struct {
	R          *http.Request
	Class      Class
	WouldBlock bool // forwarded, a stricter mode would have blocked it (WAF)
	WouldRL    bool // forwarded, an enforced rate limit would have answered 429
	Detection  bool // the WAF reached its blocking decision
	// WaitingPage: a FailBusy, FailTimeout or FailBodyBusy request answered with the
	// waiting page (D37 overlay, TrafficCounters.waiting_page_shown).
	WaitingPage bool
	Status      int
	// Upstream: 1 the proxy got no response (refused, reset, 502), 2 the
	// backend answered too late (504); 0 otherwise.
	Upstream    uint8
	BytesIn     int64
	BytesOut    int64
	Total       time.Duration
	UpstreamDur time.Duration
	Timed       bool // false for 101 upgrades and event streams
	// Rechecked: schild evaluated the request more than once; it still
	// counts once (D33 amendment, TrafficCounters.rechecked).
	Rechecked bool
	Client    netip.Addr
	Country   string
	ASN       uint32
	ASOrg     string
	NetClass  string
	Rules     []string // rule ids of a detection
	// MVP-22 request ring: the event written for the request (""
	// none), the CRS anomaly score, up to 3 matched rule ids (highest
	// severity first, also below the threshold), why a would_block was
	// passed, and whether the visitor's context is to be pinned (an
	// incident or an alert).
	EventID    string
	Score      int
	RingRules  [3]string
	NRingRules uint8
	WBReason   string
	Pin        bool
	Start      time.Time // request start (record time)
	// Crawler (D57): the crawler policy of the website alone decided the
	// outcome (blocked_crawler, or a would_block while observing or for an
	// allowlisted address that no WAF rule shares). Marked in the request
	// ring, where such a would_block is no alert.
	Crawler bool
}

// Upstream error kinds of Req.Upstream.
const (
	UpstreamOK uint8 = iota
	UpstreamError
	UpstreamTimeout
)

// shard is one stripe of the per-second accumulator; two buffers so the 1 Hz
// swap never waits for a merge.
type shard struct {
	mu  sync.Mutex
	cur *accum
	old *accum
	_   [40]byte // keep shards on separate cache lines
}

const nShards = 16

// recorder is the request path part of the monitor.
type recorder struct {
	shards [nShards]shard
	next   atomic.Uint32
	seed   maphash.Seed
	seen   *seenFilter
	tpl    tplCache
	dom    domainCache
	ua     *uaCache
	bots   *bots.Engine // MVP-22 bot catalogue and verification
	// sites resolves the website of a request (D36); nil: no per-website
	// counters.
	sites *sites.Registry
	// ring is the MVP-22 request ring (nil: off).
	ring *reqring.Ring
}

func newRecorder(now time.Time) *recorder {
	r := &recorder{seed: maphash.MakeSeed(), seen: newSeenFilter(now.Unix() / 86400), bots: bots.Default()}
	r.ua = newUACache(r.bots)
	for i := range r.shards {
		r.shards[i].cur = newAccum(true, 2*cm.TopK)
		r.shards[i].old = newAccum(true, 2*cm.TopK)
		r.shards[i].cur.siteTop, r.shards[i].old.siteTop = true, true
	}
	r.tpl.init()
	r.dom.init()
	return r
}

// clientHash is the keyed hash of the client key (IPv4 address, IPv6 /64);
// the seed is random per process and never stored.
func (rc *recorder) clientHash(a netip.Addr) (uint64, bool) {
	if !a.IsValid() {
		return 0, false
	}
	a = a.Unmap()
	b := a.As16()
	if a.Is6() {
		for i := 8; i < 16; i++ {
			b[i] = 0
		}
	} else {
		b[0] = 4
	}
	return maphash.Bytes(rc.seed, b[:]), true
}

func (rc *recorder) record(q *Req) {
	r := q.R
	ua := rc.ua.classify(r.UserAgent())
	// MVP-22: bot entry, category and verification of this request (bot
	// is what the request ring records).
	bot := BotInfo{ID: ua.id, Category: uint8(ua.bot), Verification: rc.bots.Verify(ua.id, q.Client)}
	uaClass := ua.class
	if bot.Verification == bots.VerVerified {
		uaClass = uaBotVerified
	}
	refKey, refLabel := referrerKey(r.Header.Get("Referer"), r.Host, rc.dom.registrable, rc.sites)
	ep := r.URL.EscapedPath()
	path := rc.tpl.template(ep)
	ci := countryIndex(q.Country)
	nc := netClassIndex(q.NetClass)
	mi := methodIndex(r.Method)
	si := statusIndex(q.Status)
	h, hasClient := rc.clientHash(q.Client)
	// D36 amendment (contract/monitoring.Visitor): only a browser request
	// schild forwarded makes its client a visitor (unique, new, unique_day);
	// every non-browser request counts its client as a bot client. Stopped
	// and fail-closed browser requests count in neither.
	browser := ua.class == uaBrowser && ua.bot == botLikelyBrowser
	visitor := hasClient && browser && q.Class == Forwarded
	botClient := hasClient && !browser
	fresh := visitor && !rc.seen.seen(h)
	pageView := q.Class == Forwarded && r.Method == http.MethodGet && si == 1 && ua.bot == botLikelyBrowser && isDocument(r)

	var stopped, would int64
	switch q.Class {
	case Forwarded:
		if q.WouldBlock {
			would = 1
		}
	case FailTimeout, FailBusy, FailNotReady, FailPanic, FailBodyBusy:
	default:
		stopped = 1
	}
	var det int64
	if q.Detection {
		det = 1
	}

	slot := sites.NoSlot
	siteID := ""
	if rc.sites != nil {
		siteID, slot = rc.sites.Resolve(r.Host)
	}

	s := &rc.shards[rc.next.Add(1)%nShards]
	s.mu.Lock()
	a := s.cur
	countRequest(&a.c, q, si, would, det, pageView)
	histRequest(&a.hist, q)
	d := &a.dims
	inc := func(x *dimCount) { x[0]++; x[1] += stopped; x[2] += would }
	inc(&d.country[ci])
	inc(&d.netClass[nc])
	inc(&d.uaClass[uaClass])
	inc(&d.method[mi])
	inc(&d.status[si])
	inc(&d.browser[ua.browser])
	inc(&d.os[ua.os])
	inc(&d.device[ua.device])
	inc(&d.bot[ua.bot])
	if visitor {
		a.unique.add(h)
		if fresh {
			a.fresh.add(h)
		}
	} else if botClient {
		a.bots.add(h)
	}
	a.path.add(path, "", 1, stopped, would, det, 0)
	if q.ASN != 0 {
		a.asn.add(asnKey(q.ASN), q.ASOrg, 1, stopped, would, 0, 0)
	}
	a.ref.add(refKey, refLabel, 1, stopped, would, 0, 0)
	if q.Detection {
		for _, id := range q.Rules {
			a.rule.add(id, "", 1, stopped, would, 0, 0)
		}
	}
	if slot >= 0 {
		st := a.siteSlot(slot)
		countRequest(&st.c, q, si, would, det, pageView)
		histRequest(&st.hist, q)
		if visitor {
			st.unique.add(h)
			if fresh {
				st.fresh.add(h)
			}
		} else if botClient {
			st.bots.add(h)
		}
		if t := st.top; t != nil {
			inc(&t.netClass[nc])
			inc(&t.uaClass[uaClass])
			inc(&t.method[mi])
			inc(&t.browser[ua.browser])
			inc(&t.os[ua.os])
			inc(&t.device[ua.device])
			inc(&t.bot[ua.bot])
			t.path.add(path, "", 1, stopped, would, det, 0)
			if q.ASN != 0 {
				t.asn.add(asnKey(q.ASN), q.ASOrg, 1, stopped, would, 0, 0)
			}
			t.country.add(countryCode(ci), "", 1, stopped, would, 0, 0)
			t.ref.add(refKey, refLabel, 1, stopped, would, 0, 0)
			if q.Detection {
				for _, id := range q.Rules {
					t.rule.add(id, "", 1, stopped, would, 0, 0)
				}
			}
		}
	}
	s.mu.Unlock()
	if rc.ring != nil {
		rc.toRing(q, ep, path, siteID, refKey, ua, bot, ci, nc, mi, pageView)
	}
}

// toRing hands the request to the MVP-22 request ring: the entry lives on
// this stack frame and is copied into the writer's channel (no allocation).
func (rc *recorder) toRing(q *Req, ep, path, siteID, refKey string, ua uaInfo, bot BotInfo, ci, nc, mi int, pageView bool) {
	t := q.Start
	if t.IsZero() {
		t = time.Now().Add(-q.Total)
	}
	e := reqring.Entry{T: t.UnixMilli(), Client: q.Client, Site: siteID, Host: q.R.Host, UA: q.R.UserAgent(), RawPath: ep, Template: path,
		Referrer: refKey, EventID: q.EventID, Rules: q.RingRules, NRules: q.NRingRules, Status: uint16(min(max(q.Status, 0), 999)),
		ASN: q.ASN, Method: uint8(mi), NetClass: uint8(nc), UAClass: uint8(ua.class), Browser: uint8(ua.browser), OS: uint8(ua.os),
		Device: uint8(ua.device), BotCat: bot.Category, Bot: bot.ID, Verif: bot.Verification, PageView: pageView, Pin: q.Pin, Dur: uint8(cm.BucketOf(ms(q.Total))),
		Score: uint16(min(max(q.Score, 0), 10000)), BytesOut: uint32(min(max(q.BytesOut, 0), math.MaxUint32)), WBReason: reqring.WBReasonIndex(q.WBReason),
		Outcome: ringOutcome(q), Crawler: q.Crawler}
	if ci < nCountries-1 {
		e.Country = [2]byte{byte('A' + ci/26), byte('A' + ci%26)}
	}
	rc.ring.Add(&e)
}

// ringOutcome maps the class of a request to its RequestOutcome.
func ringOutcome(q *Req) uint8 {
	switch q.Class {
	case Forwarded:
		if q.WouldBlock {
			return reqring.OutWouldBlock
		}
		return reqring.OutPassed
	case BlockedWAF:
		return reqring.OutBlockedWAF
	case BlockedBehaviour, Challenged:
		return reqring.OutBlockedBehaviour
	case RateLimited:
		return reqring.OutRateLimited
	case RejectedLimit:
		return reqring.OutRejectedLimit
	case BlockedCrawler:
		return reqring.OutBlockedCrawler
	}
	return reqring.OutFailClosed
}

func ms(d time.Duration) float64 { return float64(d) / 1e6 }

// isDocument: Sec-Fetch-Dest document, or without it an Accept naming text/html.
func isDocument(r *http.Request) bool {
	if d := r.Header.Get("Sec-Fetch-Dest"); d != "" {
		return d == "document"
	}
	return strings.Contains(r.Header.Get("Accept"), "text/html")
}

// asnKey: small ASNs come from a table, so the common case does not allocate.
func asnKey(n uint32) string {
	if n < uint32(len(asnStrings)) {
		return asnStrings[n]
	}
	return formatUint(n)
}

var asnStrings = func() []string {
	out := make([]string, 65536)
	for i := range out {
		out[i] = formatUint(uint32(i))
	}
	return out
}()

func formatUint(n uint32) string {
	var b [10]byte
	i := len(b)
	for {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
		if n == 0 {
			break
		}
	}
	return string(b[i:])
}

// swap hands the per-second accumulator of every shard to fn and resets it
// afterwards; the request path keeps counting into the other buffer.
func (rc *recorder) swap(fn func(*accum)) {
	for i := range rc.shards {
		s := &rc.shards[i]
		s.mu.Lock()
		s.cur, s.old = s.old, s.cur
		s.mu.Unlock()
		fn(s.old)
		s.old.reset()
	}
}

// boundedCache maps strings to computed values, bounded in entries and in
// bytes: keys longer than cacheKeyMax are computed and never stored, and a
// stripe that reaches cacheStripeMax entries or cacheStripeBytes starts
// over. A flood of distinct or long keys costs CPU, never memory (MVP-21
// measurement finding 4: raw paths as keys grew to 1.2 GB). A hit does not
// allocate.
type boundedCache[V ~string] struct {
	stripes [16]struct {
		mu    sync.RWMutex
		m     map[string]V
		bytes int
	}
}

const (
	cacheStripeMax   = 2048
	cacheStripeBytes = 128 << 10 // keys plus values: at most 2 MiB per cache
	cacheKeyMax      = 256
)

func (t *boundedCache[V]) init() {
	for i := range t.stripes {
		t.stripes[i].m = make(map[string]V, 256)
	}
}

func (t *boundedCache[V]) get(k string, compute func(string) V) V {
	if len(k) > cacheKeyMax {
		return compute(k)
	}
	st := &t.stripes[(len(k)+int(k[len(k)-1]))%len(t.stripes)]
	st.mu.RLock()
	v, ok := st.m[k]
	st.mu.RUnlock()
	if ok {
		return v
	}
	v = compute(k)
	size := len(k) + len(v) + 48 // map entry and string headers
	st.mu.Lock()
	if len(st.m) >= cacheStripeMax || st.bytes+size > cacheStripeBytes {
		clear(st.m)
		st.bytes = 0
	}
	if _, dup := st.m[k]; !dup {
		st.m[strings.Clone(k)] = v
		st.bytes += size
	}
	st.mu.Unlock()
	return v
}

// tplCache caches path templates (pathtpl allocates).
type tplCache struct{ c boundedCache[string] }

func (t *tplCache) init() { t.c.init() }

// tplInputMax: a longer path is templated from its first bytes only; the
// template itself is cut at pathtpl.MaxLen anyway.
const tplInputMax = 2 * pathtpl.MaxLen

func (t *tplCache) template(p string) string {
	if p == "" || p == "/" {
		return "/"
	}
	if len(p) > tplInputMax {
		p = p[:tplInputMax]
	}
	return t.c.get(p, pathtpl.Template)
}

// domainCache caches registrable domains of referrer hosts ("" = none).
type domainCache struct{ c boundedCache[string] }

func (d *domainCache) init() { d.c.init() }

func (d *domainCache) registrable(h string) string {
	return d.c.get(h, func(h string) string {
		r, err := publicsuffix.EffectiveTLDPlusOne(h)
		if err != nil {
			return ""
		}
		return r
	})
}
