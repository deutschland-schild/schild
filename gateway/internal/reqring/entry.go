// Package reqring is the MVP-22 request ring (contracts v0.5, D35): single
// requests of the last keep_hours (at most 30 days, D66) in append-only 10 min
// segment files below <storage.path>/requests, for drill-down, combined
// filters, "Kontext" around incidents and the bot overview.
//
// What a record holds and what never reaches the disk is fixed by the
// contract (contract/requests): the client address and the user agent (D49,
// D50), no query string, no cookie, no full referrer. The writer goroutine adds the daily
// visitor key (HMAC with a random key held in memory only and replaced at
// 00:00 UTC and at every start). The address stays on this gateway.
//
// The request path builds an Entry on its stack and hands it to Add, a
// non-blocking channel send: a full channel drops the record and counts it.
// Everything else (visitor key, dictionaries, sampling, files, pins) runs in
// the writer goroutine.
package reqring

import (
	"net/netip"

	"github.com/deutschland-schild/schild/contract/events"
	cm "github.com/deutschland-schild/schild/contract/monitoring"
	cr "github.com/deutschland-schild/schild/contract/requests"
)

// Entry is one finished request as the request path hands it over. Strings
// reference memory the request already owns (no copies); the writer keeps
// none of them beyond the record it writes.
type Entry struct {
	T        int64 // request start, unix ms
	Client   netip.Addr
	Site     string // website id ("" none)
	Host     string // Host header as sent (normalised by the writer)
	RawPath  string // escaped path without query (the record's real path, D63, and robots.txt checks)
	Template string // path template (pathtpl)
	Referrer string // ReferrerKey
	UA       string // User-Agent as sent (D85)
	EventID  string // the event written for this request ("" none)
	Rules    [cr.MaxRules]string
	NRules   uint8
	Score    uint16
	Status   uint16
	BytesOut uint32
	ASN      uint32
	Country  [2]byte // upper-case ISO code, zero = ZZ
	Method   uint8   // index into Methods
	Outcome  uint8   // index into cr.Outcomes
	WBReason uint8   // 0 none, else 1 + index into events.WouldBlockReasons
	NetClass uint8   // index into NetClasses
	UAClass  uint8   // index into cm.UAClasses
	Browser  uint8   // index into cm.BrowserFamilies
	OS       uint8   // index into cm.OSFamilies
	Device   uint8   // index into cm.DeviceClasses
	BotCat   uint8   // index into cm.BotCategories
	Verif    uint8   // 0 no bot, else 1 + index into contract/bots.Verifications
	Bot      uint16  // catalogue bot id (0 none)
	Dur      uint8   // latency bucket (exp1.25-0.05ms)
	PageView bool
	// Crawler (D57): the crawler policy of the website alone decided the
	// outcome (blocked_crawler, or a would_block no WAF rule shares).
	Crawler bool
	// Pin asks the writer to keep the visitor's requests from 5 min before
	// to 5 min after this one unsampled (an incident or an alert).
	Pin bool
}

// Methods in the order of the monitoring method breakdown ("OTHER" last).
var Methods = []string{"GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "CONNECT", "TRACE", "OTHER"}

// NetClasses in the order of common.schema.json netClass (the monitoring
// net class breakdown).
var NetClasses = []string{"residential", "mobile", "cgnat", "hosting", "business", "education", "government", "tor", "vpn", "proxy", "unknown"}

// Outcome indices (cr.Outcomes order).
const (
	OutPassed uint8 = iota
	OutWouldBlock
	OutBlockedWAF
	OutBlockedBehaviour
	OutRateLimited
	OutRejectedLimit
	OutFailClosed
	OutBlockedCrawler // D57
)

// Verification indices of Entry.Verif (1 + contract order).
const (
	VerifNone uint8 = iota
	VerifVerified
	VerifClaimed
	VerifMismatch
	VerifUnknownStale
)

// WBReasonIndex returns the Entry.WBReason of a would_block reason.
func WBReasonIndex(s string) uint8 {
	for i, r := range events.WouldBlockReasons {
		if r == s {
			return uint8(i + 1)
		}
	}
	return 0
}

// stopped reports whether schild stopped the request (the "stopped" of the
// monitoring counters; fail_closed is not stopped).
func stopped(o uint8) bool {
	return o == OutBlockedWAF || o == OutBlockedBehaviour || o == OutRateLimited || o == OutRejectedLimit || o == OutBlockedCrawler
}

// alert reports whether a record is a WAF alert (detection): blocked by the
// WAF or would have been.
// A would_block of the crawler policy alone is no alert (D57).
func alert(r *Rec) bool {
	return (r.Outcome == OutBlockedWAF || r.Outcome == OutWouldBlock) && !r.Crawler
}

// browserFwd: the record makes its client a visitor (contract
// monitoring.Visitor): a browser request schild forwarded.
func browserFwd(r *Rec) bool {
	return int(r.BotCat) == len(cm.BotCategories)-1 && !r.HasBot && (r.Outcome == OutPassed || r.Outcome == OutWouldBlock)
}
