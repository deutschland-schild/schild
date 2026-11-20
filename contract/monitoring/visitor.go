package monitoring

// Visitors ("Besucher"), D36 amendment (initiator, 2026-10-29): like
// Plausible, the dashboard counts people, not bots. A client key enters the
// visitor estimates (BucketClients Unique, New and UniqueDay, per website and
// gateway-wide; TrafficNow.ClientsUnique; the KPI visitors and the Echtzeit
// visitors) only with a request for which Visitor is true. Every other
// request adds its client key to the bot client estimate (BucketClients.Bots)
// instead. A client can be in both within one bucket (two user agents behind
// one address). The rule is fixed by the website-visitor vectors (Go and
// Python agree).

// Request outcomes (OpenAPI RequestOutcome, MVP-22).
var RequestOutcomes = []string{"passed", "would_block", "blocked_waf", "blocked_behaviour", "rate_limited", "rejected_limit", "fail_closed", "blocked_crawler"}

// BrowserRequest reports whether a request came from a browser user agent:
// ua_class browser and bot category likely_browser (the two come together;
// the website-visitor schema refuses one without the other). bot_verified,
// bot_unverified, tool, none and other, and every catalogue category and
// likely_automated, are no browser requests.
func BrowserRequest(uaClass, botCategory string) bool {
	return uaClass == "browser" && botCategory == CategoryLikelyBrowser
}

// Visitor reports whether a request counts its client as a visitor: a
// browser request that schild forwarded (outcome passed or would_block).
// Requests schild stopped (blocked_waf, blocked_behaviour, rate_limited,
// rejected_limit) or could not inspect (fail_closed) never make a visitor,
// so an attacker with a browser user agent is not counted as one; page views
// follow the same rule (forwarded, likely_browser).
func Visitor(uaClass, botCategory, outcome string) bool {
	return BrowserRequest(uaClass, botCategory) && (outcome == "passed" || outcome == "would_block")
}

// BotClient reports whether a request counts its client in the bot client
// estimate ("Bot-Clients"): every request that is no browser request,
// whatever schild did with it.
func BotClient(uaClass, botCategory string) bool {
	return !BrowserRequest(uaClass, botCategory)
}

// VisitorResult is the result of a website-visitor vector.
type VisitorResult struct {
	Visitor   bool `json:"visitor"`
	BotClient bool `json:"bot_client"`
}
