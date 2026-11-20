package monitoring

import (
	"regexp"
	"strings"
)

// Breakdown dimensions and their fixed value sets (OpenAPI
// BreakdownDimension, UAClass, BrowserFamily, OSFamily, DeviceClass,
// BotCategory, ReferrerKey). The 2026-10-29 addendum (MVP-22
// MVP-21 addendum) adds referrer, browser, os, device, bot_category and rule.
// Tests keep the lists equal to the OpenAPI enums, in the same order.

// Dimensions in the order of the OpenAPI enum BreakdownDimension.
var Dimensions = []string{"path", "country", "asn", "net_class", "ua_class", "method", "status_class", "site",
	"referrer", "browser", "os", "device", "bot_category", "rule"}

// RingFilterDimensions are the client address and the User-Agent (D64,
// D65): as filters (an address, a case-insensitive part of the User-Agent)
// and as breakdowns (BreakdownDimension, after Dimensions). Only the request
// ring answers them, within its window; outside it they are
// filter_unavailable like two filters. The rings never hold them.
var RingFilterDimensions = []string{"ip", "user_agent"}

// EstimatedDimensions are served from space-saving top lists (TopEntry.error,
// TrafficBreakdown.exact false); every other dimension is exact.
var EstimatedDimensions = map[string]bool{"path": true, "asn": true, "referrer": true, "rule": true}

// TopK is the size of the space-saving lists per bucket (path, asn,
// referrer, rule).
const TopK = 64

// UAClasses (MVP-21).
var UAClasses = []string{"browser", "bot_verified", "bot_unverified", "tool", "none", "other"}

// BrowserFamilies, no versions.
var BrowserFamilies = []string{"chrome", "edge", "firefox", "safari", "opera", "samsung", "ie", "other", "none"}

// OSFamilies, no versions.
var OSFamilies = []string{"windows", "macos", "ios", "android", "linux", "chromeos", "other", "none"}

// DeviceClasses from the User-Agent (client hints are never requested).
var DeviceClasses = []string{"desktop", "mobile", "tablet", "other", "unknown"}

// BotCategories: the first eleven are catalogue categories
// (bot-catalogue.schema.json), the last two describe user agents no
// catalogue entry matches.
var BotCategories = []string{"search_engine", "ai_training", "ai_search", "ai_assistant", "preview_social", "feed_reader",
	"monitoring", "seo_tool", "archive_research", "security_scanner", "tool_library", "likely_automated", "likely_browser"}

// Unmatched bot categories.
const (
	CategoryLikelyAutomated = "likely_automated"
	CategoryLikelyBrowser   = "likely_browser"
)

// Referrer keys besides registrable domains.
const (
	ReferrerDirect = "_direct" // no Referer
	ReferrerIntern = "_intern" // a host of one of the gateway's own sites
	ReferrerOther  = "_other"  // unparsable, an IP address, or no registrable domain
	ReferrerAI     = "ai:"     // prefix of a known AI assistant
)

// referrerRe: the last label of a domain starts with a letter, so an IP
// address is never a referrer key.
var referrerRe = regexp.MustCompile(`^(_direct|_intern|_other|ai:[a-z0-9][a-z0-9-]{0,31}|([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]([a-z0-9-]{0,61}[a-z0-9])?)$`)

// ValidReferrerKey reports whether k is a ReferrerKey.
func ValidReferrerKey(k string) bool { return len(k) <= 253 && referrerRe.MatchString(k) }

// AIAssistant is one known AI assistant whose referrers are grouped under
// ReferrerAI + ID.
type AIAssistant struct {
	ID    string
	Name  string   // TopEntry.label
	Hosts []string // the host or any subdomain of it
}

// AIAssistants is the fixed table of AI assistant referrers. Adding an
// entry is a contract change (it changes breakdown keys).
var AIAssistants = []AIAssistant{
	{"chatgpt", "ChatGPT", []string{"chatgpt.com", "chat.openai.com"}},
	{"perplexity", "Perplexity", []string{"perplexity.ai"}},
	{"copilot", "Microsoft Copilot", []string{"copilot.microsoft.com"}},
	{"gemini", "Gemini", []string{"gemini.google.com", "bard.google.com"}},
	{"claude", "Claude", []string{"claude.ai"}},
	{"mistral", "Le Chat", []string{"chat.mistral.ai"}},
	{"deepseek", "DeepSeek", []string{"chat.deepseek.com"}},
	{"meta", "Meta AI", []string{"meta.ai"}},
	{"grok", "Grok", []string{"grok.com"}},
	{"you", "You.com", []string{"you.com"}},
	{"phind", "Phind", []string{"phind.com"}},
}

// AIAssistantOf returns the referrer key ("ai:<id>") and name of the AI
// assistant a Referer host belongs to (case-insensitive, a trailing dot
// ignored), or false.
func AIAssistantOf(host string) (key, name string, ok bool) {
	h := strings.TrimSuffix(strings.ToLower(host), ".")
	for _, a := range AIAssistants {
		for _, d := range a.Hosts {
			if h == d || strings.HasSuffix(h, "."+d) {
				return ReferrerAI + a.ID, a.Name, true
			}
		}
	}
	return "", "", false
}
