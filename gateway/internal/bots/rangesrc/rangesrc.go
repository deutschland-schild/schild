// Package rangesrc lists and fetches the address ranges bot operators publish
// (MVP-22). It is used by the build-time catalogue generator (bots/gen) and
// by the optional runtime fetch (bots.ranges_fetch); it has no embedded
// data, so the generator builds without a catalogue.
package rangesrc

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"time"
)

// Source is where an operator publishes the address ranges of one
// range set. The build-time generator (gen) and the optional runtime fetch
// (bots.ranges_fetch) read the same list.
type Source struct {
	ID       string
	Operator string
	// URLs are merged into one set. The catalogue's range set names the
	// first (the contract has one url per set); Google publishes its
	// user-triggered fetchers in two lists that apply to the same fetchers.
	URLs []string
	// Format: FormatJSON (Google style {"prefixes":[{"ipv4Prefix":..},
	// {"ipv6Prefix":..}]}) or FormatLines (one address or prefix per line).
	Format string
}

// Range source formats.
const (
	FormatJSON  = "json"
	FormatLines = "lines"
)

// MaxRangeBytes caps one downloaded range list.
const MaxRangeBytes = 2 << 20

// MaxPrefixes per range set (bot-catalogue.schema.json).
const MaxPrefixes = 4096

// Sources are the published range lists known to schild (checked
// 2026-10-29). Operators without a machine-readable list (Anthropic, Meta,
// Yandex, Baidu, ...) are verified by FCrDNS only (off by default) and are
// otherwise claimed.
var Sources = []Source{
	{ID: "googlebot", Operator: "Google", Format: FormatJSON, URLs: []string{"https://developers.google.com/static/search/apis/ipranges/googlebot.json"}},
	{ID: "google-special", Operator: "Google", Format: FormatJSON, URLs: []string{"https://developers.google.com/static/search/apis/ipranges/special-crawlers.json"}},
	{ID: "google-fetchers", Operator: "Google", Format: FormatJSON, URLs: []string{
		"https://developers.google.com/static/search/apis/ipranges/user-triggered-fetchers.json",
		"https://developers.google.com/static/search/apis/ipranges/user-triggered-fetchers-google.json",
	}},
	{ID: "bingbot", Operator: "Microsoft", Format: FormatJSON, URLs: []string{"https://www.bing.com/toolbox/bingbot.json"}},
	{ID: "gptbot", Operator: "OpenAI", Format: FormatJSON, URLs: []string{"https://openai.com/gptbot.json"}},
	{ID: "oai-searchbot", Operator: "OpenAI", Format: FormatJSON, URLs: []string{"https://openai.com/searchbot.json"}},
	{ID: "chatgpt-user", Operator: "OpenAI", Format: FormatJSON, URLs: []string{"https://openai.com/chatgpt-user.json"}},
	{ID: "perplexitybot", Operator: "Perplexity", Format: FormatJSON, URLs: []string{"https://www.perplexity.ai/perplexitybot.json"}},
	{ID: "perplexity-user", Operator: "Perplexity", Format: FormatJSON, URLs: []string{"https://www.perplexity.ai/perplexity-user.json"}},
	{ID: "applebot", Operator: "Apple", Format: FormatJSON, URLs: []string{"https://search.developer.apple.com/applebot.json"}},
	{ID: "duckduckgo", Operator: "DuckDuckGo", Format: FormatJSON, URLs: []string{"https://duckduckgo.com/duckduckbot.json"}},
	{ID: "ccbot", Operator: "Common Crawl", Format: FormatJSON, URLs: []string{"https://index.commoncrawl.org/ccbot.json"}},
	{ID: "ahrefs", Operator: "Ahrefs", Format: FormatJSON, URLs: []string{"https://api.ahrefs.com/v3/public/crawler-ip-ranges"}},
	{ID: "mistralai-user", Operator: "Mistral AI", Format: FormatJSON, URLs: []string{"https://mistral.ai/mistralai-user-ips.json"}},
	{ID: "mojeekbot", Operator: "Mojeek", Format: FormatJSON, URLs: []string{"https://www.mojeek.com/mojeekbot.json"}},
	{ID: "uptimerobot", Operator: "UptimeRobot", Format: FormatLines, URLs: []string{"https://uptimerobot.com/inc/files/ips/IPv4andIPv6.txt"}},
	{ID: "pingdom", Operator: "Pingdom", Format: FormatLines, URLs: []string{"https://my.pingdom.com/probes/ipv4", "https://my.pingdom.com/probes/ipv6"}},
}

// ParseRanges reads one downloaded range list.
func ParseRanges(format string, raw []byte) ([]netip.Prefix, error) {
	var out []netip.Prefix
	switch format {
	case FormatJSON:
		var doc struct {
			Prefixes []struct {
				IPv4 string `json:"ipv4Prefix"`
				IPv6 string `json:"ipv6Prefix"`
			} `json:"prefixes"`
		}
		if err := json.Unmarshal(raw, &doc); err != nil {
			return nil, fmt.Errorf("range list: %w", err)
		}
		for _, p := range doc.Prefixes {
			for _, s := range []string{p.IPv4, p.IPv6} {
				if s == "" {
					continue
				}
				q, err := parseLoosePrefix(s)
				if err != nil {
					return nil, err
				}
				out = append(out, q)
			}
		}
	case FormatLines:
		sc := bufio.NewScanner(bytes.NewReader(raw))
		for sc.Scan() {
			l := strings.TrimSpace(sc.Text())
			if i := strings.IndexByte(l, '#'); i >= 0 {
				l = strings.TrimSpace(l[:i])
			}
			if l == "" {
				continue
			}
			q, err := parseLoosePrefix(l)
			if err != nil {
				return nil, err
			}
			out = append(out, q)
		}
		if err := sc.Err(); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("range list: unknown format %q", format)
	}
	if len(out) == 0 {
		return nil, errors.New("range list: no prefixes")
	}
	return out, nil
}

// Minimum prefix lengths accepted from downloaded range lists so a compromised
// upstream feed cannot whitelist large parts of the internet (e.g. 0.0.0.0/0).
const (
	minIPv4PrefixBits = 16
	minIPv6PrefixBits = 32
)

var (
	cgnatRange   = netip.MustParsePrefix("100.64.0.0/10")
	thisNetRange = netip.MustParsePrefix("0.0.0.0/8")
)

// parseLoosePrefix accepts a prefix or a single address and masks host
// bits; IPv4-mapped IPv6 is unmapped. Non-public or overly broad prefixes are
// refused.
func parseLoosePrefix(s string) (netip.Prefix, error) {
	var p netip.Prefix
	if !strings.Contains(s, "/") {
		a, err := netip.ParseAddr(s)
		if err != nil || a.Zone() != "" {
			return netip.Prefix{}, fmt.Errorf("range list: %q is no address", s)
		}
		a = a.Unmap()
		p = netip.PrefixFrom(a, a.BitLen())
	} else {
		var err error
		p, err = netip.ParsePrefix(s)
		if err != nil || p.Addr().Zone() != "" {
			return netip.Prefix{}, fmt.Errorf("range list: %q is no prefix", s)
		}
		if p.Addr().Is4In6() {
			if p.Bits() < 96 {
				return netip.Prefix{}, fmt.Errorf("range list: %q mixes IPv4 and IPv6", s)
			}
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
		}
		p = p.Masked()
	}
	if err := validateRangePrefix(p); err != nil {
		return netip.Prefix{}, err
	}
	return p, nil
}

func validateRangePrefix(p netip.Prefix) error {
	a := p.Addr()
	if (a.Is4() && p.Bits() < minIPv4PrefixBits) || (a.Is6() && p.Bits() < minIPv6PrefixBits) {
		return fmt.Errorf("range list: prefix %s is too broad", p)
	}
	if a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() || a.IsMulticast() || a.IsUnspecified() || cgnatRange.Contains(a) || thisNetRange.Contains(a) {
		return fmt.Errorf("range list: prefix %s is not a public range", p)
	}
	return nil
}

// CanonicalPrefixes sorts and de-duplicates prefixes (IPv4 first) and
// returns them as strings the contract accepts.
func CanonicalPrefixes(ps []netip.Prefix) []string {
	ps = append([]netip.Prefix(nil), ps...)
	sort.Slice(ps, func(i, j int) bool {
		a, b := ps[i], ps[j]
		if a.Addr().Is4() != b.Addr().Is4() {
			return a.Addr().Is4()
		}
		if c := a.Addr().Compare(b.Addr()); c != 0 {
			return c < 0
		}
		return a.Bits() < b.Bits()
	})
	out := make([]string, 0, len(ps))
	var last netip.Prefix
	for i, p := range ps {
		if i > 0 && p == last {
			continue
		}
		last = p
		out = append(out, p.String())
	}
	return out
}

// HTTPClient is the client for range lists: bounded time, https only,
// same host only on redirects, at most 5 redirects. It uses the default
// transport, so an HTTPS_PROXY of the environment applies.
func HTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("too many redirects")
			}
			if req.URL.Scheme != "https" {
				return errors.New("redirect to a non-https URL")
			}
			if !strings.EqualFold(req.URL.Host, via[0].URL.Host) {
				return errors.New("redirect to another host")
			}
			return nil
		},
	}
}

// FetchSource downloads and parses every list of src and returns the
// canonical prefixes. ua is the User-Agent of the requests.
func FetchSource(ctx context.Context, c *http.Client, src Source, ua string) ([]string, error) {
	var all []netip.Prefix
	for _, u := range src.URLs {
		raw, err := fetchCapped(ctx, c, u, ua, MaxRangeBytes)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", u, err)
		}
		ps, err := ParseRanges(src.Format, raw)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", u, err)
		}
		all = append(all, ps...)
	}
	out := CanonicalPrefixes(all)
	if len(out) > MaxPrefixes {
		return nil, fmt.Errorf("%s: %d prefixes > %d", src.ID, len(out), MaxPrefixes)
	}
	return out, nil
}

func fetchCapped(ctx context.Context, c *http.Client, u, ua string, max int64) ([]byte, error) {
	if pu, err := url.Parse(u); err != nil || pu.Scheme != "https" {
		return nil, errors.New("not an https URL")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept", "application/json, text/plain")
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > max {
		return nil, fmt.Errorf("larger than %d bytes", max)
	}
	return raw, nil
}
