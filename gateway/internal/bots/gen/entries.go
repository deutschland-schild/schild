package main

// own is a catalogue entry maintained by schild (no "source" in the
// catalogue). Order matters only for ties of equally long tokens.
type own struct {
	id, name, operator, category, robots string
	ua                                   []string
	ranges                               string
	rdns                                 []string
	url                                  string
}

var (
	rdnsGoogle = []string{"googlebot.com", "google.com"}
	rdnsBing   = []string{"search.msn.com"}
	rdnsYandex = []string{"yandex.ru", "yandex.net", "yandex.com"}
)

// ownBots: search engines, SEO tools, monitoring, preview and social, feed
// readers, archives and research, security scanners and tool libraries.
// The AI crawlers come from ai.robots.txt (see overrides).
var ownBots = []own{
	// Search engines. Google's common crawlers use googlebot.json, the
	// special-case crawlers special-crawlers.json, the user-triggered
	// fetchers the two user-triggered-fetchers lists.
	{id: "googlebot-image", name: "Googlebot-Image", operator: "Google", category: "search_engine", robots: "Googlebot-Image", ua: []string{"Googlebot-Image"}, ranges: "googlebot", rdns: rdnsGoogle},
	{id: "googlebot-video", name: "Googlebot-Video", operator: "Google", category: "search_engine", robots: "Googlebot-Video", ua: []string{"Googlebot-Video"}, ranges: "googlebot", rdns: rdnsGoogle},
	{id: "googlebot-news", name: "Googlebot-News", operator: "Google", category: "search_engine", robots: "Googlebot-News", ua: []string{"Googlebot-News"}, ranges: "googlebot", rdns: rdnsGoogle},
	{id: "storebot-google", name: "Storebot-Google", operator: "Google", category: "search_engine", robots: "Storebot-Google", ua: []string{"Storebot-Google"}, ranges: "googlebot", rdns: rdnsGoogle},
	{id: "google-inspectiontool", name: "Google-InspectionTool", operator: "Google", category: "search_engine", robots: "Google-InspectionTool", ua: []string{"Google-InspectionTool"}, ranges: "googlebot", rdns: rdnsGoogle},
	{id: "googlebot", name: "Googlebot", operator: "Google", category: "search_engine", robots: "Googlebot", ua: []string{"Googlebot"}, ranges: "googlebot", rdns: rdnsGoogle, url: "https://developers.google.com/search/docs/crawling-indexing/googlebot"},
	{id: "adsbot-google", name: "AdsBot-Google", operator: "Google", category: "search_engine", robots: "AdsBot-Google", ua: []string{"AdsBot-Google"}, ranges: "google-special", rdns: rdnsGoogle},
	{id: "mediapartners-google", name: "Mediapartners-Google", operator: "Google", category: "search_engine", robots: "Mediapartners-Google", ua: []string{"Mediapartners-Google"}, ranges: "google-special", rdns: rdnsGoogle},
	{id: "apis-google", name: "APIs-Google", operator: "Google", category: "search_engine", robots: "APIs-Google", ua: []string{"APIs-Google"}, ranges: "google-special", rdns: rdnsGoogle},
	{id: "google-safety", name: "Google-Safety", operator: "Google", category: "security_scanner", ua: []string{"Google-Safety"}, ranges: "google-special", rdns: rdnsGoogle},
	{id: "feedfetcher-google", name: "FeedFetcher-Google", operator: "Google", category: "feed_reader", ua: []string{"FeedFetcher-Google"}, ranges: "google-fetchers", rdns: rdnsGoogle},
	{id: "google-site-verification", name: "Google-Site-Verification", operator: "Google", category: "monitoring", ua: []string{"Google-Site-Verification"}, ranges: "google-fetchers", rdns: rdnsGoogle},
	{id: "google-read-aloud", name: "Google-Read-Aloud", operator: "Google", category: "preview_social", ua: []string{"Google-Read-Aloud"}, ranges: "google-fetchers", rdns: rdnsGoogle},
	{id: "bingbot", name: "Bingbot", operator: "Microsoft", category: "search_engine", robots: "bingbot", ua: []string{"bingbot"}, ranges: "bingbot", rdns: rdnsBing, url: "https://www.bing.com/webmasters/help/which-crawlers-does-bing-use-8c184ec0"},
	{id: "msnbot", name: "msnbot", operator: "Microsoft", category: "search_engine", robots: "msnbot", ua: []string{"msnbot"}, ranges: "bingbot", rdns: rdnsBing},
	{id: "adidxbot", name: "AdIdxBot", operator: "Microsoft", category: "search_engine", robots: "adidxbot", ua: []string{"adidxbot"}, ranges: "bingbot", rdns: rdnsBing},
	{id: "bingpreview", name: "BingPreview", operator: "Microsoft", category: "preview_social", ua: []string{"BingPreview"}, ranges: "bingbot", rdns: rdnsBing},
	{id: "applebot", name: "Applebot", operator: "Apple", category: "search_engine", robots: "Applebot", ua: []string{"Applebot"}, ranges: "applebot", rdns: []string{"applebot.apple.com"}, url: "https://support.apple.com/en-us/119829"},
	{id: "duckduckbot", name: "DuckDuckBot", operator: "DuckDuckGo", category: "search_engine", robots: "DuckDuckBot", ua: []string{"DuckDuckBot"}, ranges: "duckduckgo", url: "https://duckduckgo.com/duckduckgo-help-pages/results/duckduckbot"},
	{id: "yandexbot", name: "YandexBot", operator: "Yandex", category: "search_engine", robots: "Yandex", ua: []string{"YandexBot", "YandexMobileBot", "YandexImages", "YandexVideo", "YandexNews", "YandexRenderResourcesBot"}, rdns: rdnsYandex},
	{id: "baiduspider", name: "Baiduspider", operator: "Baidu", category: "search_engine", robots: "Baiduspider", ua: []string{"Baiduspider"}, rdns: []string{"baidu.com", "baidu.jp"}},
	{id: "seznambot", name: "SeznamBot", operator: "Seznam.cz", category: "search_engine", robots: "SeznamBot", ua: []string{"SeznamBot", "Seznam"}, rdns: []string{"seznam.cz"}},
	{id: "qwantbot", name: "Qwantbot", operator: "Qwant", category: "search_engine", robots: "Qwantbot", ua: []string{"Qwantbot", "Qwantify"}},
	{id: "petalbot", name: "PetalBot", operator: "Huawei", category: "search_engine", robots: "PetalBot", ua: []string{"PetalBot"}, rdns: []string{"petalsearch.com"}},
	{id: "sogou", name: "Sogou Spider", operator: "Sogou", category: "search_engine", robots: "Sogou", ua: []string{"Sogou"}},
	{id: "mojeekbot", name: "MojeekBot", operator: "Mojeek", category: "search_engine", robots: "MojeekBot", ua: []string{"MojeekBot"}, ranges: "mojeekbot", rdns: []string{"mojeek.com"}},
	{id: "yahoo-slurp", name: "Yahoo! Slurp", operator: "Yahoo", category: "search_engine", robots: "Slurp", ua: []string{"Yahoo! Slurp"}, rdns: []string{"crawl.yahoo.net"}},
	{id: "yeti", name: "Yeti", operator: "Naver", category: "search_engine", robots: "Yeti", ua: []string{"Yeti/"}, rdns: []string{"naver.com"}},
	{id: "coccocbot", name: "coccocbot", operator: "Coc Coc", category: "search_engine", robots: "coccocbot", ua: []string{"coccocbot"}},
	{id: "360spider", name: "360Spider", operator: "Qihoo 360", category: "search_engine", robots: "360Spider", ua: []string{"360Spider"}},
	{id: "yisouspider", name: "YisouSpider", operator: "Alibaba", category: "search_engine", robots: "YisouSpider", ua: []string{"YisouSpider"}},
	{id: "mail-ru-bot", name: "Mail.RU_Bot", operator: "VK", category: "search_engine", robots: "Mail.RU_Bot", ua: []string{"Mail.RU_Bot"}},
	{id: "seekportbot", name: "SeekportBot", operator: "Seekport", category: "search_engine", robots: "SeekportBot", ua: []string{"SeekportBot"}},

	// SEO tools.
	{id: "ahrefsbot", name: "AhrefsBot", operator: "Ahrefs", category: "seo_tool", robots: "AhrefsBot", ua: []string{"AhrefsBot", "AhrefsSiteAudit"}, ranges: "ahrefs", rdns: []string{"ahrefs.com", "ahrefs.net"}},
	{id: "semrushbot", name: "SemrushBot", operator: "Semrush", category: "seo_tool", robots: "SemrushBot", ua: []string{"SemrushBot"}, rdns: []string{"semrush.com"}},
	{id: "mj12bot", name: "MJ12bot", operator: "Majestic", category: "seo_tool", robots: "MJ12bot", ua: []string{"MJ12bot"}},
	{id: "dotbot", name: "DotBot", operator: "Moz", category: "seo_tool", robots: "dotbot", ua: []string{"DotBot"}},
	{id: "rogerbot", name: "rogerbot", operator: "Moz", category: "seo_tool", robots: "rogerbot", ua: []string{"rogerbot"}},
	{id: "screaming-frog", name: "Screaming Frog SEO Spider", operator: "Screaming Frog", category: "seo_tool", robots: "Screaming", ua: []string{"Screaming Frog"}},
	{id: "seokicks", name: "SEOkicks", operator: "SEOkicks", category: "seo_tool", robots: "SEOkicks", ua: []string{"SEOkicks"}},
	{id: "blexbot", name: "BLEXBot", operator: "WebMeUp", category: "seo_tool", robots: "BLEXBot", ua: []string{"BLEXBot"}},
	{id: "dataforseobot", name: "DataForSeoBot", operator: "DataForSEO", category: "seo_tool", robots: "DataForSeoBot", ua: []string{"DataForSeoBot"}},
	{id: "serpstatbot", name: "serpstatbot", operator: "Serpstat", category: "seo_tool", robots: "serpstatbot", ua: []string{"serpstatbot"}},
	{id: "barkrowler", name: "Barkrowler", operator: "Babbar", category: "seo_tool", robots: "Barkrowler", ua: []string{"Barkrowler"}},
	{id: "sistrix", name: "SISTRIX Crawler", operator: "SISTRIX", category: "seo_tool", robots: "SISTRIX", ua: []string{"SISTRIX"}},
	{id: "sitebulb", name: "Sitebulb", operator: "Sitebulb", category: "seo_tool", robots: "Sitebulb", ua: []string{"Sitebulb"}},
	{id: "seobility", name: "SeobilityBot", operator: "Seobility", category: "seo_tool", robots: "SeobilityBot", ua: []string{"SeobilityBot"}},

	// Monitoring.
	{id: "uptimerobot", name: "UptimeRobot", operator: "UptimeRobot", category: "monitoring", ua: []string{"UptimeRobot"}, ranges: "uptimerobot"},
	{id: "pingdom", name: "Pingdom", operator: "SolarWinds", category: "monitoring", ua: []string{"Pingdom"}, ranges: "pingdom"},
	{id: "statuscake", name: "StatusCake", operator: "StatusCake", category: "monitoring", ua: []string{"StatusCake"}},
	{id: "betteruptime", name: "Better Stack Uptime", operator: "Better Stack", category: "monitoring", ua: []string{"BetterUptime", "Better Uptime"}},
	{id: "site24x7", name: "Site24x7", operator: "Zoho", category: "monitoring", ua: []string{"Site24x7"}},
	{id: "updown", name: "updown.io", operator: "updown.io", category: "monitoring", ua: []string{"updown.io"}},
	{id: "hetrixtools", name: "HetrixTools", operator: "HetrixTools", category: "monitoring", ua: []string{"HetrixTools"}},
	{id: "uptime-kuma", name: "Uptime Kuma", operator: "Uptime Kuma", category: "monitoring", ua: []string{"Uptime-Kuma"}},
	{id: "checkly", name: "Checkly", operator: "Checkly", category: "monitoring", ua: []string{"Checkly"}},
	{id: "freshping", name: "Freshping", operator: "Freshworks", category: "monitoring", ua: []string{"Freshping"}},
	{id: "monitis", name: "Monitis", operator: "Monitis", category: "monitoring", ua: []string{"Monitis"}},
	{id: "nodeping", name: "NodePing", operator: "NodePing", category: "monitoring", ua: []string{"NodePing"}},
	{id: "datadog-synthetics", name: "Datadog Synthetics", operator: "Datadog", category: "monitoring", ua: []string{"DatadogSynthetics", "Datadog/Synthetics"}},
	{id: "newrelic-pinger", name: "NewRelicPinger", operator: "New Relic", category: "monitoring", ua: []string{"NewRelicPinger"}},
	{id: "chrome-lighthouse", name: "Lighthouse", operator: "Google", category: "monitoring", ua: []string{"Chrome-Lighthouse"}},

	// Link previews and social networks.
	{id: "facebookexternalhit", name: "facebookexternalhit", operator: "Meta", category: "preview_social", robots: "facebookexternalhit", ua: []string{"facebookexternalhit", "facebookcatalog"}, url: "https://developers.facebook.com/docs/sharing/webmasters/web-crawlers"},
	{id: "twitterbot", name: "Twitterbot", operator: "X", category: "preview_social", robots: "Twitterbot", ua: []string{"Twitterbot"}},
	{id: "linkedinbot", name: "LinkedInBot", operator: "LinkedIn", category: "preview_social", robots: "LinkedInBot", ua: []string{"LinkedInBot"}},
	{id: "slackbot", name: "Slackbot", operator: "Slack", category: "preview_social", robots: "Slackbot", ua: []string{"Slackbot", "Slack-ImgProxy"}},
	{id: "discordbot", name: "Discordbot", operator: "Discord", category: "preview_social", robots: "Discordbot", ua: []string{"Discordbot"}},
	{id: "telegrambot", name: "TelegramBot", operator: "Telegram", category: "preview_social", robots: "TelegramBot", ua: []string{"TelegramBot"}},
	{id: "whatsapp", name: "WhatsApp", operator: "Meta", category: "preview_social", ua: []string{"WhatsApp"}},
	{id: "skypeuripreview", name: "SkypeUriPreview", operator: "Microsoft", category: "preview_social", ua: []string{"SkypeUriPreview"}},
	{id: "pinterestbot", name: "Pinterestbot", operator: "Pinterest", category: "preview_social", robots: "Pinterestbot", ua: []string{"Pinterestbot", "Pinterest/"}},
	{id: "redditbot", name: "redditbot", operator: "Reddit", category: "preview_social", robots: "redditbot", ua: []string{"redditbot"}},
	{id: "mastodon", name: "Mastodon", operator: "Mastodon instances", category: "preview_social", ua: []string{"Mastodon"}},
	{id: "bluesky-cardyb", name: "Bluesky Cardyb", operator: "Bluesky", category: "preview_social", ua: []string{"Cardyb"}},
	{id: "embedly", name: "Embedly", operator: "Medium", category: "preview_social", ua: []string{"Embedly"}},
	{id: "vkshare", name: "vkShare", operator: "VK", category: "preview_social", ua: []string{"vkShare"}},
	{id: "iframely", name: "Iframely", operator: "Iframely", category: "preview_social", ua: []string{"Iframely"}},

	// Feed readers.
	{id: "feedly", name: "Feedly", operator: "Feedly", category: "feed_reader", ua: []string{"Feedly"}},
	{id: "feedbin", name: "Feedbin", operator: "Feedbin", category: "feed_reader", ua: []string{"Feedbin"}},
	{id: "inoreader", name: "Inoreader", operator: "Inoreader", category: "feed_reader", ua: []string{"Inoreader"}},
	{id: "newsblur", name: "NewsBlur", operator: "NewsBlur", category: "feed_reader", ua: []string{"NewsBlur"}},
	{id: "theoldreader", name: "The Old Reader", operator: "The Old Reader", category: "feed_reader", ua: []string{"TheOldReader"}},
	{id: "tiny-tiny-rss", name: "Tiny Tiny RSS", operator: "Tiny Tiny RSS", category: "feed_reader", ua: []string{"Tiny Tiny RSS"}},
	{id: "freshrss", name: "FreshRSS", operator: "FreshRSS", category: "feed_reader", ua: []string{"FreshRSS"}},
	{id: "miniflux", name: "Miniflux", operator: "Miniflux", category: "feed_reader", ua: []string{"Miniflux"}},
	{id: "netnewswire", name: "NetNewsWire", operator: "NetNewsWire", category: "feed_reader", ua: []string{"NetNewsWire"}},
	{id: "feedfetcher", name: "Feed fetcher", operator: "Unknown", category: "feed_reader", ua: []string{"Feedfetcher"}},

	// Archives and research.
	{id: "internet-archive", name: "Internet Archive", operator: "Internet Archive", category: "archive_research", robots: "ia_archiver", ua: []string{"archive.org_bot", "ia_archiver"}},
	{id: "heritrix", name: "Heritrix", operator: "Unknown", category: "archive_research", ua: []string{"heritrix"}},
	{id: "researchscan", name: "researchscan", operator: "RWTH Aachen", category: "archive_research", ua: []string{"researchscan"}},
	{id: "netcraft", name: "Netcraft Survey", operator: "Netcraft", category: "archive_research", ua: []string{"NetcraftSurveyAgent"}},

	// Security scanners.
	{id: "nuclei", name: "Nuclei", operator: "ProjectDiscovery", category: "security_scanner", ua: []string{"Nuclei"}},
	{id: "sqlmap", name: "sqlmap", operator: "sqlmap project", category: "security_scanner", ua: []string{"sqlmap"}},
	{id: "nikto", name: "Nikto", operator: "Nikto project", category: "security_scanner", ua: []string{"Nikto"}},
	{id: "nmap", name: "Nmap", operator: "Nmap project", category: "security_scanner", ua: []string{"Nmap"}},
	{id: "masscan", name: "masscan", operator: "masscan project", category: "security_scanner", ua: []string{"masscan"}},
	{id: "zgrab", name: "ZGrab", operator: "ZMap project", category: "security_scanner", ua: []string{"zgrab"}},
	{id: "wpscan", name: "WPScan", operator: "Automattic", category: "security_scanner", ua: []string{"WPScan"}},
	{id: "acunetix", name: "Acunetix", operator: "Invicti", category: "security_scanner", ua: []string{"Acunetix"}},
	{id: "nessus", name: "Nessus", operator: "Tenable", category: "security_scanner", ua: []string{"Nessus"}},
	{id: "openvas", name: "OpenVAS", operator: "Greenbone", category: "security_scanner", ua: []string{"OpenVAS"}},
	{id: "censys", name: "Censys", operator: "Censys", category: "security_scanner", ua: []string{"CensysInspect"}},
	{id: "expanse", name: "Expanse", operator: "Palo Alto Networks", category: "security_scanner", ua: []string{"Expanse"}},
	{id: "internet-measurement", name: "internet-measurement.com", operator: "Driftnet", category: "security_scanner", ua: []string{"internet-measurement"}},
	{id: "dirbuster", name: "DirBuster", operator: "OWASP", category: "security_scanner", ua: []string{"DirBuster"}},
	{id: "gobuster", name: "gobuster", operator: "gobuster project", category: "security_scanner", ua: []string{"gobuster"}},
	{id: "ffuf", name: "ffuf", operator: "ffuf project", category: "security_scanner", ua: []string{"ffuf", "Fuzz Faster U Fool"}},
	{id: "wfuzz", name: "Wfuzz", operator: "Wfuzz project", category: "security_scanner", ua: []string{"Wfuzz"}},
	{id: "qualys", name: "Qualys", operator: "Qualys", category: "security_scanner", ua: []string{"Qualys"}},
	{id: "leakix", name: "LeakIX", operator: "LeakIX", category: "security_scanner", ua: []string{"l9explore", "l9tcpid", "LeakIX"}},

	// Tool libraries and command line tools.
	{id: "curl", name: "curl", operator: "curl project", category: "tool_library", ua: []string{"curl/"}},
	{id: "wget", name: "Wget", operator: "GNU", category: "tool_library", ua: []string{"Wget/"}},
	{id: "python-requests", name: "python-requests", operator: "Python Software Foundation", category: "tool_library", ua: []string{"python-requests"}},
	{id: "python-urllib", name: "Python urllib", operator: "Python Software Foundation", category: "tool_library", ua: []string{"Python-urllib"}},
	{id: "python-httpx", name: "HTTPX", operator: "Encode", category: "tool_library", ua: []string{"python-httpx"}},
	{id: "aiohttp", name: "aiohttp", operator: "aio-libs", category: "tool_library", ua: []string{"aiohttp"}},
	{id: "go-http-client", name: "Go HTTP client", operator: "Go project", category: "tool_library", ua: []string{"Go-http-client"}},
	{id: "libwww-perl", name: "libwww-perl", operator: "Perl", category: "tool_library", ua: []string{"libwww-perl"}},
	{id: "okhttp", name: "OkHttp", operator: "Square", category: "tool_library", ua: []string{"okhttp"}},
	{id: "java", name: "Java HTTP client", operator: "Java", category: "tool_library", ua: []string{"Java/"}},
	{id: "apache-httpclient", name: "Apache HttpClient", operator: "Apache Software Foundation", category: "tool_library", ua: []string{"Apache-HttpClient"}},
	{id: "axios", name: "axios", operator: "axios project", category: "tool_library", ua: []string{"axios/"}},
	{id: "node-fetch", name: "node-fetch", operator: "node-fetch project", category: "tool_library", ua: []string{"node-fetch"}},
	{id: "undici", name: "undici", operator: "Node.js", category: "tool_library", ua: []string{"undici"}},
	{id: "guzzle", name: "Guzzle", operator: "Guzzle project", category: "tool_library", ua: []string{"GuzzleHttp"}},
	{id: "postman", name: "Postman", operator: "Postman", category: "tool_library", ua: []string{"PostmanRuntime"}},
	{id: "insomnia", name: "Insomnia", operator: "Kong", category: "tool_library", ua: []string{"insomnia"}},
	{id: "httpie", name: "HTTPie", operator: "HTTPie", category: "tool_library", ua: []string{"HTTPie"}},
	{id: "powershell", name: "PowerShell", operator: "Microsoft", category: "tool_library", ua: []string{"PowerShell"}},
}

// override changes an ai.robots.txt entry (keyed by its exact name).
type override struct {
	skip     bool
	operator string
	category string
	ranges   string
	rdns     []string
}

// overrides: ai.robots.txt names that are too generic as User-Agent
// substrings (they would match ordinary software) are skipped; known
// crawlers get their operator's ranges and a category where the
// ai.robots.txt function text is ambiguous.
var overrides = map[string]override{
	// Too generic as a substring of a User-Agent, or equal to an
	// automation token.
	"Code": {skip: true}, "Codex": {skip: true}, "Cursor": {skip: true}, "Dot": {skip: true}, "Spider": {skip: true},
	"Operator": {skip: true}, "Muse": {skip: true}, "Instinct": {skip: true}, "LCC": {skip: true}, "Trae": {skip: true},
	"YaK": {skip: true}, "UseAI": {skip: true}, "OpenAI": {skip: true}, "Devin": {skip: true}, "nbot": {skip: true},

	"GPTBot":                    {category: "ai_training", operator: "OpenAI", ranges: "gptbot"},
	"OAI-SearchBot":             {category: "ai_search", operator: "OpenAI", ranges: "oai-searchbot"},
	"ChatGPT-User":              {category: "ai_assistant", operator: "OpenAI", ranges: "chatgpt-user"},
	"ChatGPT Agent":             {category: "ai_assistant", operator: "OpenAI"},
	"OAI-AdsBot":                {category: "ai_search", operator: "OpenAI"},
	"PerplexityBot":             {category: "ai_search", operator: "Perplexity", ranges: "perplexitybot"},
	"Perplexity-User":           {category: "ai_assistant", operator: "Perplexity", ranges: "perplexity-user"},
	"CCBot":                     {category: "ai_training", operator: "Common Crawl", ranges: "ccbot", rdns: []string{"crawl.commoncrawl.org"}},
	"DuckAssistBot":             {category: "ai_search", operator: "DuckDuckGo", ranges: "duckduckgo"},
	"MistralAI-User":            {category: "ai_assistant", operator: "Mistral AI", ranges: "mistralai-user"},
	"GoogleOther":               {category: "ai_training", operator: "Google", ranges: "googlebot", rdns: rdnsGoogle},
	"GoogleOther-Image":         {category: "ai_training", operator: "Google", ranges: "googlebot", rdns: rdnsGoogle},
	"GoogleOther-Video":         {category: "ai_training", operator: "Google", ranges: "googlebot", rdns: rdnsGoogle},
	"Google-CloudVertexBot":     {category: "ai_training", operator: "Google", ranges: "google-special", rdns: rdnsGoogle},
	"Google-Extended":           {category: "ai_training", operator: "Google"},
	"Amazonbot":                 {category: "ai_training", operator: "Amazon", rdns: []string{"crawl.amazonbot.amazon"}},
	"Applebot-Extended":         {category: "ai_training", operator: "Apple"},
	"FacebookBot":               {category: "ai_training", operator: "Meta"},
	"meta-externalagent":        {category: "ai_training", operator: "Meta"},
	"meta-externalfetcher":      {category: "ai_assistant", operator: "Meta"},
	"meta-webindexer":           {category: "ai_search", operator: "Meta"},
	"ClaudeBot":                 {category: "ai_training", operator: "Anthropic"},
	"anthropic-ai":              {category: "ai_training", operator: "Anthropic"},
	"Claude-SearchBot":          {category: "ai_search", operator: "Anthropic"},
	"Claude-User":               {category: "ai_assistant", operator: "Anthropic"},
	"Claude-Web":                {category: "ai_assistant", operator: "Anthropic"},
	"Claude-Code":               {category: "ai_assistant", operator: "Anthropic"},
	"PanguBot":                  {category: "ai_training", operator: "Huawei"},
	"Bytespider":                {category: "ai_training", operator: "ByteDance"},
	"YouBot":                    {category: "ai_search", operator: "You.com"},
	"PhindBot":                  {category: "ai_search", operator: "Phind"},
	"Bravebot":                  {category: "search_engine", operator: "Brave"},
	"Scrapy":                    {category: "tool_library", operator: "Zyte"},
	"Lightpanda":                {category: "tool_library", operator: "Lightpanda"},
	"Crawl4AI":                  {category: "tool_library", operator: "Unknown"},
	"SemrushBot-OCOB":           {category: "seo_tool", operator: "Semrush"},
	"SemrushBot-SWA":            {category: "seo_tool", operator: "Semrush"},
	"Linguee Bot":               {category: "ai_assistant"},
	"QuillBot":                  {category: "ai_assistant"},
	"quillbot.com":              {category: "ai_assistant"},
	"wpbot":                     {category: "ai_assistant"},
	"Poseidon Research Crawler": {category: "archive_research"},
}

// automationTokens: generic tokens of automated clients for user agents no
// entry matches (contract rule 2, only for "Mozilla/..." user agents).
var automationTokens = []string{"bot", "crawl", "spider", "scrape", "headless", "python", "curl", "wget", "phantomjs", "selenium",
	"puppeteer", "playwright", "httpclient", "go-http"}
