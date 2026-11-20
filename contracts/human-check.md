# Human Check Contract (MVP-12 v1_cut)

Browser verification ("Kurze Prüfung") and Under Attack mode per website. Purely local, stateless proof-of-work (SHA-256) with an accessible no-JS button, no third-party services, no fingerprinting, no browser biometrics, and no persistent visitor identifiers.

## 1. Policy per website

Each website has a `Policy`:

- `website`: website ID (same grammar as `access-gate`).
- `mode`: `"off"` (default) | `"findings"` (*bei Auffälligkeiten*) | `"always"` (*immer*).
- `under_attack`: `{ scope: "off" | "admin" | "all", until: RFC3339 }`.
  - When `scope != "off"`, `until` is required and must be within `24h` of the time it is set (never indefinite).
  - Once `now >= until`, `under_attack` is inactive.
- `except`: optional list of up to 16 plain path prefixes (e.g. `"/api/*"`, `"/healthz"`) never challenged.
- `clearance_ttl_s`: clearance cookie lifetime in seconds (`60..3600`, default `1800` = 30 min).
- `difficulty`: PoW search upper bound (`1000..250000`, default `50000`, ~0.3–1 s in a browser Web Worker).

## 2. Decision (`Decide`)

`Decide` is a pure function evaluated on each request before forwarding:

1. **Never challenge non-navigations:** Only `GET` and `HEAD` requests where `Sec-Fetch-Mode == "navigate"` OR `Accept` contains `text/html`. APIs, `POST`, XHR/fetch, and assets always pass (`not_navigation`).
2. **Never challenge built-in bypass paths:** `/.well-known/*`, `/robots.txt`, `/favicon.ico` (`bypass_path`).
3. **Never challenge verified good bots** (`good_bot`) or **allowlisted IPs** (`allowlisted`).
4. **Never challenge excluded paths** matching `policy.except` (`excluded_path`).
5. **Valid clearance passes:** If the request carries a valid `__Host-schild_clr` cookie (`pow` or `nojs`), it passes (`clearance_valid`).
6. **Triggers** (checked in order):
   - Active `under_attack` (`now < until`):
     - `scope == "all"` → `challenge` (`under_attack`)
     - `scope == "admin"` and path matches an admin/login route (`/admin`, `/wp-admin`, `/wp-login.php`, `/login`, `/signin`, `/sign-in`, `/auth`, `/user/login`, `/typo3`, `/backend`, `/manager`, `/cms`, or subpaths) → `challenge` (`under_attack`)
   - `distributed_wave == true` (active MVP-18 wave on this website) → `challenge` (`distributed_wave`)
   - `mode == "always"` → `challenge` (`always`)
   - `mode == "findings"`:
     - `shared_scenario_hit == true` (CGNAT/mobile/Tor scenario hit that cannot be hard-blocked) → `challenge` (`shared_scenario`)
     - `aggressive_crawl_hit == true` → `challenge` (`aggressive_crawl`)
   - Otherwise → `pass` (`off` when `mode == "off"` and no active `under_attack`, else `no_trigger`).

## 3. Challenge Token (`schild-ch1`)

Format: `schild-ch1.<b64url(payload_json)>.<b64url(mac)>` (raw URL-safe base64, no padding).

Payload JSON:
```json
{
  "v": 1,
  "alg": "SHA-256",
  "salt": "<32 hex chars (16 random bytes)>",
  "challenge": "<64 hex chars = hex(sha256(salt || decimal(n)))>",
  "max": 50000,
  "exp": 1795086000,
  "host": "example.org",
  "ret": "/page"
}
```

- `mac = HMAC-SHA256(k_challenge, "schild/challenge/1\n" + host + "\n" + ip_prefix + "\n" + sha256_hex(ua) + "\n" + payload_b64)`.
- `ip_prefix`: masked IPv4 `/24` or IPv6 `/56` (e.g. `203.0.113.0/24`, `2001:db8:1234:5600::/56`).
- `exp`: at most `5 minutes` from issue time.
- `ret`: safe same-origin path (starts with `/`, not `//`, no `\`, no control characters).
- Each `salt` is single-use (tracked in a bounded in-memory spent set until `exp`).

## 4. Clearance Cookie (`__Host-schild_clr`)

Format: `c1.<kind>.<exp_unix>.<b64url(mac_128bit)>`

- `kind`: `"pow"` | `"nojs"`
- `exp_unix`: unix timestamp rounded **up** to the next whole minute (`((unix + 59) / 60) * 60`)
- `mac_128bit`: first 16 bytes of `HMAC-SHA256(k_clear, "schild/clearance/1\n" + host + "\n" + kind + "\n" + exp_unix + "\n" + ip_prefix + "\n" + sha256_hex(ua))`
- Attributes: `HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=<ttl>` (on plain HTTP loopback/dev, `Secure` follows the request scheme; in production TLS, `__Host-schild_clr` always has `Secure`).
- **No random part, no visitor ID.**

## 5. Per-Instance Prefix & Endpoints

- Prefix: `/_s-<8 lowercase base32 chars>/`, generated once per instance, stored in `schild.db`.
- `POST {prefix}verify`: form or JSON `{token, number, return}`; verifies token + PoW solution `sha256(salt || decimal(number)) == challenge`, sets `__Host-schild_clr` (`kind=pow`), redirects `303 See Other` to `ret`.
- `POST {prefix}continue`: form `{token, return}`; verifies token (no PoW), sets `__Host-schild_clr` (`kind=nojs`), redirects `303 See Other` to `ret`.
- Request body limit: 2 KiB. Rate-limited per `ip_prefix`. Fail-open on internal key/storage errors.

## 6. Interstitial Response

- HTTP status `403`, `Content-Type: text/html; charset=utf-8`
- `Cache-Control: no-store`, `X-Robots-Tag: noindex`
- Strict CSP with SHA-256 hash of the embedded inline script (`default-src 'none'; script-src 'sha256-...'; style-src 'unsafe-inline'; worker-src blob:; form-action 'self'; frame-ancestors 'none'; base-uri 'none'`)
- Calm German copy („Kurze Prüfung“), accessible No-JS button (`POST {prefix}continue`), no timed meta-refresh, honours `prefers-reduced-motion`.
