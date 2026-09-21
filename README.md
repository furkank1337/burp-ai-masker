# Burp AI Masker

*Keep the context. Remove the customer data.*

A Burp Suite extension that masks customer identifiers, credentials and personal data in HTTP traffic before it is handed to an AI model. The masking runs locally inside Burp, and a second, independent check scans the result. If anything sensitive is still recognisable, nothing is sent.

```
POST /api/login HTTP/1.1                     POST /api/login HTTP/1.1
Host: api.nday.blog                          Host: api.redacted.com
Cookie: sessionid=9f8e7d6c5b          ->     Cookie: sessionid=[COOKIE:3f9a1c2b]
X-Forwarded-For: 10.20.30.40                 X-Forwarded-For: [IP_PRIVATE:77e0a1d4]

{"username":"jane",                          {"username":"[PERSONAL:c81b02fe]",
 "password":"hunter2"}                        "password":"[SECRET:5d41a0b2]"}
```

I built this for engagements where the client allows AI-assisted analysis but does not allow their hostnames, URLs or company name to reach a third-party model provider.

## How it works

```
raw HTTP -> normalise -> mask -> leakage check -> AI-safe text -> AI
                                      |
                                      +-> anything left? block
```

1. **Normalise.** Chunked bodies are reassembled and gzip/deflate bodies are decompressed, so masking sees the real content. Binary bodies are replaced by a placeholder.
2. **Mask.** Customer domains, credentials, tokens and personal data are replaced wherever they appear: request line, headers, query string, JSON, form data, XML, HTML, JavaScript, CSS and plain text. Values inside base64 are decoded, masked and re-encoded. See [What gets masked](#what-gets-masked).
3. **Check.** The exact text that would be sent is scanned again. The scan covers the raw text plus its URL-decoded, HTML-entity-decoded, JS-unescaped, UTF-16 and base64-decoded forms. A single hit blocks the message.

The extension fails closed. Content that can't be inspected (for example a Brotli body), internal errors, a disabled extension or an empty target list all block the message instead of letting it through.

## What gets masked

**Customer domains** you configure, with all their subdomains: `api.nday.blog` → `api.redacted.com`. Optionally also **brand names** (`N-Day Blog` → `Redacted Blog`).

**Credentials and tokens**
- JWTs. The header and the timing/authorisation claims (`exp`, `iat`, `scope`, `roles`, ...) stay readable; the signature and identity claims (`sub`, `email`, ...) are masked. Encrypted JWEs are replaced entirely.
- `Authorization` and `Proxy-Authorization` values. The scheme (`Basic`, `Bearer`) is kept.
- `Cookie` and `Set-Cookie` values. Cookie names and attributes are kept.
- Headers whose name mentions a token, key, secret, session, CSRF or password (`X-API-Key`, `X-CSRF-Token`, `X-Amz-Security-Token`, ...).
- Fields named like a secret (`password`, `pwd`, `token`, `access_token`, `api_key`, `client_secret`, `sessionid`, `csrf`, `otp`, ...) in query strings, form bodies, JSON, JavaScript, XML/SOAP, hidden HTML inputs, `<meta>` tags and multipart forms. This includes percent-encoded parameters nested in other parameters, such as `redirect=...%3Ftoken%3D...`.
- API keys recognisable by format: AWS, GitHub, GitLab, Slack, Google, Stripe, OpenAI, Anthropic, SendGrid, Twilio, npm and others. Also private key blocks, and `user:password@` in URLs and connection strings.

**Personal data**
- E-mail addresses. The local part is masked and the domain kept: `[EMAIL:3f9a1c2b]@gmail.com`.
- Fields named `username`, `user`, `login`, `email`, `phone`, `address`, `birthdate` and similar.
- Payment card numbers (Luhn check), IBANs (mod-97 check) and Turkish national ID numbers (T.C. Kimlik No checksum). The checksums keep random numbers from being masked.

**IP addresses**, IPv4 and IPv6. Private and public addresses get different placeholders. Loopback addresses are left alone.

Placeholders carry a short keyed hash of the original value, so the same session cookie or user shows up as the same `[COOKIE:3f9a1c2b]` in every request. The AI can still follow a session across requests without seeing the actual value.

## What is and isn't covered

Burp's extension API (Montoya) lets an extension send prompts to Burp AI. It has no hook for intercepting what *other* components send to an AI. I checked this against the Montoya 2026.7 sources and the source of PortSwigger's MCP Server extension. Because of that, this extension does not try to intercept anything. It acts as the only route to the AI and relies on you to close the other routes.

Covered:

- Right-click → **AI Masker → Ask Burp AI (masked)**
- Right-click → **AI Masker → Copy AI-safe version**, for pasting into an external assistant
- The read-only **AI Safe** tab in every HTTP message viewer

Not covered, and cannot be with the current API:

- Burp's built-in AI features
- Other extensions, including the Burp MCP Server

On engagements with this kind of restriction, unload the MCP Server extension and don't use the built-in AI features.

## Installation

Grab [`burp-ai-masker-0.1.0.jar`](burp-ai-masker-0.1.0.jar) from this repository, or build it yourself (see [Building](#building)).

In Burp, go to **Extensions → Installed → Add**, choose **Java** as the extension type and select `burp-ai-masker-<version>.jar`. The Output tab should then show:

```
[AI Masker] Loaded. Status: ENABLED, 0 target domain(s). ...
```

"Ask Burp AI" also needs Burp AI to be enabled and the **Use AI** box ticked for this extension under **Extensions → Installed**.

Requirements: a Burp Suite version with Montoya API support (2025.x or later recommended). The jar has no runtime dependencies.

## Usage

### Targets

Open the **AI Masker** tab and use **+ Add Domain**:

| Target domain | Replacement | Brand keywords |
|---|---|---|
| `nday.blog` | `redacted.com` | `N-Day Security` |
| `customer2.com` | `redacted2.com` | |
| `example.internal` | `[REDACTED_DOMAIN]` | |

- You can paste a URL or a wildcard (`https://nday.blog/login`, `*.nday.blog`); it is normalised to `nday.blog`.
- Subdomains are always included, because every subdomain contains the target. `foo.api.nday.blog` becomes `foo.api.redacted.com`.
- A replacement may only contain letters, digits, `.`, `-`, `_`, `[` and `]`, so it can't break the JSON, HTML or URL around it.
- With no targets configured, every AI request is blocked.

Settings are stored in the Burp project file, so each engagement keeps its own list.

### Brand keywords

Company or product names show up without a TLD in page titles, footers and JS identifiers. Add them in the **Brand keywords** column. Matching ignores case and tolerates separators between letters:

```
<title>N-Day Blog</title>        ->  <title>Redacted Blog</title>
&copy; NDAY Security             ->  &copy; REDACTED Security
window.ndayConfig                ->  window.redactedConfig
```

Unrelated words such as `monday` or `ndays` are left alone. Keywords need at least four letters or digits.

The **Redact brand names from domains** option derives a keyword from each target (`nday.blog` → `nday`). It is off by default.

### Options

| Option | Default | |
|---|---|---|
| Mask credentials & tokens | on | JWTs, API keys, auth headers, cookies, secret fields |
| Mask personal data | on | e-mails, username/phone fields, cards, IBANs, national IDs |
| Mask IP addresses | on | IPv4 and IPv6 |
| Keep subdomain labels | on | `api.nday.blog` → `api.redacted.com`; when off, `redacted.com` |
| Redact brand names from domains | off | see above |
| Process requests / responses / headers / bodies | on | Unticked parts are not rewritten, but they are still checked, so a target in a skipped part blocks the message |
| Omit binary bodies | on | images, fonts and archives become `[AI Masker: binary body omitted, N bytes]` |
| Verbose audit log | off | one log line per masked value (fingerprints only) |

### Preview

Paste a raw request or response into the **Preview** tab and press **Run Preview**. The original and the AI-safe version are shown side by side, together with the check result and where each replacement happened.

### Audit

The **Audit** tab lists every replacement:

```
DOMAIN_001  DOMAIN  hmac:3f9a…  api.redacted.com  HTTP Response  body html script[src]
```

Original values are never stored or logged. Fingerprints are HMAC-SHA256 values keyed with a secret kept in your Burp user settings. A plain SHA-256 of a domain name is easy to reverse by hashing candidate domains, which is why a keyed HMAC is used.

## Known limitations

- Burp's built-in AI and other extensions are out of reach (see above).
- `nday.blog.example.com` is deliberately not treated as the target domain.
- Secrets are found by field name or by a known format. A random token stored under a neutral name (`"data": "a8f3..."`) is not recognised. Names, phone numbers and street addresses written in free text aren't recognised either, only when they sit in a field with a telling name.
- Custom identifiers (employee IDs and similar) aren't masked yet. A regex-based detector exists in the code but isn't exposed in the UI.
- At least one target domain has to be configured before anything is sent, even if you only want to mask secrets.
- Encrypted blobs, gzip-inside-base64 (for example ViewState) and text inside images aren't inspected.
- AI answers aren't un-masked.
- `redacted.com` is a real, registered domain. If an agent is allowed to send requests, use a reserved name such as `redacted.invalid` or `customer1.example`.

## Building

The source only depends on the Montoya API, which Burp provides at runtime. With JDK 17 or later and [`montoya-api`](https://central.sonatype.com/artifact/net.portswigger.burp.extensions/montoya-api) on hand:

```bash
javac --release 17 -d out -cp montoya-api-2026.7.jar $(find src/main/java -name '*.java')
jar cf burp-ai-masker.jar -C out .
```

## Project layout

```
src/main/java/aimasker/
├── core/              plain Java, no Burp dependency
│   ├── domain/        domain rules and matching
│   ├── keyword/       brand keyword matching
│   ├── secret/        JWTs, API keys, credentials, cookies, e-mails, IPs, cards/IBAN/ID
│   ├── pattern/       regex-based detector (not wired to the UI yet)
│   ├── http/          message parsing, decoding, per-location masking
│   ├── validation/    leakage check
│   ├── gateway/       the single path to the AI
│   ├── audit/         fingerprints, lineage, counters
│   ├── config/        settings and their serialisation
│   └── control/       service and control interface
└── burp/              Montoya integration and Swing UI
```

### Adding a detector

Implement `aimasker.core.Detector` and register it in `RedactorConfig.detectors()`. `detect()` must find everything that `redact()` would replace, because the leakage check depends on it. The check picks up new detectors automatically.

## Roadmap

- MCP tools served by this extension, with every result passing through the same gateway
- UI for custom regex rules
- Optional local un-masking of AI answers
