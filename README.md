# Pre-consent privacy scanner

A Playwright-based scanner that records **every network request, cookie and
storage write** on a page in three phases — **before consent**, **after
rejecting**, and **after accepting** — then reports which tracking mechanisms
were active when they should not have been.

It exists because "check the site by hand with devtools" does not scale to a
marketing site with five ad pixels, two tag managers and a consent banner that
reloads the page. It also exists because the obvious automation gets it wrong:
see [Why not just page.on('request')](#why-not-just-pageonrequest).

## What it catches

| Finding | What it means |
| --- | --- |
| `TRACKING_REQUEST_BEFORE_CONSENT` | A tracker endpoint was contacted before the user answered the banner. |
| `TRACKING_ON_UNLOAD_BEFORE_CONSENT` | A `pagehide` / `sendBeacon` call escaped the consent gate at teardown. |
| `TRACKING_COOKIE_BEFORE_CONSENT` | A tracking cookie was set before consent. |
| `TRACKING_STORAGE_BEFORE_CONSENT` | A tracking identifier was written to `localStorage` / `sessionStorage` / IndexedDB. |
| `IDENTIFIER_SENT_BEFORE_CONSENT` | A tracking cookie or identifier was transmitted, including via a **first-party** relay endpoint. |
| `TRACKING_AFTER_REJECT` | Tracking continued after the user rejected, including after the reload a real visitor performs. |
| `TRACKING_COOKIE_AFTER_REJECT` | A tracking cookie was set, or survived, after rejection. |
| `CONSENT_MECHANISM_DEFECT` | The banner has no observable reject control, or accept and reject are not equally available. |
| `CONSENT_UI_NOT_FOUND` | Tracking was observed but no consent interface was detected. |
| `GPC_SIGNAL_IGNORED` | With `simulateGpc` on, tracking fired despite a Global Privacy Control / DNT signal. |
| `NON_TRACKING_THIRD_PARTY_BEFORE_CONSENT` | Informational: unclassified third-party hosts, so a missed vendor can be added to the rules. |

Each finding carries **evidence**: the request line, the raw `Cookie` header,
the `Set-Cookie` value, the originating script and stack, and a screenshot of
the page in the relevant state.

## Quick start

```bash
npm install
npx playwright install chromium   # once

# Scan the bundled fixture sites; asserts expected verdicts
npm run demo

# Scan a real site
npm run scan -- --url https://www.example.com --out runs/example

# With a config file
npm run scan -- --config scan.example.json --out runs/example
```

Outputs: `report.html` (self-contained, evidence and screenshots inline),
`report.md`, `report.json`, plus a screenshot directory per phase.

Exit codes: `0` pass, `1` fail, `2` inconclusive — usable as a CI gate.

### Verdict semantics

- `FAIL` — at least one critical or high finding: tracking happened without a
  lawful basis.
- `PASS` — no critical or high findings. Informational notes (unclassified
  third-party hosts) do not fail a scan.
- `INCONCLUSIVE` — not every configured phase ran. A scan that could not run is
  never reported as compliant.
- If the reject control cannot be found, rejection enforcement is reported as
  **unverified** (`CONSENT_MECHANISM_DEFECT`), never as "no tracking after
  reject". Silently guessing would invert the result.

## How it works

```
                 ┌──────────────────────────────┐
   browser ──────►  intercepting proxy (MITM)    ├──► origin servers
                 └──────────────┬───────────────┘
                                │ wire truth: URL, headers, Cookie, Set-Cookie, body
                                ▼
   Playwright events ──► PhaseRecorder ◄── in-page instrumentation
   (frame, resource)        │            (storage, cookie, fetch/beacon + stacks)
                            ▼
                    analysis (three phases compared)
                            ▼
              report.json / report.md / report.html
```

### Three phases, three clean contexts

| Phase | What happens |
| --- | --- |
| `pre-consent` | Load the page, scroll and move the pointer to trigger lazy loaders, observe. The banner is never touched. |
| `post-reject` | Fresh context. Click the reject control, then **reload** — the reload is where a broken reject implementation shows itself. |
| `post-consent` | Fresh context. Click accept, reload, observe. Confirms trackers *do* load when permitted, so a clean result is not confused with a broken scanner. |

A fresh context per phase is what makes "was this cookie set before consent"
answerable at all.

### Why an intercepting proxy

The scanner captures traffic **at the network layer**, through a local
TLS-intercepting proxy with a throwaway CA generated per run. The browser is
launched with `proxy: { server, bypass: '<-loopback>' }` so even loopback
fixture hosts go through it.

### Why not just `page.on('request')`

Browser-side event APIs are excellent at *attribution* but they drop requests.
This was measured, not assumed:

- A `navigator.sendBeacon` fired in `pagehide` is **received by the server** but
  **never reported** to Playwright's `request` event or to CDP
  `Network.requestWillBeSent`.
- Cross-site iframes frequently report an empty `frame.url()`.

So each channel does what it is good at:

| Signal | Used for |
| --- | --- |
| Proxy | *What actually left the machine* — authoritative request list, raw `Cookie`/`Set-Cookie`, bodies. |
| Playwright | Frame URL, resource type. |
| CDP | Initiator script and line. |
| Instrumentation | Which script wrote a storage key, and the cookie string. |

The proxy is also why the unload window works: the scanner brackets its own
teardown navigation (`about:blank`) with `markUnloadStart()`/`markUnloadEnd()`,
and anything the proxy sees in that window is labelled unload traffic. That
label is what turns an invisible beacon into `TRACKING_ON_UNLOAD_BEFORE_CONSENT`.

### Cookies, and why HTTPS

Third-party cookies are only observable over HTTPS with `Secure; SameSite=None`;
a plain-HTTP fixture would make the scanner quietly miss them. The bundled
fixtures therefore run over TLS, as real sites do. Plain `http://` targets are
supported too (the proxy picks the matching upstream agent), but expect fewer
third-party cookies to survive there — that is the browser's behaviour, not a
scanner limitation.

Cookies are collected from three sources, and each record says which one it came
from:

1. raw `Set-Cookie` headers seen by the proxy;
2. the in-page `document.cookie` setter (JS-written cookies never appear as a header);
3. the browser's cookie jar, as a `jar-snapshot` for anything not otherwise observed.

### Consent UI interaction

Layered, and deliberately conservative on reject:

1. explicit selectors from config;
2. built-in selectors for OneTrust, Cookiebot, Usercentrics, Didomi, CookieYes,
   Quantcast, TrustArc, iubenda, Sourcepoint;
3. scored visible-text matching in every frame, including open shadow roots.

On the reject path, any control whose text matches an *accept* phrase is
excluded. If no reject control can be found, the scan reports that instead of
guessing — clicking "Accept" while trying to reject would silently invert the
result.

### Classification

Hosts are matched against a curated vendor table (analytics, advertising,
social, session replay, CMP, CDN, security), plus cookie-name rules that catch
first-party server-side tagging (`_ga`, `_fbp`, `_vuid`, …). Anything unmatched
is `unknown` and is **not** reported as tracking; it is listed as informational
so a real vendor cannot hide behind the default.

Override anything per site in config:

```json
{
  "domains": [
    { "match": "collect.example.com", "purpose": "analytics", "tracking": true },
    { "match": "*.cdn.example.com", "purpose": "cdn", "tracking": false }
  ],
  "trackingCookies": ["my_tracker_id"],
  "exemptDomains": ["consent.example.com"]
}
```

## Configuration

See `scan.example.json`. The fields that matter most:

- `consent.accept` / `consent.reject` — `selectors` beat `text`; add your CMP's
  real selectors when the built-ins do not match.
- `settle.preConsentMs` / `afterChoiceMs` — observation windows. Long enough to
  catch delayed loaders (6 s default), short enough to keep a scan usable.
- `settle.quietMs` — how long traffic must be quiet before a phase ends.
- `interaction` — scroll / pointer / typing, to trigger lazy loaders and
  behavioural trackers.
- `simulateGpc` — present the visitor as sending Global Privacy Control and Do
  Not Track. Tracking that fires anyway is reported as `GPC_SIGNAL_IGNORED`.
- `keepResponseBodies` — embed response bodies in the JSON output.
- `hostMap` — `host -> IP`, for staging or fixture hosts that do not resolve.

## The fixture sites

`fixtures/server.ts` serves five sites on one port, over TLS, on synthetic
`.test` hostnames (no DNS changes needed):

| Site | Pattern | Expected |
| --- | --- | --- |
| `clean.example.test` | Analytics loads only after accept; teardown beacon re-checks consent. | PASS |
| `eager.example.test` | GA-style script and cookie set on load, before the banner. | FAIL |
| `sneaky.example.test` | Banner looks correct, but a hidden iframe, a `localStorage` id and a `pagehide` beacon fire anyway; tracking also relays through a first-party endpoint. | FAIL |
| `rejector.example.test` | Accept and reject both clickable; rejecting does not stop the tracker. | FAIL |
| `adwall.example.test` | Accept-only banner, tracker loads unconditionally. | FAIL |

`npm run demo` scans all five and asserts the verdicts, so a regression in the
detection pipeline shows up as a failing demo rather than a quietly wrong
report.

## Tests

```bash
npm test                  # unit + integration
node --import tsx --test tests/unit.test.ts        # rules only, no browser
node --import tsx --test tests/integration.test.ts # real scans of the fixtures
```

The integration tests assert not just verdicts but *evidence*: that the
`pagehide` beacon is present with `onUnload: true`, that the `_snk_uid` storage
write is captured with its origin, that the first-party relay is flagged.

## Limitations

- **Not a legal opinion.** It measures technical behaviour; whether a given
  cookie is "strictly necessary" remains a legal judgement.
- Unclassified third-party hosts are not called violations. Review
  `NON_TRACKING_THIRD_PARTY_BEFORE_CONSENT` and add vendors you care about.
- CMP markup varies enormously. Unrecognised banners produce
  `CONSENT_MECHANISM_DEFECT` / `CONSENT_UI_NOT_FOUND` rather than a false
  "compliant".
- Service workers, web workers and native app traffic are only observed if they
  hit the network through the browser; a worker's `Set-Cookie` may appear only
  as a jar snapshot.
- Server-side tagging that never touches the browser (CNAME'd endpoints,
  server-to-server events) is out of scope for any browser-based scanner.
- The CA is generated per run and trusted only for that run. Do not reuse it.
