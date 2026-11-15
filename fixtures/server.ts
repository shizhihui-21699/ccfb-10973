/**
 * Fixture web server.
 *
 * Hosts several small sites on one port, distinguished by hostname, so the
 * scanner can exercise real cross-site behaviour (cross-origin iframes,
 * third-party cookies, unload beacons) rather than mocking it.
 *
 * Every scenario is a deliberate compliance pattern:
 *
 *   clean.example.test    consent-first: nothing third-party until accept
 *   eager.example.test    GA fires on load, before the banner is answered
 *   sneaky.example.test   consent gate looks correct but beacons on pagehide,
 *                         writes localStorage from a script, and tags through
 *                         a first-party collect endpoint
 *   rejector.example.test  accept works, reject does not actually stop trackers
 *   adwall.example.test   banner with Accept only (no reject option)
 *
 * Hosts are synthetic `.test` names, so DNS never resolves them; the scanner
 * maps them to 127.0.0.1 through its own resolver. HTTPS is used because
 * third-party cookies only behave realistically there.
 */
import http from 'node:http';
import https from 'node:https';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import type { AddressInfo } from 'node:net';

export interface FixtureHit {
  at: number;
  host: string;
  path: string;
  method: string;
  cookie: string | null;
  body: string;
}

export interface FixtureServer {
  origin: string;
  host: string;
  port: number;
  hosts: string[];
  hits: FixtureHit[];
  close: () => Promise<void>;
  /** Clear recorded hits, for a fresh scan. */
  reset: () => void;
}

export const FIXTURE_HOSTS = [
  'clean.example.test',
  'eager.example.test',
  'sneaky.example.test',
  'rejector.example.test',
  'adwall.example.test',
  'analytics.vendor.test',
  'cdn.vendor.test',
  'pixel.vendor.test',
  'collect.example.test',
];

/** Common vendor endpoints: they record what they receive and return 204/gif. */
function vendorHandler(host: string, path: string, res: http.ServerResponse): boolean {
  if (host === 'analytics.vendor.test') {
    if (path.startsWith('/collect') || path.startsWith('/ga')) {
      res.writeHead(204, {
        // A realistic third-party analytics cookie, SameSite=None so it works
        // from a cross-site iframe exactly as a real tracker would.
        'set-cookie': '_vuid=vendor-uid-123456; Path=/; SameSite=None; Secure; Max-Age=63072000',
      });
      res.end();
      return true;
    }
    res.writeHead(200, { 'content-type': 'application/javascript' });
    res.end(`/* analytics.js */
      window.__vendorLoaded = (window.__vendorLoaded || 0) + 1;
      window.vendorTrack = function(event, props) {
        var payload = JSON.stringify({ event: event, props: props, uid: readCookie('_vuid'), url: location.href });
        if (navigator.sendBeacon) navigator.sendBeacon('https://analytics.vendor.test/collect', payload);
        else fetch('https://analytics.vendor.test/collect', { method: 'POST', body: payload, keepalive: true });
      };
      function readCookie(n) {
        var m = document.cookie.match(new RegExp('(^| )' + n + '=([^;]+)'));
        return m ? m[2] : null;
      }
      vendorTrack('pageview', { path: location.pathname });
    `);
    return true;
  }

  if (host === 'pixel.vendor.test') {
    res.writeHead(200, { 'content-type': 'image/gif' });
    res.end(Buffer.from('R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7', 'base64'));
    return true;
  }

  if (host === 'cdn.vendor.test') {
    res.writeHead(200, { 'content-type': 'application/javascript' });
    res.end('/* harmless shared library */\nwindow.__cdnLoaded = true;');
    return true;
  }

  return false;
}

function bannerScript(host: string): string {
  // A small self-contained CMP. It stores the decision in localStorage and
  // exposes it as a global the site's own code reads.
  return `
  <script>
    window.__cmp = {
      get decision() { try { return localStorage.getItem('consent-decision'); } catch (e) { return null; } },
      set(d) { try { localStorage.setItem('consent-decision', d); } catch (e) {} },
      granted(purpose) {
        var d = this.decision;
        if (d === 'accept') return true;
        if (d === 'reject') return false;
        return false; // no decision yet
      }
    };
    addEventListener('DOMContentLoaded', function () {
      if (window.__cmp.decision) return; // already answered
      var wrap = document.createElement('div');
      wrap.id = 'cookie-banner';
      wrap.style.cssText = 'position:fixed;left:0;right:0;bottom:0;background:#111;color:#eee;padding:16px;font:14px/1.4 system-ui;z-index:9999;display:flex;gap:12px;align-items:center;justify-content:space-between';
      var acceptOnly = ${host === 'adwall.example.test' ? 'true' : 'false'};
      wrap.innerHTML =
        '<span>We use cookies to improve your experience. Read our <a style="color:#9cf" href="/privacy">privacy policy</a>.</span>' +
        '<span style="display:flex;gap:8px">' +
        (acceptOnly ? '' : '<button id="reject-all" style="padding:10px 18px;border:1px solid #666;background:#222;color:#eee;border-radius:6px;cursor:pointer">Reject all</button>') +
        '<button id="accept-all" style="padding:10px 18px;border:0;background:#2f7d32;color:#fff;border-radius:6px;cursor:pointer">Accept all</button>' +
        '</span>';
      document.body.appendChild(wrap);
      var a = document.getElementById('accept-all');
      if (a) a.addEventListener('click', function () { window.__cmp.set('accept'); wrap.remove(); location.reload(); });
      var r = document.getElementById('reject-all');
      if (r) r.addEventListener('click', function () {
        // The defect in rejector.example.test: it records the rejection but
        // never removes the tracking cookies or stops the tag.
        window.__cmp.set('reject');
        wrap.remove();
        ${host === 'rejector.example.test' ? 'location.reload();' : "try { localStorage.removeItem('_uid-shim'); } catch(e){} location.reload();"}
      });
    });
  </script>`;
}

function pageShell(host: string, extraScript: string): string {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8">
<title>${host}</title></head>
<body style="font:16px/1.6 system-ui;margin:0">
<header style="padding:20px 24px;border-bottom:1px solid #ddd"><strong>${host}</strong> · fixture site</header>
<main style="padding:24px;max-width:860px">
  <h1>Welcome to ${host}</h1>
  <p>This is a local fixture used to test the pre-consent privacy scanner.
  It is not a real site and collects nothing outside this machine.</p>
  <p id="status">status: loading</p>
</main>
${bannerScript(host)}
<script>document.getElementById('status').textContent = 'status: page body loaded';</script>
${extraScript}
</body></html>`;
}

function buildPage(host: string, port: number): string {
  const vendor = (name: string) => `https://${name}:${port}`;

  switch (host) {
    case 'clean.example.test':
      // Compliant: the tag is only fetched after the banner decision, and an
      // unload beacon is sent only when consent was granted.
      return pageShell(host, `
<script>
(function(){
  function start() {
    if (!window.__cmp || !window.__cmp.granted('analytics')) return;
    var s = document.createElement('script');
    s.src = '${vendor('analytics.vendor.test')}/analytics.js';
    s.async = true;
    document.head.appendChild(s);
    addEventListener('pagehide', function () {
      // Correctly re-checks consent at teardown.
      if (window.__cmp && window.__cmp.granted('analytics')) {
        navigator.sendBeacon('${vendor('analytics.vendor.test')}/collect?exit=1', 'x');
      }
    });
  }
  // Poll until the CMP has a decision: this models a real consent gate.
  var tries = 0;
  var timer = setInterval(function () {
    tries += 1;
    if (window.__cmp && window.__cmp.decision) { clearInterval(timer); start(); }
    if (tries > 200) clearInterval(timer);
  }, 100);
})();
</script>`);

    case 'eager.example.test':
      // Non-compliant: Google Analytics loads immediately, before consent.
      return pageShell(host, `
<script>
  document.cookie = '_ga=GA1.1.1234567890.1700000000; path=/; max-age=63072000; SameSite=None; Secure';
  localStorage.setItem('_ga_user', 'eager-user-98765');
  (function(){
    var s = document.createElement('script');
    s.src = '${vendor('analytics.vendor.test')}/analytics.js';
    s.async = true;
    document.head.appendChild(s);
  })();
  addEventListener('pagehide', function () {
    navigator.sendBeacon('${vendor('analytics.vendor.test')}/collect?exit=1', 'exit');
  });
</script>`);

    case 'sneaky.example.test':
      // The banner works, the gate looks right, but:
      //  - a third-party iframe is injected on load regardless of consent;
      //  - an unload beacon fires without re-checking consent;
      //  - tracking happens through a *first-party* collect endpoint, which
      //    host-only classification would miss;
      //  - a localStorage identifier is written from an inline script.
      return pageShell(host, `
<script>
  localStorage.setItem('_snk_uid', 'sneaky-visitor-44444');
  document.cookie = '_snk=visitor-44444; path=/; max-age=3600; SameSite=None; Secure';
  // Third-party iframe that tags on load, before any decision.
  (function(){
    var f = document.createElement('iframe');
    f.src = '${vendor('analytics.vendor.test')}/frame?embedded=1';
    f.width = '1'; f.height = '1'; f.style.cssText = 'position:absolute;left:-9999px';
    document.body.appendChild(f);
  })();
  // First-party relay: looks same-site, carries the identifier, feeds a tracker.
  setTimeout(function(){
    fetch('/collect.example.test/track?uid=sneaky-visitor-44444&event=pageview', { keepalive: true });
  }, 300);
  addEventListener('pagehide', function () {
    // The gate is not re-checked here, so this escapes the banner.
    navigator.sendBeacon('${vendor('analytics.vendor.test')}/collect?exit=1&uid=sneaky-visitor-44444', 'exit');
  });
  function startTrackers(){
    var s = document.createElement('script');
    s.src = '${vendor('analytics.vendor.test')}/analytics.js';
    document.head.appendChild(s);
    fetch('${vendor('pixel.vendor.test')}/pixel.gif?uid=sneaky-visitor-44444');
  }
  var t = setInterval(function(){
    if (window.__cmp && window.__cmp.decision === 'accept') { clearInterval(t); startTrackers(); }
  }, 100);
</script>`);

    case 'rejector.example.test':
      // Accept and reject both work at the UI level, but rejecting does not
      // stop the analytics tag: it keeps its identifier and re-fires.
      return pageShell(host, `
<script>
  document.cookie = '_ga=GA1.1.999.1700000000; path=/; max-age=63072000; SameSite=None; Secure';
  localStorage.setItem('_rj_uid', 'rejector-user-77777');
  function alwaysLoad(){
    var s = document.createElement('script');
    s.src = '${vendor('analytics.vendor.test')}/analytics.js';
    s.async = true;
    document.head.appendChild(s);
  }
  // Loaded regardless of decision.
  alwaysLoad();
  addEventListener('pagehide', function(){
    navigator.sendBeacon('${vendor('analytics.vendor.test')}/collect?exit=1', 'exit');
  });
</script>`);

    case 'adwall.example.test':
      // Banner with Accept only: no reject control exists.
      return pageShell(host, `
<script>
  (function(){
    var s = document.createElement('script');
    s.src = '${vendor('analytics.vendor.test')}/analytics.js';
    document.head.appendChild(s);
  })();
</script>`);

    default:
      return pageShell(host, '');
  }
}

/** Minimal TLS material for the fixtures, generated once per run. */
function makeCert(): { key: string; cert: string } {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pcs-fixtures-'));
  const keyPath = path.join(dir, 'key.pem');
  const certPath = path.join(dir, 'cert.pem');
  const alt = FIXTURE_HOSTS.map((h) => `DNS:${h}`).join(',');
  execFileSync(
    'openssl',
    [
      'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
      '-keyout', keyPath, '-out', certPath,
      '-days', '3650', '-subj', '/CN=fixture',
      '-addext', `subjectAltName=${alt},DNS:localhost,IP:127.0.0.1`,
    ],
    { stdio: 'ignore' },
  );
  const key = fs.readFileSync(keyPath, 'utf8');
  const cert = fs.readFileSync(certPath, 'utf8');
  fs.rmSync(dir, { recursive: true, force: true });
  return { key, cert };
}

export function createFixtureServer(options: { tls?: { key: string; cert: string } } = {}): Promise<FixtureServer> {
  const { key, cert } = options.tls ?? makeCert();
  const hits: FixtureHit[] = [];

  const handler = (req: http.IncomingMessage, res: http.ServerResponse): void => {
    const rawHost = req.headers.host ?? '';
    const host = rawHost.split(':')[0]!.toLowerCase();
    const url = new URL(req.url ?? '/', `https://${rawHost}`);
    const chunks: string[] = [];
    req.on('data', (c) => chunks.push(c.toString()));
    req.on('end', () => {
      hits.push({
        at: Date.now(),
        host,
        path: url.pathname + url.search,
        method: req.method ?? 'GET',
        cookie: req.headers.cookie ?? null,
        body: chunks.join(''),
      });

      if (req.method === 'OPTIONS') {
        res.writeHead(204, { 'access-control-allow-origin': '*', 'access-control-allow-headers': '*' });
        res.end();
        return;
      }

      if (vendorHandler(host, url.pathname, res)) return;

      if (host === 'collect.example.test') {
        // First-party relay endpoint that a tracker is posting into.
        res.writeHead(204, { 'set-cookie': '_relay=1; Path=/; SameSite=None; Secure' });
        res.end();
        return;
      }

      if (url.pathname === '/privacy') {
        res.writeHead(200, { 'content-type': 'text/html' });
        res.end('<html><body><h1>Privacy policy</h1><p>Fixture page.</p></body></html>');
        return;
      }

      const port = Number(rawHost.split(':')[1] ?? 443);
      res.writeHead(200, {
        'content-type': 'text/html; charset=utf-8',
        'cache-control': 'no-store',
      });
      res.end(buildPage(host, port));
    });
  };

  const server = https.createServer({ key, cert }, handler);

  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address() as AddressInfo;
      resolve({
        origin: `https://${FIXTURE_HOSTS[0]}:${port}`,
        host: FIXTURE_HOSTS[0]!,
        port,
        hosts: FIXTURE_HOSTS,
        hits,
        reset: () => {
          hits.length = 0;
        },
        close: () =>
          new Promise<void>((done) => {
            server.closeAllConnections?.();
            server.close(() => done());
          }),
      });
    });
  });
}

/** Playwright launch args that make synthetic hosts reachable. */
export function fixtureResolverArgs(server: Pick<FixtureServer, 'hosts'>): string[] {
  return [
    '--no-proxy-server',
    `--host-resolver-rules=${server.hosts.map((h) => `MAP ${h} 127.0.0.1`).join(', ')}`,
    '--ignore-certificate-errors',
  ];
}

