/**
 * End-to-end tests: run the real scanner against the fixture sites and assert
 * on the verdicts. These are the tests that prove the pipeline actually
 * observes what it claims to observe; unit tests only prove the rules are
 * consistent with each other.
 */
import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { resolveConfig } from '../src/config.js';
import { Classifier } from '../src/lib/classify.js';
import { analyse } from '../src/lib/analyse.js';
import { runScan } from '../src/lib/scanner.js';
import { SCANNER_VERSION } from '../src/version.js';
import { createFixtureServer, FIXTURE_HOSTS, type FixtureServer } from '../fixtures/server.js';
import type { ScanResult } from '../src/types.js';

const SCANNED_HOSTS = [
  'clean.example.test',
  'eager.example.test',
  'sneaky.example.test',
  'rejector.example.test',
  'adwall.example.test',
];

let fixture: FixtureServer;
let workDir: string;
const hostMap: Record<string, string> = {};

before(async () => {
  fixture = await createFixtureServer();
  workDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pcs-e2e-'));
  for (const host of FIXTURE_HOSTS) hostMap[host] = '127.0.0.1';

  // Each scan owns its own browser (the proxy is a browser-level option), so
  // they are independent and can run together;
  // each takes ~15 s and the suite would otherwise be dominated by waiting.
  await Promise.all(SCANNED_HOSTS.map((host) => scan(host)));
});

after(async () => {
  await fixture?.close();
  fs.rmSync(workDir, { recursive: true, force: true });
});

/**
 * Scan results are cached per host: several tests assert different properties
 * of the same site, and a full scan is ~20 s. Running each site once keeps the
 * suite usable while still exercising the real pipeline end to end.
 */
const results = new Map<string, Promise<ScanResult>>();

async function scan(host: string): Promise<ScanResult> {
  const cached = results.get(host);
  if (cached) return cached;
  const pending = doScan(host);
  results.set(host, pending);
  return pending;
}

async function doScan(host: string): Promise<ScanResult> {
  const config = resolveConfig({
    url: `https://${host}:${fixture.port}/`,
    hostMap,
    settle: { preConsentMs: 2000, afterChoiceMs: 2000, quietMs: 800, maxPhaseMs: 18000 },
    consent: {
      accept: { selectors: ['#accept-all'], text: ['accept all'] },
      reject: { selectors: ['#reject-all'], text: ['reject all'] },
    },
  });
  const out = path.join(workDir, host.replace(/\W/g, '_'));
  const outcome = await runScan({ config, artefactDir: path.join(out, 'artefacts') });
  const classifier = new Classifier({ siteDomain: outcome.siteDomain, config: {} });
  return analyse({
    config,
    phases: outcome.phases,
    siteHost: outcome.siteHost,
    siteDomain: outcome.siteDomain,
    classifier,
    scanner: { name: 'pre-consent-privacy-scanner', version: SCANNER_VERSION, playwright: outcome.playwrightVersion },
    startedAt: outcome.startedAt,
    finishedAt: outcome.finishedAt,
    coverageNotes: outcome.coverageNotes,
  });
}

function codes(result: ScanResult): Set<string> {
  return new Set(result.findings.map((f) => f.code));
}

describe('integration: fixture sites', () => {
  it('passes a consent-first site and finds no tracking before consent', async () => {
    const result = await scan('clean.example.test');
    assert.equal(result.summary.verdict, 'PASS', JSON.stringify(result.findings.map((f) => f.code)));
    assert.equal(result.summary.critical, 0);

    // The site must still load its tracker after consent, otherwise a PASS
    // could mean the scanner simply failed to see anything.
    const postConsent = result.phases.find((p) => p.phase === 'post-consent')!;
    const vendorHits = postConsent.requests.filter((r) => r.host === 'analytics.vendor.test');
    assert.ok(vendorHits.length > 0, 'analytics must load after consent');

    const preConsent = result.phases.find((p) => p.phase === 'pre-consent')!;
    const preVendor = preConsent.requests.filter((r) => r.party === 'third' || r.purpose === 'analytics');
    assert.equal(preVendor.length, 0, 'no third-party traffic before consent');
  });

  it('fails a site that fires analytics on load', async () => {
    const result = await scan('eager.example.test');
    assert.equal(result.summary.verdict, 'FAIL');
    assert.ok(codes(result).has('TRACKING_REQUEST_BEFORE_CONSENT'));
    assert.ok(codes(result).has('TRACKING_COOKIE_BEFORE_CONSENT'));
  });

  it('catches a pagehide beacon that the banner does not stop', async () => {
    const result = await scan('sneaky.example.test');
    assert.equal(result.summary.verdict, 'FAIL');
    assert.ok(codes(result).has('TRACKING_ON_UNLOAD_BEFORE_CONSENT'), 'unload beacon must be detected');

    const unloadFinding = result.findings.find((f) => f.code === 'TRACKING_ON_UNLOAD_BEFORE_CONSENT')!;
    assert.ok(
      unloadFinding.evidence.items.some(
        (item) => item.kind === 'request' && item.request.onUnload,
      ),
      'evidence must include the unload request',
    );
  });

  it('catches a localStorage identifier written before consent', async () => {
    const result = await scan('sneaky.example.test');
    const storage = result.findings.find((f) => f.code === 'TRACKING_STORAGE_BEFORE_CONSENT');
    assert.ok(storage, 'localStorage identifier must be reported');
    assert.ok(storage.evidence.items.some((item) => item.kind === 'storage' && item.write.key === '_snk_uid'));
  });

  it('catches a first-party relay carrying an identifier', async () => {
    const result = await scan('sneaky.example.test');
    const relay = result.findings.find(
      (f) => f.code === 'IDENTIFIER_SENT_BEFORE_CONSENT' && f.title.includes('first-party'),
    );
    assert.ok(relay, 'the same-site collect endpoint must be reported');
  });

  it('fails a site whose reject button does not stop the tracker', async () => {
    const result = await scan('rejector.example.test');
    assert.equal(result.summary.verdict, 'FAIL');
    assert.ok(codes(result).has('TRACKING_AFTER_REJECT'));
    const rejectPhase = result.phases.find((p) => p.phase === 'post-reject')!;
    assert.ok(rejectPhase.consent?.found, 'the reject control must have been found and clicked');
  });

  it('reports a banner that has no reject control', async () => {
    const result = await scan('adwall.example.test');
    assert.equal(result.summary.verdict, 'FAIL');
    assert.ok(codes(result).has('CONSENT_MECHANISM_DEFECT'));
  });

  it('records every phase with real request data', async () => {
    const result = await scan('eager.example.test');
    assert.deepEqual(
      result.phases.map((p) => p.phase),
      ['pre-consent', 'post-reject', 'post-consent'],
    );
    for (const phase of result.phases) {
      assert.ok(phase.requests.length > 0, `${phase.phase} must record traffic`);
      // The main document must always be present; an empty phase means the
      // browser never reached the site.
      assert.ok(
        phase.requests.some((r) => r.host === 'eager.example.test' && r.path === '/'),
        `${phase.phase} must include the main document`,
      );
    }
  });

  it('captures unload beacons that Playwright itself misses', async () => {
    const result = await scan('eager.example.test');
    const pre = result.phases.find((p) => p.phase === 'pre-consent')!;
    const unload = pre.requests.filter((r) => r.onUnload && r.host === 'analytics.vendor.test');
    assert.ok(unload.length > 0, 'the proxy must capture the teardown beacon');

    // The distinguishing property: at least one unload request has no
    // browser-side attribution at all. That is precisely the request type that
    // a Playwright-only scanner drops, so its presence proves the proxy path is
    // doing real work rather than echoing the browser event stream.
    const invisible = unload.filter(
      (r) => r.attribution.frameUrl === null && r.attribution.trigger === null,
    );
    assert.ok(
      invisible.length > 0,
      'expected a request the browser never reported, proving the proxy capture channel works',
    );
    for (const request of unload) {
      assert.ok(request.channels.includes('proxy'));
    }
  });

  it('never reports the scanner own artefacts as findings', async () => {
    const result = await scan('clean.example.test');
    assert.ok(
      result.findings.every((f) =>
        f.evidence.items.every((item) => item.kind !== 'request' || !item.request.url.includes('__pcs-')),
      ),
      'scanner traffic must not appear as evidence',
    );
  });

  it('scans a plain-HTTP site, not only TLS targets', async () => {
    // The proxy must use an http agent for http:// upstreams; passing the
    // https agent throws ERR_INVALID_PROTOCOL and no report is produced.
    const httpFixture = await createHttpFixture();
    try {
      const config = resolveConfig({
        url: httpFixture.url,
        settle: { preConsentMs: 1500, afterChoiceMs: 1500, quietMs: 600, maxPhaseMs: 12000 },
        consent: {
          accept: { selectors: ['#accept-all'], text: ['accept all'] },
          reject: { selectors: ['#reject-all'], text: ['reject all'] },
        },
      });
      const out = path.join(workDir, 'http');
      const outcome = await runScan({ config, artefactDir: path.join(out, 'artefacts') });
      const pre = outcome.phases.find((p) => p.phase === 'pre-consent')!;
      assert.ok(pre.requests.length > 0, 'plain-HTTP traffic must be proxied');
      // A _ga cookie set by plain HTTP is still a pre-consent tracking cookie.
      assert.ok(
        pre.cookiesSet.some((c) => c.name === '_ga'),
        'cookies must be observed over plain HTTP too',
      );
      assert.equal(outcome.phases.length, 3);
    } finally {
      await httpFixture.close();
    }
  });
});

/** A minimal plain-HTTP site: a banner, a tracking cookie, and a first-party relay. */
async function createHttpFixture(): Promise<{ url: string; close: () => Promise<void> }> {
  const server = http.createServer((req, res) => {
    if (req.url?.startsWith('/collect')) {
      res.writeHead(204, { 'set-cookie': '_relay=1; Path=/' });
      res.end();
      return;
    }
    res.writeHead(200, { 'content-type': 'text/html' });
    res.end(`<!doctype html><body>
      <div><button id="accept-all">Accept all</button><button id="reject-all">Reject all</button></div>
      <script>
        document.cookie = '_ga=GA1.1.111; path=/';
        fetch('/collect?uid=plain-http-12345');
      </script></body>`);
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', () => resolve()));
  const port = (server.address() as import('node:net').AddressInfo).port;
  return {
    url: `http://127.0.0.1:${port}/`,
    close: () =>
      new Promise<void>((done) => {
        server.closeAllConnections?.();
        server.close(() => done());
      }),
  };
}
