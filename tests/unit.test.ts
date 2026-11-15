/**
 * Unit tests for the pure logic: classification, cookie parsing, and the
 * analyser's verdicts. These run without a browser, so they pin the rules that
 * decide whether a site is compliant — the part most likely to break silently.
 */
import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { Classifier } from '../src/lib/classify.js';
import { parseCookieHeader, parseSetCookie, redactValue } from '../src/lib/cookies.js';
import { analyse, __testing } from '../src/lib/analyse.js';
import { resolveConfig } from '../src/config.js';
import type { CookieRecord, NetworkEvent, PhaseResult, StorageWrite } from '../src/types.js';

function classifier(): Classifier {
  return new Classifier({ siteDomain: 'example.test', config: {} });
}

function request(overrides: Partial<NetworkEvent>): NetworkEvent {
  return {
    id: Math.random().toString(36).slice(2),
    phase: 'pre-consent',
    atMs: 100,
    startedAt: Date.now(),
    scheme: 'https',
    host: 'analytics.vendor.test',
    siteDomain: 'vendor.test',
    party: 'third',
    purpose: 'analytics',
    method: 'POST',
    path: '/collect',
    url: 'https://analytics.vendor.test/collect',
    headers: {},
    requestBody: null,
    requestBodyTruncated: false,
    cookieHeader: null,
    referer: null,
    status: 204,
    setCookies: [],
    responseBody: null,
    attribution: { frameUrl: null, initiatorUrl: null, resourceType: null, trigger: null },
    channels: ['proxy'],
    onUnload: false,
    aborted: false,
    ...overrides,
  };
}

function phase(overrides: Partial<PhaseResult>): PhaseResult {
  return {
    phase: 'pre-consent',
    startedAt: new Date().toISOString(),
    durationMs: 1000,
    requests: [],
    cookiesSet: [],
    cookieJar: [],
    storage: [],
    consent: null,
    screenshots: [],
    checkpoints: [],
    firstPartyRelays: [],
    warnings: [],
    ...overrides,
  };
}

function cookie(overrides: Partial<CookieRecord>): CookieRecord {
  return {
    name: '_ga',
    value: 'GA1.1.123',
    domainAttr: null,
    domain: '.vendor.test',
    siteDomain: 'vendor.test',
    party: 'third',
    purpose: 'analytics',
    path: '/',
    secure: true,
    httpOnly: false,
    sameSite: 'None',
    expires: null,
    session: true,
    setInPhase: 'pre-consent',
    setByUrl: 'https://analytics.vendor.test/collect',
    atMs: 120,
    origin: 'observed-set',
    known: { vendor: 'Google Analytics', purpose: 'analytics', tracking: true },
    ...overrides,
  };
}

function analyseWith(phases: PhaseResult[], configOverrides: Record<string, unknown> = {}) {
  const config = resolveConfig({ url: 'https://example.test/', ...configOverrides });
  return analyse({
    config,
    phases,
    siteHost: 'example.test',
    siteDomain: 'example.test',
    classifier: classifier(),
    scanner: { name: 'test', version: '0', playwright: '0' },
    startedAt: new Date().toISOString(),
    finishedAt: new Date().toISOString(),
    coverageNotes: [],
  });
}

describe('classifier', () => {
  it('identifies known trackers by registrable domain, including subdomains', () => {
    const c = classifier();
    assert.equal(c.classifyHost('region1.google-analytics.com').purpose, 'analytics');
    assert.equal(c.classifyHost('www.google-analytics.com').tracking, true);
    assert.equal(c.classifyHost('connect.facebook.net').purpose, 'social');
    assert.equal(c.classifyHost('doubleclick.net').purpose, 'advertising');
  });

  it('prefers the most specific vendor rule', () => {
    const c = classifier();
    // google.com is an ad host, but googletagmanager.com is its own vendor.
    assert.equal(c.classifyHost('www.googletagmanager.com').purpose, 'tag-manager');
    assert.equal(c.classifyHost('www.googletagmanager.com').vendor, 'Google Tag Manager');
  });

  it('does not classify a CDN as tracking', () => {
    const c = classifier();
    const info = c.classifyHost('cdn.jsdelivr.net');
    assert.equal(info.tracking, false);
    assert.equal(info.purpose, 'cdn');
  });

  it('treats subdomains of the site as first party', () => {
    const c = classifier();
    assert.equal(c.partyOf('static.example.test'), 'first');
    assert.equal(c.partyOf('example.test'), 'first');
    assert.equal(c.partyOf('vendor.test'), 'third');
  });

  it('recognises tracking cookie names including generic identifiers', () => {
    const c = classifier();
    assert.equal(c.classifyCookie('_ga').purpose, 'analytics');
    assert.equal(c.classifyCookie('_fbp').purpose, 'social');
    assert.equal(c.classifyCookie('_vuid').purpose, 'analytics');
    assert.equal(c.classifyCookie('sessionid').purpose, 'unknown');
  });

  it('honours config overrides before the built-in table', () => {
    const c = new Classifier({
      siteDomain: 'example.test',
      config: {
        domains: [{ match: '*.vendor.test', purpose: 'functional', firstParty: true, tracking: false }],
      },
    });
    const info = c.classifyHost('analytics.vendor.test');
    assert.equal(info.purpose, 'functional');
    assert.equal(info.tracking, false);
  });

  it('honours exempt domains', () => {
    const c = new Classifier({
      siteDomain: 'example.test',
      config: { exemptDomains: ['consent.example.test'] },
    });
    assert.equal(c.classifyHost('consent.example.test').tracking, false);
  });

  it('flags identifier-looking keys', () => {
    const c = classifier();
    assert.equal(c.looksLikeIdentifier('_ga_user', 'abc123'), true);
    assert.equal(c.looksLikeIdentifier('visitor_id', '123'), true);
    assert.equal(c.looksLikeIdentifier('theme', 'dark'), false);
  });
});

describe('cookie parsing', () => {
  it('parses attributes verbatim', () => {
    const parsed = parseSetCookie('_ga=GA1.2.3; Path=/; Domain=.example.test; Secure; HttpOnly; SameSite=None; Max-Age=63072000');
    assert.ok(parsed);
    assert.equal(parsed.name, '_ga');
    assert.equal(parsed.value, 'GA1.2.3');
    assert.equal(parsed.domain, 'example.test', 'leading dot is dropped for matching');
    assert.equal(parsed.path, '/');
    assert.equal(parsed.secure, true);
    assert.equal(parsed.httpOnly, true);
    assert.equal(parsed.sameSite, 'None');
    assert.equal(parsed.maxAge, 63072000);
  });

  it('handles cookies whose value contains =', () => {
    const parsed = parseSetCookie('token=abc==; Path=/');
    assert.ok(parsed);
    assert.equal(parsed.value, 'abc==');
  });

  it('parses a Cookie request header', () => {
    const pairs = parseCookieHeader('_ga=GA1.1; _gid=XYZ; empty=');
    assert.deepEqual(pairs.map((p) => p.name), ['_ga', '_gid', 'empty']);
    assert.equal(pairs[2]!.value, '');
  });

  it('redacts long or whitespace-bearing values', () => {
    assert.equal(redactValue('abc'), 'abc');
    assert.ok(redactValue('x'.repeat(200)).length < 200);
  });
});

describe('analyser', () => {
  it('passes when nothing tracking fires before consent', () => {
    const result = analyseWith([
      phase({ phase: 'pre-consent', requests: [request({ host: 'example.test', party: 'first', purpose: 'unknown', url: 'https://example.test/' })] }),
      phase({ phase: 'post-reject' }),
      phase({ phase: 'post-consent' }),
    ]);
    assert.equal(result.summary.verdict, 'PASS');
    assert.equal(result.findings.filter((f) => f.severity === 'critical').length, 0);
  });

  it('fails on a third-party tracking request before consent', () => {
    const result = analyseWith([
      phase({ phase: 'pre-consent', requests: [request({})] }),
      phase({ phase: 'post-reject' }),
      phase({ phase: 'post-consent' }),
    ]);
    assert.equal(result.summary.verdict, 'FAIL');
    const finding = result.findings.find((f) => f.code === 'TRACKING_REQUEST_BEFORE_CONSENT');
    assert.ok(finding, 'expected TRACKING_REQUEST_BEFORE_CONSENT');
    assert.equal(finding.severity, 'critical');
    assert.equal(finding.domain, 'analytics.vendor.test');
  });

  it('separates unload beacons from page-load requests', () => {
    const result = analyseWith([
      phase({
        phase: 'pre-consent',
        requests: [
          request({ method: 'GET', path: '/analytics.js', url: 'https://analytics.vendor.test/analytics.js' }),
          request({ method: 'POST', path: '/collect?exit=1', url: 'https://analytics.vendor.test/collect?exit=1', onUnload: true }),
        ],
      }),
      phase({ phase: 'post-reject' }),
      phase({ phase: 'post-consent' }),
    ]);
    const codes = result.findings.map((f) => f.code);
    assert.ok(codes.includes('TRACKING_ON_UNLOAD_BEFORE_CONSENT'));
    assert.ok(codes.includes('TRACKING_REQUEST_BEFORE_CONSENT'));
  });

  it('does not flag a first-party request that carries no tracking cookie', () => {
    const result = analyseWith([
      phase({
        phase: 'pre-consent',
        requests: [
          request({
            host: 'example.test',
            siteDomain: 'example.test',
            party: 'first',
            purpose: 'analytics',
            url: 'https://example.test/metrics',
            cookieHeader: 'session=abc',
          }),
        ],
      }),
      phase({ phase: 'post-reject' }),
      phase({ phase: 'post-consent' }),
    ]);
    assert.equal(result.findings.filter((f) => f.code === 'TRACKING_REQUEST_BEFORE_CONSENT').length, 0);
  });

  it('flags a first-party request that carries a tracking cookie', () => {
    const result = analyseWith([
      phase({
        phase: 'pre-consent',
        requests: [
          request({
            host: 'example.test',
            siteDomain: 'example.test',
            party: 'first',
            purpose: 'analytics',
            url: 'https://example.test/collect',
            cookieHeader: '_ga=GA1.1.999',
          }),
        ],
      }),
      phase({ phase: 'post-reject' }),
      phase({ phase: 'post-consent' }),
    ]);
    assert.equal(result.findings.filter((f) => f.code === 'TRACKING_REQUEST_BEFORE_CONSENT').length, 1);
  });

  it('flags a tracking cookie set before consent', () => {
    const result = analyseWith([
      phase({ phase: 'pre-consent', cookiesSet: [cookie({})], cookieJar: [cookie({})] }),
      phase({ phase: 'post-reject' }),
      phase({ phase: 'post-consent' }),
    ]);
    const finding = result.findings.find((f) => f.code === 'TRACKING_COOKIE_BEFORE_CONSENT');
    assert.ok(finding);
    assert.equal(finding.domain, '.vendor.test');
  });

  it('flags storage writes of identifiers before consent', () => {
    const write: StorageWrite = {
      phase: 'pre-consent',
      atMs: 50,
      storage: 'localStorage',
      key: '_ga_user',
      valuePreview: 'user-123',
      valueBytes: 8,
      documentUrl: 'https://example.test/',
      documentHost: 'example.test',
      party: 'first',
      purpose: 'analytics',
      origin: 'https://example.test/app.js <- :12',
    };
    const result = analyseWith([
      phase({ phase: 'pre-consent', storage: [write] }),
      phase({ phase: 'post-reject' }),
      phase({ phase: 'post-consent' }),
    ]);
    assert.ok(result.findings.some((f) => f.code === 'TRACKING_STORAGE_BEFORE_CONSENT'));
  });

  it('flags tracking that continues after rejection', () => {
    const result = analyseWith([
      phase({ phase: 'pre-consent' }),
      phase({
        phase: 'post-reject',
        consent: { phase: 'post-reject', wanted: 'reject', found: true, clicked: '#reject-all — "reject all"', inFrameUrl: null, candidates: [], note: null },
        requests: [request({ phase: 'post-reject' })],
      }),
      phase({ phase: 'post-consent' }),
    ]);
    const finding = result.findings.find((f) => f.code === 'TRACKING_AFTER_REJECT');
    assert.ok(finding);
    assert.equal(finding.severity, 'critical');
  });

  it('does not evaluate rejection when no reject control was found', () => {
    const result = analyseWith([
      phase({ phase: 'pre-consent' }),
      phase({
        phase: 'post-reject',
        consent: { phase: 'post-reject', wanted: 'reject', found: false, clicked: null, inFrameUrl: null, candidates: [], note: 'not found' },
        requests: [request({ phase: 'post-reject' })],
      }),
      phase({ phase: 'post-consent' }),
    ]);
    assert.equal(result.findings.filter((f) => f.code === 'TRACKING_AFTER_REJECT').length, 0);
    assert.ok(result.findings.some((f) => f.code === 'CONSENT_MECHANISM_DEFECT'));
  });

  it('reports a banner with no reject control', () => {
    const result = analyseWith([
      phase({
        phase: 'pre-consent',
        consentUi: { hasBanner: true, hasReject: false, hasAccept: true, rejectCandidates: [] },
      }),
      phase({ phase: 'post-reject' }),
      phase({ phase: 'post-consent' }),
    ]);
    const finding = result.findings.find((f) => f.code === 'CONSENT_MECHANISM_DEFECT');
    assert.ok(finding);
    assert.equal(finding.severity, 'high');
  });

  it('flags a first-party relay that carries an identifier', () => {
    const relayRequest = request({
      host: 'example.test',
      siteDomain: 'example.test',
      party: 'first',
      purpose: 'unknown',
      method: 'GET',
      path: '/track?uid=abc123&event=pageview',
      url: 'https://example.test/track?uid=abc123&event=pageview',
    });
    const result = analyseWith([
      phase({ phase: 'pre-consent', requests: [relayRequest], firstPartyRelays: [{ host: 'example.test', request: relayRequest }] }),
      phase({ phase: 'post-reject' }),
      phase({ phase: 'post-consent' }),
    ]);
    const finding = result.findings.find(
      (f) => f.code === 'IDENTIFIER_SENT_BEFORE_CONSENT' && f.title.includes('first-party'),
    );
    assert.ok(finding, 'expected a first-party relay finding');
  });

  it('reports unclassified third-party hosts as info, not violations', () => {
    const result = analyseWith([
      phase({
        phase: 'pre-consent',
        requests: [request({ host: 'widgets.example.net', siteDomain: 'example.net', purpose: 'unknown', url: 'https://widgets.example.net/w.js' })],
      }),
      phase({ phase: 'post-reject' }),
      phase({ phase: 'post-consent' }),
    ]);
    const info = result.findings.find((f) => f.code === 'NON_TRACKING_THIRD_PARTY_BEFORE_CONSENT');
    assert.ok(info);
    assert.equal(info.severity, 'info');
    assert.equal(result.summary.critical, 0);
  });

  it('produces stable vendor summaries across phases', () => {
    const result = analyseWith([
      phase({ phase: 'pre-consent', requests: [request({})] }),
      phase({ phase: 'post-reject' }),
      phase({ phase: 'post-consent', requests: [request({ phase: 'post-consent' })] }),
    ]);
    const vendor = result.vendors.find((v) => v.domain === 'analytics.vendor.test');
    assert.ok(vendor);
    assert.equal(vendor.preConsentRequests, 1);
    assert.equal(vendor.postConsentRequests, 1);
    assert.equal(vendor.verdict, 'fires-before-consent');
  });

  it('keeps distinct hosts as distinct vendors instead of merging on eTLD+1', () => {
    const result = analyseWith([
      phase({
        phase: 'pre-consent',
        requests: [
          request({ host: 'analytics.vendor.test', purpose: 'analytics', url: 'https://analytics.vendor.test/collect' }),
          request({ host: 'pixel.vendor.test', purpose: 'advertising', url: 'https://pixel.vendor.test/px.gif' }),
        ],
      }),
      phase({ phase: 'post-reject' }),
      phase({ phase: 'post-consent' }),
    ]);
    const domains = result.vendors.map((v) => v.domain);
    assert.ok(domains.includes('analytics.vendor.test'), domains.join(','));
    assert.ok(domains.includes('pixel.vendor.test'), domains.join(','));
    assert.ok(!domains.includes('vendor.test'), 'must not collapse to the registrable domain');
  });

  it('omits non-tracking hosts from the vendor matrix', () => {
    const result = analyseWith([
      phase({
        phase: 'pre-consent',
        requests: [
          request({ host: 'example.test', party: 'first', purpose: 'unknown', url: 'https://example.test/' }),
          request({ host: 'cdn.jsdelivr.net', siteDomain: 'jsdelivr.net', purpose: 'cdn', url: 'https://cdn.jsdelivr.net/lib.js' }),
        ],
      }),
      phase({ phase: 'post-reject' }),
      phase({ phase: 'post-consent' }),
    ]);
    assert.ok(!result.vendors.some((v) => v.domain === 'cdn.jsdelivr.net'));
  });

  it('attributes a cookie to the host that set it, without the port', () => {
    const result = analyseWith([
      phase({
        phase: 'pre-consent',
        requests: [
          request({
            url: 'https://analytics.vendor.test:8443/collect',
            host: 'analytics.vendor.test',
            setCookies: ['_vuid=1'],
          }),
        ],
        cookiesSet: [
          cookie({
            name: '_vuid',
            setByUrl: 'https://analytics.vendor.test:8443/collect',
            domain: 'analytics.vendor.test',
            purpose: 'analytics',
          }),
        ],
      }),
      phase({ phase: 'post-reject' }),
      phase({ phase: 'post-consent' }),
    ]);
    const vendor = result.vendors.find((v) => v.domain === 'analytics.vendor.test');
    assert.ok(vendor, result.vendors.map((v) => v.domain).join(','));
    assert.equal(vendor.cookiesSetPreConsent, 1);
    assert.ok(!result.vendors.some((v) => v.domain.includes(':8443')));
  });

  it('reports GPC as ignored when tracking fires despite the opt-out signal', () => {
    const result = analyseWith(
      [
        phase({ phase: 'pre-consent', requests: [request({})] }),
        phase({ phase: 'post-reject' }),
        phase({ phase: 'post-consent' }),
      ],
      { simulateGpc: true },
    );
    const finding = result.findings.find((f) => f.code === 'GPC_SIGNAL_IGNORED');
    assert.ok(finding, 'expected GPC_SIGNAL_IGNORED');
    assert.equal(finding.severity, 'high');
  });

  it('does not raise a GPC finding when the signal is not simulated', () => {
    const result = analyseWith([
      phase({ phase: 'pre-consent', requests: [request({})] }),
      phase({ phase: 'post-reject' }),
      phase({ phase: 'post-consent' }),
    ]);
    assert.ok(!result.findings.some((f) => f.code === 'GPC_SIGNAL_IGNORED'));
  });

  it('does not raise a GPC finding when nothing tracking fires', () => {
    const result = analyseWith(
      [
        phase({
          phase: 'pre-consent',
          requests: [request({ host: 'example.test', party: 'first', purpose: 'unknown', url: 'https://example.test/' })],
        }),
        phase({ phase: 'post-reject' }),
        phase({ phase: 'post-consent' }),
      ],
      { simulateGpc: true },
    );
    assert.ok(!result.findings.some((f) => f.code === 'GPC_SIGNAL_IGNORED'));
  });

  it('does not list a tracking vendor that never fired', () => {
    // The matrix only lists tracking hosts that were actually observed firing;
    // an absent vendor is not a row with zeros, it is simply absent.
    const result = analyseWith([
      phase({ phase: 'pre-consent', requests: [request({ host: 'example.test', party: 'first', purpose: 'unknown', url: 'https://example.test/' })] }),
      phase({ phase: 'post-reject' }),
      phase({ phase: 'post-consent' }),
    ]);
    assert.equal(result.vendors.length, 0);
  });
});

describe('analysis helpers', () => {
  it('recognises identifier keys', () => {
    assert.equal(__testing.looksLikeIdentifierKey('visitor_id'), true);
    assert.equal(__testing.looksLikeIdentifierKey('theme'), false);
  });
  it('recognises scanner traffic', () => {
    assert.equal(__testing.isScannerTraffic('https://example.test/__pcs-unload-sink'), true);
    assert.equal(__testing.isScannerTraffic('https://example.test/app.js'), false);
  });

  it('normalises a request key', () => {
    assert.equal(
      __testing.urlKey(request({ method: 'GET', url: 'https://a.test/x', scheme: 'https', host: 'a.test', path: '/x' })),
      'GET https://a.test/x',
    );
  });

  it('collapses the same warning repeated across phases into one note', () => {
    const notes = __testing.compactNotes([
      '[pre-consent] cached request not sent',
      '[post-reject] cached request not sent',
      '[post-consent] another warning',
    ]);
    assert.deepEqual(notes, [
      'cached request not sent (pre-consent, post-reject)',
      'another warning (post-consent)',
    ]);
  });

  it('strips the port when attributing a cookie to a host', () => {
    assert.equal(__testing.hostForCookie({ setByUrl: 'https://a.test:8443/x', domain: 'a.test' }), 'a.test');
    assert.equal(__testing.hostForCookie({ setByUrl: null, domain: '.a.test' }), 'a.test');
  });
});
