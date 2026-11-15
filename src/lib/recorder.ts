/**
 * Phase recorder.
 *
 * Merges three signals into one chronological event stream:
 *  - the proxy's `onRequestStart` (wire truth: URL, headers, Cookie header);
 *  - Playwright's `request` event (frame + resource type attribution);
 *  - in-page instrumentation (storage/cookie writes with their call stacks).
 *
 * Ordering uses proxy start times as the spine. Browser-side attribution is
 * matched by URL+method against unresolved wire records within a short window,
 * which is the only reliable join key when the browser fires a beacon the
 * Playwright event loop never reports.
 */
import type { Request } from 'playwright';
import type { ProxyExchange } from '../lib/proxy.js';
import type {
  CaptureChannel,
  CookieRecord,
  NetworkEvent,
  PhaseId,
  PhaseResult,
  StorageWrite,
  Party,
} from '../types.js';
import type { Classifier } from './classify.js';
import { parseSetCookie, redactValue } from './cookies.js';

export interface InstrumentationEvent {
  type: 'storage' | 'indexeddb' | 'cookie' | 'fetch' | 'xhr' | 'beacon' | 'websocket' | 'pagehide' | 'visibilityhidden';
  url: string;
  docHost?: string;
  origin?: string;
  t: number;
  storage?: string;
  key?: string;
  value?: string;
  valueBytes?: number;
  store?: string;
  raw?: string;
  requestUrl?: string;
  method?: string;
  keepalive?: boolean;
  body?: string | null;
  stack?: string | null;
}

interface PendingAttribution {
  url: string;
  method: string;
  frameUrl: string | null;
  resourceType: string;
  initiatorUrl: string | null;
  trigger: string | null;
  at: number;
  channel: CaptureChannel;
  used: boolean;
}

/**
 * Last-resort purpose heuristics for hosts the vendor table does not know.
 * These are separate lists because the naive "any ad-ish substring means
 * advertising" rule misclassifies `/analytics.js` and `/collect` endpoints,
 * which are analytics far more often than advertising.
 */
const ADVERTISING_HINTS = [
  'doubleclick',
  'googlesyndication',
  'googleadservices',
  'adservice',
  'adsystem',
  'adnxs',
  'rubicon',
  'pubmatic',
  'criteo',
  'taboola',
  'outbrain',
  'adsrvr',
  'adform',
  'smartadserver',
  '/ads/',
  '/adserver',
  '/pixel',
  '/banner',
  '/rtb',
];

const ANALYTICS_HINTS = [
  '/analytics',
  '/collect',
  '/track',
  '/telemetry',
  '/metrics',
  '/beacon',
  '/event',
  '/ping',
  '/stat',
];

/** Query/body markers that indicate a payload is relaying an identifier. */
const RELAY_IDENTIFIER = /(uid|user_?id|visitor|client_?id|device_?id|distinct_?id|email|ga_?id)/i;

export class PhaseRecorder {
  readonly phase: PhaseId;
  readonly startedAt: number;
  private readonly classifier: Classifier;
  private readonly keepBodies: boolean;

  private readonly wire = new Map<string, ProxyExchange>();
  private readonly requestsByUrl = new Map<string, ProxyExchange[]>();
  private readonly attributions: PendingAttribution[] = [];
  private readonly storageWrites: StorageWrite[] = [];
  private readonly jsCookieSets: { name: string; value: string; url: string; at: number; raw: string; stack: string | null }[] = [];
  private readonly cookieSets: CookieRecord[] = [];
  private readonly instrumentEvents: InstrumentationEvent[] = [];
  private readonly warnings: string[] = [];
  private readonly checkpoints: { label: string; atMs: number }[] = [];
  private readonly seenStorage = new Map<string, number>();
  private consentUi: { hasBanner: boolean; hasReject: boolean; hasAccept: boolean; rejectCandidates: string[] } | null =
    null;
  /**
   * Window during which the scanner is deliberately tearing the document down.
   * Requests from the proxy inside this window are unload traffic. The proxy is
   * the only channel that reliably sees them, and no browser-side trigger
   * (`beacon`, `ping`) is guaranteed to be attributed.
   */
  private unloadWindow: { from: number; to: number } | null = null;

  constructor(options: {
    phase: PhaseId;
    startedAt: number;
    classifier: Classifier;
    siteDomain: string;
    keepBodies: boolean;
    respectGpc: boolean;
  }) {
    this.phase = options.phase;
    this.startedAt = options.startedAt;
    this.classifier = options.classifier;
    this.keepBodies = options.keepBodies;
  }

  // ----------------------------------------------------------------- wire input

  onProxyStart(exchange: ProxyExchange): void {
    this.wire.set(exchange.id, exchange);
    const key = `${exchange.method} ${exchange.scheme}://${authority(exchange.host, exchange.port, exchange.scheme)}${exchange.path}`;
    const list = this.requestsByUrl.get(key) ?? [];
    list.push(exchange);
    this.requestsByUrl.set(key, list);
  }

  onProxyComplete(exchange: ProxyExchange): void {
    this.wire.set(exchange.id, exchange);
  }

  // ------------------------------------------------------------- browser input

  onPlaywrightRequest(request: Request): void {
    const frame = request.frame();
    let frameUrl: string | null = null;
    try {
      frameUrl = frame.url();
    } catch {
      frameUrl = null;
    }
    this.attributions.push({
      url: request.url(),
      method: request.method(),
      frameUrl,
      resourceType: request.resourceType(),
      initiatorUrl: null,
      trigger: mapResourceType(request.resourceType()),
      at: Date.now(),
      channel: 'playwright',
      used: false,
    });
  }

  onCdpInitiator(url: string, initiatorUrl: string | null, resourceType: string | null, trigger: string | null): void {
    this.attributions.push({
      url,
      method: 'ANY',
      frameUrl: null,
      resourceType: resourceType ?? 'other',
      initiatorUrl,
      trigger,
      at: Date.now(),
      channel: 'cdp',
      used: false,
    });
  }

  onInstrumentation(event: InstrumentationEvent): void {
    this.instrumentEvents.push(event);
    const at = event.t - this.startedAt;
    const docUrl = event.url || '';
    let docHost = '';
    try {
      docHost = event.docHost ?? new URL(docUrl).hostname;
    } catch {
      docHost = '';
    }
    const party: Party = this.classifier.partyOf(docHost);
    const hostInfo = this.classifier.classifyHost(docHost);
    const purposeForDoc = hostInfo.purpose;

    if ((event.type === 'storage' || event.type === 'indexeddb') && event.key !== undefined) {
      const storageKind =
        event.type === 'indexeddb'
          ? 'indexedDB'
          : event.storage === 'sessionStorage'
            ? 'sessionStorage'
            : 'localStorage';
      const key = String(event.key);
      // Deduplicate repeated writes of the same key/value in the same phase so a
      // tracker writing on every tick does not flood the evidence.
      const dedupeKey = `${storageKind}\u0000${docUrl}\u0000${key}\u0000${event.value ?? ''}`;
      const prev = this.seenStorage.get(dedupeKey);
      if (prev !== undefined) {
        this.seenStorage.set(dedupeKey, prev + 1);
        return;
      }
      this.seenStorage.set(dedupeKey, 1);

      const byKey = this.classifier.classifyCookie(key);
      const sensitive = this.classifier.looksSensitiveKey(key) || this.classifier.looksLikeIdentifier(key, String(event.value ?? ''));
      const purpose =
        byKey.purpose !== 'unknown' ? byKey.purpose : sensitive ? ('analytics' as const) : purposeForDoc;
      this.storageWrites.push({
        phase: this.phase,
        atMs: Math.max(0, at),
        storage: storageKind,
        key,
        valuePreview: redactValue(String(event.value ?? '')),
        valueBytes: event.valueBytes ?? String(event.value ?? '').length,
        documentUrl: docUrl,
        documentHost: docHost,
        party,
        purpose,
        origin: event.stack ?? event.origin ?? docUrl,
      });
      return;
    }

    if (event.type === 'cookie' && event.key !== undefined) {
      this.jsCookieSets.push({
        name: String(event.key),
        value: String(event.value ?? ''),
        url: docUrl,
        at,
        raw: event.raw ?? String(event.key),
        stack: event.stack ?? null,
      });
      return;
    }

    if (event.type === 'fetch' || event.type === 'xhr' || event.type === 'beacon' || event.type === 'websocket') {
      if (!event.requestUrl) return;
      this.attributions.push({
        url: event.requestUrl,
        method: event.method ?? 'GET',
        frameUrl: docUrl || null,
        resourceType: event.type,
        initiatorUrl: event.stack ?? null,
        trigger: event.type,
        at: Date.now(),
        channel: 'instrumentation',
        used: false,
      });
    }
  }

  // ----------------------------------------------------------------- finalise

  private attributionFor(method: string, url: string, startedAt: number): PendingAttribution | null {
    // Prefer an unused attribution with the same URL and method.
    let best: PendingAttribution | null = null;
    let bestDelta = Infinity;
    for (const a of this.attributions) {
      if (a.used) continue;
      if (a.url !== url) continue;
      if (a.method !== 'ANY' && a.method !== method) continue;
      const delta = Math.abs(a.at - startedAt);
      if (delta > 4000) continue;
      if (delta < bestDelta) {
        best = a;
        bestDelta = delta;
      }
    }
    if (best) best.used = true;
    return best;
  }


  toNetworkEvent(exchange: ProxyExchange): NetworkEvent {
    const attribution = this.attributionFor(
      exchange.method,
      `${exchange.scheme}://${authority(exchange.host, exchange.port, exchange.scheme)}${exchange.path}`,
      exchange.startedAt,
    );
    let url = `${exchange.scheme}://${authority(exchange.host, exchange.port, exchange.scheme)}${exchange.path}`;
    // Instrumentation reports the URL as the page wrote it (relative URLs are
    // resolved by the browser, so this is usually absolute).
    const hostInfo = this.classifier.classifyHost(exchange.host);
    const party = this.classifier.partyOf(exchange.host);
    const channels: CaptureChannel[] = ['proxy'];
    if (attribution) channels.push(attribution.channel);

    const cookieHeader = exchange.requestHeaders['cookie'] ?? null;
    const referer = exchange.requestHeaders['referer'] ?? null;

    let purpose = hostInfo.purpose;
    if (purpose === 'unknown') {
      const lowerUrl = url.toLowerCase();
      const contentType = (exchange.requestHeaders['content-type'] ?? '').toLowerCase();
      const body = exchange.requestBody ?? '';
      if (ADVERTISING_HINTS.some((hint) => lowerUrl.includes(hint))) {
        purpose = 'advertising';
      } else if (
        ANALYTICS_HINTS.some((hint) => lowerUrl.includes(hint)) ||
        // A POST whose body or content type looks like an event payload is an
        // analytics call even when the path is opaque.
        (/json|urlencoded/i.test(contentType) && /event|track|collect|analytics|uid|id=/i.test(body))
      ) {
        purpose = 'analytics';
      }
    }

    return {
      id: exchange.id,
      phase: this.phase,
      atMs: Math.max(0, exchange.startedAt - this.startedAt),      startedAt: exchange.startedAt,
      scheme: exchange.scheme,
      host: exchange.host,
      siteDomain: this.classifier.siteDomainOf(exchange.host),
      party,
      purpose,
      method: exchange.method,
      path: exchange.path,
      url,
      headers: sanitiseHeaders(exchange.requestHeaders),
      requestBody: this.keepBodies || looksLikeTrackingBody(exchange) ? exchange.requestBody : null,
      requestBodyTruncated: exchange.requestBodyTruncated,
      cookieHeader,
      referer,
      status: exchange.status,
      setCookies: exchange.setCookies,
      responseBody: this.keepBodies ? exchange.responseBody : null,
      attribution: {
        frameUrl: attribution?.frameUrl ?? null,
        initiatorUrl: attribution?.initiatorUrl ?? null,
        resourceType: attribution?.resourceType ?? null,
        trigger: attribution?.trigger ?? null,
      },
      channels,
      onUnload: this.isUnload(exchange) || attribution?.trigger === 'beacon',
      aborted: exchange.aborted,
    };
  }

  collectCookies(
    jar: {
      name: string;
      value: string;
      domain: string;
      path: string;
      secure: boolean;
      httpOnly: boolean;
      sameSite: string;
      expires: number;
    }[],
    host: string,
  ): void {
    const now = Date.now();
    const observed = new Map<string, CookieRecord>();

    const record = (input: {
      name: string;
      value: string;
      domain: string;
      path: string;
      secure: boolean;
      httpOnly: boolean;
      sameSite: string | null;
      expires: string | null;
      setInPhase: PhaseId | null;
      setByUrl: string | null;
      atMs: number | null;
      domainAttr: string | null;
    }): CookieRecord => {
      const domain = input.domain.replace(/^\./, '');
      const hostForClass = domain || input.setByUrl || host;
      const info = this.classifier.classifyCookieWithHost(input.name, hostForClass);
      return {
        name: input.name,
        value: input.value,
        domainAttr: input.domainAttr,
        domain,
        siteDomain: this.classifier.siteDomainOf(domain),
        party: this.classifier.partyOf(domain),
        purpose: info.purpose,
        path: input.path,
        secure: input.secure,
        httpOnly: input.httpOnly,
        sameSite: input.sameSite,
        expires: input.expires,
        session: input.expires === null,
        setInPhase: input.setInPhase,
        setByUrl: input.setByUrl,
        atMs: input.atMs,
        origin: input.setInPhase ? 'observed-set' : 'jar-snapshot',
        known: { vendor: info.vendor, purpose: info.purpose, tracking: info.tracking },
      };
    };

    // Cookies actually set by responses in this phase.
    for (const exchange of this.wire.values()) {
      for (const raw of exchange.setCookies) {
        const parsed = parseSetCookie(raw);
        if (!parsed) continue;
        const domain = parsed.domain ?? exchange.host;
        const recordI = record({
          name: parsed.name,
          value: parsed.value,
          domain,
          path: parsed.path ?? '/',
          secure: parsed.secure,
          httpOnly: parsed.httpOnly,
          sameSite: parsed.sameSite,
          expires: parsed.expires ? parsed.expires.toISOString() : null,
          setInPhase: this.phase,
          setByUrl: `${exchange.scheme}://${authority(exchange.host, exchange.port, exchange.scheme)}${exchange.path}`,
          atMs: Math.max(0, exchange.startedAt - this.startedAt),
          domainAttr: parsed.domain ?? null,
        });
        observed.set(`${recordI.name}\u0000${recordI.domain}`, recordI);
      }
    }

    // Cookies written from JavaScript (instrumentation), which never appear as
    // a Set-Cookie header.
    for (const js of this.jsCookieSets) {
      const parsed = parseSetCookie(js.raw);
      if (!parsed) continue;
      let docHost = '';
      try {
        docHost = new URL(js.url).hostname;
      } catch {
        docHost = '';
      }
      const recordI = record({
        name: parsed.name,
        value: parsed.value,
        domain: parsed.domain ?? docHost,
        path: parsed.path ?? '/',
        secure: parsed.secure,
        httpOnly: parsed.httpOnly,
        sameSite: parsed.sameSite,
        expires: parsed.expires ? parsed.expires.toISOString() : null,
        setInPhase: this.phase,
        setByUrl: js.url,
        atMs: js.at,
        domainAttr: parsed.domain ?? null,
      });
      observed.set(`${recordI.name}\u0000${recordI.domain}`, recordI);
    }

    // The browser's authoritative jar. Any cookie here that was not observed
    // being set is still real, and its absence from the Set-Cookie stream is
    // marked `jar-snapshot` rather than hidden.
    for (const c of jar) {
      const expires = c.expires > 0 ? new Date(c.expires * 1000).toISOString() : null;
      if (expires && new Date(expires).getTime() < now) continue;
      const key = `${c.name}\u0000${c.domain.replace(/^\./, '')}`;
      if (observed.has(key)) continue;
      const recordI = record({
        name: c.name,
        value: c.value,
        domain: c.domain,
        path: c.path,
        secure: c.secure,
        httpOnly: c.httpOnly,
        sameSite: c.sameSite || null,
        expires,
        setInPhase: null,
        setByUrl: null,
        atMs: null,
        domainAttr: null,
      });
      observed.set(key, recordI);
    }

    for (const c of observed.values()) this.cookieSets.push(c);
  }

  addWarning(message: string): void {
    this.warnings.push(message);
  }

  addCheckpoint(label: string): void {
    this.checkpoints.push({ label, atMs: Math.max(0, Date.now() - this.startedAt) });
  }

  /** Record what the consent UI looked like, for mechanism-quality findings. */
  setConsentUi(ui: { hasBanner: boolean; hasReject: boolean; hasAccept: boolean; rejectCandidates: string[] }): void {
    this.consentUi = ui;
  }

  get consentUiSnapshot(): typeof this.consentUi {
    return this.consentUi;
  }

  get instrumentedEvents(): InstrumentationEvent[] {
    return this.instrumentEvents;
  }

  /** Number of proxied exchanges seen so far; drives the quiet-period logic. */
  get proxyCount(): number {
    return this.wire.size;
  }

  /**
   * Open the teardown window. Requests that start inside it are classified as
   * unload traffic, which is the only dependable way to catch `pagehide`
   * beacons: the browser does not reliably surface them to Playwright, and
   * `navigator.sendBeacon` can be called from code the shim never sees.
   */
  markUnloadStart(): void {
    this.unloadWindow = { from: Date.now(), to: Number.POSITIVE_INFINITY };
  }

  markUnloadEnd(graceMs = 400): void {
    if (!this.unloadWindow) return;
    this.unloadWindow = { from: this.unloadWindow.from, to: Date.now() + graceMs };
  }

  private isUnload(exchange: ProxyExchange): boolean {
    if (!this.unloadWindow) return false;
    return exchange.startedAt >= this.unloadWindow.from && exchange.startedAt <= this.unloadWindow.to;
  }

  /**
   * True when a storage write for this key/value was already recorded from
   * instrumentation. The snapshot harvest then skips it instead of double
   * counting the same write.
   */
  storageKeys(storage: string, documentUrl: string, key: string, value: string): boolean {
    const wantValue = value.slice(0, 2048);
    return this.storageWrites.some(
      (w) =>
        w.storage === storage &&
        w.key === key &&
        w.documentUrl === documentUrl &&
        (w.valuePreview === redactValue(wantValue) || w.valuePreview === wantValue),
    );
  }

  /**
   * Record a key found in a storage snapshot but never observed being written.
   * This catches writes that happened before instrumentation loaded and writes
   * performed inside a worker, which are invisible to the main-thread shim.
   */
  addStorageSnapshot(input: {
    storage: 'localStorage' | 'sessionStorage';
    key: string;
    value: string;
    documentUrl: string;
    documentHost: string;
    party: Party;
    purpose: import('../types.js').Purpose;
  }): void {
    if (input.value === '') return;
    const byKey = this.classifier.classifyCookie(input.key);
    const sensitive =
      this.classifier.looksSensitiveKey(input.key) ||
      this.classifier.looksLikeIdentifier(input.key, input.value);
    this.storageWrites.push({
      phase: this.phase,
      atMs: Math.max(0, Date.now() - this.startedAt),
      storage: input.storage,
      key: input.key,
      valuePreview: redactValue(input.value),
      valueBytes: input.value.length,
      documentUrl: input.documentUrl,
      documentHost: input.documentHost,
      party: input.party,
      purpose:
        byKey.purpose !== 'unknown'
          ? byKey.purpose
          : sensitive
            ? 'analytics'
            : input.purpose,
      origin: `${input.documentUrl} (present in storage snapshot; set before instrumentation or from a worker)`,
    });
  }

  finalise(options: {
    durationMs: number;
    consent: PhaseResult['consent'];
    screenshots: PhaseResult['screenshots'];
  }): PhaseResult {
    // Every wire exchange becomes a request record; unresolved attributions are
    // irrelevant but unused ones are reported as a coverage note.
    const requests = Array.from(this.wire.values())
      .sort((a, b) => a.startedAt - b.startedAt)
      .map((e) => this.toNetworkEvent(e));

    // First-party server-side relaying: a same-origin endpoint receiving an
    // identifier. Host-based classification sees ordinary site traffic here,
    // which is exactly why this pattern survives manual reviews.
    const relayRequests = requests.filter(
      (r) => r.party === 'first' && RELAY_IDENTIFIER.test(`${r.path} ${r.requestBody ?? ''}`),
    );
    const relays: { host: string; request: NetworkEvent }[] = [];
    const seenRelayHosts = new Set<string>();
    for (const request of relayRequests) {
      if (seenRelayHosts.has(request.host)) continue;
      seenRelayHosts.add(request.host);
      relays.push({ host: request.host, request });
    }

    const unusedAttr = this.attributions.filter((a) => !a.used);
    if (unusedAttr.length > 0) {
      // This is not a coverage gap: the proxy is authoritative and every
      // request it saw is in `requests`. An unmatched attribution only means
      // the browser reported a request that never reached the wire — served
      // from cache, blocked before transmission, or aborted. It is recorded as
      // a note so nobody mistakes it for missing evidence.
      this.warnings.push(
        `${unusedAttr.length} request(s) were reported by the browser but never reached the network (cached, blocked, or aborted before transmission). They are not evidence of anything leaving the device.`,
      );
    }

    return {
      phase: this.phase,
      startedAt: new Date(this.startedAt).toISOString(),
      durationMs: options.durationMs,
      requests,
      cookiesSet: dedupeCookies(this.cookieSets),
      cookieJar: dedupeCookies(this.cookieSets).filter((c) => c.origin === 'jar-snapshot' || c.setInPhase),
      storage: this.storageWrites,
      consent: options.consent,
      screenshots: options.screenshots,
      firstPartyRelays: relays,
      checkpoints: this.checkpoints,
      consentUi: this.consentUi,
      warnings: this.warnings,
    };
  }
}

/**
 * Rebuild the absolute URL as the browser saw it. The port must be preserved:
 * fixture and staging sites rarely run on 443, and Playwright reports URLs with
 * the port included, so omitting it silently breaks attribution.
 */
function authority(host: string, port: number, scheme: 'http' | 'https'): string {
  const isDefault = (scheme === 'https' && port === 443) || (scheme === 'http' && port === 80);
  return isDefault ? host : `${host}:${port}`;
}

function dedupeCookies(cookies: CookieRecord[]): CookieRecord[] {  const map = new Map<string, CookieRecord>();
  for (const c of cookies) {
    const key = `${c.name}\u0000${c.domain}\u0000${c.path}`;
    const prev = map.get(key);
    // Prefer the record that carries a real set event over a jar snapshot.
    if (!prev || (prev.origin === 'jar-snapshot' && c.origin === 'observed-set')) {
      map.set(key, c);
    }
  }
  return Array.from(map.values()).sort((a, b) => a.name.localeCompare(b.name));
}

function sanitiseHeaders(headers: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) {
    // Drop credentials and the Cookie header (kept separately, parsed).
    if (/^(authorization|proxy-authorization|cookie|x-api-key)$/i.test(k)) continue;
    out[k] = redactValue(v);
  }
  return out;
}

function looksLikeTrackingBody(exchange: ProxyExchange): boolean {
  if (!exchange.requestBody) return false;
  const ct = (exchange.requestHeaders['content-type'] ?? '').toLowerCase();
  return /json|urlencoded|text\/plain/i.test(ct) && exchange.requestBody.length < 4096;
}

function mapResourceType(type: string): string {
  switch (type) {
    case 'document':
      return 'document';
    case 'script':
      return 'script';
    case 'image':
      return 'image';
    case 'xhr':
      return 'xhr';
    case 'fetch':
      return 'fetch';
    case 'websocket':
      return 'websocket';
    case 'media':
      return 'media';
    case 'stylesheet':
      return 'stylesheet';
    case 'font':
      return 'font';
    case 'iframe':
      return 'iframe';
    default:
      return type;
  }
}

/** Export for tests. */
export const __testing = { mapResourceType, sanitiseHeaders, looksLikeTrackingBody };
export type { PendingAttribution };
