/**
 * Scan orchestration.
 *
 * Each phase runs in a *fresh* browser context so no state leaks between
 * "before consent" and "after consent". Within a phase:
 *
 *   load -> observe -> (interact with consent UI) -> reload -> observe again
 *
 * The pre-consent phase never touches the banner. The reject phase clicks the
 * reject control and then reloads in the same context: the reload is what a
 * real visitor experiences, and it is where "we rejected you, but the tracker
 * still fired" bugs actually show up. The consent phase accepts and reloads for
 * the same reason.
 */
import fs from 'node:fs';
import path from 'node:path';
import { chromium, type Browser, type BrowserContext, type Frame, type Page } from 'playwright';
import { getDomain } from 'tldts';
import type { ConsentAttempt, PhaseId, PhaseResult } from '../types.js';
import type { ScanConfig } from '../config.js';
import { InterceptProxy, type ProxyExchange } from './proxy.js';
import { generateCa, type CaMaterial } from './ca.js';
import { Classifier } from './classify.js';
import { PhaseRecorder, type InstrumentationEvent } from './recorder.js';
import { INSTRUMENTATION_BINDING, makeInitScript } from './instrumentation.js';
import { inspectConsentUi, performConsent } from './consent.js';

export interface ScanOptions {
  config: ScanConfig;
  /** Directory for screenshots and other artefacts. */
  artefactDir: string;
  /** Where to write the CA certificate. Defaults to `<artefactDir>/ca`. */
  caDir?: string;
  /** Run with a visible browser. */
  headless?: boolean;
  /** Callback for progress messages. */
  onProgress?: (message: string) => void;
}

export interface ScanOutcome {
  phases: PhaseResult[];
  ca: CaMaterial;
  caCertPath: string;
  siteHost: string;
  siteDomain: string;
  playwrightVersion: string;
  startedAt: string;
  finishedAt: string;
  coverageNotes: string[];
  proxyUsed: boolean;
}

const IGNORED_URL = /^(chrome-extension:|devtools:|chrome:|data:|about:)/;

export async function runScan(options: ScanOptions): Promise<ScanOutcome> {
  const { config, artefactDir } = options;
  const progress = options.onProgress ?? (() => {});
  const startedAt = new Date();

  fs.mkdirSync(artefactDir, { recursive: true });

  const target = new URL(config.url);
  const siteHost = target.hostname;
  const siteDomain = getDomain(siteHost) ?? siteHost;

  const ca = generateCa();
  const caDir = options.caDir ?? path.join(artefactDir, 'ca');
  fs.mkdirSync(caDir, { recursive: true });
  const caCertPath = path.join(caDir, 'scanner-ca.pem');
  fs.writeFileSync(caCertPath, ca.caCertPem, { mode: 0o644 });
  fs.writeFileSync(path.join(caDir, 'scanner-ca-key.pem'), ca.caKeyPem, { mode: 0o600 });

  const proxy = new InterceptProxy({
    ca,
    upstreamHostMap: buildUpstreamMap(config, siteHost),
    verifyUpstream: false,
    // Chromium exposes navigator.globalPrivacyControl but does not send the
    // header, so a server-side opt-out check would otherwise never see it.
    sendGpcHeader: config.simulateGpc === true,
  });
  await proxy.start();
  progress(`proxy listening on ${proxy.url}`);

  // The proxy is process-wide; each phase owns its own recorder, so the
  // scanner points these sinks at the phase that is currently running.
  let activeRecorder: PhaseRecorder | null = null;
  proxy.onRequestStart = (exchange: ProxyExchange) => activeRecorder?.onProxyStart(exchange);
  proxy.onExchange = (exchange: ProxyExchange) => activeRecorder?.onProxyComplete(exchange);

  // The proxy is configured on the browser, not on a context: Playwright's
  // per-context `proxy` option only exists for `request` contexts, and a
  // browser launched without `proxy` would silently send no traffic through
  // us. That failure mode produces an empty report that looks compliant, so
  // the browser is always launched here with the proxy wired in.
  const browser = await chromium.launch({
    headless: options.headless ?? true,
    // `bypass: <-loopback>` is required: without it Chromium silently
    // connects directly for 127.0.0.1 and the proxy sees nothing.
    proxy: { server: proxy.url, bypass: '<-loopback>' },
    args: [
      '--ignore-certificate-errors',
      // Do not flatter the site with a hardened browser profile: scan with
      // third-party cookies permitted, as a default consumer browser would.
      '--no-first-run',
      '--disable-background-networking',
      '--disable-component-update',
      '--disable-domain-reliability',
      '--disable-breakpad',
      '--metrics-recording-only',
      '--disable-sync',
      '--disable-default-apps',
    ],
  });

  const phases: PhaseResult[] = [];
  const coverageNotes: string[] = [];
  const classifier = new Classifier({
    siteDomain,
    config: {
      domains: config.domains,
      trackingCookies: config.trackingCookies,
      exemptDomains: config.exemptDomains,
    },
  });

  try {
    for (const phase of config.phases ?? ['pre-consent', 'post-reject', 'post-consent']) {
      progress(`running phase ${phase}`);
      const result = await runPhase({
        phase,
        config,
        browser,
        proxy,
        classifier,
        siteDomain,
        siteHost,
        siteDir: artefactDir,
        onRecorder: (recorder) => {
          activeRecorder = recorder;
        },
      });
      phases.push(result);
      for (const warning of result.warnings) coverageNotes.push(`[${phase}] ${warning}`);

      // A phase that recorded no document request means the browser never
      // reached the site through the proxy. Treat that as a hard error: silently
      // returning an empty report would read as "compliant".
      const sawDocument = result.requests.some((r) => r.attribution.resourceType === 'document' || r.path === '/');
      if (!sawDocument && result.requests.length === 0) {
        throw new Error(
          `phase ${phase} recorded no traffic at all. The browser is probably not using the proxy (${proxy.url}); refusing to report a result that would look compliant.`,
        );
      }
    }
  } finally {
    activeRecorder = null;
    await browser.close();
    await proxy.stop();
  }

  return {
    phases,
    ca,
    caCertPath,
    siteHost,
    siteDomain,
    playwrightVersion: await detectPlaywrightVersion(),
    startedAt: startedAt.toISOString(),
    finishedAt: new Date().toISOString(),
    coverageNotes,
    proxyUsed: true,
  };
}

/**
 * Map synthetic or staging hosts to an upstream IP. `SCANNER_HOST_MAP` is
 * `host=ip,host2=ip2`; `config.hostMap` is merged over it. The target host and
 * any `.test` override always resolve to loopback so fixtures work.
 */
export function buildUpstreamMap(config: ScanConfig, siteHost: string): Record<string, string> {
  const map: Record<string, string> = {
    ...parseHostMap(process.env.SCANNER_HOST_MAP),
    ...(config.hostMap ?? {}),
  };
  if (siteHost.endsWith('.test') || siteHost === 'localhost') {
    map[siteHost] ??= '127.0.0.1';
  }
  for (const domain of config.domains ?? []) {
    const plain = domain.match.replace(/^\*\.?/, '').replace(/^\./, '');
    if (plain && !plain.includes('*') && plain.endsWith('.test')) map[plain] ??= '127.0.0.1';
  }
  return map;
}
export function parseHostMap(value: string | undefined): Record<string, string> {
  if (!value) return {};
  const out: Record<string, string> = {};
  for (const pair of value.split(',')) {
    const [host, ip] = pair.split('=').map((s) => s.trim());
    if (host && ip) out[host] = ip;
  }
  return out;
}

interface PhaseInput {
  phase: PhaseId;
  config: ScanConfig;
  browser: Browser;
  proxy: InterceptProxy;
  classifier: Classifier;
  siteDomain: string;
  siteHost: string;
  siteDir: string;
  onRecorder: (recorder: PhaseRecorder) => void;
}

async function runPhase(input: PhaseInput): Promise<PhaseResult> {
  const { phase, config, browser, classifier, siteDomain, siteHost, siteDir } = input;
  const settle = config.settle!;
  const startedAt = Date.now();
  const phaseDir = path.join(siteDir, phase);
  fs.mkdirSync(phaseDir, { recursive: true });

  const recorder = new PhaseRecorder({
    phase,
    startedAt,
    classifier,
    siteDomain,
    keepBodies: config.keepResponseBodies ?? false,
    respectGpc: config.simulateGpc ?? false,
  });
  input.onRecorder(recorder);

  const context: BrowserContext = await browser.newContext({
    ignoreHTTPSErrors: true,
    viewport: { width: 1280, height: 900 },
    locale: 'en-US',
    timezoneId: 'UTC',
    serviceWorkers: 'allow',
  });

  if (config.simulateGpc) {
    await context.addInitScript(() => {
      Object.defineProperty(navigator, 'globalPrivacyControl', { get: () => true });
      Object.defineProperty(navigator, 'doNotTrack', { get: () => '1' });
    });
  }

  await context.exposeBinding(INSTRUMENTATION_BINDING, (_source, payload) => {
    const event = payload as InstrumentationEvent;
    if (!event || typeof event !== 'object') return;
    recorder.onInstrumentation(event);
  });
  await context.addInitScript({ content: makeInitScript() });

  const page = await context.newPage();
  page.on('request', (request) => {
    if (IGNORED_URL.test(request.url())) return;
    recorder.onPlaywrightRequest(request);
  });

  // CDP supplies initiators (which script line fired the request) — including
  // for frames where Playwright exposes no frame object.
  const cdp = await context.newCDPSession(page);
  cdp.on('Network.requestWillBeSent', (event) => {
    if (IGNORED_URL.test(event.request.url)) return;
    const frame = event.initiator?.stack?.callFrames?.[0];
    const initiatorUrl = frame ? `${frame.url}:${frame.lineNumber}` : null;
    recorder.onCdpInitiator(
      event.request.url,
      initiatorUrl,
      event.type ?? null,
      mapCdpType(event.type),
    );
  });
  await cdp.send('Network.enable');

  const screenshots: PhaseResult['screenshots'] = [];
  const screenshot = async (label: string): Promise<void> => {
    const file = `${String(screenshots.length + 1).padStart(2, '0')}-${label}.png`;
    try {
      await page.screenshot({ path: path.join(phaseDir, file), timeout: 8000 });
      screenshots.push({
        atMs: Math.max(0, Date.now() - startedAt),
        label,
        file: path.relative(siteDir, path.join(phaseDir, file)),
      });
    } catch {
      /* the page may be navigating; a missing screenshot is not fatal */
    }
  };

  let attempt: ConsentAttempt | null = null;

  try {
    await page.goto(config.url, { waitUntil: 'domcontentloaded', timeout: 30_000 });
    await settlePage(page, settle.preConsentMs!, settle.maxPhaseMs!);
    await interact(page, config);
    await waitForQuiet(recorder, settle.quietMs!, settle.maxPhaseMs!);
    await screenshot('loaded');

    if (phase === 'pre-consent') {
      const ui = await inspectConsentUi(page, config.consent);
      recorder.setConsentUi(ui);
      recorder.addCheckpoint('consent-ui-inspected');    } else {
      const wanted = phase === 'post-reject' ? 'reject' : 'accept';
      await screenshot(`before-${wanted}`);
      attempt = await performConsent({ page, config: config.consent, phase, wanted });
      recorder.addCheckpoint(`${wanted}-clicked`);
      if (!attempt.found) {
        recorder.addWarning(attempt.note ?? 'consent control not found');
        await screenshot(`${wanted}-not-found`);
      } else {
        await sleep(400);
        await screenshot(`after-${wanted}-click`);

        // Replay the reload a real visitor performs after choosing. Only then
        // can the scanner tell whether the choice was respected.
        recorder.addCheckpoint(`reload-after-${wanted}`);
        await page.goto(config.url, { waitUntil: 'domcontentloaded', timeout: 30_000 }).catch(() => {});
        await settlePage(page, settle.afterChoiceMs!, settle.maxPhaseMs!);
        await interact(page, config);
        await waitForQuiet(recorder, settle.quietMs!, settle.maxPhaseMs!);
        await screenshot(`after-${wanted}-reload`);
      }
    }

    for (const frame of page.frames()) {
      await harvestFrameStorage(frame, recorder, classifier);
    }

    // Release any beacon bound to `pagehide` into the proxy before closing.
    recorder.markUnloadStart();
    await flushUnloadBeacons(page);
    recorder.markUnloadEnd();
    const jar = await context.cookies();
    recorder.collectCookies(jar, siteHost);
  } catch (error) {
    recorder.addWarning(`phase failed: ${(error as Error).message}`);
  } finally {
    await page.close().catch(() => {});
    await context.close().catch(() => {});
  }

  return recorder.finalise({
    durationMs: Date.now() - startedAt,
    consent: attempt,
    screenshots,
  });
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function settlePage(page: Page, ms: number, capMs: number): Promise<void> {
  await page.waitForLoadState('load', { timeout: Math.min(15_000, capMs) }).catch(() => {});
  await sleep(ms);
}

async function interact(page: Page, config: ScanConfig): Promise<void> {
  const cfg = config.interaction ?? {};
  try {
    if (cfg.scroll) {
      await page.evaluate(async () => {
        const step = Math.max(200, Math.floor(innerHeight * 0.8));
        const limit = Math.min(document.body?.scrollHeight ?? 0, 8000);
        for (let y = 0; y <= limit; y += step) {
          scrollTo(0, y);
          await new Promise((r) => setTimeout(r, 120));
        }
        scrollTo(0, 0);
      });
    }
    if (cfg.pointer) {
      await page.mouse.move(640, 400).catch(() => {});
      await page.mouse.move(700, 450, { steps: 8 }).catch(() => {});
    }
    if (cfg.type) {
      const input = page.locator('input[type="text"], input[type="search"], input:not([type])').first();
      if ((await input.count()) > 0 && (await input.isVisible().catch(() => false))) {
        await input.click({ timeout: 1500 }).catch(() => {});
        await input.type('probe', { delay: 60 }).catch(() => {});
      }
    }
  } catch {
    /* interaction is best-effort; a failure must not abort the phase */
  }
}

/**
 * Wait until no new proxied exchange has arrived for `quietMs`, capped at
 * `maxMs`. Proxy traffic is the right signal: a beacon fired in the last
 * milliseconds still counts, whereas Playwright may never report it.
 */
async function waitForQuiet(recorder: PhaseRecorder, quietMs: number, maxMs: number): Promise<void> {
  const cap = Date.now() + maxMs;
  let lastCount = recorder.proxyCount;
  let lastActivity = Date.now();
  while (Date.now() < cap) {
    await sleep(150);
    const count = recorder.proxyCount;
    if (count !== lastCount) {
      lastCount = count;
      lastActivity = Date.now();
    } else if (Date.now() - lastActivity >= quietMs) {
      return;
    }
  }
}

async function harvestFrameStorage(
  frame: Frame,
  recorder: PhaseRecorder,
  classifier: Classifier,
): Promise<void> {
  let snapshot: { url: string; host: string; local: Record<string, string>; session: Record<string, string> } | null;
  try {
    snapshot = await frame.evaluate(() => {
      const local: Record<string, string> = {};
      const session: Record<string, string> = {};
      try {
        for (const k of Object.keys(localStorage)) local[k] = localStorage.getItem(k) ?? '';
      } catch {
        /* cross-origin or blocked */
      }
      try {
        for (const k of Object.keys(sessionStorage)) session[k] = sessionStorage.getItem(k) ?? '';
      } catch {
        /* ignore */
      }
      return { url: location.href, host: location.hostname, local, session };
    });
  } catch {
    return; // frame detached or storage blocked
  }
  if (!snapshot) return;

  for (const [storage, entries] of [
    ['localStorage', snapshot.local],
    ['sessionStorage', snapshot.session],
  ] as const) {
    for (const [key, value] of Object.entries(entries)) {
      if (recorder.storageKeys(storage, snapshot.url, key, value)) continue;
      recorder.addStorageSnapshot({
        storage,
        key,
        value,
        documentUrl: snapshot.url,
        documentHost: snapshot.host,
        party: classifier.partyOf(snapshot.host),
        purpose: classifier.classifyHost(snapshot.host).purpose,
      });
    }
  }
}

/**
 * `pagehide` only fires on a real navigation or close, and the browser does not
 * reliably surface unload beacons to Playwright. Navigating to `about:blank`
 * forces the browser to flush them into the proxy.
 *
 * `about:blank` is deliberately chosen over a same-origin sink URL: a sink on
 * the scanned site would return a 404 page which may itself load trackers,
 * polluting the very evidence we are trying to collect. The caller brackets
 * this call with `markUnloadStart`/`markUnloadEnd` so only traffic in that
 * window is labelled as unload traffic.
 */
async function flushUnloadBeacons(page: Page): Promise<void> {
  try {
    await page.goto('about:blank', { waitUntil: 'commit', timeout: 2500 }).catch(() => {});
    // Beacons are queued on a background thread and can land shortly after the
    // new document commits.
    await sleep(700);
  } catch {
    /* page may already be closed */
  }
}

function mapCdpType(type: string | undefined): string | null {
  switch (type) {
    case 'Fetch':
      return 'fetch';
    case 'XHR':
      return 'xhr';
    case 'Ping':
      return 'beacon';
    case 'WebSocket':
      return 'websocket';
    case 'Image':
      return 'image';
    case 'Script':
      return 'script';
    case 'Document':
      return 'document';
    case 'Media':
      return 'media';
    case 'Font':
      return 'font';
    case 'Stylesheet':
      return 'stylesheet';
    default:
      return type ? String(type).toLowerCase() : null;
  }
}

async function detectPlaywrightVersion(): Promise<string> {
  try {
    const { createRequire } = await import('node:module');
    const require = createRequire(import.meta.url);
    const path = require.resolve('playwright/package.json');
    const pkg = JSON.parse(fs.readFileSync(path, 'utf8')) as { version?: string };
    return pkg.version ?? 'unknown';
  } catch {
    return 'unknown';
  }
}

