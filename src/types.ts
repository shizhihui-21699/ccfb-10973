/**
 * Core domain model for the pre-consent privacy scanner.
 *
 * Everything the scanner observes is normalised into a small set of records
 * (NetworkEvent, CookieRecord, StorageWrite) tagged with the *phase* in which
 * it happened. The analyser then compares phases to decide what was lawful.
 */

/** A phase of the consent lifecycle that is scanned in a fresh browser context. */
export type PhaseId = 'pre-consent' | 'post-reject' | 'post-consent';

export const PHASES: PhaseId[] = ['pre-consent', 'post-reject', 'post-consent'];

/** Data-processing purpose assigned to a domain / cookie / request. */
export type Purpose =
  | 'analytics'
  | 'advertising'
  | 'social'
  | 'session-replay'
  | 'tag-manager'
  | 'consent-management'
  | 'cdn'
  | 'functional'
  | 'security'
  | 'unknown';

/** Purposes that constitute "tracking" under a consent-first regime. */
export const TRACKING_PURPOSES: ReadonlySet<Purpose> = new Set<Purpose>([
  'analytics',
  'advertising',
  'social',
  'session-replay',
  'tag-manager',
]);

/** Host relation to the site under test. */
export type Party = 'first' | 'third';

/** Which capture channel produced a record. Used to state evidence confidence. */
export type CaptureChannel = 'proxy' | 'playwright' | 'instrumentation' | 'cdp';

export interface NetworkEvent {
  id: string;
  phase: PhaseId;
  /** Milliseconds since the phase's page load began. */
  atMs: number;
  startedAt: number;
  scheme: 'http' | 'https';
  host: string;
  /** Registrable domain (eTLD+1) of `host`. */
  siteDomain: string;
  party: Party;
  purpose: Purpose;
  method: string;
  /** Path + query string. */
  path: string;
  url: string;
  /** Request headers as observed on the wire by the proxy. */
  headers: Record<string, string>;
  /** Body sent by the page, if any (already truncated). */
  requestBody: string | null;
  requestBodyTruncated: boolean;
  /** `Cookie` header sent with this request, verbatim. */
  cookieHeader: string | null;
  referer: string | null;
  /** Response status when a response was observed. */
  status: number | null;
  /** `Set-Cookie` header values returned by this response. */
  setCookies: string[];
  /** Response body prefix, for evidence on collection endpoints. */
  responseBody: string | null;
  /** Attribution gathered from Playwright/CDP when the same request was seen there. */
  attribution: {
    frameUrl: string | null;
    initiatorUrl: string | null;
    resourceType: string | null;
    /** `fetch` | `xhr` | `beacon` | `image` | `script` | `iframe` | ... */
    trigger: string | null;
  };
  /** How many independent channels saw this request (>=1). */
  channels: CaptureChannel[];
  /**
   * True when this request was sent while the document was being torn down
   * (navigation away, reload, tab close). Determined by the scanner from the
   * moment it triggered the teardown, because browsers do not reliably report
   * `sendBeacon`/keepalive requests to their own event APIs.
   */
  onUnload: boolean;
  /** True when the request was still in flight when the phase was flushed. */
  aborted: boolean;
}

export interface CookieRecord {
  name: string;
  /** Value as written; may be redacted in reports. */
  value: string;
  /** `Domain=` attribute, if present. */
  domainAttr: string | null;
  /** Domain the cookie belongs to as reported by the browser. */
  domain: string;
  siteDomain: string;
  party: Party;
  purpose: Purpose;
  path: string | null;
  secure: boolean;
  httpOnly: boolean;
  sameSite: string | null;
  /** ISO timestamp or null for session cookies. */
  expires: string | null;
  session: boolean;
  /** True when this record came from a parsed `Set-Cookie` response header. */
  setInPhase: PhaseId | null;
  setByUrl: string | null;
  atMs: number | null;
  /** True when the cookie existed in the browser jar but was not seen being set
   *  during the scan (e.g. pre-existing or set inside a blocked path). */
  origin: 'observed-set' | 'jar-snapshot';
  /** Known tracking-cookie classification. */
  known: { vendor: string | null; purpose: Purpose | null; tracking: boolean } | null;
}

export interface StorageWrite {
  phase: PhaseId;
  atMs: number;
  storage: 'localStorage' | 'sessionStorage' | 'indexedDB';
  key: string;
  valuePreview: string;
  valueBytes: number;
  /** URL of the document performing the write (may be a cross-site iframe). */
  documentUrl: string;
  documentHost: string;
  party: Party;
  purpose: Purpose;
  origin: string;
}

export interface ConsentAttempt {
  phase: PhaseId;
  wanted: 'accept' | 'reject';
  found: boolean;
  /** Description of the control that was clicked, e.g. "button#accept-all". */
  clicked: string | null;
  inFrameUrl: string | null;
  candidates: string[];
  note: string | null;
}

export interface ConsentUiSnapshot {
  hasBanner: boolean;
  hasReject: boolean;
  hasAccept: boolean;
  rejectCandidates: string[];
}

export interface PhaseCheckpoint {
  label: string;
  atMs: number;
}

export interface PhaseResult {
  phase: PhaseId;
  startedAt: string;
  durationMs: number;
  requests: NetworkEvent[];
  cookiesSet: CookieRecord[];
  /** Cookie jar as observed at the end of the phase. */
  cookieJar: CookieRecord[];
  storage: StorageWrite[];
  consent: ConsentAttempt | null;
  screenshots: { atMs: number; label: string; file: string }[];
  /** Named moments inside the phase, e.g. the reload that follows a rejection. */
  checkpoints: PhaseCheckpoint[];
  /** The consent interface as observed in this phase, when inspected. */
  consentUi?: ConsentUiSnapshot | null;
  /**
   * First-party requests that carried an identifier-bearing payload. These are
   * server-side relays and would otherwise look like ordinary same-site traffic.
   */
  firstPartyRelays: { host: string; request: NetworkEvent }[];
  /** Human-readable problems with the phase run itself (not compliance). */
  warnings: string[];
}

export type FindingSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type FindingCode =
  | 'TRACKING_REQUEST_BEFORE_CONSENT'
  | 'TRACKING_COOKIE_BEFORE_CONSENT'
  | 'TRACKING_STORAGE_BEFORE_CONSENT'
  | 'IDENTIFIER_SENT_BEFORE_CONSENT'
  | 'TRACKING_ON_UNLOAD_BEFORE_CONSENT'
  | 'CONSENT_UI_NOT_FOUND'
  | 'REJECT_NOT_ENFORCED'
  | 'TRACKING_AFTER_REJECT'
  | 'TRACKING_COOKIE_AFTER_REJECT'
  | 'PRE_EXISTING_TRACKING_COOKIE'
  | 'CONSENT_MECHANISM_DEFECT'
  | 'GPC_SIGNAL_IGNORED'
  | 'NON_TRACKING_THIRD_PARTY_BEFORE_CONSENT';

export interface Evidence {
  summary: string;
  /** Raw artefacts, each rendered in the report. */
  items: EvidenceItem[];
}

export type EvidenceItem =
  | { kind: 'request'; request: NetworkEvent }
  | { kind: 'cookie'; cookie: CookieRecord }
  | { kind: 'storage'; write: StorageWrite }
  | { kind: 'screenshot'; file: string; label: string; phase: PhaseId }
  | { kind: 'text'; label: string; text: string };

export interface Finding {
  id: string;
  code: FindingCode;
  severity: FindingSeverity;
  title: string;
  /** What the scanner saw, in factual terms. */
  detail: string;
  /** Why it matters legally / operationally. */
  impact: string;
  domain: string | null;
  purpose: Purpose | null;
  phase: PhaseId;
  /** Times this pattern occurred. */
  count: number;
  firstAtMs: number | null;
  evidence: Evidence;
  recommendation: string;
}

export interface VendorSummary {
  domain: string;
  purpose: Purpose;
  party: Party;
  preConsentRequests: number;
  postRejectRequests: number;
  postConsentRequests: number;
  cookiesSetPreConsent: number;
  cookiesSetPostReject: number;
  cookiesSetPostConsent: number;
  tracking: boolean;
  verdict: 'blocked-until-consent' | 'fires-before-consent' | 'fires-after-reject' | 'unknown';
}

export interface ScanSummary {
  verdict: 'PASS' | 'FAIL' | 'INCONCLUSIVE';
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  trackingDomains: number;
  requests: { phase: PhaseId; total: number; thirdParty: number; tracking: number }[];
  coverage: { proxy: boolean; consentUiFound: boolean; phases: PhaseId[]; notes: string[] };
}

export interface ScanResult {
  schemaVersion: 1;
  target: string;
  siteHost: string;
  siteDomain: string;
  startedAt: string;
  finishedAt: string;
  scanner: { name: string; version: string; playwright: string };
  config: import('./config.js').ScanConfig;
  phases: PhaseResult[];
  findings: Finding[];
  vendors: VendorSummary[];
  summary: ScanSummary;
}
