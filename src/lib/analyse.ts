/**
 * Compliance analysis.
 *
 * The analyser never observes the browser. It takes the three phase recordings
 * and answers one question per finding: *was a tracking mechanism active in a
 * phase where consent had not been given?*
 *
 * Deliberate design choices:
 *  - A finding is only raised for a *tracking* purpose. Unknown third-party
 *    hosts are reported separately so the report does not cry wolf.
 *  - First-party requests are only findings when the cookie/identifier they
 *    carry is a known tracker (server-side tagging at `collect.example.com` is
 *    still Google Analytics).
 *  - "Rejected but still tracking" is compared against the pre-consent phase,
 *    not against zero: a tracker that fires identically before and after reject
 *    is a stronger finding than one that merely continues to load.
 */
import type {
  EvidenceItem,
  Finding,
  FindingSeverity,
  NetworkEvent,
  PhaseId,
  PhaseResult,
  ScanResult,
  ScanSummary,
  Party,
  Purpose,
  VendorSummary,
} from '../types.js';
import { TRACKING_PURPOSES } from '../types.js';
import type { ScanConfig } from '../config.js';
import type { Classifier } from './classify.js';
import { parseCookieHeader, redactValue } from './cookies.js';

/** Scanner-generated traffic that must never be reported as site behaviour. */
const SCANNER_URL_MARKERS = ['/__pcs-unload-sink', '/__pcs-'];

export interface AnalyseInput {
  config: ScanConfig;
  phases: PhaseResult[];
  siteHost: string;
  siteDomain: string;
  classifier: Classifier;
  scanner: { name: string; version: string; playwright: string };
  startedAt: string;
  finishedAt: string;
  coverageNotes: string[];
}

export function analyse(input: AnalyseInput): ScanResult {
  const findings: Finding[] = [];
  const phaseOf = (id: PhaseId): PhaseResult | undefined => input.phases.find((p) => p.phase === id);
  const pre = phaseOf('pre-consent');
  const reject = phaseOf('post-reject');
  const consent = phaseOf('post-consent');

  if (!pre) {
    throw new Error('a pre-consent phase is required to analyse consent compliance');
  }

  findings.push(...analyseConsentGating(input, pre));
  if (reject) findings.push(...analyseRejection(input, pre, reject));
  findings.push(...analyseConsentMechanism(pre, reject));
  if (input.config.simulateGpc) findings.push(...analyseGpc(pre));

  const vendors = summarizeVendors(pre, reject, consent);
  const summary = summarize(input, findings, pre, reject, consent, vendors);

  return {
    schemaVersion: 1,
    target: input.config.url,
    siteHost: input.siteHost,
    siteDomain: input.siteDomain,
    startedAt: input.startedAt,
    finishedAt: input.finishedAt,
    scanner: input.scanner,
    config: redactConfig(input.config),
    phases: input.phases,
    findings: orderFindings(findings),
    vendors,
    summary,
  };
}

// --------------------------------------------------------------- pre consent

/**
 * Checks the pre-consent phase. Comparing against the accepted phase is
 * deliberately not done here: acceptance is expected to enable tracking, so a
 * difference proves nothing. The accepted phase exists to confirm the scanner
 * *can* see this vendor, which keeps a PASS from hiding a broken pipeline.
 */
function analyseConsentGating(input: AnalyseInput, pre: PhaseResult): Finding[] {
  const findings: Finding[] = [];
  const { classifier } = input;

  const preRequests = pre.requests.filter((r) => !isScannerTraffic(r.url));
  const trackingRequests = preRequests.filter((r) => {
    if (r.purpose === 'consent-management') return false;
    if (!TRACKING_PURPOSES.has(r.purpose)) return false;
    // A first-party request to a first-party host is only tracking when the
    // request itself carries a known tracker cookie.
    if (r.party === 'first' && !hasTrackingCookie(r, classifier)) return false;
    return true;
  });

  // Unload traffic is grouped separately from page-load traffic: a tracker
  // that loads legitimately after consent but beacons on teardown is a
  // different defect from one that fires while the page is live, and merging
  // them would hide the teardown escape.
  for (const group of groupBy(
    trackingRequests,
    (r) => `${r.host}\u0000${r.purpose}\u0000${r.onUnload ? 'unload' : 'live'}`,
  )) {
    const first = group[0]!;
    const isThird = first.party === 'third';
    const onUnload = first.onUnload;
    findings.push({
      id: `pre-request-${first.host}-${first.purpose}${onUnload ? '-unload' : ''}`,
      code: onUnload ? 'TRACKING_ON_UNLOAD_BEFORE_CONSENT' : 'TRACKING_REQUEST_BEFORE_CONSENT',
      severity: isThird ? 'critical' : 'high',
      title: onUnload
        ? `Tracking beacon to ${first.host} sent while leaving the page, before consent`
        : `Tracking request to ${first.host} before any consent`,
      detail: onUnload
        ? `${group.length} request(s) to ${first.host} were observed while the page was being left, with no consent recorded. Unload beacons often escape consent checks because the CMP blocks scripts on load but not on teardown.`
        : `${group.length} request(s) to ${first.host} (${first.purpose}) were observed during the pre-consent phase, before any consent control was touched. First request at ${first.atMs} ms.`,
      impact:
        'Sending personal data to a tracking endpoint before consent is a direct breach of the consent-first requirement in GDPR/ePrivacy and the site\'s own cookie policy. It cannot be cured by the banner alone.',
      domain: first.host,
      purpose: first.purpose,
      phase: 'pre-consent',
      count: group.length,
      firstAtMs: first.atMs,
      evidence: {
        summary: `${group.length} request(s) to ${first.host} before consent`,
        items: group.slice(0, 4).map((request): EvidenceItem => ({ kind: 'request', request })),
      },
      recommendation: `Gate ${first.host} behind the consent state: do not load its script, and do not fire the endpoint, until consent for "${first.purpose}" is recorded. For unload beacons, check the consent state again inside the pagehide handler rather than relying on load-time gating.`,
    });
  }

  // Cookies set before consent.
  const trackingCookies = pre.cookiesSet.filter(
    (c) => c.known?.tracking || TRACKING_PURPOSES.has(c.purpose),
  );
  for (const group of groupBy(trackingCookies, (c) => `${c.domain}\u0000${c.purpose}`)) {
    const first = group[0]!;
    findings.push({
      id: `pre-cookie-${first.domain}-${first.purpose}`,
      code: 'TRACKING_COOKIE_BEFORE_CONSENT',
      severity: 'critical',
      title: `Tracking cookie "${first.name}" set before consent`,
      detail: `${group.length} tracking cookie(s) were set on ${first.domain} during the pre-consent phase: ${group
        .slice(0, 6)
        .map((c) => c.name)
        .join(', ')}${group.length > 6 ? ', …' : ''}. ${
        first.setByUrl
          ? `Set by ${first.setByUrl}.`
          : 'Present in the browser jar without being observed being set during the scan.'
      }`,
      impact:
        'A tracking cookie placed before consent is the clearest evidence of non-compliant cookie use: it establishes an identifier on the device without a lawful basis.',
      domain: first.domain,
      purpose: first.purpose,
      phase: 'pre-consent',
      count: group.length,
      firstAtMs: first.atMs,
      evidence: {
        summary: `${group.length} tracking cookie(s) on ${first.domain}`,
        items: group.slice(0, 6).map((cookie): EvidenceItem => ({ kind: 'cookie', cookie })),
      },
      recommendation: `Suppress the Set-Cookie for ${group
        .map((c) => c.name)
        .join(', ')} until consent is recorded. If it is set server-side, the server must receive and honour the consent signal.`,
    });
  }

  // Storage writes before consent.
  const trackingStorage = pre.storage.filter((w) => {
    if (!TRACKING_PURPOSES.has(w.purpose)) return false;
    if (w.party === 'first' && !looksLikeIdentifierKey(w.key)) {
      // A first-party key classified only by the host's purpose needs the key
      // itself to look like an identifier before it is called tracking.
      return false;
    }
    return true;
  });
  for (const group of groupBy(trackingStorage, (w) => `${w.documentHost}\u0000${w.key}`)) {
    const first = group[0]!;
    findings.push({
      id: `pre-storage-${first.documentHost}-${first.key}`,
      code: 'TRACKING_STORAGE_BEFORE_CONSENT',
      severity: 'critical',
      title: `Tracking identifier written to ${first.storage} before consent ("${first.key}")`,
      detail: `${group.length} write(s) to ${first.storage} on ${first.documentHost} with key "${first.key}", value ${redactValue(
        first.valuePreview,
      )}. The write originated from ${first.origin}.`,
      impact:
        'localStorage and sessionStorage are not covered by cookie banners in most implementations, so identifier writes there frequently bypass the CMP entirely. They are in scope for the same consent requirement.',
      domain: first.documentHost,
      purpose: first.purpose,
      phase: 'pre-consent',
      count: group.length,
      firstAtMs: first.atMs,
      evidence: {
        summary: `${group.length} write(s) of "${first.key}"`,
        items: group.slice(0, 4).map((write): EvidenceItem => ({ kind: 'storage', write })),
      },
      recommendation:
        'Move the identifier write behind the same consent gate as cookies, and clear it when consent is withdrawn.',
    });
  }

  // Identifiers transmitted in request headers (cookie header) before consent,
  // even if the endpoint itself is not a known tracker host.
  const identifierRequests = preRequests.filter((r) => {
    if (!r.cookieHeader) return false;
    if (r.purpose === 'consent-management' || r.purpose === 'security') return false;
    const cookies = parseCookieHeader(r.cookieHeader);
    const tracked = cookies.filter(({ name }) => {
      const info = classifier.classifyCookieWithHost(name, r.host);
      return info.tracking;
    });
    return tracked.length > 0 && r.party === 'third';
  });
  if (identifierRequests.length > 0) {
    const byDomain = groupBy(identifierRequests, (r) => r.host);
    for (const group of byDomain) {
      const first = group[0]!;
      const names = new Set<string>();
      for (const r of group) for (const c of parseCookieHeader(r.cookieHeader)) names.add(c.name);
      findings.push({
        id: `pre-identifier-${first.host}`,
        code: 'IDENTIFIER_SENT_BEFORE_CONSENT',
        severity: 'critical',
        title: `Tracking cookie sent to ${first.host} before consent`,
        detail: `${group.length} request(s) carried tracking cookie(s) ${[...names].join(', ')} in the Cookie header to ${first.host} before consent.`,
        impact:
          'Transmitting an existing identifier is a data transfer in its own right, even when no new cookie is set. It is often missed because the endpoint returns 204 and nothing appears in the UI.',
        domain: first.host,
        purpose: first.purpose,
        phase: 'pre-consent',
        count: group.length,
        firstAtMs: first.atMs,
        evidence: {
          summary: `${group.length} request(s) carrying ${[...names].join(', ')}`,
          items: group.slice(0, 4).map((request): EvidenceItem => ({ kind: 'request', request })),
        },
        recommendation:
          'Do not send requests to tracking domains until consent exists; a request that carries an identifier is a transfer, not a neutral load.',
      });
    }
  }

  // Informational: third-party requests that are not classified as tracking.
  const unknownThirdParty = preRequests.filter(
    (r) =>
      r.party === 'third' &&
      r.purpose === 'unknown' &&
      !hasTrackingCookie(r, classifier),
  );
  if (unknownThirdParty.length > 0) {
    const byDomain = groupBy(unknownThirdParty, (r) => r.siteDomain);
    const top = [...byDomain].sort((a, b) => b.length - a.length).slice(0, 8);
    findings.push({
      id: 'pre-unclassified-third-party',
      code: 'NON_TRACKING_THIRD_PARTY_BEFORE_CONSENT',
      severity: 'info',
      title: `${top.length} third-party domain(s) not classified as tracking fired before consent`,
      detail: top
        .map((group) => `${group[0]!.siteDomain} (${group.length} request(s))`)
        .join(', '),
      impact:
        'These were not matched to a known tracker and were not reported as violations. Review the list: an unlisted analytics or ad SDK would be a missed finding, so add it to config.domains.',
      domain: null,
      purpose: 'unknown',
      phase: 'pre-consent',
      count: unknownThirdParty.length,
      firstAtMs: Math.min(...unknownThirdParty.map((r) => r.atMs)),
      evidence: {
        summary: 'Unclassified third-party requests',
        items: top.slice(0, 3).map((group) => ({
          kind: 'request' as const,
          request: group[0]!,
        })),
      },
      recommendation:
        'Either confirm each host is non-tracking (CDN, fonts, support widget) or add it to the vendor table with its purpose so future scans classify it correctly.',
    });
  }

  // First-party relay: the site's own host receives an identifier-bearing
  // payload. Host-based classification sees only a same-site request, which is
  // exactly why this pattern survives most manual reviews.
  for (const relay of pre.firstPartyRelays) {
    if (!looksLikeRelayPayload(`${relay.request.path} ${relay.request.requestBody ?? ''}`)) continue;
    findings.push({
      id: `pre-relay-${relay.host}`,
      code: 'IDENTIFIER_SENT_BEFORE_CONSENT',
      severity: 'high',
      title: `Identifier sent to a first-party endpoint before consent (${relay.host})`,
      detail: `The page sent an identifier-bearing payload to its own origin before any consent: ${relay.request.method} ${relay.request.url}. Because the host matches the site, this traffic looks like ordinary first-party behaviour in most scans; it is reported here because the payload carries an identifier.`,
      impact:
        'Server-side relaying moves the transfer out of the banner\'s view: the tracker sees the identifier through the site\'s own domain, so third-party blocking and host-based consent rules do not stop it.',
      domain: relay.host,
      purpose: 'analytics',
      phase: 'pre-consent',
      count: 1,
      firstAtMs: relay.request.atMs,
      evidence: {
        summary: 'First-party relay request',
        items: [{ kind: 'request', request: relay.request }],
      },
      recommendation:
        'Treat first-party collection endpoints as tracking endpoints: they must not receive identifiers until consent is recorded, and the server must enforce that rather than trusting the client.',
    });
  }

  return findings;
}

/** Does a first-party request carry an identifier in its query or body? */
function looksLikeRelayPayload(text: string): boolean {
  return /(uid|user_?id|visitor|client_?id|device_?id|distinct_?id|email|ga_?id)=?[^&\s]*[0-9a-z]/i.test(text);
}

// -------------------------------------------------------------------- reject

function analyseRejection(
  input: AnalyseInput,
  pre: PhaseResult,
  reject: PhaseResult,
): Finding[] {
  const findings: Finding[] = [];
  const { classifier } = input;

  const attempt = reject.consent;
  if (attempt && !attempt.found) {
    // Cannot evaluate enforcement without having expressed a choice.
    return findings;
  }

  const rejectRequests = reject.requests.filter((r) => !isScannerTraffic(r.url));
  const preUrls = new Set(pre.requests.filter((r) => !isScannerTraffic(r.url)).map((r) => urlKey(r)));

  const trackingAfterReject = rejectRequests.filter((r) => {
    if (!TRACKING_PURPOSES.has(r.purpose)) return false;
    if (r.purpose === 'consent-management') return false;
    if (r.party === 'first' && !hasTrackingCookie(r, classifier)) return false;
    return true;
  });

  for (const group of groupBy(
    trackingAfterReject,
    (r) => `${r.host}\u0000${r.purpose}\u0000${r.onUnload ? 'unload' : 'live'}`,
  )) {
    const first = group[0]!;
    // Distinguish "kept firing after reject" from "fired even before consent":
    // the latter is already a pre-consent finding and this one compounds it.
    const firedBeforeConsent = group.some((r) => preUrls.has(urlKey(r)));
    findings.push({
      id: `reject-request-${first.host}-${first.purpose}${first.onUnload ? '-unload' : ''}`,
      code: 'TRACKING_AFTER_REJECT',
      severity: 'critical',
      title: first.onUnload
        ? `Tracking beacon to ${first.host} sent while leaving the page, after consent was rejected`
        : `Tracking request to ${first.host} continued after the user rejected consent`,
      detail: `${group.length} request(s) to ${first.host} during the post-reject phase${
        first.atMs !== null ? ` (first at ${first.atMs} ms)` : ''
      }. The reject control was clicked${
        reject.consent?.clicked ? ` (${reject.consent.clicked})` : ''
      } and the page was reloaded.${firedBeforeConsent ? ' The same endpoints also fired before any consent was given.' : ''}`,
      impact:
        'Rejecting must be as easy and as effective as accepting. Traffic that continues after a rejection means the choice was not wired to the tracking code, which is the most common finding in DPA complaints.',
      domain: first.host,
      purpose: first.purpose,
      phase: 'post-reject',
      count: group.length,
      firstAtMs: first.atMs,
      evidence: {
        summary: `${group.length} request(s) after reject`,
        items: group.slice(0, 4).map((request): EvidenceItem => ({ kind: 'request', request })),
      },
      recommendation:
        'Route the reject decision into the same consent state the trackers read. Where a vendor cannot run without consent, do not initialise it at all when consent is refused.',
    });
  }

  const trackingCookiesAfterReject = reject.cookiesSet.filter(
    (c) => (c.known?.tracking || TRACKING_PURPOSES.has(c.purpose)) && c.setInPhase === 'post-reject',
  );
  for (const group of groupBy(trackingCookiesAfterReject, (c) => `${c.domain}\u0000${c.purpose}`)) {
    const first = group[0]!;
    findings.push({
      id: `reject-cookie-${first.domain}-${first.purpose}`,
      code: 'TRACKING_COOKIE_AFTER_REJECT',
      severity: 'critical',
      title: `Tracking cookie "${first.name}" set after the user rejected consent`,
      detail: `${group.length} tracking cookie(s) were set on ${first.domain} after rejection: ${group
        .slice(0, 6)
        .map((c) => c.name)
        .join(', ')}.`,
      impact:
        'Setting a tracking cookie after an explicit refusal defeats the consent decision and is likely to be treated as a serious infringement.',
      domain: first.domain,
      purpose: first.purpose,
      phase: 'post-reject',
      count: group.length,
      firstAtMs: first.atMs,
      evidence: {
        summary: `${group.length} cookie(s) set after reject`,
        items: group.slice(0, 6).map((cookie): EvidenceItem => ({ kind: 'cookie', cookie })),
      },
      recommendation:
        'Delete tracking cookies on rejection and prevent their re-creation on subsequent page loads.',
    });
  }

  // A tracking cookie that survives in the jar after rejection even if no new
  // Set-Cookie was observed (e.g. it was written by a worker or restored).
  const surviving = reject.cookieJar.filter(
    (c) => (c.known?.tracking || TRACKING_PURPOSES.has(c.purpose)) && c.origin === 'jar-snapshot',
  );
  if (surviving.length > 0) {
    findings.push({
      id: 'reject-cookie-survived',
      code: 'TRACKING_COOKIE_AFTER_REJECT',
      severity: 'high',
      title: `${surviving.length} tracking cookie(s) remained in the jar after rejection`,
      detail: `After clicking reject and reloading, these tracking cookies were still present: ${surviving
        .map((c) => `${c.name}@${c.domain}`)
        .join(', ')}.`,
      impact:
        'Rejection should clear identifiers that were placed without consent. A surviving jar entry means the identifier can still be read and transmitted on the next request.',
      domain: surviving[0]!.domain,
      purpose: surviving[0]!.purpose,
      phase: 'post-reject',
      count: surviving.length,
      firstAtMs: null,
      evidence: {
        summary: 'Tracking cookies surviving rejection',
        items: surviving.slice(0, 6).map((cookie): EvidenceItem => ({ kind: 'cookie', cookie })),
      },
      recommendation: 'Clear tracking cookies (client-side and server-side) when consent is withdrawn.',
    });
  }

  return findings;
}

// ---------------------------------------------------------------- mechanism

function analyseConsentMechanism(pre: PhaseResult, reject: PhaseResult | undefined): Finding[] {
  const findings: Finding[] = [];
  const ui = pre.consentUi ?? null;

  if (ui && ui.hasBanner && !ui.hasReject) {
    findings.push({
      id: 'consent-no-reject',
      code: 'CONSENT_MECHANISM_DEFECT',
      severity: 'high',
      title: 'Consent banner offers no observable reject option',
      detail:
        'A consent interface was detected on load, but no visible control matching a rejection ("Reject all", "Only necessary", …) was found in any frame. Accept controls were found.',
      impact:
        'Where consent is the legal basis, refusing must be offered in the same layer as accepting. A banner with only "Accept" is not freely given consent.',
      domain: null,
      purpose: 'consent-management',
      phase: 'pre-consent',
      count: 1,
      firstAtMs: 0,
      evidence: {
        summary: 'Consent UI inspection',
        items: [
          {
            kind: 'text',
            label: 'Detected controls',
            text: `accept controls: yes\nreject controls: no\nreject candidates: ${
              ui.rejectCandidates.length ? ui.rejectCandidates.join('\n') : '(none)'
            }`,
          },
          ...pre.screenshots.slice(0, 2).map(
            (s): EvidenceItem => ({ kind: 'screenshot', file: s.file, label: s.label, phase: 'pre-consent' }),
          ),
        ],
      },
      recommendation:
        'Add a first-layer "Reject all" control with the same visual weight as accept, and make sure its text is a literal reject phrase so both users and scanners can find it.',
    });
  }

  if (!ui || !ui.hasBanner) {
    // No banner at all: fine if nothing tracks, a problem if it does.
    const tracks = pre.requests.some(
      (r) => TRACKING_PURPOSES.has(r.purpose) && r.party === 'third' && !isScannerTraffic(r.url),
    );
    if (tracks) {
      findings.push({
        id: 'consent-ui-missing',
        code: 'CONSENT_UI_NOT_FOUND',
        severity: 'high',
        title: 'Tracking observed but no consent interface was detected',
        detail:
          'The pre-consent phase recorded third-party tracking traffic, but no recognisable consent banner was found in any frame. The site may record consent on a previous page, use a CMP whose markup is unrecognised, or have no banner at all.',
        impact:
          'If the site genuinely has no consent interface while loading trackers, there is no lawful basis. If it does have one, the scan configuration needs the CMP selectors so the reject phase can be evaluated.',
        domain: null,
        purpose: 'consent-management',
        phase: 'pre-consent',
        count: 1,
        firstAtMs: 0,
        evidence: {
          summary: 'No consent UI detected',
          items: pre.screenshots.slice(0, 2).map(
            (s): EvidenceItem => ({ kind: 'screenshot', file: s.file, label: s.label, phase: 'pre-consent' }),
          ),
        },
        recommendation:
          'Confirm whether a CMP is deployed. If it is, add its selectors under consent.accept/consent.reject in the scan config so reject enforcement can be tested.',
      });
    }
  }

  if (reject && reject.consent && !reject.consent.found) {
    findings.push({
      id: 'reject-not-found',
      code: 'CONSENT_MECHANISM_DEFECT',
      severity: 'medium',
      title: 'Reject control could not be located for the post-reject phase',
      detail: reject.consent.note ?? 'No reject control was found.',
      impact:
        'The scanner could not express a rejection, so it cannot verify whether rejection is enforced. This is inconclusive rather than compliant.',
      domain: null,
      purpose: 'consent-management',
      phase: 'post-reject',
      count: 1,
      firstAtMs: null,
      evidence: {
        summary: 'Reject attempt',
        items: [
          {
            kind: 'text',
            label: 'Candidates considered',
            text: reject.consent.candidates.length
              ? reject.consent.candidates.join('\n')
              : '(no candidate controls found)',
          },
        ],
      },
      recommendation:
        'Add the reject control selector to consent.reject.selectors so the phase can be evaluated, or fix the banner to expose a reject option.',
    });
  }

  return findings;
}

// ----------------------------------------------------------------------- GPC

/**
 * When the visitor sends Global Privacy Control / Do Not Track, tracking that
 * still fires is a distinct obligation from consent: the signal must be honoured
 * regardless of a banner. The finding is separate so it is not mistaken for a
 * banner problem.
 */
function analyseGpc(pre: PhaseResult): Finding[] {
  const findings: Finding[] = [];
  const tracking = pre.requests.filter(
    (r) => !isScannerTraffic(r.url) && TRACKING_PURPOSES.has(r.purpose) && r.purpose !== 'consent-management',
  );
  if (tracking.length === 0) return findings;

  const hosts = [...new Set(tracking.map((r) => r.host))];
  findings.push({
    id: 'gpc-ignored',
    code: 'GPC_SIGNAL_IGNORED',
    severity: 'high',
    title: 'Global Privacy Control signal was not honoured',
    detail: `The browser advertised Global Privacy Control and Do Not Track, yet ${tracking.length} tracking request(s) were sent to ${hosts
      .slice(0, 6)
      .join(', ')}${hosts.length > 6 ? ', …' : ''} before any consent interaction.`,
    impact:
      'A GPC/opt-out preference signal is a legally binding opt-out in several US states (CCPA/CPRA) and is treated as a withdrawal of consent under GDPR in many interpretations. It must be honoured independently of a cookie banner.',
    domain: hosts[0] ?? null,
    purpose: 'unknown',
    phase: 'pre-consent',
    count: tracking.length,
    firstAtMs: Math.min(...tracking.map((r) => r.atMs)),
    evidence: {
      summary: `${tracking.length} tracking request(s) despite GPC`,
      items: tracking.slice(0, 4).map((request): EvidenceItem => ({ kind: 'request', request })),
    },
    recommendation:
      'Read navigator.globalPrivacyControl (and the Sec-GPC request header) before initialising any tracker, and treat a true value as an explicit refusal.',
  });
  return findings;
}

// ------------------------------------------------------------------- vendors

/**
 * Vendor matrix, one row per *tracking-relevant* host.
 *
 * Grouping is by host, not by registrable domain: `analytics.vendor.test` and
 * `pixel.vendor.test` are separate vendors with separate purposes, and merging
 * them into `vendor.test` loses exactly the information a reviewer needs.
 *
 * Non-tracking hosts are counted in the request summary but not listed here; a
 * matrix of CDNs and font hosts would bury the three rows that matter.
 */
function summarizeVendors(
  pre: PhaseResult,
  reject: PhaseResult | undefined,
  consent: PhaseResult | undefined,
): VendorSummary[] {
  const domains = new Map<string, VendorSummary>();

  const ensure = (host: string, purpose: Purpose, party: Party, tracking: boolean): VendorSummary => {
    let entry = domains.get(host);
    if (!entry) {
      entry = {
        domain: host,
        purpose,
        party,
        preConsentRequests: 0,
        postRejectRequests: 0,
        postConsentRequests: 0,
        cookiesSetPreConsent: 0,
        cookiesSetPostReject: 0,
        cookiesSetPostConsent: 0,
        tracking,
        verdict: 'unknown',
      };
      domains.set(host, entry);
    } else if (TRACKING_PURPOSES.has(purpose)) {
      // A host is tracking if any of its observed traffic is tracking traffic.
      entry.tracking = true;
      entry.purpose = purpose;
    }
    return entry;
  };

  const tallyRequests = (phase: PhaseResult | undefined, field: 'preConsentRequests' | 'postRejectRequests' | 'postConsentRequests'): void => {
    for (const request of phase?.requests ?? []) {
      if (isScannerTraffic(request.url)) continue;
      const tracking = TRACKING_PURPOSES.has(request.purpose);
      if (!tracking) continue;
      ensure(request.host, request.purpose, request.party, true)[field] += 1;
    }
  };
  tallyRequests(pre, 'preConsentRequests');
  tallyRequests(reject, 'postRejectRequests');
  tallyRequests(consent, 'postConsentRequests');

  const tallyCookies = (
    phase: PhaseResult | undefined,
    field: 'cookiesSetPreConsent' | 'cookiesSetPostReject' | 'cookiesSetPostConsent',
  ): void => {
    for (const cookie of phase?.cookiesSet ?? []) {
      const tracking = !!cookie.known?.tracking || TRACKING_PURPOSES.has(cookie.purpose);
      if (!tracking) continue;
      // A cookie is attributed to the host that set it when known, otherwise to
      // its own domain (e.g. a cookie written from JavaScript on a third-party
      // frame's document).
      const host = hostForCookie(cookie);
      ensure(host, cookie.purpose, cookie.party, true)[field] += 1;
    }
  };

  tallyCookies(pre, 'cookiesSetPreConsent');
  tallyCookies(reject, 'cookiesSetPostReject');
  tallyCookies(consent, 'cookiesSetPostConsent');

  for (const entry of domains.values()) {
    if (entry.preConsentRequests > 0) entry.verdict = 'fires-before-consent';
    else if (entry.postRejectRequests > 0) entry.verdict = 'fires-after-reject';
    else entry.verdict = 'blocked-until-consent';
  }

  return [...domains.values()].sort((a, b) => {
    const rank = (v: VendorSummary) =>
      v.verdict === 'fires-before-consent' ? 0 : v.verdict === 'fires-after-reject' ? 1 : 2;
    if (rank(a) !== rank(b)) return rank(a) - rank(b);
    return b.preConsentRequests - a.preConsentRequests;
  });
}

/**
 * The host a cookie belongs to for the vendor matrix: the endpoint that set it
 * when that is known, otherwise its own domain. The hostname is used without
 * the port so a scan of a staging port does not create a phantom vendor row.
 */
function hostForCookie(cookie: { setByUrl: string | null; domain: string }): string {
  if (cookie.setByUrl) {
    try {
      return new URL(cookie.setByUrl).hostname;
    } catch {
      /* fall through */
    }
  }
  return cookie.domain.replace(/^\./, '');
}

// ------------------------------------------------------------------- summary

/**
 * Collapse the per-phase warnings into one note per distinct message. The same
 * warning repeated for three phases reads as three problems and pushes the
 * findings below the fold.
 */
function compactNotes(notes: string[]): string[] {
  const byMessage = new Map<string, string[]>();
  for (const note of notes) {
    const match = /^\[([^\]]+)\]\s*(.*)$/.exec(note);
    const phase = match ? match[1]! : '';
    const message = match ? match[2]! : note;
    const phases = byMessage.get(message) ?? [];
    if (phase && !phases.includes(phase)) phases.push(phase);
    byMessage.set(message, phases);
  }
  const out: string[] = [];
  for (const [message, phases] of byMessage) {
    out.push(phases.length > 0 ? `${message} (${phases.join(', ')})` : message);
  }
  return out;
}

function summarize(
  input: AnalyseInput,
  findings: Finding[],
  pre: PhaseResult,
  reject: PhaseResult | undefined,
  consent: PhaseResult | undefined,
  vendors: VendorSummary[],
): ScanSummary {
  const count = (severity: FindingSeverity): number => findings.filter((f) => f.severity === severity).length;
  const trackingDomains = vendors.filter((v) => v.tracking).length;

  const phaseStats = (phase: PhaseResult | undefined) => {
    const requests = (phase?.requests ?? []).filter((r) => !isScannerTraffic(r.url));
    const thirdParty = requests.filter((r) => r.party === 'third');
    const tracking = requests.filter((r) => TRACKING_PURPOSES.has(r.purpose));
    return {
      phase: phase?.phase ?? ('pre-consent' as PhaseId),
      total: requests.length,
      thirdParty: thirdParty.length,
      tracking: tracking.length,
    };
  };

  const coveragePhases = input.phases.map((p) => p.phase);
  const consentUiFound = Boolean(pre.consentUi?.hasBanner);
  const notes: string[] = compactNotes(input.coverageNotes);

  if (!input.phases.some((p) => p.phase === 'post-consent')) {
    notes.push('post-consent phase did not run: cannot confirm trackers load after acceptance.');
  }
  if (reject && reject.consent && !reject.consent.found) {
    notes.push('reject control was not found: rejection enforcement is unverified, not compliant.');
  }

  const critical = count('critical');
  const high = count('high');
  const blocking = critical + high;

  // Only critical/high findings constitute a failure. Medium findings (e.g. a
  // missing reject control we could not click) make the scan inconclusive for
  // rejection enforcement, which is reported explicitly rather than as a
  // compliance failure.
  const verdict: ScanSummary['verdict'] = blocking > 0 ? 'FAIL' : 'PASS';

  return {
    verdict: coveragePhases.length < (input.config.phases ?? []).length ? 'INCONCLUSIVE' : verdict,
    critical,
    high,
    medium: count('medium'),
    low: count('low'),
    info: count('info'),
    trackingDomains,
    requests: [phaseStats(pre), phaseStats(reject), phaseStats(consent)],
    coverage: {
      proxy: true,
      consentUiFound,
      phases: coveragePhases,
      notes,
    },
  };
}

// ------------------------------------------------------------------- helpers

function hasTrackingCookie(request: NetworkEvent, classifier: Classifier): boolean {
  if (!request.cookieHeader) return false;
  return parseCookieHeader(request.cookieHeader).some(({ name }) => {
    const info = classifier.classifyCookieWithHost(name, request.host);
    return info.tracking;
  });
}

function looksLikeIdentifierKey(key: string): boolean {
  return /(^|_)(uid|uuid|user_?id|visitor_?id|client_?id|device_?id|distinct_?id|anonymous_?id|sid|session_?id)($|_)/i.test(
    key,
  ) || /^_?(ga|fb|hj|cl|uet|ttp)/i.test(key);
}

function isScannerTraffic(url: string): boolean {
  return SCANNER_URL_MARKERS.some((marker) => url.includes(marker));
}

function urlKey(request: NetworkEvent): string {
  return `${request.method} ${request.scheme}://${request.host}${request.path}`;
}

function groupBy<T>(items: T[], key: (item: T) => string): T[][] {
  const map = new Map<string, T[]>();
  for (const item of items) {
    const k = key(item);
    const list = map.get(k);
    if (list) list.push(item);
    else map.set(k, [item]);
  }
  return [...map.values()];
}

const SEVERITY_RANK: Record<FindingSeverity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

function orderFindings(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => {
    if (SEVERITY_RANK[a.severity] !== SEVERITY_RANK[b.severity]) {
      return SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity];
    }
    return b.count - a.count;
  });
}

/** Remove secrets from the config before it is embedded in the report. */
function redactConfig(config: ScanConfig): ScanConfig {
  return { ...config };
}

export const __testing = { looksLikeIdentifierKey, isScannerTraffic, urlKey, groupBy, compactNotes, hostForCookie };
