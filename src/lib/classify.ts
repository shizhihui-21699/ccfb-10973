/**
 * Vendor / purpose classification.
 *
 * The goal is not a complete tracker list (an entire industry maintains those);
 * it is a transparent, auditable default that a legal team can override in
 * config. Two kinds of signal are used:
 *
 *  1. Host matching against a curated table of well-known trackers. Matching is
 *     on the registrable domain and its subdomains, so `region1.google-analytics.com`
 *     resolves to analytics.
 *  2. Cookie-name patterns for trackers that share a first-party host (server-side
 *     tagging) or whose host is unrecognised.
 *
 * Everything unmatched is `unknown` and is *not* reported as tracking: false
 * positives erode trust in the report faster than missed long-tail vendors do,
 * and `unknown` third-party requests are surfaced separately.
 */
import { getDomain } from 'tldts';
import type { DomainOverride, ScanConfig } from '../config.js';
import type { Party, Purpose } from '../types.js';

export interface VendorInfo {
  vendor: string | null;
  purpose: Purpose;
  tracking: boolean;
}

interface VendorRule {
  /** Registrable domain, e.g. "google-analytics.com". */
  domain: string;
  vendor: string;
  purpose: Purpose;
}

/**
 * Curated vendor table. Order does not matter: longest-suffix match wins, so a
 * specific entry such as `googleadservices.com` is not shadowed by `google.com`.
 */
const VENDOR_RULES: VendorRule[] = [
  // Analytics
  { domain: 'google-analytics.com', vendor: 'Google Analytics', purpose: 'analytics' },
  { domain: 'analytics.google.com', vendor: 'Google Analytics', purpose: 'analytics' },
  { domain: 'googletagmanager.com', vendor: 'Google Tag Manager', purpose: 'tag-manager' },
  { domain: 'segment.com', vendor: 'Segment', purpose: 'analytics' },
  { domain: 'segment.io', vendor: 'Segment', purpose: 'analytics' },
  { domain: 'mixpanel.com', vendor: 'Mixpanel', purpose: 'analytics' },
  { domain: 'amplitude.com', vendor: 'Amplitude', purpose: 'analytics' },
  { domain: 'heapanalytics.com', vendor: 'Heap', purpose: 'analytics' },
  { domain: 'hotjar.com', vendor: 'Hotjar', purpose: 'analytics' },
  { domain: 'hotjar.io', vendor: 'Hotjar', purpose: 'analytics' },
  { domain: 'clarity.ms', vendor: 'Microsoft Clarity', purpose: 'analytics' },
  { domain: 'matomo.cloud', vendor: 'Matomo', purpose: 'analytics' },
  { domain: 'plausible.io', vendor: 'Plausible', purpose: 'analytics' },
  { domain: 'statcounter.com', vendor: 'StatCounter', purpose: 'analytics' },
  { domain: 'newrelic.com', vendor: 'New Relic', purpose: 'analytics' },
  { domain: 'nr-data.net', vendor: 'New Relic', purpose: 'analytics' },
  { domain: 'sentry.io', vendor: 'Sentry', purpose: 'functional' },
  { domain: 'bugsnag.com', vendor: 'Bugsnag', purpose: 'functional' },

  // Advertising / ad tech
  { domain: 'doubleclick.net', vendor: 'Google DoubleClick', purpose: 'advertising' },
  { domain: 'googleadservices.com', vendor: 'Google Ads', purpose: 'advertising' },
  { domain: 'googlesyndication.com', vendor: 'Google AdSense', purpose: 'advertising' },
  { domain: 'google.com', vendor: 'Google Ads', purpose: 'advertising' },
  { domain: 'adnxs.com', vendor: 'Xandr / AppNexus', purpose: 'advertising' },
  { domain: 'rubiconproject.com', vendor: 'Magnite', purpose: 'advertising' },
  { domain: 'pubmatic.com', vendor: 'PubMatic', purpose: 'advertising' },
  { domain: 'casalemedia.com', vendor: 'Index Exchange', purpose: 'advertising' },
  { domain: 'openx.net', vendor: 'OpenX', purpose: 'advertising' },
  { domain: 'criteo.com', vendor: 'Criteo', purpose: 'advertising' },
  { domain: 'criteo.net', vendor: 'Criteo', purpose: 'advertising' },
  { domain: 'adsrvr.org', vendor: 'The Trade Desk', purpose: 'advertising' },
  { domain: 'taboola.com', vendor: 'Taboola', purpose: 'advertising' },
  { domain: 'outbrain.com', vendor: 'Outbrain', purpose: 'advertising' },
  { domain: 'amazon-adsystem.com', vendor: 'Amazon Ads', purpose: 'advertising' },
  { domain: 'smartadserver.com', vendor: 'Equativ', purpose: 'advertising' },
  { domain: 'adform.net', vendor: 'Adform', purpose: 'advertising' },
  { domain: 'tradedoubler.com', vendor: 'Tradedoubler', purpose: 'advertising' },
  { domain: 'bing.com', vendor: 'Microsoft Advertising', purpose: 'advertising' },
  { domain: 'bat.bing.com', vendor: 'Microsoft Advertising', purpose: 'advertising' },
  { domain: 'snap.licdn.com', vendor: 'LinkedIn Ads', purpose: 'advertising' },
  { domain: 'tiktok.com', vendor: 'TikTok Ads', purpose: 'advertising' },

  // Social
  { domain: 'facebook.net', vendor: 'Meta Pixel', purpose: 'social' },
  { domain: 'facebook.com', vendor: 'Meta', purpose: 'social' },
  { domain: 'connect.facebook.net', vendor: 'Meta Pixel', purpose: 'social' },
  { domain: 'twitter.com', vendor: 'X / Twitter', purpose: 'social' },
  { domain: 'x.com', vendor: 'X / Twitter', purpose: 'social' },
  { domain: 'linkedin.com', vendor: 'LinkedIn', purpose: 'social' },
  { domain: 'licdn.com', vendor: 'LinkedIn', purpose: 'social' },
  { domain: 'youtube.com', vendor: 'YouTube', purpose: 'social' },
  { domain: 'pinterest.com', vendor: 'Pinterest', purpose: 'social' },

  // Session replay / UX
  { domain: 'fullstory.com', vendor: 'FullStory', purpose: 'session-replay' },
  { domain: 'logrocket.com', vendor: 'LogRocket', purpose: 'session-replay' },
  { domain: 'logrocket.io', vendor: 'LogRocket', purpose: 'session-replay' },
  { domain: 'smartlook.com', vendor: 'Smartlook', purpose: 'session-replay' },
  { domain: 'mouseflow.com', vendor: 'Mouseflow', purpose: 'session-replay' },
  { domain: 'inspectlet.com', vendor: 'Inspectlet', purpose: 'session-replay' },
  { domain: 'quantummetric.com', vendor: 'Quantum Metric', purpose: 'session-replay' },
  { domain: 'siteimprove.com', vendor: 'Siteimprove', purpose: 'analytics' },

  // CMP / consent
  { domain: 'onetrust.com', vendor: 'OneTrust', purpose: 'consent-management' },
  { domain: 'cookielaw.org', vendor: 'OneTrust', purpose: 'consent-management' },
  { domain: 'cookiebot.com', vendor: 'Cookiebot', purpose: 'consent-management' },
  { domain: 'cookieyes.com', vendor: 'CookieYes', purpose: 'consent-management' },
  { domain: 'usercentrics.eu', vendor: 'Usercentrics', purpose: 'consent-management' },
  { domain: 'usercentrics.com', vendor: 'Usercentrics', purpose: 'consent-management' },
  { domain: 'trustarc.com', vendor: 'TrustArc', purpose: 'consent-management' },
  { domain: 'quantcast.com', vendor: 'Quantcast Choice', purpose: 'consent-management' },
  { domain: 'iubenda.com', vendor: 'iubenda', purpose: 'consent-management' },
  { domain: 'didomi.io', vendor: 'Didomi', purpose: 'consent-management' },
  { domain: 'privacy-mgmt.com', vendor: 'Sourcepoint', purpose: 'consent-management' },
  { domain: 'consensu.org', vendor: 'IAB TCF', purpose: 'consent-management' },

  // Tag managers / testing that inject trackers
  { domain: 'optimizely.com', vendor: 'Optimizely', purpose: 'analytics' },
  { domain: 'vwo.com', vendor: 'VWO', purpose: 'analytics' },
  { domain: 'abtasty.com', vendor: 'AB Tasty', purpose: 'analytics' },
  { domain: 'nr-data.net', vendor: 'New Relic', purpose: 'analytics' },

  // Infrastructure (not tracking, but useful for classification)
  { domain: 'cloudflare.com', vendor: 'Cloudflare', purpose: 'cdn' },
  { domain: 'cloudflareinsights.com', vendor: 'Cloudflare Insights', purpose: 'analytics' },
  { domain: 'akamaihd.net', vendor: 'Akamai', purpose: 'cdn' },
  { domain: 'fastly.net', vendor: 'Fastly', purpose: 'cdn' },
  { domain: 'gstatic.com', vendor: 'Google Static', purpose: 'cdn' },
  { domain: 'googleapis.com', vendor: 'Google APIs', purpose: 'functional' },
  { domain: 'jsdelivr.net', vendor: 'jsDelivr', purpose: 'cdn' },
  { domain: 'unpkg.com', vendor: 'unpkg', purpose: 'cdn' },
  { domain: 'cdnjs.com', vendor: 'cdnjs', purpose: 'cdn' },
  { domain: 'stripe.com', vendor: 'Stripe', purpose: 'functional' },
  { domain: 'stripe.network', vendor: 'Stripe', purpose: 'functional' },
  { domain: 'recaptcha.net', vendor: 'Google reCAPTCHA', purpose: 'security' },
  { domain: 'hcaptcha.com', vendor: 'hCaptcha', purpose: 'security' },
  { domain: 'sentry-cdn.com', vendor: 'Sentry', purpose: 'functional' },
];

const RULE_BY_DOMAIN = new Map(VENDOR_RULES.map((r) => [r.domain, r]));

/** Cookie names that identify a device even on a first-party host. */
const TRACKING_COOKIE_RULES: { pattern: RegExp; vendor: string | null; purpose: Purpose }[] = [
  { pattern: /^_ga(_|$)/i, vendor: 'Google Analytics', purpose: 'analytics' },
  { pattern: /^_gid$/i, vendor: 'Google Analytics', purpose: 'analytics' },
  { pattern: /^_gat/i, vendor: 'Google Analytics', purpose: 'analytics' },
  { pattern: /^_gcl_/i, vendor: 'Google Ads', purpose: 'advertising' },
  { pattern: /^_fbp$/i, vendor: 'Meta Pixel', purpose: 'social' },
  { pattern: /^_fbc$/i, vendor: 'Meta Pixel', purpose: 'social' },
  { pattern: /^fr$/i, vendor: 'Meta Pixel', purpose: 'social' },
  { pattern: /^_hjid$/i, vendor: 'Hotjar', purpose: 'analytics' },
  { pattern: /^_hjSession/i, vendor: 'Hotjar', purpose: 'analytics' },
  { pattern: /^_hjAbsoluteSessionInProgress$/i, vendor: 'Hotjar', purpose: 'analytics' },
  { pattern: /^_clck$/i, vendor: 'Microsoft Clarity', purpose: 'analytics' },
  { pattern: /^_clsk$/i, vendor: 'Microsoft Clarity', purpose: 'analytics' },
  { pattern: /^_uetsid$/i, vendor: 'Microsoft Advertising', purpose: 'advertising' },
  { pattern: /^_uetvid$/i, vendor: 'Microsoft Advertising', purpose: 'advertising' },
  { pattern: /^IDE$/i, vendor: 'Google DoubleClick', purpose: 'advertising' },
  { pattern: /^_ttp$/i, vendor: 'TikTok Ads', purpose: 'advertising' },
  { pattern: /^_pin_unauth$/i, vendor: 'Pinterest', purpose: 'social' },
  { pattern: /^personalization_id$/i, vendor: 'X / Twitter', purpose: 'social' },
  { pattern: /^_scid$/i, vendor: 'Snapchat', purpose: 'advertising' },
  { pattern: /^(__utm|utm_)/i, vendor: 'Google Analytics', purpose: 'analytics' },
  { pattern: /^ajs_(anonymous_)?id$/i, vendor: 'Segment', purpose: 'analytics' },
  { pattern: /^mp_/i, vendor: 'Mixpanel', purpose: 'analytics' },
  { pattern: /^amplitude_/i, vendor: 'Amplitude', purpose: 'analytics' },
  { pattern: /^fs_uid$/i, vendor: 'FullStory', purpose: 'session-replay' },
  { pattern: /^_lr_/i, vendor: 'LogRocket', purpose: 'session-replay' },
  { pattern: /^intercom-/i, vendor: 'Intercom', purpose: 'functional' },
  { pattern: /^(MUID|ANONCHK|CLID|SM)$/i, vendor: 'Microsoft Advertising', purpose: 'advertising' },
  { pattern: /^(cto_bundle|uid)$/i, vendor: 'Criteo', purpose: 'advertising' },
  { pattern: /^t_gid$/i, vendor: 'Taboola', purpose: 'advertising' },
  { pattern: /^(obuid|_outbrain_cid_fetch)$/i, vendor: 'Outbrain', purpose: 'advertising' },
  // Generic vendor-assigned identifiers seen at third-party collection hosts.
  // `_vuid` in particular is what many analytics SDKs ship by default.
  { pattern: /^_vuid$/i, vendor: null, purpose: 'analytics' },
  { pattern: /^(vuid|visitor_?id|vid)$/i, vendor: null, purpose: 'analytics' },
  { pattern: /^(_ga_|_gid_|gcl_)/i, vendor: 'Google Analytics', purpose: 'analytics' },
];

/** Names that are conventionally identifiers even without a known vendor. */
const IDENTIFIER_PATTERNS = [
  /(^|_)(uid|uuid|user_?id|visitor_?id|client_?id|device_?id|distinct_?id|anonymous_?id)($|_)/i,
  /^_?ga/i,
  /^_fb/i,
  /^_hj/i,
  /^_cl/i,
  /^_uet/i,
  /^amp_/i,
  /^ajs_/i,
];

const SENSITIVE_KEY_PATTERNS = [
  /email/i,
  /e-?mail/i,
  /phone/i,
  /ssn/i,
  /passport/i,
  /credit/i,
  /card_?number/i,
  /address/i,
  /user_?id/i,
  /customer_?id/i,
  /account_?id/i,
  /(^|_)uid($|_)/i,
  /device/i,
];

export interface ClassifierOptions {
  siteDomain: string;
  config: Pick<ScanConfig, 'domains' | 'trackingCookies' | 'exemptDomains'>;
}

export class Classifier {
  private readonly siteDomain: string;
  private readonly overrides: { regex: RegExp; override: DomainOverride }[];
  private readonly extraTrackingCookies: Set<string>;
  private readonly exempt: Set<string>;

  constructor(options: ClassifierOptions) {
    this.siteDomain = options.siteDomain.toLowerCase();
    this.overrides = (options.config.domains ?? []).map((o) => ({
      regex: globToRegex(o.match),
      override: o,
    }));
    this.extraTrackingCookies = new Set(
      (options.config.trackingCookies ?? []).map((n) => n.toLowerCase()),
    );
    this.exempt = new Set((options.config.exemptDomains ?? []).map((h) => h.toLowerCase()));
  }

  siteDomainOf(host: string): string {
    return getDomain(host) ?? host.toLowerCase();
  }

  partyOf(host: string): Party {
    const domain = this.siteDomainOf(host);
    if (domain === this.siteDomain) return 'first';
    // Subdomains of the site's registrable domain are first party even when the
    // cookie is served from e.g. `static.www.example.com`.
    if (host.toLowerCase() === this.siteDomain || host.toLowerCase().endsWith(`.${this.siteDomain}`)) {
      return 'first';
    }
    return 'third';
  }

  classifyHost(host: string): VendorInfo {
    const lower = host.toLowerCase();
    for (const { regex, override } of this.overrides) {
      if (regex.test(lower)) {
        return {
          vendor: override.vendor ?? null,
          purpose: override.purpose ?? 'unknown',
          tracking:
            override.tracking ?? (override.purpose ? TRACKING.has(override.purpose) : false),
        };
      }
    }
    if (this.isExempt(lower)) {
      return { vendor: null, purpose: 'functional', tracking: false };
    }

    // Longest-suffix match across the curated table.
    const domain = this.siteDomainOf(lower);
    const direct = RULE_BY_DOMAIN.get(domain);
    let rule = direct ?? null;
    if (!rule) {
      let best: VendorRule | null = null;
      for (const candidate of VENDOR_RULES) {
        if (lower === candidate.domain || lower.endsWith(`.${candidate.domain}`)) {
          if (!best || candidate.domain.length > best.domain.length) best = candidate;
        }
      }
      rule = best;
    }
    if (rule) {
      return { vendor: rule.vendor, purpose: rule.purpose, tracking: TRACKING.has(rule.purpose) };
    }
    return { vendor: null, purpose: 'unknown', tracking: false };
  }

  classifyCookie(name: string): VendorInfo {
    const lower = name.toLowerCase();
    if (this.extraTrackingCookies.has(lower)) {
      return { vendor: null, purpose: 'advertising', tracking: true };
    }
    for (const rule of TRACKING_COOKIE_RULES) {
      if (rule.pattern.test(name)) {
        return { vendor: rule.vendor, purpose: rule.purpose, tracking: TRACKING.has(rule.purpose) };
      }
    }
    return { vendor: null, purpose: 'unknown', tracking: false };
  }

  isExempt(host: string): boolean {
    const lower = host.toLowerCase();
    if (this.exempt.has(lower)) return true;
    for (const entry of this.exempt) {
      if (entry.startsWith('*.') && lower.endsWith(entry.slice(1))) return true;
      if (entry.startsWith('.') && (lower === entry.slice(1) || lower.endsWith(entry))) return true;
    }
    return false;
  }

  /**
   * Classify a cookie's purpose, preferring the cookie name's vendor signal and
   * falling back to the host that set it.
   */
  classifyCookieWithHost(name: string, host: string): VendorInfo {
    const byName = this.classifyCookie(name);
    if (byName.purpose !== 'unknown') {
      const byHost = this.classifyHost(host);
      return { vendor: byName.vendor ?? byHost.vendor, purpose: byName.purpose, tracking: byName.tracking };
    }
    const byHost = this.classifyHost(host);
    if (byHost.purpose !== 'unknown') {
      // A session/functional cookie on a known tracker host is still not
      // necessarily tracking; only inherit the host's classification when the
      // host is itself a tracking vendor.
      return byHost.tracking ? { ...byHost, vendor: byHost.vendor } : { vendor: byHost.vendor, purpose: byHost.purpose, tracking: false };
    }
    return { vendor: null, purpose: 'unknown', tracking: false };
  }

  /** Heuristic: does this key/value look like it carries personal data or an id? */
  looksLikeIdentifier(key: string, value: string): boolean {
    if (IDENTIFIER_PATTERNS.some((p) => p.test(key))) return true;
    if (value.length >= 8 && /^[0-9a-f-]{8,}$/i.test(value) && /id/i.test(key)) return true;
    return false;
  }

  looksSensitiveKey(key: string): boolean {
    return SENSITIVE_KEY_PATTERNS.some((p) => p.test(key));
  }
}

const TRACKING: ReadonlySet<Purpose> = new Set<Purpose>([
  'analytics',
  'advertising',
  'social',
  'session-replay',
  'tag-manager',
]);

function globToRegex(glob: string): RegExp {
  const escaped = glob
    .toLowerCase()
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replace(/\*\*/g, '\u0000')
    .replace(/\*/g, '[^.]*')
    .replace(/\u0000/g, '.*')
    .replace(/\?/g, '.');
  return new RegExp(`^${escaped}$`);
}
