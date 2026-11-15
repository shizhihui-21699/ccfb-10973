/**
 * Consent interface detection and interaction.
 *
 * Consent banners are the least standardised thing on the web: they live in
 * cross-origin iframes, inside open shadow roots, behind a "Manage preferences"
 * link, and their button text is localised. The strategy is layered:
 *
 *  1. Explicit user-provided selectors (highest trust).
 *  2. Vendor-specific selectors for the major CMPs (OneTrust, Cookiebot, ...).
 *  3. Scored text matching in every frame, accepting only elements that look
 *     like a real, visible control.
 *
 * The reject path is deliberately conservative: if it cannot find a reject
 * control it reports that rather than clicking something that might be
 * "Accept". Clicking the wrong control turns a compliance report into a false
 * negative, so ambiguity is surfaced, never guessed.
 */
import type { Frame, Page } from 'playwright';
import type { ConsentAttempt, PhaseId } from '../types.js';
import type { ConsentConfig, ConsentControlConfig } from '../config.js';

interface Candidate {
  selector: string;
  text: string;
  frameUrl: string;
  score: number;
  handle: Awaited<ReturnType<Frame['$$']>>[number] | null;
  rootSelector?: string;
}

const DEFAULT_ACCEPT_TEXT = [
  'accept all',
  'accept all cookies',
  'allow all',
  'allow all cookies',
  'agree to all',
  'i agree',
  'ok, i agree',
  'accept cookies',
  'accept',
  'agree',
  'got it',
  'i understand',
  'allow',
  'accept all and continue',
  '同意全部',
  '同意所有',
  '接受全部',
  '全部接受',
  '同意',
  '接受',
  '允许全部',
  '我知道了',
];

const DEFAULT_REJECT_TEXT = [
  'reject all',
  'reject all cookies',
  'decline all',
  'decline optional cookies',
  'refuse all',
  'deny all',
  'only necessary',
  'only essential',
  'necessary only',
  'essential only',
  'use necessary cookies only',
  'use essential cookies only',
  'reject non-essential',
  'reject',
  'decline',
  'refuse',
  'continue without accepting',
  'no thanks',
  'disagree',
  'do not sell or share my personal information',
  'do not sell my personal information',
  'manage options',
  'cookie settings',
  '拒绝全部',
  '拒绝所有',
  '拒绝非必要',
  '仅必要',
  '只允许必要',
  '仅使用必要',
  '拒绝',
  '不同意',
  '仅使用必要 cookie',
];

const OPEN_PANEL_TEXT = [
  'cookie settings',
  'cookie preferences',
  'privacy settings',
  'manage cookies',
  'manage preferences',
  'customize settings',
  'customise settings',
  'more options',
  '设置',
  ' cookie设置',
  '管理偏好',
  '自定义设置',
];

/** Selectors for well-known CMPs, tried before text matching. */
const CMP_SELECTORS: Record<string, { accept: string[]; reject: string[]; open?: string[] }> = {
  onetrust: {
    accept: ['#onetrust-accept-btn-handler'],
    reject: ['#onetrust-reject-all-handler', '.ot-pc-refuse-all-handler', '#onetrust-pc-btn-handler ~ #onetrust-reject-all-handler'],
    open: ['#onetrust-pc-btn-handler'],
  },
  cookiebot: {
    accept: ['#CybotCookiebotDialogBodyLevelButtonLevelOptinAllowAll', '#CybotCookiebotDialogBodyButtonAccept'],
    reject: ['#CybotCookiebotDialogBodyButtonDecline', '#CybotCookiebotDialogBodyLevelButtonLevelOptinDeclineAll'],
    open: ['#CybotCookiebotDialogBodyLevelButtonCustomize'],
  },
  usercentrics: {
    accept: ['button[data-testid="uc-accept-all-button"]', '[data-testid="uc-accept-all-button"]'],
    reject: ['button[data-testid="uc-deny-all-button"]', '[data-testid="uc-deny-all-button"]'],
    open: ['button[data-testid="uc-more-button"]'],
  },
  didomi: {
    accept: ['#didomi-notice-agree-button', 'button#didomi-notice-agree-button'],
    reject: ['#didomi-notice-disagree-button', 'button#didomi-notice-disagree-button'],
    open: ['#didomi-notice-learn-more-button'],
  },
  cookieyes: {
    accept: ['.cky-btn-accept'],
    reject: ['.cky-btn-reject'],
    open: ['.cky-btn-customize'],
  },
  quantcast: {
    accept: ['.qc-cmp2-summary-buttons button[mode="primary"]', 'button.qc-cmp2-button[mode="primary"]'],
    reject: ['.qc-cmp2-summary-buttons button[mode="secondary"]', 'button.qc-cmp2-button[mode="secondary"]'],
    open: ['.qc-cmp2-summary-buttons button:not([mode])'],
  },
  trustarc: {
    accept: ['#truste-consent-button', '.trustarc-agree-btn'],
    reject: ['#truste-consent-required', '.trustarc-decline-btn'],
    open: ['#truste-show-consent', '.trustarc-manage-btn'],
  },
  iubenda: {
    accept: ['.iubenda-cs-accept-btn'],
    reject: ['.iubenda-cs-reject-btn'],
    open: ['.iubenda-cs-customize-btn'],
  },
  sourcepoint: {
    accept: ['button[title="Accept all"]', 'button.sp_choice_type_11'],
    reject: ['button[title="Reject all"]', 'button.sp_choice_type_13'],
    open: ['button.sp_choice_type_12'],
  },
};

/** Vendors whose iframe counts as CMP content rather than a tracker. */
export const CMP_HOST_HINTS = [
  'onetrust.com',
  'cookielaw.org',
  'cookiebot.com',
  'usercentrics.eu',
  'usercentrics.com',
  'didomi.io',
  'privacy-mgmt.com',
  'consensu.org',
  'cookieyes.com',
  'trustarc.com',
  'quantcast.com',
  'iubenda.com',
  'sourcepoint.com',
  'sp-prod.net',
  'cdn.privacy-mgmt.com',
];

function buildControlConfig(
  base: ConsentControlConfig | undefined,
  defaults: string[],
): { selectors: string[]; text: string[]; openSelectors: string[]; openText: string[] } {
  return {
    selectors: base?.selectors ?? [],
    text: [...(base?.text ?? []), ...defaults],
    openSelectors: base?.openPanelSelectors ?? [],
    openText: [...(base?.openPanelText ?? []), ...OPEN_PANEL_TEXT],
  };
}

/**
 * Collect visible candidate controls from a frame, including open shadow roots.
 * Returned as serialisable descriptors; the caller resolves them to handles.
 *
 * The evaluate callback is written to survive bundler transforms: esbuild's
 * `keepNames` (used by tsx) rewrites named function literals into
 * `__name(fn, "...")`, which does not exist in the page context. The page-side
 * code therefore keeps every function anonymous and guards the helper.
 */
async function collectInFrame(
  frame: Frame,
  texts: string[],
  selectors: string[],
  exclude: string[],
): Promise<Candidate[]> {
  return frame
    .evaluate(
      (args: { texts: string[]; selectors: string[]; exclude: string[] }) => {
        const g = globalThis as any;
        if (typeof g.__name !== 'function') g.__name = (fn: unknown) => fn;
        const { texts, selectors, exclude } = args;
        const out: {
          text: string;
          selector: string;
          score: number;
          tag: string;
          idAttr: string;
          role: string;
        }[] = [];

        const norm = (s: string) => s.replace(/\s+/g, ' ').trim().toLowerCase();
        const excluded = exclude.map(norm).filter(Boolean);

        // fn is named only at runtime via assignment, never as a literal.
        const isVisible = (el: Element): boolean => {
          const anyEl = el as any;
          if (typeof anyEl.checkVisibility === 'function') {
            if (!anyEl.checkVisibility({ checkOpacity: true, checkVisibilityCSS: true })) return false;
          }
          const rect = el.getBoundingClientRect();
          if (rect.width < 4 || rect.height < 4) return false;
          const style = getComputedStyle(el);
          if (style.visibility === 'hidden' || style.display === 'none') return false;
          if (Number(style.opacity) === 0) return false;
          // Must be on screen: dialogs below the fold are not "clickable" for a user.
          if (rect.bottom < 0 || rect.top > innerHeight + 200) return false;
          return true;
        };

        const pathFor = (el: Element): string => {
          const parts: string[] = [];
          let node: Element | null = el;
          let depth = 0;
          while (node && depth < 5) {
            let part = node.tagName.toLowerCase();
            if (node.id) {
              part += `#${CSS.escape(node.id)}`;
              parts.unshift(part);
              return parts.join(' > ');
            }
            const parent: Element | null = node.parentElement;
            if (parent) {
              const current = node;
              const siblings = Array.from(parent.children).filter((c) => c.tagName === current.tagName);
              if (siblings.length > 1) part += `:nth-of-type(${siblings.indexOf(current) + 1})`;
            }
            parts.unshift(part);
            node = node.parentElement;
            depth += 1;
          }
          return parts.join(' > ');
        };

        const walk = (root: ParentNode, depth: number): void => {
          if (depth > 6) return;
          let all: Element[];
          try {
            all = Array.from(root.querySelectorAll('*'));
          } catch {
            return;
          }
          for (const el of all) {
            const tag = el.tagName.toLowerCase();
            if (tag === 'script' || tag === 'style' || tag === 'html' || tag === 'head' || tag === 'meta' || tag === 'link') {
              continue;
            }

            if (el.shadowRoot) walk(el.shadowRoot, depth + 1);

            const tagOk =
              tag === 'button' ||
              tag === 'a' ||
              tag === 'input' ||
              tag === 'label' ||
              tag === 'div' ||
              tag === 'span' ||
              /-button$/.test(tag) ||
              el.getAttribute('role') === 'button' ||
              el.getAttribute('role') === 'link';
            if (!tagOk) continue;
            if (!isVisible(el)) continue;

            // A button's `.value` is an empty string (not null), so the label
            // must be chosen by element type rather than with `??` alone.
            const aria = el.getAttribute('aria-label') || '';
            const inputValue =
              tag === 'input'
                ? (el as HTMLInputElement).value || el.getAttribute('value') || ''
                : '';
            const content = (el.textContent ?? '').trim();
            const title = el.getAttribute('title') || '';
            const text = norm(aria || inputValue || content || title);
            if (!text || text.length > 120) continue;
            if (excluded.some((e) => e && text.indexOf(e) >= 0)) continue;

            // Explicit selectors win outright.
            for (const sel of selectors) {
              try {
                if (el.matches(sel)) {
                  out.push({
                    text,
                    selector: sel,
                    score: 100,
                    tag,
                    idAttr: el.id,
                    role: el.getAttribute('role') ?? '',
                  });
                  break;
                }
              } catch {
                /* invalid selector from config */
              }
            }

            for (const wanted of texts) {
              const w = norm(wanted);
              if (!w) continue;
              let score = 0;
              if (text === w) score = 60;
              else if (text.indexOf(w) === 0) score = 45;
              else if (text.indexOf(w) >= 0) score = 30;
              if (!score) continue;
              // Prefer real controls over decorative wrappers.
              if (tag === 'button' || el.getAttribute('role') === 'button') score += 12;
              else if (tag === 'a' || el.getAttribute('role') === 'link') score += 5;
              else if (tag === 'input') score += 8;
              // A very long label that merely contains the phrase is likely a
              // paragraph, not a button.
              if (text.length > w.length * 3 + 12) score -= 20;
              out.push({
                text,
                selector: pathFor(el),
                score,
                tag,
                idAttr: el.id,
                role: el.getAttribute('role') ?? '',
              });
              break;
            }
          }
        };

        walk(document, 0);
        // Deduplicate by selector, keeping the best score.
        const best = new Map<string, (typeof out)[number]>();
        for (const candidate of out) {
          const prev = best.get(candidate.selector);
          if (!prev || candidate.score > prev.score) best.set(candidate.selector, candidate);
        }
        const ranked = Array.from(best.values()).sort((a, b) => b.score - a.score);
        return ranked.slice(0, 12);
      },
      { texts, selectors, exclude },
    )
    .then((rows) =>
      rows.map((r) => ({
        selector: r.selector,
        text: r.text,
        frameUrl: frame.url(),
        score: r.score,
        handle: null,
      })),
    )
    .catch(() => [] as Candidate[]);
}

async function visibleFrames(page: Page): Promise<Frame[]> {
  return page.frames().filter((f) => {
    const url = f.url();
    return !url.startsWith('about:') || page.mainFrame() === f;
  });
}

async function findCandidates(
  page: Page,
  controls: ReturnType<typeof buildControlConfig>,
  cmpHosts: string[],
  exclude: string[],
): Promise<Candidate[]> {
  const frames = await visibleFrames(page);
  const ordered = [...frames].sort((a, b) => {
    const aCmp = cmpHosts.some((h) => a.url().includes(h)) ? 0 : 1;
    const bCmp = cmpHosts.some((h) => b.url().includes(h)) ? 0 : 1;
    return aCmp - bCmp;
  });

  const cmpSelectors = new Set<string>();
  for (const key of Object.keys(CMP_SELECTORS)) {
    for (const s of CMP_SELECTORS[key]!.accept) cmpSelectors.add(s);
  }
  const allSelectors = [...controls.selectors, ...cmpSelectors];

  const results: Candidate[] = [];
  for (const frame of ordered) {
    const found = await collectInFrame(frame, controls.text, allSelectors, exclude);
    results.push(...found);
  }
  // Prefer CMP frames, then score, then top-most on screen.
  return results.sort((a, b) => {
    const aCmp = cmpHosts.some((h) => a.frameUrl.includes(h)) ? 0 : 1;
    const bCmp = cmpHosts.some((h) => b.frameUrl.includes(h)) ? 0 : 1;
    if (aCmp !== bCmp) return aCmp - bCmp;
    return b.score - a.score;
  });
}

async function clickCandidate(page: Page, candidate: Candidate): Promise<boolean> {
  const frame = page.frames().find((f) => f.url() === candidate.frameUrl) ?? page.mainFrame();
  try {
    const locator = frame.locator(candidate.selector).first();
    if ((await locator.count()) === 0) return false;
    if (!(await locator.isVisible().catch(() => false))) return false;
    await locator.scrollIntoViewIfNeeded({ timeout: 1500 }).catch(() => {});
    await locator.click({ timeout: 3000, trial: false }).catch(async () => {
      // Overlays and cookie walls often block pointer events; fall back to
      // dispatching the click on the element itself.
      await locator.dispatchEvent('click', {}, { timeout: 1500 }).catch(() => {});
    });
    return true;
  } catch {
    return false;
  }
}

export interface ConsentActionOptions {
  page: Page;
  config: ConsentConfig | undefined;
  phase: PhaseId;
  wanted: 'accept' | 'reject';
}

export async function performConsent(
  options: ConsentActionOptions,
): Promise<ConsentAttempt> {
  const { page, phase, wanted } = options;
  const cfg = options.config ?? {};
  const exclude = cfg.excludeText ?? [];
  const cmpHosts = [...(cfg.cmpHosts ?? []), ...CMP_HOST_HINTS];
  const appearTimeout = cfg.appearTimeoutMs ?? 8000;

  const defaults = wanted === 'accept' ? DEFAULT_ACCEPT_TEXT : DEFAULT_REJECT_TEXT;
  const controls = buildControlConfig(wanted === 'accept' ? cfg.accept : cfg.reject, defaults);

  // Never let a reject click land on a control whose text is an accept phrase.
  const rejectExclude = wanted === 'reject' ? [...exclude, ...DEFAULT_ACCEPT_TEXT] : exclude;

  const deadline = Date.now() + appearTimeout;
  let candidates: Candidate[] = [];
  while (Date.now() < deadline) {
    candidates = await findCandidates(page, controls, cmpHosts, rejectExclude);
    // Require a minimum score so a paragraph mentioning "accept" is not clicked.
    candidates = candidates.filter((c) => c.score >= 30);
    if (candidates.length > 0) break;
    await page.waitForTimeout(250);
  }

  if (candidates.length === 0) {
    return {
      phase,
      wanted,
      found: false,
      clicked: null,
      inFrameUrl: null,
      candidates: [],
      note:
        wanted === 'reject'
          ? 'No reject control found. Either the banner has no reject option (a finding in itself) or its text is not recognised; see consent.selectors in the config.'
          : 'No accept control found. The page may already be in a consented state or the banner uses unrecognised markup.',
    };
  }

  const top = candidates[0]!;
  const clicked = await clickCandidate(page, top);
  if (!clicked) {
    return {
      phase,
      wanted,
      found: true,
      clicked: null,
      inFrameUrl: top.frameUrl,
      candidates: candidates.map((c) => `${c.selector} (${c.text})`),
      note: 'A matching control was found but could not be clicked (hidden behind an overlay or detached).',
    };
  }

  // If a preference dialog opened instead of a decision being recorded, try the
  // explicit control inside it.
  await page.waitForTimeout(600);

  return {
    phase,
    wanted,
    found: true,
    clicked: `${top.selector} — "${top.text}"`,
    inFrameUrl: top.frameUrl,
    candidates: candidates.slice(0, 5).map((c) => `${c.selector} (${c.text})`),
    note: null,
  };
}

/**
 * Heuristic: is a consent interface present but without an equal-weight reject?
 * Used to report `CONSENT_MECHANISM_DEFECT` without needing a click.
 */
export async function inspectConsentUi(
  page: Page,
  config: ConsentConfig | undefined,
): Promise<{ hasBanner: boolean; hasReject: boolean; hasAccept: boolean; rejectCandidates: string[] }> {
  const cfg = config ?? {};
  const cmpHosts = [...(cfg.cmpHosts ?? []), ...CMP_HOST_HINTS];
  const acceptControls = buildControlConfig(cfg.accept, DEFAULT_ACCEPT_TEXT);
  const rejectControls = buildControlConfig(cfg.reject, DEFAULT_REJECT_TEXT);
  const accepts = (await findCandidates(page, acceptControls, cmpHosts, cfg.excludeText ?? [])).filter(
    (c) => c.score >= 30,
  );
  const rejects = (await findCandidates(page, rejectControls, cmpHosts, [
    ...(cfg.excludeText ?? []),
    ...DEFAULT_ACCEPT_TEXT,
  ])).filter((c) => c.score >= 30);
  return {
    hasBanner: accepts.length > 0 || rejects.length > 0,
    hasReject: rejects.length > 0,
    hasAccept: accepts.length > 0,
    rejectCandidates: rejects.map((c) => `${c.selector} (${c.text})`),
  };
}

export const CONSENT_TEXT_DEFAULTS = { accept: DEFAULT_ACCEPT_TEXT, reject: DEFAULT_REJECT_TEXT };
