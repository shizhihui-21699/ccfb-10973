/** Scan configuration: everything a legal/engineering team can tune per site. */

export interface ConsentControlConfig {
  /** CSS selectors tried first, in every frame. */
  selectors?: string[];
  /** Case-insensitive button/label text, tried when selectors fail. */
  text?: string[];
  /** Optional selector to open a preference panel before this control is used. */
  openPanelSelectors?: string[];
  openPanelText?: string[];
}

export interface ConsentConfig {
  accept?: ConsentControlConfig;
  reject?: ConsentControlConfig;
  /** Hosts that are known CMP containers; searched first and reported specially. */
  cmpHosts?: string[];
  /** Never click anything matching these texts (e.g. "Accept all" when you want reject). */
  excludeText?: string[];
  /** Milliseconds to wait for the banner to appear. */
  appearTimeoutMs?: number;
}

export interface SettleConfig {
  /** Observation window before touching consent UI. */
  preConsentMs?: number;
  /** Observation window after clicking accept/reject. */
  afterChoiceMs?: number;
  /** Extra quiet period with no network activity before ending a phase. */
  quietMs?: number;
  /** Hard cap for a phase. */
  maxPhaseMs?: number;
}

export interface InteractionConfig {
  /** Scroll the page to trigger lazy loaders. */
  scroll?: boolean;
  /** Move the mouse and click on a neutral area. */
  pointer?: boolean;
  /** Type into the first text field if one exists (focus triggers trackers). */
  type?: boolean;
}

export interface DomainOverride {
  /** Host glob, e.g. "*.example.com" or "example.com". */
  match: string;
  purpose?: import('./types.js').Purpose;
  vendor?: string;
  /** Treat as first-party (e.g. your own analytics subdomain). */
  firstParty?: boolean;
  tracking?: boolean;
}

export interface ScanConfig {
  url: string;
  consent?: ConsentConfig;
  settle?: SettleConfig;
  interaction?: InteractionConfig;
  /** Vendor knowledge overrides, evaluated before the built-in database. */
  domains?: DomainOverride[];
  /** Additional tracking cookie names (lower-case). */
  trackingCookies?: string[];
  /** Additional hosts that are strictly necessary and may always be contacted. */
  exemptDomains?: string[];
  /** Run phases. Defaults to all three. */
  phases?: import('./types.js').PhaseId[];
  /**
   * Present the visitor as sending Global Privacy Control and Do Not Track.
   * When set, any tracking that still fires is reported as
   * `GPC_SIGNAL_IGNORED`, which is the CCPA/CPRA "opt-out preference signal"
   * obligation. Also useful for checking whether a CMP reads GPC at all.
   */
  simulateGpc?: boolean;
  /** Keep raw response bodies in the JSON output (defaults to evidence only). */
  keepResponseBodies?: boolean;
  /**
   * host -> upstream IP. Needed when the scanner runs against fixtures or
   * staging hosts that the machine cannot resolve (e.g. `www.site.test`).
   */
  hostMap?: Record<string, string>;
}

export const DEFAULT_CONFIG: Required<
  Pick<ScanConfig, 'settle' | 'interaction' | 'phases' | 'simulateGpc'>
> = {
  settle: {
    preConsentMs: 6000,
    afterChoiceMs: 6000,
    quietMs: 1500,
    maxPhaseMs: 30000,
  },
  interaction: { scroll: true, pointer: true, type: false },
  phases: ['pre-consent', 'post-reject', 'post-consent'],
  simulateGpc: false,
};

export function resolveConfig(input: Partial<ScanConfig> & { url: string }): ScanConfig {
  if (!input.url) throw new Error('config.url is required');
  let url: URL;
  try {
    url = new URL(input.url);
  } catch {
    throw new Error(`config.url is not a valid URL: ${input.url}`);
  }
  if (!['http:', 'https:'].includes(url.protocol)) {
    throw new Error('config.url must be http(s)');
  }
  return {
    ...input,
    url: url.toString(),
    settle: { ...DEFAULT_CONFIG.settle, ...input.settle },
    interaction: { ...DEFAULT_CONFIG.interaction, ...input.interaction },
    phases: input.phases ?? DEFAULT_CONFIG.phases,
    simulateGpc: input.simulateGpc ?? DEFAULT_CONFIG.simulateGpc,
  };
}
