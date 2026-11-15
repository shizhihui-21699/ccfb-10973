/**
 * Demo: scan every fixture site and assert the expected verdict.
 *
 * This is both a demonstration and the end-to-end integration test: each
 * fixture encodes a known compliance pattern, so the expected findings tell
 * us whether the scanner actually works — not just whether it ran.
 *
 *   npm run demo              scan all fixtures, write reports
 *   npm run demo -- --only eager
 */
import fs from 'node:fs';
import path from 'node:path';
import { resolveConfig } from '../src/config.js';
import { Classifier } from '../src/lib/classify.js';
import { analyse } from '../src/lib/analyse.js';
import { renderHtml, renderJson, renderMarkdown } from '../src/lib/report.js';
import { runScan } from '../src/lib/scanner.js';
import { SCANNER_VERSION } from '../src/version.js';
import { createFixtureServer, FIXTURE_HOSTS } from './server.js';

interface Expectation {
  host: string;
  label: string;
  expect: 'PASS' | 'FAIL';
  /** Finding codes that must be present. */
  codes: import('../src/types.js').FindingCode[];
  /** What the site does, in plain language, for the demo output. */
  note: string;
}

const EXPECTATIONS: Expectation[] = [
  {
    host: 'clean.example.test',
    label: 'Consent-first (compliant)',
    expect: 'PASS',
    codes: [],
    note: 'Analytics only loads after accept; the unload beacon re-checks consent.',
  },
  {
    host: 'eager.example.test',
    label: 'Analytics fires on load (violation)',
    expect: 'FAIL',
    codes: ['TRACKING_REQUEST_BEFORE_CONSENT', 'TRACKING_COOKIE_BEFORE_CONSENT'],
    note: 'GA-style script and cookie are set before the banner is answered.',
  },
  {
    host: 'sneaky.example.test',
    label: 'Looks compliant, leaks on teardown (violation)',
    expect: 'FAIL',
    codes: ['TRACKING_STORAGE_BEFORE_CONSENT', 'TRACKING_ON_UNLOAD_BEFORE_CONSENT'],
    note: 'Banner works, but a hidden iframe, a localStorage id and a pagehide beacon fire regardless.',
  },
  {
    host: 'rejector.example.test',
    label: 'Reject does not stop tracking (violation)',
    expect: 'FAIL',
    codes: ['TRACKING_REQUEST_BEFORE_CONSENT', 'TRACKING_AFTER_REJECT'],
    note: 'Accept and reject both clickable; rejecting leaves the analytics tag running.',
  },
  {
    host: 'adwall.example.test',
    label: 'Banner has no reject option (violation)',
    expect: 'FAIL',
    codes: ['CONSENT_MECHANISM_DEFECT', 'TRACKING_REQUEST_BEFORE_CONSENT'],
    note: 'Accept-only banner, with a tracker that loads unconditionally.',
  },
];

async function main(): Promise<number> {
  const only = parseOnly(process.argv.slice(2));
  const outRoot = path.join(process.cwd(), 'runs', 'demo');
  fs.mkdirSync(outRoot, { recursive: true });

  const fixture = await createFixtureServer();
  const hostMap: Record<string, string> = {};
  for (const host of FIXTURE_HOSTS) hostMap[host] = '127.0.0.1';

  let failures = 0;
  const summary: string[] = [];

  try {
    for (const expectation of EXPECTATIONS) {
      if (only && !expectation.host.includes(only)) continue;
      const url = `https://${expectation.host}:${fixture.port}/`;
      fixture.reset();

      process.stdout.write(`\n=== ${expectation.host} — ${expectation.label}\n`);

      const config = resolveConfig({
        url,
        hostMap,
        // Keep the demo quick; a real scan uses the defaults (6s windows).
        settle: { preConsentMs: 2200, afterChoiceMs: 2200, quietMs: 900, maxPhaseMs: 20000 },
        consent: {
          accept: { selectors: ['#accept-all'], text: ['accept all'] },
          reject: { selectors: ['#reject-all'], text: ['reject all'] },
        },
      });

      const outcome = await runScan({
        config,
        artefactDir: path.join(outRoot, expectation.host.replace(/\W/g, '_'), 'artefacts'),
        onProgress: (message) => process.stdout.write(`  · ${message}\n`),
      });

      const classifier = new Classifier({
        siteDomain: outcome.siteDomain,
        config: {
          domains: config.domains,
          trackingCookies: config.trackingCookies,
          exemptDomains: config.exemptDomains,
        },
      });
      const result = analyse({
        config,
        phases: outcome.phases,
        siteHost: outcome.siteHost,
        siteDomain: outcome.siteDomain,
        classifier,
        scanner: {
          name: 'pre-consent-privacy-scanner',
          version: SCANNER_VERSION,
          playwright: outcome.playwrightVersion,
        },
        startedAt: outcome.startedAt,
        finishedAt: outcome.finishedAt,
        coverageNotes: outcome.coverageNotes,
      });

      const dir = path.join(outRoot, expectation.host.replace(/\W/g, '_'));
      fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(path.join(dir, 'report.json'), renderJson(result));
      fs.writeFileSync(path.join(dir, 'report.md'), renderMarkdown(result));
      fs.writeFileSync(
        path.join(dir, 'report.html'),
        renderHtml(result, { artefactRoot: path.join(dir, 'artefacts') }),
      );

      const codes = new Set(result.findings.map((f) => f.code));
      const verdictOk = result.summary.verdict === expectation.expect;
      const codesOk = expectation.expect === 'PASS'
        ? result.findings.filter((f) => f.severity === 'critical').length === 0
        : expectation.codes.every((code) => codes.has(code));

      const ok = verdictOk && codesOk;
      if (!ok) failures += 1;

      process.stdout.write(
        `  verdict ${result.summary.verdict} (expected ${expectation.expect}) ${verdictOk ? '✓' : '✗'}\n`,
      );
      for (const code of expectation.codes) {
        process.stdout.write(`  expected finding ${code}: ${codes.has(code) ? '✓' : '✗'}\n`);
      }
      if (result.findings.length) {
        process.stdout.write(`  findings:\n`);
        for (const finding of result.findings) {
          process.stdout.write(`    [${finding.severity}] ${finding.code} — ${finding.title}\n`);
        }
      } else {
        process.stdout.write('  findings: none\n');
      }
      summary.push(
        `${ok ? 'PASS' : 'FAIL'}  ${expectation.host.padEnd(24)} verdict=${result.summary.verdict.padEnd(12)} findings=${result.findings.length}`,
      );
    }
  } finally {
    await fixture.close();
  }

  process.stdout.write(`\n===== summary =====\n${summary.join('\n')}\n`);
  process.stdout.write(`\nreports in ${outRoot}\n`);
  if (failures > 0) {
    process.stdout.write(`\n${failures} fixture(s) did not match expectations\n`);
    return 1;
  }
  return 0;
}

function parseOnly(argv: string[]): string | null {
  const idx = argv.indexOf('--only');
  return idx >= 0 ? (argv[idx + 1] ?? null) : null;
}

main()
  .then((code) => process.exit(code))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
