#!/usr/bin/env node
/**
 * CLI entry point.
 *
 *   privacy-scan scan --url https://www.example.com --out runs/example
 *   privacy-scan scan --config scan.json --out runs/example
 *   privacy-scan demo --out runs/demo
 *
 * Exit code is 1 when the verdict is FAIL, 2 when INCONCLUSIVE, 0 otherwise
 * so CI can gate a release on it.
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { resolveConfig, type ScanConfig } from './config.js';
import { Classifier } from './lib/classify.js';
import { analyse } from './lib/analyse.js';
import { renderHtml, renderJson, renderMarkdown } from './lib/report.js';
import { runScan } from './lib/scanner.js';
import { SCANNER_VERSION } from './version.js';

interface ParsedArgs {
  command: string;
  url?: string;
  out?: string;
  config?: string;
  headless: boolean;
  quiet: boolean;
  hostMap?: string;
}

function parseArgs(argv: string[]): ParsedArgs {
  const args: ParsedArgs = { command: argv[0] ?? 'help', headless: true, quiet: false };
  for (let i = 1; i < argv.length; i += 1) {
    const arg = argv[i]!;
    const next = argv[i + 1];
    switch (arg) {
      case '--url':
        args.url = next;
        i += 1;
        break;
      case '--out':
      case '-o':
        args.out = next;
        i += 1;
        break;
      case '--config':
      case '-c':
        args.config = next;
        i += 1;
        break;
      case '--headed':
        args.headless = false;
        break;
      case '--quiet':
      case '-q':
        args.quiet = true;
        break;
      case '--host-map':
        args.hostMap = next;
        i += 1;
        break;
      case '--help':
      case '-h':
        args.command = 'help';
        break;
      default:
        if (arg.startsWith('-')) {
          throw new Error(`unknown option: ${arg}`);
        }
    }
  }
  return args;
}

function usage(): string {
  return `Pre-consent privacy scanner ${SCANNER_VERSION}

Usage:
  privacy-scan scan --url <url> [--out <dir>] [--config <file>] [--headed]
  privacy-scan demo [--out <dir>] [--headed]

Options:
  --url <url>        Page to scan, e.g. https://www.example.com
  --config <file>    JSON scan config (see scan.example.json)
  --out, -o <dir>    Output directory (default: ./runs/<host>-<timestamp>)
  --host-map <list>  host=ip pairs for hosts that do not resolve locally
  --headed           Show the browser window
  --quiet, -q        Suppress progress output

Exit codes:
  0  scan completed, verdict PASS
  1  verdict FAIL (tracking before consent, or after rejection)
  2  verdict INCONCLUSIVE (the consent interaction could not be evaluated)

Outputs, in the chosen directory:
  report.html    self-contained report with evidence and screenshots
  report.md      markdown report
  report.json    full machine-readable result
  <phase>/       one screenshot set per phase
`;
}

function timestamp(): string {
  return new Date().toISOString().replace(/[:.]/g, '-').replace('T', '_').slice(0, 19);
}

export async function runCli(argv: string[]): Promise<number> {
  let args: ParsedArgs;
  try {
    args = parseArgs(argv);
  } catch (error) {
    console.error((error as Error).message);
    console.error(usage());
    return 2;
  }

  if (args.command === 'help' || args.command === '') {
    process.stdout.write(usage());
    return 0;
  }

  let config: ScanConfig | null = null;
  if (args.config) {
    const raw = fs.readFileSync(args.config, 'utf8');
    config = resolveConfig(JSON.parse(raw) as Partial<ScanConfig> & { url: string });
  }
  if (args.url) {
    config = resolveConfig({ ...(config ?? { url: '' }), url: args.url });
  }
  if (!config) {
    console.error('a scan needs --url or --config');
    console.error(usage());
    return 2;
  }

  if (args.hostMap) process.env.SCANNER_HOST_MAP = args.hostMap;

  const target = new URL(config.url);
  const outDir =
    args.out ?? path.join('runs', `${target.hostname.replace(/[^a-z0-9.-]/gi, '_')}-${timestamp()}`);
  const artefactDir = path.join(outDir, 'artefacts');
  fs.mkdirSync(outDir, { recursive: true });

  const progress = args.quiet ? () => {} : (message: string) => process.stderr.write(`· ${message}\n`);

  const outcome = await runScan({
    config,
    artefactDir,
    headless: args.headless,
    onProgress: progress,
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
    scanner: { name: 'pre-consent-privacy-scanner', version: SCANNER_VERSION, playwright: outcome.playwrightVersion },
    startedAt: outcome.startedAt,
    finishedAt: outcome.finishedAt,
    coverageNotes: outcome.coverageNotes,
  });

  const jsonPath = path.join(outDir, 'report.json');
  const mdPath = path.join(outDir, 'report.md');
  const htmlPath = path.join(outDir, 'report.html');
  fs.writeFileSync(jsonPath, renderJson(result));
  fs.writeFileSync(mdPath, renderMarkdown(result));
  fs.writeFileSync(htmlPath, renderHtml(result, { artefactRoot: artefactDir }));

  const s = result.summary;
  process.stdout.write(`\nverdict: ${s.verdict}\n`);
  process.stdout.write(
    `critical ${s.critical} · high ${s.high} · medium ${s.medium} · low ${s.low} · info ${s.info}\n`,
  );
  for (const finding of result.findings.filter((f) => f.severity === 'critical' || f.severity === 'high')) {
    process.stdout.write(`  ${finding.severity.toUpperCase()}  ${finding.title} (${finding.count})\n`);
  }
  process.stdout.write(`\nreports:\n  ${htmlPath}\n  ${mdPath}\n  ${jsonPath}\n`);

  if (s.verdict === 'FAIL') return 1;
  if (s.verdict === 'INCONCLUSIVE') return 2;
  return 0;
}

/* istanbul ignore next -- CLI plumbing */
if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
  runCli(process.argv.slice(2))
    .then((code) => process.exit(code))
    .catch((error) => {
      console.error(error);
      process.exit(2);
    });
}
