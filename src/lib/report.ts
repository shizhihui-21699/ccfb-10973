/**
 * Report rendering.
 *
 * Three outputs from one ScanResult:
 *  - JSON   machine-readable, for ticketing and trend tracking;
 *  - Markdown  for a PR, a ticket or a legal memo;
 *  - HTML   a self-contained page (evidence embedded inline, screenshots as
 *           data URIs) that can be attached to a complaint or a review.
 *
 * Evidence is the point. Every finding carries the actual request line, the
 * Cookie header, the Set-Cookie value and the originating script, so a
 * reviewer can reproduce it by hand rather than trusting the verdict.
 */
import fs from 'node:fs';
import path from 'node:path';
import type {
  CookieRecord,
  EvidenceItem,
  Finding,
  NetworkEvent,
  ScanResult,
  StorageWrite,
} from '../types.js';
import { redactValue } from './cookies.js';

export function renderJson(result: ScanResult): string {
  return `${JSON.stringify(result, null, 2)}\n`;
}

export function renderMarkdown(result: ScanResult): string {
  const lines: string[] = [];
  const s = result.summary;

  lines.push(`# Pre-consent privacy scan — ${result.target}`);
  lines.push('');
  lines.push(`**Verdict: ${s.verdict}** · scanned ${result.startedAt} · scanner ${result.scanner.name} ${result.scanner.version}`);
  lines.push('');
  lines.push('| Severity | Count |');
  lines.push('| --- | --- |');
  for (const [label, count] of [
    ['Critical', s.critical],
    ['High', s.high],
    ['Medium', s.medium],
    ['Low', s.low],
    ['Info', s.info],
  ] as const) {
    lines.push(`| ${label} | ${count} |`);
  }
  lines.push('');
  lines.push(
    `Tracking domains seen: ${s.trackingDomains}. Requests per phase: ${s.requests
      .filter((r) => r.total > 0)
      .map((r) => `${r.phase} ${r.total} total / ${r.thirdParty} third-party / ${r.tracking} tracking`)
      .join('; ')}.`,
  );
  lines.push('');

  if (s.coverage.notes.length) {
    lines.push('## Coverage notes');
    lines.push('');
    for (const note of s.coverage.notes) lines.push(`- ${note}`);
    lines.push('');
  }

  if (result.findings.length === 0) {
    lines.push('No findings. No tracking mechanism was observed before consent or after rejection.');
    lines.push('');
  }

  for (const finding of result.findings) {
    lines.push(`## ${severityBadge(finding.severity)} ${finding.title}`);
    lines.push('');
    lines.push(`- **Code**: \`${finding.code}\``);
    lines.push(`- **Phase**: ${finding.phase}`);
    if (finding.domain) lines.push(`- **Domain**: \`${finding.domain}\``);
    if (finding.purpose) lines.push(`- **Purpose**: ${finding.purpose}`);
    if (finding.firstAtMs !== null) lines.push(`- **First seen**: ${finding.firstAtMs} ms after page load`);
    if (finding.count > 1) lines.push(`- **Occurrences**: ${finding.count}`);
    lines.push('');
    lines.push(finding.detail);
    lines.push('');
    lines.push(`**Why it matters.** ${finding.impact}`);
    lines.push('');
    lines.push(`**Recommendation.** ${finding.recommendation}`);
    lines.push('');
    lines.push('**Evidence**');
    lines.push('');
    for (const item of finding.evidence.items) {
      lines.push(...renderEvidenceMarkdown(item));
      lines.push('');
    }
  }

  lines.push('## Vendor matrix');
  lines.push('');
  lines.push('| Domain | Purpose | Party | Pre-consent | After reject | After accept | Verdict |');
  lines.push('| --- | --- | --- | --- | --- | --- | --- |');
  for (const v of result.vendors) {
    lines.push(
      `| \`${v.domain}\` | ${v.purpose} | ${v.party} | ${v.preConsentRequests} | ${v.postRejectRequests} | ${v.postConsentRequests} | ${v.verdict} |`,
    );
  }
  lines.push('');

  lines.push('## Method');
  lines.push('');
  lines.push(
    'The page was opened three times, each in a clean browser profile: once without touching the consent interface, once after clicking reject (followed by a reload, as a visitor would), and once after clicking accept. All traffic was captured at the network layer through a TLS-intercepting proxy, so requests that the browser\'s own event APIs drop — most importantly `sendBeacon` during page teardown — are still recorded. Cookies were read from the browser jar and from raw `Set-Cookie` headers; storage writes were captured by instrumenting `localStorage`/`sessionStorage`/IndexedDB before any site script ran.',
  );
  lines.push('');
  return lines.join('\n');
}

function renderEvidenceMarkdown(item: EvidenceItem): string[] {
  switch (item.kind) {
    case 'request': {
      const r = item.request;
      const out = [
        '```',
        `${r.method} ${r.url}`,
        `host: ${r.host}   party: ${r.party}   purpose: ${r.purpose}   status: ${r.status ?? 'no response'}   at: ${r.atMs} ms`,
      ];
      if (r.cookieHeader) out.push(`Cookie: ${r.cookieHeader}`);
      if (r.referer) out.push(`Referer: ${r.referer}`);
      if (r.requestBody) out.push(`body: ${redactValue(r.requestBody, true)}`);
      if (r.attribution.initiatorUrl) out.push(`initiator: ${r.attribution.initiatorUrl}`);
      if (r.attribution.frameUrl) out.push(`frame: ${r.attribution.frameUrl}`);
      out.push('```');
      return out;
    }
    case 'cookie': {
      const c = item.cookie;
      return [
        '```',
        `${c.name}=${redactValue(c.value)}   domain=${c.domain}   path=${c.path ?? '/'}   party=${c.party}   purpose=${c.purpose}`,
        `secure=${c.secure} httpOnly=${c.httpOnly} sameSite=${c.sameSite ?? '-'} session=${c.session}`,
        c.setByUrl ? `set by: ${c.setByUrl}${c.atMs !== null ? ` at ${c.atMs} ms` : ''}` : 'origin: not observed being set (jar snapshot)',
        '```',
      ];
    }
    case 'storage': {
      const w = item.write;
      return [
        '```',
        `${w.storage}.setItem("${w.key}", ${redactValue(w.valuePreview)})   at ${w.atMs} ms`,
        `document: ${w.documentUrl}   party=${w.party}   purpose=${w.purpose}`,
        `origin: ${w.origin}`,
        '```',
      ];
    }
    case 'screenshot':
      return [`![${item.label}](${item.file})`];
    case 'text':
      return [`**${item.label}**`, '', '```', item.text, '```'];
  }
}

function severityBadge(severity: Finding['severity']): string {
  switch (severity) {
    case 'critical':
      return '🔴 CRITICAL';
    case 'high':
      return '🟠 HIGH';
    case 'medium':
      return '🟡 MEDIUM';
    case 'low':
      return '🔵 LOW';
    default:
      return 'ℹ️ INFO';
  }
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function readScreenshotDataUri(artefactRoot: string, file: string): string | null {
  try {
    const p = path.join(artefactRoot, file);
    const buf = fs.readFileSync(p);
    return `data:image/png;base64,${buf.toString('base64')}`;
  } catch {
    return null;
  }
}

export function renderHtml(result: ScanResult, options: { artefactRoot: string }): string {
  const s = result.summary;
  const findingsHtml = result.findings
    .map((finding) => {
      const evidence = finding.evidence.items
        .map((item) => renderEvidenceHtml(item, options.artefactRoot))
        .join('');
      return `<article class="finding sev-${finding.severity}">
  <header>
    <span class="sev">${escapeHtml(finding.severity.toUpperCase())}</span>
    <h2>${escapeHtml(finding.title)}</h2>
  </header>
  <dl class="meta">
    <div><dt>Code</dt><dd><code>${escapeHtml(finding.code)}</code></dd></div>
    <div><dt>Phase</dt><dd>${escapeHtml(finding.phase)}</dd></div>
    ${finding.domain ? `<div><dt>Domain</dt><dd><code>${escapeHtml(finding.domain)}</code></dd></div>` : ''}
    ${finding.purpose ? `<div><dt>Purpose</dt><dd>${escapeHtml(finding.purpose)}</dd></div>` : ''}
    <div><dt>Occurrences</dt><dd>${finding.count}</dd></div>
    ${finding.firstAtMs !== null ? `<div><dt>First seen</dt><dd>${finding.firstAtMs} ms</dd></div>` : ''}
  </dl>
  <p class="detail">${escapeHtml(finding.detail)}</p>
  <p class="impact"><strong>Why it matters.</strong> ${escapeHtml(finding.impact)}</p>
  <p class="rec"><strong>Recommendation.</strong> ${escapeHtml(finding.recommendation)}</p>
  <h3>Evidence</h3>
  ${evidence || '<p class="muted">No artefacts captured.</p>'}
</article>`;
    })
    .join('\n');

  const vendorRows = result.vendors
    .map(
      (v) => `<tr class="${v.tracking ? 'tracking' : ''}">
      <td><code>${escapeHtml(v.domain)}</code></td>
      <td>${escapeHtml(v.purpose)}</td>
      <td>${escapeHtml(v.party)}</td>
      <td class="num">${v.preConsentRequests}</td>
      <td class="num">${v.postRejectRequests}</td>
      <td class="num">${v.postConsentRequests}</td>
      <td><span class="verdict ${v.verdict}">${escapeHtml(v.verdict)}</span></td>
    </tr>`,
    )
    .join('\n');

  const phaseRows = s.requests
    .map(
      (r) =>
        `<tr><td>${escapeHtml(r.phase)}</td><td class="num">${r.total}</td><td class="num">${r.thirdParty}</td><td class="num">${r.tracking}</td></tr>`,
    )
    .join('\n');

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Pre-consent scan — ${escapeHtml(result.target)}</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  :root { color-scheme: light dark; --bg:#ffffff; --fg:#16181d; --muted:#6b7280; --line:#e5e7eb; --panel:#f9fafb;
          --critical:#b91c1c; --high:#c2410c; --medium:#a16207; --low:#1d4ed8; --info:#4b5563; --ok:#15803d; }
  @media (prefers-color-scheme: dark) {
    :root { --bg:#0f1115; --fg:#e6e8ee; --muted:#9aa3b2; --line:#262b36; --panel:#161a22;
            --critical:#f87171; --high:#fb923c; --medium:#fbbf24; --low:#60a5fa; --info:#9ca3af; --ok:#4ade80; }
  }
  * { box-sizing: border-box; }
  body { margin:0; background:var(--bg); color:var(--fg); font:15px/1.6 system-ui, -apple-system, Segoe UI, sans-serif; }
  .wrap { max-width: 1040px; margin: 0 auto; padding: 32px 24px 64px; }
  h1 { font-size: 26px; margin: 0 0 4px; letter-spacing: -0.01em; }
  .target { font-family: ui-monospace, monospace; color: var(--muted); font-size: 14px; word-break: break-all; }
  .summary { display: flex; flex-wrap: wrap; gap: 12px; margin: 24px 0 8px; }
  .stat { border:1px solid var(--line); background:var(--panel); border-radius:10px; padding:12px 16px; min-width:128px; }
  .stat .n { font-size: 24px; font-weight:650; display:block; line-height:1.2; }
  .stat .l { font-size: 12px; color: var(--muted); text-transform: uppercase; letter-spacing:.06em; }
  .verdict { display:inline-block; border-radius:8px; padding:6px 12px; font-weight:650; letter-spacing:.04em; }
  .verdict.PASS { background: color-mix(in srgb, var(--ok) 16%, transparent); color: var(--ok); }
  .verdict.FAIL { background: color-mix(in srgb, var(--critical) 18%, transparent); color: var(--critical); }
  .verdict.INCONCLUSIVE { background: color-mix(in srgb, var(--medium) 18%, transparent); color: var(--medium); }
  section { margin-top: 40px; min-width: 0; }
  section, article, dl.meta, .detail, .impact, .rec { overflow-wrap: anywhere; }
  h2.sec { font-size: 18px; text-transform: uppercase; letter-spacing:.08em; color: var(--muted); border-bottom:1px solid var(--line); padding-bottom:8px; }
  article.finding { border:1px solid var(--line); border-left:5px solid var(--info); border-radius:10px; padding:18px 20px; margin:16px 0; background:var(--panel); min-width: 0; }
  .sev-critical { border-left-color: var(--critical); } .sev-high { border-left-color: var(--high); }
  .sev-medium { border-left-color: var(--medium); } .sev-low { border-left-color: var(--low); }
  article header { display:flex; gap:10px; align-items:baseline; margin-bottom:8px; }
  article h2 { font-size:17px; margin:0; }
  .sev { font-size:11px; font-weight:700; letter-spacing:.08em; color:var(--muted); }
  dl.meta { display:flex; flex-wrap:wrap; gap:8px 24px; margin:0 0 12px; font-size:13px; }
  dl.meta div { display:flex; gap:6px; min-width: 0; max-width: 100%; flex-wrap: wrap; }
  dl.meta dt { color:var(--muted); } dl.meta dd { margin:0; }
  .detail, .impact, .rec { margin:10px 0; }
  .detail { font-size:14px; }
  h3 { font-size:13px; text-transform:uppercase; letter-spacing:.06em; color:var(--muted); margin:16px 0 8px; }
  pre { background: var(--bg); border:1px solid var(--line); border-radius:8px; padding:12px; overflow-x:auto; font:12.5px/1.5 ui-monospace, monospace; margin:0 0 12px; }
  pre.evidence { white-space: pre-wrap; word-break: break-word; }
  img.shot { max-width:100%; border:1px solid var(--line); border-radius:8px; margin:8px 0; display:block; }
  table { width:100%; border-collapse:collapse; font-size:13px; margin-top:12px; display:block; overflow-x:auto; }
  th, td { text-align:left; padding:8px 10px; border-bottom:1px solid var(--line); white-space:nowrap; }
  th { color:var(--muted); font-weight:600; text-transform:uppercase; font-size:11px; letter-spacing:.05em; }
  td.num { text-align:right; font-variant-numeric: tabular-nums; }
  .verdict.fires-before-consent { color:var(--critical); } .verdict.fires-after-reject { color:var(--high); }
  .verdict.blocked-until-consent { color:var(--ok); } .verdict.unknown { color:var(--muted); }
  .muted { color:var(--muted); font-size:13px; }
  ul.notes { margin:8px 0 0; padding-left:20px; font-size:13.5px; color:var(--muted); }
  .method { font-size:13.5px; color:var(--muted); border-top:1px solid var(--line); margin-top:40px; padding-top:16px; }
</style>
</head>
<body>
<div class="wrap">
  <h1>Pre-consent privacy scan</h1>
  <p class="target">${escapeHtml(result.target)}</p>
  <p><span class="verdict ${s.verdict}">${s.verdict}</span></p>

  <div class="summary">
    <div class="stat"><span class="n">${s.critical}</span><span class="l">Critical</span></div>
    <div class="stat"><span class="n">${s.high}</span><span class="l">High</span></div>
    <div class="stat"><span class="n">${s.medium}</span><span class="l">Medium</span></div>
    <div class="stat"><span class="n">${s.low}</span><span class="l">Low</span></div>
    <div class="stat"><span class="n">${s.trackingDomains}</span><span class="l">Tracking domains</span></div>
  </div>

  <section>
    <h2 class="sec">Requests per phase</h2>
    <table>
      <thead><tr><th>Phase</th><th>Total</th><th>Third-party</th><th>Tracking</th></tr></thead>
      <tbody>${phaseRows}</tbody>
    </table>
    ${s.coverage.notes.length ? `<ul class="notes">${s.coverage.notes.map((n) => `<li>${escapeHtml(n)}</li>`).join('')}</ul>` : ''}
  </section>

  <section>
    <h2 class="sec">Findings (${result.findings.length})</h2>
    <p class="muted">Each finding is grouped by tracking endpoint and phase. Evidence items are the actual requests,
    cookies and storage writes observed, not summaries.</p>
    ${findingsHtml || '<p class="muted">No findings: no tracking mechanism was active before consent or after rejection.</p>'}
  </section>

  <section>
    <h2 class="sec">Vendor matrix</h2>
    <table>
      <thead><tr><th>Domain</th><th>Purpose</th><th>Party</th><th>Pre-consent</th><th>After reject</th><th>After accept</th><th>Verdict</th></tr></thead>
      <tbody>${vendorRows}</tbody>
    </table>
  </section>

  <p class="method">
    <strong>Method.</strong> Three clean browser profiles: no consent interaction, reject-then-reload, accept-then-reload.
    Traffic was captured at the network layer through a TLS-intercepting proxy, so requests the browser's own APIs drop —
    most importantly <code>sendBeacon</code> during teardown — are still recorded. Cookies come from the browser jar and
    from raw <code>Set-Cookie</code> headers; storage writes were captured by instrumenting
    <code>localStorage</code>, <code>sessionStorage</code> and IndexedDB before any site script ran.
    Report generated ${escapeHtml(result.finishedAt)} by ${escapeHtml(result.scanner.name)} ${escapeHtml(result.scanner.version)}.
  </p>
</div>
</body>
</html>
`;
}

function renderEvidenceHtml(item: EvidenceItem, artefactRoot: string): string {
  switch (item.kind) {
    case 'request': {
      const r: NetworkEvent = item.request;
      const lines = [
        `${r.method} ${r.url}`,
        `host: ${r.host}   party: ${r.party}   purpose: ${r.purpose}   status: ${r.status ?? 'no response'}   at: ${r.atMs} ms`,
      ];
      if (r.cookieHeader) lines.push(`Cookie: ${redactValue(r.cookieHeader, true)}`);
      if (r.referer) lines.push(`Referer: ${redactValue(r.referer, true)}`);
      if (r.requestBody) lines.push(`body: ${redactValue(r.requestBody, true)}`);
      if (r.attribution.initiatorUrl) lines.push(`initiator: ${r.attribution.initiatorUrl}`);
      if (r.attribution.frameUrl) lines.push(`frame: ${r.attribution.frameUrl}`);
      return `<pre class="evidence">${escapeHtml(lines.join('\n'))}</pre>`;
    }
    case 'cookie': {
      const c: CookieRecord = item.cookie;
      const lines = [
        `${c.name}=${redactValue(c.value)}   domain=${c.domain}   path=${c.path ?? '/'}   party=${c.party}   purpose=${c.purpose}`,
        `secure=${c.secure} httpOnly=${c.httpOnly} sameSite=${c.sameSite ?? '-'} session=${c.session}`,
        c.setByUrl
          ? `set by: ${c.setByUrl}${c.atMs !== null ? ` at ${c.atMs} ms` : ''}`
          : 'origin: not observed being set (jar snapshot)',
      ];
      return `<pre class="evidence">${escapeHtml(lines.join('\n'))}</pre>`;
    }
    case 'storage': {
      const w: StorageWrite = item.write;
      const lines = [
        `${w.storage}.setItem("${w.key}", ${redactValue(w.valuePreview)})   at ${w.atMs} ms`,
        `document: ${w.documentUrl}   party=${w.party}   purpose=${w.purpose}`,
        `origin: ${w.origin}`,
      ];
      return `<pre class="evidence">${escapeHtml(lines.join('\n'))}</pre>`;
    }
    case 'screenshot': {
      const data = readScreenshotDataUri(artefactRoot, item.file);
      const shown = data ? `<img class="shot" alt="${escapeHtml(item.label)}" src="${data}">` : `<p class="muted">${escapeHtml(item.file)} (not embedded)</p>`;
      return `<figure><figcaption class="muted">${escapeHtml(item.label)}</figcaption>${shown}</figure>`;
    }
    case 'text':
      return `<p class="muted"><strong>${escapeHtml(item.label)}</strong></p><pre class="evidence">${escapeHtml(item.text)}</pre>`;
  }
}
