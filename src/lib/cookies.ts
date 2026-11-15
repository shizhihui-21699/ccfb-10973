/**
 * Cookie and storage parsing helpers.
 *
 * `Set-Cookie` is parsed by hand rather than with a library because the scanner
 * needs every attribute verbatim for the evidence trail (a `Domain=` attribute
 * that widens a cookie to the whole site is itself a finding).
 */

export interface ParsedSetCookie {
  name: string;
  value: string;
  domain: string | null;
  path: string | null;
  secure: boolean;
  httpOnly: boolean;
  sameSite: string | null;
  maxAge: number | null;
  expires: Date | null;
  raw: string;
}

export function parseSetCookie(raw: string): ParsedSetCookie | null {
  const parts = raw.split(';');
  const first = parts.shift();
  if (!first) return null;
  const eq = first.indexOf('=');
  if (eq < 0) return null;
  const name = first.slice(0, eq).trim();
  if (!name) return null;
  const value = first.slice(eq + 1).trim();

  const parsed: ParsedSetCookie = {
    name,
    value,
    domain: null,
    path: null,
    secure: false,
    httpOnly: false,
    sameSite: null,
    maxAge: null,
    expires: null,
    raw,
  };

  for (const attr of parts) {
    const trimmed = attr.trim();
    if (!trimmed) continue;
    const idx = trimmed.indexOf('=');
    const key = (idx < 0 ? trimmed : trimmed.slice(0, idx)).trim().toLowerCase();
    const val = idx < 0 ? '' : trimmed.slice(idx + 1).trim();
    switch (key) {
      case 'domain':
        parsed.domain = val.replace(/^\./, '').toLowerCase() || null;
        break;
      case 'path':
        parsed.path = val || '/';
        break;
      case 'secure':
        parsed.secure = true;
        break;
      case 'httponly':
        parsed.httpOnly = true;
        break;
      case 'samesite':
        parsed.sameSite = val || null;
        break;
      case 'max-age': {
        const n = Number(val);
        if (Number.isFinite(n)) parsed.maxAge = n;
        break;
      }
      case 'expires': {
        const d = new Date(val);
        if (!Number.isNaN(d.getTime())) parsed.expires = d;
        break;
      }
      default:
        break;
    }
  }
  return parsed;
}

/** Parse a `Cookie:` request header into name/value pairs. */
export function parseCookieHeader(header: string | null | undefined): { name: string; value: string }[] {
  if (!header) return [];
  const out: { name: string; value: string }[] = [];
  for (const part of header.split(';')) {
    const trimmed = part.trim();
    if (!trimmed) continue;
    const eq = trimmed.indexOf('=');
    if (eq < 0) {
      out.push({ name: trimmed, value: '' });
      continue;
    }
    out.push({ name: trimmed.slice(0, eq).trim(), value: trimmed.slice(eq + 1).trim() });
  }
  return out;
}

/**
 * Redact a value while keeping enough of it to be recognisable as evidence.
 * Values that look like plain identifiers are kept (they are the whole point of
 * the finding); anything longer than 64 chars or containing whitespace is
 * truncated so accidental PII does not spread into reports.
 */
export function redactValue(value: string, keepFull = false): string {
  if (keepFull) return truncate(value, 80);
  if (value.length > 64 || /\s/.test(value)) return `${truncate(value, 48)}…`;
  return value;
}

export function truncate(s: string, n: number): string {
  return s.length <= n ? s : `${s.slice(0, n)}…(${s.length} chars)`;
}

/** Build a Cookie header that a browser would send for `domain`/`path`. */
export function cookieHeaderFor(
  jar: { name: string; value: string; domain: string; path: string; secure: boolean; expires: string | null; httpOnly: boolean }[],
  host: string,
  path: string,
  secure: boolean,
): string {
  const now = Date.now();
  return jar
    .filter((c) => {
      if (c.secure && !secure) return false;
      if (c.expires && new Date(c.expires).getTime() < now) return false;
      const d = c.domain.replace(/^\./, '');
      const hostMatch = host === d || host.endsWith(`.${d}`);
      if (!hostMatch) return false;
      const p = c.path || '/';
      if (path === p) return true;
      if (path.startsWith(p.endsWith('/') ? p : `${p}/`)) return true;
      return false;
    })
    .map((c) => `${c.name}=${c.value}`)
    .join('; ');
}
