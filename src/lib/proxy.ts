/**
 * TLS-intercepting HTTP proxy.
 *
 * This is the scanner's authoritative capture channel. Browser-side APIs
 * (Playwright's request events, CDP `Network`) are good at attribution but
 * provably lose requests fired during unload (e.g. `sendBeacon` in `pagehide`),
 * and they cannot see raw `Set-Cookie` headers from every response. A proxy
 * sees what actually left the machine, which is what a regulator means by
 * "was data sent before consent".
 *
 * Design notes
 * - Plain `http://` requests are proxied by `http.createServer`'s `request`
 *   handler (absolute-form request target).
 * - `https://` requests arrive as a `CONNECT` tunnel. We answer 200, wrap the
 *   socket in a TLS server side with a leaf certificate signed by the scan CA,
 *   and hand the socket to an internal `http.Server`. Using Node's own HTTP
 *   parser means chunked encoding, keep-alive and trailers are handled correctly
 *   instead of re-implemented.
 * - Every exchange is recorded at request start, so a request whose response
 *   never returns (aborted beacon, dead tracker) still appears with its
 *   pathological status visible.
 */
import http from 'node:http';
import https from 'node:https';
import tls from 'node:tls';
import net from 'node:net';
import zlib from 'node:zlib';
import { randomUUID } from 'node:crypto';
import type { AddressInfo } from 'node:net';
import { leafFor, type CaMaterial } from './ca.js';

const MAX_BODY_BYTES = 64 * 1024;
const MAX_CAPTURE_BYTES = 16 * 1024;
const HOP_BY_HOP = new Set([
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'proxy-connection',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
]);

export interface ProxyExchange {
  id: string;
  startedAt: number;
  endedAt: number | null;
  scheme: 'http' | 'https';
  host: string;
  port: number;
  method: string;
  path: string;
  requestHeaders: Record<string, string>;
  requestBody: string | null;
  requestBodyTruncated: boolean;
  status: number | null;
  responseHeaders: Record<string, string>;
  setCookies: string[];
  responseBody: string | null;
  aborted: boolean;
  error: string | null;
  viaConnect: boolean;
  /** Host the browser believed it was connecting to (CONNECT authority). */
  tunnelHost: string | null;
}

export interface ProxyOptions {
  ca: CaMaterial;
  /** host -> IP override, needed for fixtures with synthetic domains. */
  upstreamHostMap?: Record<string, string>;
  /** Verify upstream certificates. Off by default so scans work against staging. */
  verifyUpstream?: boolean;
  /** Sink for every recorded exchange, called once it is finalised. */
  onExchange?: (exchange: ProxyExchange) => void;
  /** Called the moment the request starts, before the response is known. */
  onRequestStart?: (exchange: ProxyExchange) => void;
  /**
   * Send `Sec-GPC: 1` upstream. Chromium exposes
   * `navigator.globalPrivacyControl` to page script but does not emit the
   * header itself, so a server-side opt-out check would never see the signal.
   */
  sendGpcHeader?: boolean;
}

function lowerHeaders(raw: string[], skip: Set<string> = HOP_BY_HOP): Record<string, string> {
  const out: Record<string, string> = {};
  for (let i = 0; i + 1 < raw.length; i += 2) {
    const name = raw[i]!.toLowerCase();
    if (skip.has(name)) continue;
    const value = raw[i + 1]!;
    out[name] = name in out ? `${out[name]}, ${value}` : value;
  }
  return out;
}

function rawHeaderList(headers: Record<string, string>): string[] {
  const out: string[] = [];
  for (const [k, v] of Object.entries(headers)) out.push(k, v);
  return out;
}

function decodeBody(buf: Buffer, headers: Record<string, string>): string | null {
  const encoding = (headers['content-encoding'] ?? '').toLowerCase();
  let data = buf;
  try {
    if (encoding.includes('br')) data = zlib.brotliDecompressSync(buf);
    else if (encoding.includes('gzip')) data = zlib.gunzipSync(buf);
    else if (encoding.includes('deflate')) data = zlib.inflateSync(buf);
    else if (encoding.includes('zstd') && typeof (zlib as any).zstdDecompressSync === 'function') {
      data = (zlib as any).zstdDecompressSync(buf);
    }
  } catch {
    return null;
  }
  if (data.length === 0) return '';
  const slice = data.subarray(0, MAX_CAPTURE_BYTES);
  if (slice.includes(0)) return null;
  const text = slice.toString('utf8');
  return text.includes('�') ? null : text;
}

function truncate(buf: Buffer, limit = MAX_CAPTURE_BYTES): { text: string | null; truncated: boolean } {
  if (buf.length === 0) return { text: '', truncated: false };
  const slice = buf.subarray(0, limit);
  if (slice.includes(0)) return { text: null, truncated: buf.length > limit };
  return { text: slice.toString('utf8'), truncated: buf.length > limit };
}

function authorityHostPort(host: string, port: number): string {
  return port === 80 || port === 443 ? host : `${host}:${port}`;
}

export class InterceptProxy {
  private readonly options: ProxyOptions;
  /** Mutable sinks: the scanner points these at the active phase recorder. */
  onExchange?: (exchange: ProxyExchange) => void;
  onRequestStart?: (exchange: ProxyExchange) => void;
  private readonly server: http.Server;
  private readonly tlsServer: http.Server;
  private readonly sockets = new Set<net.Socket>();
  private readonly upstreamAgent: https.Agent;
  private readonly plainAgent: http.Agent;
  private port: number | null = null;
  private started = false;

  constructor(options: ProxyOptions) {
    this.options = options;
    this.upstreamAgent = new https.Agent({
      keepAlive: true,
      maxSockets: 48,
      rejectUnauthorized: options.verifyUpstream ?? false,
    });
    // Plain HTTP needs its own agent: passing an https.Agent to http.request
    // throws ERR_INVALID_PROTOCOL and would abort every non-TLS target.
    this.plainAgent = new http.Agent({ keepAlive: true, maxSockets: 48 });

    this.server = http.createServer((req, res) => this.handlePlain(req, res));
    this.server.on('connect', (req, socket, head) => this.handleConnect(req, socket as net.Socket, head));
    this.server.on('connection', (socket) => this.trackSocket(socket));
    this.server.on('clientError', (_err, socket) => {
      socket.destroy();
    });

    this.tlsServer = http.createServer((req, res) => this.handleTunneled(req, res));
    this.tlsServer.on('upgrade', (req, socket, head) =>
      void this.handleUpgrade(req, socket as net.Socket, head, true),
    );
    this.tlsServer.on('clientError', (_err, socket) => socket.destroy());
  }

  get address(): { host: string; port: number } {
    if (this.port === null) throw new Error('proxy is not listening');
    return { host: '127.0.0.1', port: this.port };
  }

  /** The proxy URL for Playwright's `proxy.server`. */
  get url(): string {
    return `http://127.0.0.1:${this.address.port}`;
  }

  async start(port = 0): Promise<this> {
    if (this.started) return this;
    await new Promise<void>((resolve, reject) => {
      const onError = (err: Error) => reject(err);
      this.server.once('error', onError);
      this.server.listen(port, '127.0.0.1', () => {
        this.server.off('error', onError);
        resolve();
      });
    });
    this.port = (this.server.address() as AddressInfo).port;
    this.started = true;
    return this;
  }

  async stop(): Promise<void> {
    if (!this.started) return;
    this.started = false;
    for (const socket of this.sockets) socket.destroy();
    this.sockets.clear();
    this.upstreamAgent.destroy();
    this.plainAgent.destroy();
    await new Promise<void>((resolve) => this.server.close(() => resolve()));
    await new Promise<void>((resolve) => this.tlsServer.close(() => resolve()));
  }

  private trackSocket(socket: net.Socket): void {
    this.sockets.add(socket);
    socket.on('close', () => this.sockets.delete(socket));
    socket.on('error', () => {});
  }

  private resolveUpstream(host: string): string {
    return this.options.upstreamHostMap?.[host] ?? host;
  }

  // ---------------------------------------------------------------- plain HTTP

  private handlePlain(req: http.IncomingMessage, res: http.ServerResponse): void {
    let target: URL;
    try {
      target = new URL(req.url!, `http://${req.headers.host ?? 'unknown'}`);
    } catch {
      res.writeHead(400).end('bad request target');
      return;
    }
    this.exchange(
      {
        scheme: 'http',
        host: target.hostname,
        port: Number(target.port || 80),
        method: req.method ?? 'GET',
        path: target.pathname + target.search,
        headers: lowerHeaders(req.rawHeaders),
        bodyStream: req,
        viaConnect: false,
        tunnelHost: null,
      },
      res,
    );
  }

  // ---------------------------------------------------------------- CONNECT

  private handleConnect(req: http.IncomingMessage, socket: net.Socket, head: Buffer): void {
    const authority = req.url ?? '';
    const match = /^([^:]+):(\d+)$/.exec(authority);
    if (!match) {
      socket.end('HTTP/1.1 400 Bad Request\r\n\r\n');
      return;
    }
    const host = match[1]!;
    const port = Number(match[2]);

    socket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
    if (head?.length) socket.unshift(head);

    const leaf = leafFor(this.options.ca, host);
    const secure = new tls.TLSSocket(socket, {
      isServer: true,
      secureContext: tls.createSecureContext({ key: leaf.keyPem, cert: leaf.certPem }),
      requestCert: false,
    });
    this.trackSocket(secure);
    secure.once('secure', () => {
      (secure as any).__tunnelHost = host;
      (secure as any).__tunnelPort = port;
      this.tlsServer.emit('connection', secure);
    });
    secure.once('error', () => socket.destroy());
    // A TLS server socket only starts handshaking once it resumes.
    secure.resume();
  }

  private handleTunneled(req: http.IncomingMessage, res: http.ServerResponse): void {
    const sock = req.socket as any;
    const tunnelHost = (sock.__tunnelHost as string) ?? (req.headers.host ?? '').split(':')[0] ?? '';
    const tunnelPort = (sock.__tunnelPort as number) ?? 443;
    let path = req.url ?? '/';
    let host = tunnelHost;
    let port = tunnelPort;
    if (path.startsWith('http://') || path.startsWith('https://')) {
      const parsed = new URL(path);
      host = parsed.hostname;
      port = Number(parsed.port || 443);
      path = parsed.pathname + parsed.search;
    }
    this.exchange(
      {
        scheme: 'https',
        host,
        port,
        method: req.method ?? 'GET',
        path,
        headers: lowerHeaders(req.rawHeaders),
        bodyStream: req,
        viaConnect: true,
        tunnelHost,
      },
      res,
    );
  }

  // ---------------------------------------------------------------- exchange

  private exchange(
    input: {
      scheme: 'http' | 'https';
      host: string;
      port: number;
      method: string;
      path: string;
      headers: Record<string, string>;
      bodyStream: http.IncomingMessage;
      viaConnect: boolean;
      tunnelHost: string | null;
    },
    clientRes: http.ServerResponse,
  ): void {
    const startedAt = Date.now();
    const requestChunks: Buffer[] = [];
    let requestBytes = 0;

    const record: ProxyExchange = {
      id: randomUUID(),
      startedAt,
      endedAt: null,
      scheme: input.scheme,
      host: input.host,
      port: input.port,
      method: input.method,
      path: input.path,
      requestHeaders: input.headers,
      requestBody: null,
      requestBodyTruncated: false,
      status: null,
      responseHeaders: {},
      setCookies: [],
      responseBody: null,
      aborted: false,
      error: null,
      viaConnect: input.viaConnect,
      tunnelHost: input.tunnelHost,
    };
    this.onRequestStart?.(record);

    let completed = false;
    const finish = () => {
      if (completed) return;
      completed = true;
      record.endedAt = Date.now();
      const body = Buffer.concat(requestChunks);
      const t = truncate(body, MAX_BODY_BYTES);
      record.requestBody = t.text;
      record.requestBodyTruncated = t.truncated;
      this.onExchange?.(record);
    };

    input.bodyStream.on('data', (chunk: Buffer) => {
      if (requestBytes <= MAX_BODY_BYTES) {
        requestChunks.push(chunk);
        requestBytes += chunk.length;
      }
    });
    input.bodyStream.on('aborted', () => {
      record.aborted = true;
    });

    const headers: Record<string, string> = { ...input.headers };
    for (const name of HOP_BY_HOP) delete headers[name];
    headers['host'] = authorityHostPort(input.host, input.port);
    if (this.options.sendGpcHeader && !headers['sec-gpc']) {
      headers['sec-gpc'] = '1';
      // Record the injected header on the wire record, marked so the report
      // can distinguish browser-sent headers from scanner-sent ones.
      record.requestHeaders['sec-gpc'] = '1 (injected by scanner)';
    }

    const upstreamOptions: https.RequestOptions = {
      host: this.resolveUpstream(input.host),
      port: input.port,
      method: input.method,
      path: input.path,
      headers,
      servername: input.host,
      rejectUnauthorized: this.options.verifyUpstream ?? false,
      agent: input.scheme === 'https' ? this.upstreamAgent : this.plainAgent,
      timeout: 20_000,
    };

    const upstreamReq = (input.scheme === 'https' ? https.request : http.request)(
      upstreamOptions as https.RequestOptions,
      (upstreamRes) => {
        record.status = upstreamRes.statusCode ?? null;
        const respHeaders = lowerHeaders(upstreamRes.rawHeaders);
        record.responseHeaders = respHeaders;
        const rawSetCookie: string[] = [];
        for (let i = 0; i + 1 < upstreamRes.rawHeaders.length; i += 2) {
          if (upstreamRes.rawHeaders[i]!.toLowerCase() === 'set-cookie') {
            rawSetCookie.push(upstreamRes.rawHeaders[i + 1]!);
          }
        }
        record.setCookies = rawSetCookie;

        const chunks: Buffer[] = [];
        let bytes = 0;
        upstreamRes.on('data', (chunk: Buffer) => {
          if (bytes < MAX_CAPTURE_BYTES) {
            chunks.push(chunk);
            bytes += chunk.length;
          }
        });
        upstreamRes.on('end', () => {
          record.responseBody = decodeBody(Buffer.concat(chunks), respHeaders);
        });
        upstreamRes.on('error', () => {});

        // Relay: drop hop-by-hop framing so Node re-frames the body correctly.
        const outHeaders: Record<string, string> = { ...respHeaders };
        for (const name of HOP_BY_HOP) delete outHeaders[name];
        delete outHeaders['content-length'];
        clientRes.writeHead(upstreamRes.statusCode ?? 502, rawHeaderList(outHeaders));
        upstreamRes.pipe(clientRes);
        upstreamRes.on('end', finish);
        upstreamRes.on('aborted', () => {
          record.aborted = true;
          finish();
        });
      },
    );

    upstreamReq.on('timeout', () => {
      record.error = 'upstream timeout';
      upstreamReq.destroy(new Error('upstream timeout'));
    });
    upstreamReq.on('error', (err: NodeJS.ErrnoException) => {
      record.error = `${err.code ?? 'ERR'} ${err.message}`;
      if (!clientRes.headersSent) {
        try {
          clientRes.writeHead(502, { 'content-type': 'text/plain' });
          clientRes.end('upstream proxy error');
        } catch {
          /* client already gone */
        }
      } else {
        clientRes.destroy();
      }
      finish();
    });

    input.bodyStream.pipe(upstreamReq);
    input.bodyStream.on('end', () => {
      // A request with no response yet is finalised once the response arrives.
      // If the client disconnects first, `clientRes` close handles it.
    });

    clientRes.on('close', () => {
      if (!completed && record.status === null) {
        record.aborted = true;
        finish();
      }
    });
  }

  // ---------------------------------------------------------------- upgrades

  private async handleUpgrade(
    req: http.IncomingMessage,
    socket: net.Socket,
    head: Buffer,
    isSecure: boolean,
  ): Promise<void> {
    const sock = req.socket as any;
    const tunnelHost = (sock.__tunnelHost as string) ?? (req.headers.host ?? '').split(':')[0] ?? '';
    const tunnelPort = (sock.__tunnelPort as number) ?? 443;
    const record: ProxyExchange = {
      id: randomUUID(),
      startedAt: Date.now(),
      endedAt: null,
      scheme: isSecure ? 'https' : 'http',
      host: tunnelHost,
      port: tunnelPort,
      method: req.method ?? 'GET',
      path: req.url ?? '/',
      requestHeaders: lowerHeaders(req.rawHeaders),
      requestBody: null,
      requestBodyTruncated: false,
      status: 101,
      responseHeaders: {},
      setCookies: [],
      responseBody: null,
      aborted: false,
      error: null,
      viaConnect: isSecure,
      tunnelHost: isSecure ? tunnelHost : null,
    };
    this.onExchange?.(record);

    const connectOpts = {
      host: this.resolveUpstream(tunnelHost),
      port: tunnelPort,
      servername: tunnelHost,
      rejectUnauthorized: this.options.verifyUpstream ?? false,
    };
    const upstream: net.Socket | tls.TLSSocket = isSecure
      ? tls.connect(connectOpts, onConnected)
      : net.connect(connectOpts, onConnected);

    let connected = false;
    const sendGpc = this.options.sendGpcHeader === true;
    function onConnected(): void {
      if (connected) return;
      connected = true;
      const headers = lowerHeaders(req.rawHeaders, new Set(['proxy-connection']));
      delete headers['content-length'];
      delete headers['host'];
      headers['host'] = authorityHostPort(tunnelHost, tunnelPort);
      if (sendGpc && !headers['sec-gpc']) {
        headers['sec-gpc'] = '1';
        record.requestHeaders['sec-gpc'] = '1 (injected by scanner)';
      }
      upstream.write(`${req.method} ${req.url} HTTP/1.1\r\n`);
      for (const [k, v] of Object.entries(headers)) upstream.write(`${k}: ${v}\r\n`);
      upstream.write('\r\n');
      if (head?.length) upstream.write(head);
      upstream.pipe(socket);
      socket.pipe(upstream);
      record.endedAt = Date.now();
    }
    upstream.on('error', (err) => {
      record.error = err.message;
      socket.destroy();
    });
    socket.on('error', () => upstream.destroy());
  }
}
