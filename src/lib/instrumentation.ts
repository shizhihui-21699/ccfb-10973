/**
 * In-page instrumentation.
 *
 * Runs in every frame of every phase before any site script. It cannot see
 * network traffic (the proxy does that); its job is *attribution*:
 *
 *  - which storage key was written, with what value, from which stack;
 *  - which cookie string was written by JavaScript;
 *  - which script called `fetch` / `sendBeacon` / `XMLHttpRequest` / WebSocket,
 *    including inside a cross-origin iframe where CDP gives no initiator.
 *
 * Each emit is a small JSON object handed to the exposed binding. The binding
 * disappears if the page navigates before the call resolves, so the binding
 * wrapper is fire-and-forget and must never throw into page code.
 *
 * The script is serialised with `Function.prototype.toString`, so it must be a
 * self-contained function with no imports or outer references.
 */
export const INSTRUMENTATION_BINDING = '__pcs_emit_7f3a';

export function makeInitScript(): string {
  const fn = function instrument(this: unknown): void {
    const BINDING = '__pcs_emit_7f3a';
    const w = window as any;
    const emit = (payload: Record<string, unknown>): void => {
      try {
        const fn = w[BINDING];
        if (typeof fn === 'function') fn(payload);
      } catch {
        /* binding gone or page froze the object */
      }
    };
    if (w.__pcsInstalled) return;
    try {
      Object.defineProperty(w, '__pcsInstalled', { value: true, enumerable: false });
    } catch {
      return;
    }

    const callerStack = (): string | null => {
      try {
        const err = new Error();
        const stack = err.stack;
        if (!stack) return null;
        const lines = stack.split('\n').slice(1);
        const frames: string[] = [];
        for (const line of lines) {
          const trimmed = line.trim();
          if (!trimmed) continue;
          // Skip frames belonging to this instrumentation shim.
          if (trimmed.includes('__pcsInstalled') || trimmed.includes('pcsEmit')) continue;
          const m = /(?:at\s+(?:.*?\s+\()?)(https?:\/\/[^)\s]+|about:[^)\s]+|blob:[^)\s]+)/.exec(trimmed);
          if (m) frames.push(m[1]!);
          else if (trimmed.startsWith('at ')) frames.push(trimmed.replace(/^at\s+/, ''));
          if (frames.length >= 4) break;
        }
        return frames.length ? frames.join(' <- ') : null;
      } catch {
        return null;
      }
    };

    const base = (): Record<string, unknown> => ({
      url: location.href,
      docHost: location.hostname,
      origin: location.origin,
      t: Date.now(),
    });

    // ---------------------------------------------------------------- storage
    try {
      const proto = Storage.prototype;
      const original = proto.setItem;
      proto.setItem = function (this: Storage, key: string, value: string) {
        try {
          let kind = 'localStorage';
          try {
            if (this === w.sessionStorage) kind = 'sessionStorage';
            else if (this !== w.localStorage) kind = 'otherStorage';
          } catch {
            /* access can throw in sandboxed frames */
          }
          const strKey = String(key);
          const strValue = String(value);
          emit({
            ...base(),
            type: 'storage',
            storage: kind,
            key: strKey,
            value: strValue.slice(0, 2048),
            valueBytes: strValue.length,
            stack: callerStack(),
          });
        } catch {
          /* never break the page */
        }
        return original.call(this, key, value);
      } as typeof proto.setItem;
    } catch {
      /* ignore */
    }

    // ---------------------------------------------------------------- IndexedDB
    try {
      const storeProto = (w as any).IDBObjectStore && (w as any).IDBObjectStore.prototype;
      if (storeProto) {
        for (const method of ['put', 'add'] as const) {
          const orig = storeProto[method];
          if (typeof orig !== 'function') continue;
          storeProto[method] = function (this: any, value: unknown, key?: unknown) {
            try {
              let preview = '';
              try {
                preview = JSON.stringify(value).slice(0, 1024);
              } catch {
                preview = String(value).slice(0, 1024);
              }
              emit({
                ...base(),
                type: 'indexeddb',
                storage: 'indexedDB',
                key: String(key ?? this.keyPath ?? this.name ?? ''),
                store: this.name,
                value: preview,
                valueBytes: preview.length,
                stack: callerStack(),
              });
            } catch {
              /* ignore */
            }
            return arguments.length > 1 ? orig.call(this, value, key) : orig.call(this, value);
          };
        }
      }
    } catch {
      /* ignore */
    }

    // ---------------------------------------------------------------- cookies
    try {
      const desc = Object.getOwnPropertyDescriptor(Document.prototype, 'cookie');
      if (desc && desc.set && desc.get) {
        Object.defineProperty(Document.prototype, 'cookie', {
          configurable: true,
          enumerable: desc.enumerable,
          get: desc.get,
          set: function (this: Document, value: string) {
            try {
              const str = String(value);
              const first = str.split(';')[0] ?? '';
              const eq = first.indexOf('=');
              emit({
                ...base(),
                type: 'cookie',
                key: eq >= 0 ? first.slice(0, eq).trim() : str.slice(0, 64),
                value: eq >= 0 ? first.slice(eq + 1).trim() : '',
                raw: str,
                stack: callerStack(),
              });
            } catch {
              /* ignore */
            }
            return desc.set!.call(this, value);
          },
        });
      }
    } catch {
      /* ignore */
    }

    // ---------------------------------------------------------------- network
    try {
      const originalFetch = w.fetch;
      if (typeof originalFetch === 'function') {
        w.fetch = function (input: any, init?: any) {
          try {
            const url = typeof input === 'string' ? input : input && input.url ? input.url : String(input);
            emit({
              ...base(),
              type: 'fetch',
              requestUrl: url,
              method: (init && init.method) || (input && input.method) || 'GET',
              keepalive: !!(init && init.keepalive),
              body: init && typeof init.body === 'string' ? init.body.slice(0, 1024) : null,
              stack: callerStack(),
            });
          } catch {
            /* ignore */
          }
          return originalFetch.apply(this, arguments as any);
        };
      }
    } catch {
      /* ignore */
    }

    try {
      const xhrProto = w.XMLHttpRequest && w.XMLHttpRequest.prototype;
      if (xhrProto) {
        const open = xhrProto.open;
        const send = xhrProto.send;
        xhrProto.open = function (this: any, method: string, url: string) {
          try {
            this.__pcs = { method: String(method), url: String(url) };
          } catch {
            /* ignore */
          }
          return open.apply(this, arguments as any);
        };
        xhrProto.send = function (this: any, body?: unknown) {
          try {
            emit({
              ...base(),
              type: 'xhr',
              requestUrl: this.__pcs ? this.__pcs.url : null,
              method: this.__pcs ? this.__pcs.method : 'GET',
              body: typeof body === 'string' ? body.slice(0, 1024) : null,
              stack: callerStack(),
            });
          } catch {
            /* ignore */
          }
          return send.apply(this, arguments as any);
        };
      }
    } catch {
      /* ignore */
    }

    try {
      const nav = w.navigator;
      const beacon = nav && nav.sendBeacon;
      if (typeof beacon === 'function') {
        nav.sendBeacon = function (url: string, data?: unknown) {
          try {
            emit({
              ...base(),
              type: 'beacon',
              requestUrl: String(url),
              method: 'POST',
              body: typeof data === 'string' ? data.slice(0, 1024) : null,
              stack: callerStack(),
            });
          } catch {
            /* ignore */
          }
          return beacon.apply(nav, arguments as any);
        };
      }
    } catch {
      /* ignore */
    }

    try {
      const WS = w.WebSocket;
      if (typeof WS === 'function') {
        w.WebSocket = new Proxy(WS, {
          construct(target, args) {
            try {
              emit({
                ...base(),
                type: 'websocket',
                requestUrl: String(args[0]),
                method: 'GET',
                stack: callerStack(),
              });
            } catch {
              /* ignore */
            }
            return Reflect.construct(target, args);
          },
        });
      }
    } catch {
      /* ignore */
    }

    // ---------------------------------------------------------------- unload
    try {
      addEventListener(
        'pagehide',
        () => {
          emit({ ...base(), type: 'pagehide', stack: callerStack() });
        },
        true,
      );
      addEventListener(
        'visibilitychange',
        () => {
          if (document.visibilityState === 'hidden') {
            emit({ ...base(), type: 'visibilityhidden', stack: null });
          }
        },
        true,
      );
    } catch {
      /* ignore */
    }
  };
  return `;(function(){
  // Some bundlers (esbuild's keepNames, used by tsx and vite in dev) rewrite
  // function literals into __name(fn, "fn"). Inside a page evaluate that
  // helper does not exist and every call throws. Defining a pass-through shim
  // keeps the serialised script correct under both plain tsc and bundlers.
  if (typeof window !== 'undefined' && typeof window.__name !== 'function') {
    window.__name = function (fn) { return fn; };
  }
  (${fn.toString()})();
})();`;
}
