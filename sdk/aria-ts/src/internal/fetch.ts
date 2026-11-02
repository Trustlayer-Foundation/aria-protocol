/** Bounds on one fetch: an exact origin from the trusted configuration, no redirects, a time and a size. */
export interface Bounds {
  readonly allowedOrigins: readonly string[];
  readonly timeoutMs: number;
  readonly maxBytes: number;
  readonly fetch: typeof fetch;
}

export type Fetched = { readonly ok: true; readonly body: Uint8Array } | { readonly ok: false; readonly reason: 'origin_not_allowed' | 'fetch_failed' | 'too_large' };

/** GETs `url` over HTTPS from an allowed origin, refusing redirects and bodies over the bound. */
export async function boundedGet(url: string, bounds: Bounds): Promise<Fetched> {
  let target: URL;
  try {
    target = new URL(url);
  } catch {
    return { ok: false, reason: 'origin_not_allowed' };
  }
  if (target.protocol !== 'https:' || !bounds.allowedOrigins.includes(target.origin)) return { ok: false, reason: 'origin_not_allowed' };
  const abort = new AbortController();
  const timer = setTimeout(() => abort.abort(), bounds.timeoutMs);
  try {
    const response = await bounds.fetch(target.href, { redirect: 'error', signal: abort.signal, headers: { accept: 'application/json' } });
    if (response.status !== 200 || !response.body) return { ok: false, reason: 'fetch_failed' };
    const declared = Number(response.headers.get('content-length') ?? '0');
    if (declared > bounds.maxBytes) return { ok: false, reason: 'too_large' };
    const chunks: Uint8Array[] = [];
    let size = 0;
    const reader = response.body.getReader();
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > bounds.maxBytes) {
        await reader.cancel();
        return { ok: false, reason: 'too_large' };
      }
      chunks.push(value);
    }
    const body = new Uint8Array(size);
    let at = 0;
    for (const c of chunks) {
      body.set(c, at);
      at += c.byteLength;
    }
    return { ok: true, body };
  } catch {
    return { ok: false, reason: 'fetch_failed' };
  } finally {
    clearTimeout(timer);
  }
}

/** Gunzips at most `maxBytes`; `null` if the data is not GZIP or decompresses to more. */
export async function gunzipBounded(data: Uint8Array, maxBytes: number): Promise<Uint8Array | null> {
  try {
    const stream = new Blob([data]).stream().pipeThrough(new DecompressionStream('gzip'));
    const reader = stream.getReader();
    const chunks: Uint8Array[] = [];
    let size = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > maxBytes) {
        await reader.cancel();
        return null;
      }
      chunks.push(value);
    }
    const out = new Uint8Array(size);
    let at = 0;
    for (const c of chunks) {
      out.set(c, at);
      at += c.byteLength;
    }
    return out;
  } catch {
    return null;
  }
}
