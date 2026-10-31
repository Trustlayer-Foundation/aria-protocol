import { sha256 } from '@noble/hashes/sha2.js';

// Encodings ARIA AP reads and writes. Decoders are strict: only the canonical
// encoding of some bytes is accepted, so one value has one spelling.

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

export const utf8 = (text: string): Uint8Array => new TextEncoder().encode(text);

export function toBase64(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i += 3) {
    const n = (bytes[i]! << 16) | ((bytes[i + 1] ?? 0) << 8) | (bytes[i + 2] ?? 0);
    out += ALPHABET[(n >> 18) & 63]! + ALPHABET[(n >> 12) & 63]!;
    out += i + 1 < bytes.length ? ALPHABET[(n >> 6) & 63]! : '=';
    out += i + 2 < bytes.length ? ALPHABET[n & 63]! : '=';
  }
  return out;
}

/** Padded base64 (RFC 4648 §4); `null` unless `text` is the canonical encoding of its bytes. */
export function fromBase64(text: string): Uint8Array | null {
  if (text.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(text)) return null;
  const body = text.replace(/=+$/, '');
  const bytes = new Uint8Array(Math.floor((body.length * 6) / 8));
  let bits = 0;
  let value = 0;
  let at = 0;
  for (const ch of body) {
    value = (value << 6) | ALPHABET.indexOf(ch);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      bytes[at++] = (value >> bits) & 255;
    }
  }
  return toBase64(bytes) === text ? bytes : null;
}

export const toBase64url = (bytes: Uint8Array): string => toBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

/** Unpadded base64url (RFC 4648 §5); `null` unless canonical. */
export function fromBase64url(text: string): Uint8Array | null {
  if (!/^[A-Za-z0-9_-]*$/.test(text) || text.length % 4 === 1) return null;
  const padded = text.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (text.length % 4)) % 4);
  return fromBase64(padded);
}

/** The RFC 9530 `sha-256` member of `bytes`, as ARIA writes digests: `sha-256=:<base64>:`. */
export const digestField = (bytes: Uint8Array): string => `sha-256=:${toBase64(sha256(bytes))}:`;

export const sameBytes = (a: Uint8Array, b: Uint8Array): boolean => a.length === b.length && a.every((x, i) => x === b[i]);

export function randomToken(bytes: number): string {
  return toBase64url(globalThis.crypto.getRandomValues(new Uint8Array(bytes)));
}

/** RFC 3339 in UTC to the second, as ARIA writes instants. */
export const instantText = (ms: number): string => new Date(Math.floor(ms / 1000) * 1000).toISOString().replace('.000Z', 'Z');

/** Milliseconds of an instant written as ARIA writes them, or `null`. */
export function instantOf(value: unknown): number | null {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(value)) return null;
  const t = Date.parse(value);
  return Number.isFinite(t) && instantText(t) === value ? t : null;
}

export const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
export const DIGEST = /^sha-256=:[A-Za-z0-9+/]{43}=:$/;
