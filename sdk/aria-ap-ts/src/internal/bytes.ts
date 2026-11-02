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

/**
 * The profile's origin rule (D3): `https://<host>[:<port>]`, or `http://` with a
 * loopback host for local use; a lower-case host, no default port, path, query, fragment
 * or user information; exactly its own URL serialization. Never normalised: a value
 * that is not already canonical is refused.
 */
export function isProfileOrigin(value: unknown): value is string {
  if (typeof value !== 'string' || !(HTTPS_ORIGIN.test(value) || LOOPBACK_ORIGIN.test(value))) return false;
  try {
    return new URL(value).origin === value;
  } catch {
    return false;
  }
}

// The same expressions as schema/aria-ap-identity-1.json: a DNS name whose last label
// starts with a letter, or a dotted-quad IPv4 address, so URL parsing leaves it unchanged.
const LABEL = '[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?';
const HOST = `(?:(?:${LABEL}\\.)*[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?|(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9]))`;
const PORT = '(?:[1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])';
const HTTPS_ORIGIN = new RegExp(`^https://${HOST}(?::(?!443$)${PORT})?$`);
const LOOPBACK_ORIGIN = new RegExp(`^http://(?:localhost|127\\.0\\.0\\.1|\\[::1\\])(?::(?!80$)${PORT})?$`);

export const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
export const DIGEST = /^sha-256=:[A-Za-z0-9+/]{43}=:$/;
