// Reading the AP1 vectors (conformance/ap) for the adapters. The
// vectors carry verified views of credentials, not AID documents: the adapters
// stand in for the credential verifier with those views and run ARIA AP's own
// rules unchanged. Credential verification itself is the credential package's.
import { readFileSync } from 'node:fs';
import type { Did } from '@trustlayer-foundation/aria-sdk';
import type { HttpRequestLike } from '../src';
import type { Holder } from '../src/internal/request';

const dir = new URL('../../../conformance/ap/', import.meta.url);
export const load = (name: string): any => JSON.parse(readFileSync(new URL(name, dir), 'utf8'));

const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
export function multibaseKey(multibase: string): Uint8Array {
  let n = 0n;
  for (const ch of multibase.slice(1)) n = n * 58n + BigInt(B58.indexOf(ch));
  const hex = n.toString(16).padStart(64, '0');
  return Uint8Array.from(hex.match(/../g)!.map((h) => parseInt(h, 16)));
}

export interface View {
  readonly url: string;
  readonly digest: string;
  readonly did: string;
  readonly holderKey: { readonly id: string; readonly publicKeyMultibase: string };
  readonly validFrom?: string;
  readonly validUntil?: string;
}

export const holderOf = (v: View): Holder => ({ credentialId: v.url, digest: v.digest, did: v.did as Did, keyId: v.holderKey.id, publicKey: multibaseKey(v.holderKey.publicKeyMultibase) });

export function requestOf(r: { method: string; target: string; headers: [string, string][]; body?: { utf8: string } }): HttpRequestLike {
  const headers: Record<string, string | string[]> = {};
  for (const [name, value] of r.headers) {
    const k = name.toLowerCase();
    const prev = headers[k];
    headers[k] = prev === undefined ? value : [...(Array.isArray(prev) ? prev : [prev]), value];
  }
  return { method: r.method, target: r.target, headers, ...(r.body ? { body: new TextEncoder().encode(r.body.utf8) } : {}) };
}
