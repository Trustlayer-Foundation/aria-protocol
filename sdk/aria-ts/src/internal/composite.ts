import { ed25519 } from '@noble/curves/ed25519.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { canonicalJson } from './canonical';
import { fromBase64url } from './encoding';

const HEADER = 4;
const ML_DSA_65_SIGNATURE = 3309;
const ED25519_SIGNATURE = 64;

/** The composite suite every issuer signature in profile 1 uses. */
export const SUITE = 'mldsa65-ed25519-2026';

export interface IssuerKeys {
  readonly mldsa65: Uint8Array;
  readonly ed25519: Uint8Array;
}

/**
 * Splits a composite `proofValue` (multibase `u` + base64url, or the bare form of
 * earlier issuance) into its two signatures. The length header decides between the
 * readings, not the first character.
 */
function decode(proofValue: string): { pq: Uint8Array; classical: Uint8Array } | null {
  const readings = proofValue.startsWith('u') ? [proofValue.slice(1), proofValue] : [proofValue];
  for (const reading of readings) {
    const bytes = fromBase64url(reading);
    if (!bytes || bytes.length !== HEADER + ML_DSA_65_SIGNATURE + ED25519_SIGNATURE) continue;
    if (new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(0, false) !== ML_DSA_65_SIGNATURE) continue;
    return { pq: bytes.slice(HEADER, HEADER + ML_DSA_65_SIGNATURE), classical: bytes.slice(HEADER + ML_DSA_65_SIGNATURE) };
  }
  return null;
}

/**
 * True only when both halves verify under `keys` over the canonical JSON of
 * `document` without its `proof`. The proof object itself is outside the signed
 * bytes in this suite.
 */
export function verifyComposite(document: Record<string, unknown>, proofValue: string, keys: IssuerKeys): boolean {
  const signatures = decode(proofValue);
  if (!signatures) return false;
  const { proof: _, ...unsigned } = document;
  const payload = new TextEncoder().encode(canonicalJson(unsigned));
  try {
    return ml_dsa65.verify(signatures.pq, payload, keys.mldsa65) && ed25519.verify(signatures.classical, payload, keys.ed25519);
  } catch {
    return false;
  }
}
