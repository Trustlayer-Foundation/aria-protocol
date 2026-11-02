import { ed25519 } from '@noble/curves/ed25519.js';
import { sameBytes } from './bytes';

// Ed25519 as the ARIA AP profile verifies it: stricter than RFC 8032's strict mode,
// so every implementation reaches the same verdict on every signature.

const Point = ed25519.Point;
const L = Point.Fn.ORDER;

/** A point in the prime-order subgroup, in its canonical encoding: not small order, torsion free. */
function subgroupPoint(bytes: Uint8Array): boolean {
  try {
    const p = Point.fromBytes(bytes, false);
    return sameBytes(p.toBytes(), bytes) && !p.isSmallOrder() && p.isTorsionFree();
  } catch {
    return false;
  }
}

/** The authority's holder-key rule. */
export const acceptableKey = (key: Uint8Array): boolean => key.length === 32 && subgroupPoint(key);

/**
 * The key and `R` acceptable, `S < L`, then RFC 8032 verification. With both points
 * in the prime-order subgroup the cofactored and cofactorless equations agree.
 */
export function strictVerify(signature: Uint8Array, message: Uint8Array, key: Uint8Array): boolean {
  if (signature.length !== 64 || !acceptableKey(key) || !subgroupPoint(signature.subarray(0, 32))) return false;
  let s = 0n;
  for (let i = 63; i >= 32; i--) s = (s << 8n) | BigInt(signature[i]!);
  if (s >= L) return false;
  try {
    return ed25519.verify(signature, message, key, { zip215: false });
  } catch {
    return false;
  }
}
