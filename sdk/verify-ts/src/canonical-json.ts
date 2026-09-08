// ─────────────────────────────────────────────────────────
// @aria-registry/verify — Canonical JSON Serialization
// Part of the ARIA Protocol by TrustLayer Foundation
// https://aria.bar/docs/sdk
// ─────────────────────────────────────────────────────────
//
// This module produces a deterministic JSON string by recursively
// sorting object keys. The output MUST be byte-identical to the
// canonicalization in ARIACORE (aid-issuer.service.ts) and ARIAAPI
// (verifier.service.ts). A single-byte divergence will cause every
// signature verification to fail.

/**
 * Produce a deterministic JSON string with recursively sorted keys.
 *
 * Used internally by {@link verifyAgent} to reconstruct the exact
 * byte sequence that was originally signed by the ARIA Registry.
 * Also useful for content-hash computation or comparing credentials.
 *
 * @param obj - Any JSON-serializable value
 * @returns Canonical JSON string with sorted keys and no whitespace
 *
 * @example
 * ```typescript
 * import { canonicalJson } from '@aria-registry/verify';
 *
 * canonicalJson({ b: 2, a: 1 }); // '{"a":1,"b":2}'
 * ```
 *
 * @since 0.1.0
 */
export function canonicalJson(obj: unknown): string {
  return JSON.stringify(obj, (_, value) => {
    if (value && typeof value === 'object' && !Array.isArray(value)) {
      return Object.keys(value).sort().reduce((sorted: Record<string, unknown>, key) => {
        sorted[key] = (value as Record<string, unknown>)[key];
        return sorted;
      }, {});
    }
    return value;
  });
}
