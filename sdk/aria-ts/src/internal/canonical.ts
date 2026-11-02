/**
 * ARIA canonical JSON (INVARIANTS §3): keys sorted at every level, no whitespace,
 * `JSON.stringify` escaping. The same function as `@aria-registry/verify`'s, so the
 * bytes match what the authority signs. It is not generic JCS; the closed AID
 * schema keeps it out of the cases where the two differ.
 */
export function canonicalJson(value: unknown): string {
  return JSON.stringify(value, (_, v) => {
    if (v && typeof v === 'object' && !Array.isArray(v)) {
      return Object.keys(v).sort().reduce((sorted: Record<string, unknown>, key) => {
        sorted[key] = (v as Record<string, unknown>)[key];
        return sorted;
      }, {});
    }
    return v;
  });
}
