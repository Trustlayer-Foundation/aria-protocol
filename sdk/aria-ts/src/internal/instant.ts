// RFC 3339 date-time in UTC or with an offset; seconds required, fraction optional.
const RFC3339 = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(\.\d{1,9})?(Z|[+-]\d{2}:\d{2})$/;

/** Milliseconds since the epoch for a strict RFC 3339 instant; `null` for anything else, including impossible dates. */
export function instant(value: unknown): number | null {
  if (typeof value !== 'string') return null;
  const m = RFC3339.exec(value);
  if (!m) return null;
  const [, y, mo, d, h, mi, s] = m.map(Number) as [number, number, number, number, number, number, number];
  if (mo < 1 || mo > 12 || d < 1 || d > 31 || h > 23 || mi > 59 || s > 59) return null;
  const ms = Date.parse(value);
  if (Number.isNaN(ms)) return null;
  // Date.parse rolls 2026-02-31 over to March; the calendar day must survive.
  const offset = m[8] === 'Z' ? 0 : (m[8]!.startsWith('-') ? -1 : 1) * (Number(m[8]!.slice(1, 3)) * 60 + Number(m[8]!.slice(4, 6)));
  const local = new Date(ms + offset * 60_000);
  if (local.getUTCFullYear() !== y || local.getUTCMonth() + 1 !== mo || local.getUTCDate() !== d) return null;
  return ms;
}

export function iso(ms: number): string {
  return new Date(ms).toISOString().replace('.000Z', 'Z');
}
