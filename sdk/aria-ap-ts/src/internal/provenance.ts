import { AriaUsageError } from '@trustlayer-foundation/aria-sdk';

/**
 * Where ARIA AP keeps what it established: presentations, admissions, claims,
 * outcomes, refusals and receipt statements. A result object is a frozen view;
 * the authoritative snapshot lives here, keyed by the object's identity and owned
 * by the instance that produced it. Credential and status results are not here:
 * they stay in the credential verifier and are read through its `facts` and
 * `standing`.
 */
const records = new WeakMap<object, { readonly owner: object; readonly kind: string; readonly snapshot: unknown }>();

/** Freezes `view`, records its snapshot for `owner`, and returns the view. */
export function issue<T extends object>(owner: object, kind: string, view: T, snapshot: unknown): T {
  deepFreeze(view);
  records.set(view, { owner, kind, snapshot });
  return view;
}

/** The snapshot `owner` recorded for `value` as `kind`; throws for anything else. */
export function recall<S>(owner: object, kind: string, value: unknown): S {
  const record = typeof value === 'object' && value !== null ? records.get(value) : undefined;
  if (!record || record.kind !== kind) {
    throw new AriaUsageError(`not a ${kind} this SDK produced: copies and altered values are refused`);
  }
  if (record.owner !== owner) {
    throw new AriaUsageError(`a ${kind} produced by another ARIA AP instance is not trusted here`);
  }
  return record.snapshot as S;
}

function deepFreeze(value: unknown): void {
  if (typeof value !== 'object' || value === null || Object.isFrozen(value)) return;
  Object.freeze(value);
  for (const key of Reflect.ownKeys(value)) deepFreeze((value as Record<PropertyKey, unknown>)[key]);
}
