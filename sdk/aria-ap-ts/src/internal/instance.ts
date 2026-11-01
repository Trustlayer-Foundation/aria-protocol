import { AriaUsageError, type Did, type StatusEvidence, type Verifier, type VerifiedCredential } from '@aria-registry/sdk';
import type { AttemptRefusal } from '../operations';
import type { OperationDescriptor } from '../presentation';
import type { ApprovalSnapshot } from './policy';
import { issue } from './provenance';
import type { Holder } from './request';

/** What an `Ap` instance keeps besides its methods, for the ledger and tracker built on it. */
export interface Internals {
  readonly credentials: Verifier;
  readonly now: () => number;
}

const instances = new WeakMap<object, Internals>();

export function register(ap: object, internals: Internals): void {
  instances.set(ap, internals);
}

export function internalsOf(ap: unknown): Internals {
  const found = typeof ap === 'object' && ap !== null ? instances.get(ap) : undefined;
  if (!found) throw new AriaUsageError('not an ARIA AP instance from createAp');
  return found;
}

/** What a verified presentation established, kept by the instance; the view callers get carries no authority. */
export interface PresentationSnapshot {
  readonly credential: VerifiedCredential;
  readonly holder: Holder;
  readonly descriptor: OperationDescriptor;
  readonly operationId: string | null;
  readonly lookupOf: string | null;
  readonly audience: string;
  readonly fingerprint: string | null;
  readonly requestDigest: string;
  /** The receiver that verified it. */
  readonly receiverDid: Did;
  /** The end of the signature's window, with the skew (ms): no admission made from it is used later. */
  readonly expiresAt: number;
}

export interface AdmissionSnapshot {
  readonly decision: 'allow' | 'deny' | 'indeterminate';
  readonly presentation: PresentationSnapshot;
  /** The evidence the decision used, judged again when the admission is used. */
  readonly status: StatusEvidence;
  readonly approval: ApprovalSnapshot | null;
}

export interface RefusalSnapshot {
  readonly status: 403 | 409 | 503;
  readonly code: string;
  readonly operationId: string;
  readonly requestDigest: string;
  readonly sender: { readonly did: Did; readonly credential: string };
  readonly receiverDid: Did;
}

export const newReceiptId = (): string => `urn:uuid:${globalThis.crypto.randomUUID()}`;

/** Admissions that already claimed, resumed or answered: each admits one use, judged when it was made. */
export const spentAdmissions = new WeakSet<object>();

/** An attempt refusal as callers see it; the snapshot stays with the instance that refused. */
export function refusalOf(ap: object, s: RefusalSnapshot): AttemptRefusal {
  const view = { status: s.status, code: s.code, operationId: s.operationId, requestDigest: s.requestDigest };
  return issue(ap, 'refusal', view as unknown as AttemptRefusal, s);
}
