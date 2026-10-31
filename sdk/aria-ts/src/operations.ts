import type { Admitted } from './admission';
import { pending, type issued } from './internal';
import type { ReceiverSelf } from './presentation';
import type { Receipt } from './receipt';
import type { Did } from './types';

/** A logical operation: one sender's operation id at one receiver. */
export interface OperationKey {
  readonly receiver: Did;
  readonly sender: Did;
  readonly operationId: string;
}

/** What the adopter stores per operation. The SDK owns the transitions; storage only persists them. */
export type StoredOperation =
  | { readonly state: 'claimed'; readonly fingerprint: string; readonly claimedAt: Date }
  | {
      readonly state: 'accepted' | 'completed' | 'rejected';
      readonly fingerprint: string;
      /** Every operation receipt, oldest first. Never rewritten. */
      readonly receipts: readonly Receipt[];
    };

/**
 * Persistence the adopter provides (its database, or the in-memory reference).
 * `claim` is a compare-and-set; `settle` must run in the same transaction as the
 * business effect, so an effect without its outcome, or the reverse, cannot be stored.
 */
export interface OperationStorage {
  get(key: OperationKey): Promise<StoredOperation | null>;
  claim(key: OperationKey, fingerprint: string, at: Date): Promise<{ readonly claimed: true } | { readonly claimed: false; readonly existing: StoredOperation }>;
  settle(key: OperationKey, next: Exclude<StoredOperation, { state: 'claimed' }>): Promise<void>;
  /** Drops a `claimed` record whose handler failed before its commit point, without effect. */
  release(key: OperationKey): Promise<void>;
}

/** The right to run one admitted operation once. */
export interface OperationClaim {
  readonly [issued]: 'claim';
  readonly key: OperationKey;
  readonly admission: Admitted;
}

/** An operation's outcome as recorded at its commit point: the only input of an operation receipt. */
export interface RecordedOperationOutcome {
  readonly [issued]: 'outcome';
  readonly key: OperationKey;
  readonly state: 'accepted' | 'completed' | 'rejected';
  readonly status: number;
  readonly code: string;
  readonly receipt: Receipt;
}

/**
 * An authenticated refusal of one attempt, which neither claims nor changes its
 * operation: the only input of an attempt receipt. Errors before authentication
 * have none and stay unsigned.
 */
export interface AttemptRefusal {
  readonly [issued]: 'refusal';
  readonly status: 403 | 409 | 503;
  readonly code: string;
  readonly operationId: string | null;
  readonly requestDigest: string;
}

export type Begin =
  | { readonly kind: 'claimed'; readonly claim: OperationClaim }
  /** The operation already has an outcome for this content: answer with its governing receipt, no second effect. */
  | { readonly kind: 'existing'; readonly governing: Receipt; readonly status: number }
  /** Other content under this id (`aria.idempotency_conflict`), or another attempt holds it (`aria.operation_in_progress`). */
  | { readonly kind: 'refused'; readonly refusal: AttemptRefusal };

/** How the business handler ended, at its commit point. */
export type Settlement =
  | { readonly state: 'completed'; readonly status: 200 | 201; readonly resultDigest?: string }
  /** Durably accepted for later processing; completion comes in a new receipt. */
  | { readonly state: 'accepted'; readonly status: 202 }
  /** Evaluated and refused without effect; final for this operation id. */
  | { readonly state: 'rejected'; readonly status: 422; readonly code: string };

/**
 * The operation state machine over the adopter's storage. Operation receipts
 * come only from here, from a settled outcome; an admission alone cannot make one.
 */
export class OperationLedger {
  constructor(
    private readonly storage: OperationStorage,
    private readonly receiver: ReceiverSelf,
  ) {}

  /** Claims the admitted operation, or returns its existing outcome or a refusal of this attempt. */
  begin(admission: Admitted): Promise<Begin> {
    void admission;
    void this.storage;
    return pending('AP2');
  }

  /** Records the outcome and signs its receipt; call inside the transaction of the business effect. */
  settle(claim: OperationClaim, settlement: Settlement): Promise<RecordedOperationOutcome> {
    void claim;
    void settlement;
    void this.receiver;
    return pending('AP2');
  }

  /** Releases a claim whose handler failed before its commit point. The caller answers unsigned; the client stays unknown. */
  release(claim: OperationClaim): Promise<void> {
    void claim;
    return pending('AP2');
  }

  /** The governing receipt (`current`) and every operation receipt (`history`), for a retrieval. */
  lookup(key: OperationKey): Promise<{ readonly current: Receipt; readonly history: readonly Receipt[] } | null> {
    void key;
    return pending('AP2');
  }
}
