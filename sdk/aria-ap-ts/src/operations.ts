import type { Did, Produced } from '@aria-registry/sdk';
import type { Admitted } from './admission';
import type { Ap } from './ap';
import { pending } from './errors';
import type { ReceiverSelf } from './presentation';
import type { Receipt } from './receipt';

/** A logical operation: one sender's operation id at one receiver. */
export interface OperationKey {
  readonly receiver: Did;
  readonly sender: Did;
  readonly operationId: string;
}

/**
 * What the adopter stores per operation. The SDK owns the transitions; storage
 * only persists them. `revision` increases on every write, and every write but the
 * first is conditional on it.
 */
export type StoredOperation =
  | {
      readonly state: 'claimed';
      readonly fingerprint: string;
      readonly revision: number;
      /** Who holds the claim, and since when (RFC 3339). */
      readonly claim: { readonly id: string; readonly at: string };
      /** The authenticated attempt that claimed it: the binding its receipt must name. A fingerprint cannot rebuild a signature-base digest. */
      readonly attempt: { readonly requestDigest: string; readonly sender: { readonly did: Did; readonly credential: string } };
      /** Operation receipts already issued: an `accepted` one when this claim continues it. */
      readonly receipts: readonly Receipt[];
    }
  | {
      readonly state: 'accepted' | 'completed' | 'rejected';
      readonly fingerprint: string;
      readonly revision: number;
      /** Every operation receipt, oldest first. Never rewritten. */
      readonly receipts: readonly Receipt[];
    };

/** The revision and claim a conditional write expects to find. */
export interface Expected {
  readonly revision: number;
  readonly claimId: string;
}

/**
 * Persistence the adopter provides (its database, or the in-memory reference).
 * Each method is one atomic compare-and-set. `settle` runs in the same transaction
 * as the business effect, so an effect without its outcome, or the reverse, cannot
 * be stored. A `false` answer means another worker got there first: the caller
 * stops, and nothing is overwritten.
 */
export interface OperationStorage {
  get(key: OperationKey): Promise<StoredOperation | null>;
  /** Creates the record as `claimed` if there is none; otherwise returns it untouched. */
  create(key: OperationKey, record: Extract<StoredOperation, { state: 'claimed' }>): Promise<{ readonly created: true } | { readonly created: false; readonly existing: StoredOperation }>;
  /** Replaces the record only if it still has `expected`'s revision and claim. */
  replace(key: OperationKey, expected: Expected, next: StoredOperation): Promise<boolean>;
  /** Claims an `accepted` record, or takes over a claim older than the ledger's timeout, only at `revision`. */
  reclaim(key: OperationKey, revision: number, next: Extract<StoredOperation, { state: 'claimed' }>): Promise<boolean>;
  /** Deletes a `claimed` record without receipts, only if it still holds `expected`'s claim. */
  remove(key: OperationKey, expected: Expected): Promise<boolean>;
}

/** The right of one worker to run one admitted operation once. */
export interface OperationClaim extends Produced<'claim'> {
  readonly key: OperationKey;
  readonly claimId: string;
  readonly revision: number;
  readonly admission: Admitted;
}

/** An operation's outcome as recorded at its commit point: the only input of an operation receipt. */
export interface RecordedOperationOutcome extends Produced<'outcome'> {
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
export interface AttemptRefusal extends Produced<'refusal'> {
  readonly status: 403 | 409 | 503;
  readonly code: string;
  readonly operationId: string | null;
  readonly requestDigest: string;
}

export type Begin =
  | { readonly kind: 'claimed'; readonly claim: OperationClaim }
  /** The operation already has an outcome for this content: answer with its governing receipt, no second effect. */
  | { readonly kind: 'existing'; readonly governing: Receipt; readonly status: number }
  /** Other content under this id (`aria.idempotency_conflict`), or another worker holds it (`aria.operation_in_progress`). */
  | { readonly kind: 'refused'; readonly refusal: AttemptRefusal };

/** How the business handler ended, at its commit point. */
export type Settlement =
  | { readonly state: 'completed'; readonly status: 200 | 201; readonly resultDigest?: string }
  /** Durably accepted for later processing; completion comes in a new receipt, through `resume`. */
  | { readonly state: 'accepted'; readonly status: 202 }
  /** Evaluated and refused without effect; final for this operation id. */
  | { readonly state: 'rejected'; readonly status: 422; readonly code: string };

/** How a handler that threw ended: only a proven rollback releases the claim. */
export type Failure =
  /** The effect's transaction rolled back: nothing happened. The claim is released and a retry may run. */
  | 'rolled-back'
  /** Whether the effect committed is unknown. The claim stays; `reconcile` decides later from the adopter's own records. */
  | 'uncertain';

export interface LedgerOptions {
  /** A claim older than this may be taken over by `reconcile` or `resume`. Default 300. */
  readonly claimTimeoutSeconds?: number;
}

/**
 * The operation state machine over the adopter's storage. Operation receipts come
 * only from here, from a settled outcome; an admission alone cannot make one.
 *
 * Every transition is conditional on the revision and claim it read, so two
 * workers cannot both settle an operation, a late `fail` cannot release another
 * worker's claim, and a stale worker cannot replace a final outcome.
 */
export class OperationLedger {
  constructor(
    /** The instance whose admissions this ledger accepts and whose claims it issues. */
    private readonly ap: Ap,
    private readonly storage: OperationStorage,
    private readonly receiver: ReceiverSelf,
    private readonly options: LedgerOptions = {},
  ) {}

  /** Claims the admitted operation, or returns its existing outcome or a refusal of this attempt. */
  begin(admission: Admitted): Promise<Begin> {
    void admission;
    void this.ap;
    void this.storage;
    return pending('AP2');
  }

  /** Records the outcome and signs its receipt; call inside the transaction of the business effect. Fails if the claim is no longer this worker's. */
  settle(claim: OperationClaim, settlement: Settlement): Promise<RecordedOperationOutcome> {
    void claim;
    void settlement;
    void this.receiver;
    return pending('AP2');
  }

  /** Ends a claim whose handler threw. `rolled-back` releases it; `uncertain` keeps it for `reconcile`. */
  fail(claim: OperationClaim, failure: Failure): Promise<void> {
    void claim;
    void failure;
    return pending('AP2');
  }

  /**
   * Continues an `accepted` operation, for instance after a restart: a fresh
   * admission (current status and policy) of the same operation and fingerprint,
   * then a new claim at the stored revision. Only one worker obtains it.
   */
  resume(key: OperationKey, admission: Admitted): Promise<Begin> {
    void key;
    void admission;
    void this.options;
    return pending('AP2');
  }

  /**
   * Decides a claim left `uncertain`, or abandoned past the timeout, from the
   * adopter's own record of whether the effect committed. Because the effect and
   * its signed outcome commit in one transaction, a committed effect already has
   * its stored receipt: that receipt is returned, never regenerated. A claim still
   * open while the adopter reports the effect committed breaks that invariant and
   * fails. Only an explicit `committed: false` releases the claim; a timeout alone
   * never proves the effect absent.
   */
  reconcile(key: OperationKey, effect: { readonly committed: boolean }): Promise<{ readonly current: Receipt } | null> {
    void key;
    void effect;
    return pending('AP2');
  }

  /** The governing receipt (`current`) and every operation receipt (`history`), for a retrieval. */
  lookup(key: OperationKey): Promise<{ readonly current: Receipt; readonly history: readonly Receipt[] } | null> {
    void key;
    return pending('AP2');
  }
}
