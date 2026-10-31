import { AriaUsageError, type Did, type Produced } from '@aria-registry/sdk';
import type { Admitted, LookupAdmission } from './admission';
import type { Ap } from './ap';
import { InvariantViolation, StaleClaim } from './errors';
import { instantText } from './internal/bytes';
import { internalsOf, newReceiptId, refusalOf, type AdmissionSnapshot, type Internals } from './internal/instance';
import { issue, recall } from './internal/provenance';
import { isReceiverCode, RECEIPT_TYPE, signReceipt } from './internal/receipt';
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

type Claimed = Extract<StoredOperation, { state: 'claimed' }>;

/** The revision and claim a conditional write expects to find. */
export interface Expected {
  readonly revision: number;
  readonly claimId: string;
}

/**
 * Persistence the adopter provides (its database, or `MemoryOperationStorage`).
 * Each method is one atomic compare-and-set. `replace` runs in the same
 * transaction as the business effect, so an effect without its outcome, or the
 * reverse, cannot be stored. A `false` answer means another worker got there
 * first: the caller stops, and nothing is overwritten.
 */
export interface OperationStorage {
  get(key: OperationKey): Promise<StoredOperation | null>;
  /** Creates the record as `claimed` if there is none; otherwise returns it untouched. */
  create(key: OperationKey, record: Claimed): Promise<{ readonly created: true } | { readonly created: false; readonly existing: StoredOperation }>;
  /** Replaces a `claimed` record only if it still has `expected`'s revision and claim. */
  replace(key: OperationKey, expected: Expected, next: StoredOperation): Promise<boolean>;
  /** Claims an `accepted` record only if it is still at `revision`. */
  reclaim(key: OperationKey, revision: number, next: Claimed): Promise<boolean>;
  /** Deletes a `claimed` record without receipts, only if it still holds `expected`'s revision and claim. */
  remove(key: OperationKey, expected: Expected): Promise<boolean>;
}

/** The right of one worker to run one admitted operation once. */
export interface OperationClaim extends Produced<'claim'> {
  readonly key: OperationKey;
  readonly claimId: string;
  readonly revision: number;
}

/** An operation's outcome as recorded at its commit point: the only source of an operation receipt. */
export interface RecordedOperationOutcome extends Produced<'outcome'> {
  readonly key: OperationKey;
  readonly state: 'accepted' | 'completed' | 'rejected';
  readonly status: number;
  readonly code: string;
  readonly receipt: Receipt;
}

/**
 * An authenticated refusal of one attempt, which neither claims nor changes its
 * operation: the only source of an attempt receipt. Errors before authentication
 * have none and stay unsigned.
 */
export interface AttemptRefusal extends Produced<'refusal'> {
  readonly status: 403 | 409 | 503;
  readonly code: string;
  readonly operationId: string;
  readonly requestDigest: string;
}

export type Begin =
  | { readonly kind: 'claimed'; readonly claim: OperationClaim }
  /** The operation already has an outcome for this content: answer with its governing receipt and original status, no second effect. */
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

export type Reconciled =
  | { readonly kind: 'absent' }
  /** The claim was released without effect: back to no record, or to `accepted`. */
  | { readonly kind: 'released' }
  /** The effect committed with its outcome: the stored receipt, never a new one. */
  | { readonly kind: 'committed'; readonly current: Receipt };

/** The governing receipt: the final one if any, else the latest `accepted`. */
export function governing(receipts: readonly Receipt[]): Receipt | null {
  return receipts.find((r) => r.outcome.state !== 'accepted') ?? receipts.at(-1) ?? null;
}

interface ClaimSnapshot {
  readonly ledger: OperationLedger;
  readonly key: OperationKey;
  readonly claimId: string;
  readonly revision: number;
  readonly fingerprint: string;
  readonly attempt: Claimed['attempt'];
  readonly receipts: readonly Receipt[];
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
  readonly #ap: Ap;
  readonly #internals: Internals;
  readonly #storage: OperationStorage;
  readonly #receiver: ReceiverSelf;
  readonly #receiverCredential: string;
  readonly #spent = new WeakSet<object>();

  constructor(
    /** The instance whose admissions this ledger accepts and whose claims it issues. */
    ap: Ap,
    storage: OperationStorage,
    receiver: ReceiverSelf,
  ) {
    this.#internals = internalsOf(ap);
    const facts = this.#internals.credentials.facts(receiver.credential);
    if (facts.did !== receiver.did) throw new AriaUsageError('the receiver credential is for another DID');
    if (receiver.signer?.keyId !== facts.holderKey.id || receiver.signer.algorithm !== 'ed25519') throw new AriaUsageError("the receiver signer must be its credential's Ed25519 holder key");
    this.#ap = ap;
    this.#storage = storage;
    this.#receiver = receiver;
    this.#receiverCredential = facts.binding.credentialId;
  }

  /** Claims the admitted operation, or returns its existing outcome, or refuses this attempt. */
  async begin(admission: Admitted): Promise<Begin> {
    const { presentation: p } = this.#admitted(admission);
    const key = this.#keyOf(p);
    const attempt = { requestDigest: p.requestDigest, sender: { did: p.holder.did, credential: p.holder.credentialId } };
    let existing = await this.#storage.get(key);
    if (!existing) {
      const record: Claimed = { state: 'claimed', fingerprint: p.fingerprint!, revision: 1, claim: { id: globalThis.crypto.randomUUID(), at: this.#now() }, attempt, receipts: [] };
      const created = await this.#storage.create(key, record);
      if (created.created) return { kind: 'claimed', claim: this.#claim(key, record) };
      existing = created.existing;
    }
    return this.#existing(key, existing, p.fingerprint!, attempt);
  }

  /** Records the outcome and signs its receipt; call inside the transaction of the business effect. Throws `StaleClaim` if the claim is no longer this worker's. */
  async settle(claim: OperationClaim, settlement: Settlement): Promise<RecordedOperationOutcome> {
    const c = this.#claimOf(claim);
    const outcome = outcomeOf(settlement);
    const receipt = await signReceipt(
      {
        type: RECEIPT_TYPE,
        id: newReceiptId(),
        request: { id: c.key.operationId, sender: c.attempt.sender, digest: c.attempt.requestDigest },
        receiver: { did: this.#receiver.did, credential: this.#receiverCredential },
        issuedAt: this.#now(),
        outcome,
      },
      this.#receiver.signer,
    );
    const next: StoredOperation = { state: outcome.state, fingerprint: c.fingerprint, revision: c.revision + 1, receipts: [...c.receipts, receipt] };
    if (!(await this.#storage.replace(c.key, { revision: c.revision, claimId: c.claimId }, next))) throw new StaleClaim();
    this.#spent.add(claim);
    const view = { key: c.key, state: outcome.state, status: outcome.status, code: outcome.code, receipt };
    return issue(this.#ap, 'outcome', view as unknown as RecordedOperationOutcome, view);
  }

  /** Ends a claim whose handler threw. `rolled-back` releases it; `uncertain` keeps it for `reconcile`. Throws `StaleClaim` if it is no longer this worker's. */
  async fail(claim: OperationClaim, failure: Failure): Promise<void> {
    const c = this.#claimOf(claim);
    const record = await this.#storage.get(c.key);
    if (!record || record.state !== 'claimed' || record.claim.id !== c.claimId || record.revision !== c.revision) throw new StaleClaim();
    if (failure === 'uncertain') return;
    if (!(await this.#release(c.key, record))) throw new StaleClaim();
    this.#spent.add(claim);
  }

  /**
   * Continues an `accepted` operation: a fresh admission of the same operation,
   * sender and fingerprint (current status, policy and approval), then a new claim
   * at the stored revision. Only one worker obtains it. A final operation answers
   * with its governing receipt; other content, or a claim held, is refused.
   */
  async resume(key: OperationKey, admission: Admitted): Promise<Begin> {
    const { presentation: p } = this.#admitted(admission);
    const own = this.#keyOf(p);
    if (own.sender !== key.sender || own.operationId !== key.operationId || own.receiver !== key.receiver) throw new AriaUsageError('the admission is for another operation');
    const record = await this.#storage.get(key);
    if (!record) throw new AriaUsageError('there is no operation to resume');
    const attempt = { requestDigest: p.requestDigest, sender: { did: p.holder.did, credential: p.holder.credentialId } };
    if (record.state !== 'accepted') return this.#existing(key, record, p.fingerprint!, attempt);
    if (record.fingerprint !== p.fingerprint) return this.#refuse(key, attempt, 409, 'aria.idempotency_conflict');
    const next: Claimed = { state: 'claimed', fingerprint: record.fingerprint, revision: record.revision + 1, claim: { id: globalThis.crypto.randomUUID(), at: this.#now() }, attempt, receipts: record.receipts };
    if (!(await this.#storage.reclaim(key, record.revision, next))) return this.#refuse(key, attempt, 409, 'aria.operation_in_progress');
    return { kind: 'claimed', claim: this.#claim(key, next) };
  }

  /**
   * Decides a claim left `uncertain` from the adopter's own record of whether the
   * effect committed. Because the effect and its signed outcome commit in one
   * transaction, a committed effect already has its stored receipt: that receipt
   * is returned, never regenerated. An open claim reported committed, or an outcome
   * reported not committed, breaks that invariant and throws `InvariantViolation`.
   * Only an explicit `committed: false` releases a claim; a timeout alone never
   * proves the effect absent.
   */
  async reconcile(key: OperationKey, effect: { readonly committed: boolean }): Promise<Reconciled> {
    const record = await this.#storage.get(key);
    if (!record) {
      if (effect.committed) throw new InvariantViolation('an effect without an operation record');
      return { kind: 'absent' };
    }
    if (record.state === 'claimed') {
      if (effect.committed) throw new InvariantViolation('a committed effect whose outcome was not recorded');
      if (!(await this.#release(key, record))) throw new StaleClaim();
      return { kind: 'released' };
    }
    if (!effect.committed) throw new InvariantViolation(`a recorded ${record.state} outcome without its effect`);
    return { kind: 'committed', current: governing(record.receipts)! };
  }

  /** The governing receipt (`current`) and every operation receipt (`history`) for an admitted retrieval; `null` when there is no record. */
  async lookup(admission: Extract<LookupAdmission, { decision: 'allow' }>): Promise<{ readonly current: Receipt | null; readonly history: readonly Receipt[] } | null> {
    const { key } = recall<{ key: OperationKey }>(this.#ap, 'lookup', admission);
    if (key.receiver !== this.#receiver.did) throw new AriaUsageError('the retrieval was admitted for another receiver');
    const record = await this.#storage.get(key);
    return record ? { current: governing(record.receipts), history: [...record.receipts] } : null;
  }

  #now(): string {
    return instantText(this.#internals.now());
  }

  #admitted(admission: Admitted): AdmissionSnapshot {
    const a = recall<AdmissionSnapshot>(this.#ap, 'admission', admission);
    if (a.decision !== 'allow') throw new AriaUsageError('only an allowed admission claims an operation');
    if (a.presentation.receiverDid !== this.#receiver.did) throw new AriaUsageError('the admission is for another receiver');
    return a;
  }

  #keyOf(p: AdmissionSnapshot['presentation']): OperationKey {
    return { receiver: this.#receiver.did, sender: p.holder.did, operationId: p.operationId! };
  }

  #claim(key: OperationKey, record: Claimed): OperationClaim {
    const snapshot: ClaimSnapshot = { ledger: this, key, claimId: record.claim.id, revision: record.revision, fingerprint: record.fingerprint, attempt: record.attempt, receipts: record.receipts };
    return issue(this.#ap, 'claim', { key, claimId: record.claim.id, revision: record.revision } as unknown as OperationClaim, snapshot);
  }

  #claimOf(claim: OperationClaim): ClaimSnapshot {
    const c = recall<ClaimSnapshot>(this.#ap, 'claim', claim);
    if (c.ledger !== this) throw new AriaUsageError('a claim of another ledger');
    if (this.#spent.has(claim)) throw new StaleClaim();
    return c;
  }

  #existing(key: OperationKey, record: StoredOperation, fingerprint: string, attempt: Claimed['attempt']): Begin {
    if (record.fingerprint !== fingerprint) return this.#refuse(key, attempt, 409, 'aria.idempotency_conflict');
    if (record.state === 'claimed') return this.#refuse(key, attempt, 409, 'aria.operation_in_progress');
    const current = governing(record.receipts)!;
    return { kind: 'existing', governing: current, status: current.outcome.status };
  }

  #refuse(key: OperationKey, attempt: Claimed['attempt'], status: 409, code: string): Begin {
    return { kind: 'refused', refusal: refusalOf(this.#ap, { status, code, operationId: key.operationId, requestDigest: attempt.requestDigest, sender: attempt.sender, receiverDid: key.receiver }) };
  }

  /** Back to no record, or to `accepted` when the claim continued an accepted operation. */
  #release(key: OperationKey, record: Claimed): Promise<boolean> {
    const expected = { revision: record.revision, claimId: record.claim.id };
    return record.receipts.length === 0
      ? this.#storage.remove(key, expected)
      : this.#storage.replace(key, expected, { state: 'accepted', fingerprint: record.fingerprint, revision: record.revision + 1, receipts: record.receipts });
  }
}

function outcomeOf(s: Settlement): Receipt['outcome'] {
  if (s.state === 'completed' && (s.status === 200 || s.status === 201)) {
    return { state: 'completed', applies: 'operation', status: s.status, code: 'aria.completed', ...(s.resultDigest === undefined ? {} : { result: { digest: s.resultDigest } }) };
  }
  if (s.state === 'accepted' && s.status === 202) return { state: 'accepted', applies: 'operation', status: 202, code: 'aria.accepted' };
  if (s.state === 'rejected' && s.status === 422 && isReceiverCode(s.code)) return { state: 'rejected', applies: 'operation', status: 422, code: s.code };
  throw new AriaUsageError('a settlement is completed (200, 201), accepted (202) or rejected (422 with the receiver’s own code)');
}

const keyText = (k: OperationKey): string => JSON.stringify([k.receiver, k.sender, k.operationId]);

/**
 * The reference `OperationStorage`, in memory: the demo's and the tests'. Each
 * method is atomic within one process; nothing survives a restart.
 */
export class MemoryOperationStorage implements OperationStorage {
  readonly #records = new Map<string, StoredOperation>();

  async get(key: OperationKey): Promise<StoredOperation | null> {
    return this.#records.get(keyText(key)) ?? null;
  }

  async create(key: OperationKey, record: Claimed): Promise<{ readonly created: true } | { readonly created: false; readonly existing: StoredOperation }> {
    const existing = this.#records.get(keyText(key));
    if (existing) return { created: false, existing };
    this.#records.set(keyText(key), freeze(record));
    return { created: true };
  }

  async replace(key: OperationKey, expected: Expected, next: StoredOperation): Promise<boolean> {
    const r = this.#records.get(keyText(key));
    if (!r || r.state !== 'claimed' || r.revision !== expected.revision || r.claim.id !== expected.claimId) return false;
    this.#records.set(keyText(key), freeze(next));
    return true;
  }

  async reclaim(key: OperationKey, revision: number, next: Claimed): Promise<boolean> {
    const r = this.#records.get(keyText(key));
    if (!r || r.state !== 'accepted' || r.revision !== revision) return false;
    this.#records.set(keyText(key), freeze(next));
    return true;
  }

  async remove(key: OperationKey, expected: Expected): Promise<boolean> {
    const r = this.#records.get(keyText(key));
    if (!r || r.state !== 'claimed' || r.revision !== expected.revision || r.claim.id !== expected.claimId || r.receipts.length > 0) return false;
    this.#records.delete(keyText(key));
    return true;
  }
}

function freeze<T>(value: T): T {
  const copy = structuredClone(value);
  const deep = (v: unknown): void => {
    if (typeof v !== 'object' || v === null || Object.isFrozen(v)) return;
    Object.freeze(v);
    for (const k of Object.keys(v)) deep((v as Record<string, unknown>)[k]);
  };
  deep(copy);
  return copy;
}
