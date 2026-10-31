import type { Did, Produced } from '@aria-registry/sdk';
import { pending } from './errors';

/**
 * The receipt on the wire (type `aria-ap-receipt/1`, pending decision D4). The
 * signature covers the whole object without `proof.value`, so `alg` and `keyid`
 * are signed too.
 */
export interface Receipt {
  readonly type: 'aria-ap-receipt/1';
  readonly id: string;
  readonly request: {
    readonly id: string;
    readonly sender: { readonly did: Did; readonly credential: string };
    /** `sha-256=:<base64>:` of the attempt's RFC 9421 signature base. */
    readonly digest: string;
  };
  readonly receiver: { readonly did: Did; readonly credential: string };
  /** Asserted by the receiver; not an independent timestamp. */
  readonly issuedAt: string;
  readonly outcome: {
    readonly state: 'accepted' | 'completed' | 'rejected';
    /** `operation`: the operation's outcome. `attempt`: this attempt only; says nothing of the operation. */
    readonly applies: 'operation' | 'attempt';
    /** The original decision's HTTP status, whatever status later carries the receipt. */
    readonly status: number;
    readonly code: string;
    readonly result?: { readonly digest: string };
  };
  readonly proof: { readonly alg: 'ed25519'; readonly keyid: string; readonly value: string };
}


/** What the client signed for one attempt and must keep: the evidence its receipts are checked against. */
export interface SentAttempt {
  readonly operationId: string;
  readonly requestDigest: string;
  readonly sender: { readonly did: Did; readonly credential: string };
  readonly receiver: ReceiverPin;
}

/** The receiver the client expects: pinned by the client, never learnt from the answer. */
export interface ReceiverPin {
  readonly origin: string;
  readonly did: Did;
}

/**
 * Evidence retained for checking a receipt offline, later. The receipt names the
 * receiver's exact credential; its document must be supplied, since the receipt
 * carries only its URL and the DID's current document may be another one.
 */
export interface RetainedEvidence {
  /** The exact receiver credential document the receipt names. */
  readonly receiverCredential: unknown;
  /** The signed status list of that credential, as retained near the receipt's time. */
  readonly receiverStatusList?: unknown;
}

export type ReceiptCheck = {
  readonly receiver: ReceiverPin;
  /**
   * Every attempt the client sent for this operation. The receipt's digest only
   * selects one; its signature and every binding are then checked against it.
   * Without the matching attempt the binding is reported unverifiable, not assumed.
   */
  readonly attempts?: readonly SentAttempt[];
} & (
  /** A fresh answer to a request: transport status and signed status must agree. */
  | { readonly mode: 'decision'; readonly transportStatus: number }
  /** A stored receipt fetched later: HTTP 200 may carry a signed 422. */
  | { readonly mode: 'retrieval' }
  /** Kept evidence checked offline: no network, and no use of the DID's current document. */
  | { readonly mode: 'historical'; readonly evidence: RetainedEvidence }
);

export type ReceiptFailure =
  | 'malformed'
  | 'unsupported_type'
  | 'wrong_receiver'
  | 'receiver_credential'
  | 'signature_invalid'
  | 'binding_mismatch'
  | 'status_mismatch'
  /** Historical mode without the exact receiver credential the receipt names. */
  | 'evidence_missing';

/** What a valid receipt says. A valid receipt can say `rejected`: validity is not success. */
export interface ReceiptStatement extends Produced<'receipt'> {
  readonly receiptId: string;
  readonly operationId: string;
  readonly state: 'accepted' | 'completed' | 'rejected';
  readonly applies: 'operation' | 'attempt';
  readonly status: number;
  readonly code: string;
  /** As the receiver asserts it (RFC 3339). */
  readonly issuedAt: string;
  readonly receiver: { readonly did: Did; readonly credential: string };
  readonly sender: { readonly did: Did; readonly credential: string };
}

/**
 * In historical mode, what the retained evidence supports and what nothing here
 * establishes. The receiver's signing time is its own claim: no mode proves that
 * it signed before its credential expired or was revoked.
 */
export interface HistoricalFindings {
  /** The retained receiver credential verifies under the trusted issuer now (signature, schema, proof profile). */
  readonly receiverCredentialAuthentic: boolean;
  /** Whether `issuedAt` falls inside that credential's signed validity, as the receiver claims it. */
  readonly claimedTimeWithinValidity: boolean;
  /** The retained list's answer for that credential, or `none` when no verifiable list was retained. */
  readonly retainedStatus: 'active' | 'revoked' | 'none';
  readonly notEstablished: readonly ['signing-time'];
}

export type ReceiptResult =
  | {
      readonly ok: true;
      readonly statement: ReceiptStatement;
      /** `verified` only when a retained attempt matched every binding. */
      readonly binding: 'verified' | 'unverifiable';
      readonly historical?: HistoricalFindings;
    }
  | { readonly ok: false; readonly reason: ReceiptFailure };

export type OperationState = 'unknown' | 'accepted' | 'completed' | 'rejected' | 'inconsistent';

/** What one observation did to the tracker. */
export type Observation =
  /** A verified operation receipt bound to one of this operation's attempts moved the state. */
  | { readonly applied: 'operation'; readonly state: OperationState }
  /** A verified refusal of one attempt: kept as evidence, the operation's state unchanged. */
  | { readonly applied: 'attempt'; readonly state: OperationState }
  /** Not this operation's evidence (failed check, unverifiable binding, other sender or receiver): nothing changed. */
  | { readonly applied: 'none'; readonly state: OperationState; readonly reason: ReceiptFailure | 'unverifiable_binding' | 'other_operation' };

/**
 * The client's view of one operation at one receiver. It keeps every attempt
 * sent, checks each receipt against the attempt it names, and moves only on a
 * verified operation receipt bound to this operation, sender and receiver. It
 * never moves back; two different final receipts make it `inconsistent`. A
 * failure to send a later attempt is that attempt's problem, never the operation's.
 */
export class OperationTracker {
  private current: OperationState = 'unknown';
  private readonly sent: SentAttempt[] = [];
  private readonly kept: ReceiptStatement[] = [];

  constructor(readonly operation: { readonly operationId: string; readonly sender: { readonly did: Did; readonly credential: string }; readonly receiver: ReceiverPin }) {}

  get state(): OperationState {
    return this.current;
  }

  /** True once any attempt of this operation was sent: from then on, not sending a retry does not mean the operation was not sent. */
  get everSent(): boolean {
    return this.sent.length > 0;
  }

  get attempts(): readonly SentAttempt[] {
    return [...this.sent];
  }

  get evidence(): readonly ReceiptStatement[] {
    return [...this.kept];
  }

  /** Keeps an attempt before it is sent. */
  record(attempt: SentAttempt): void {
    void attempt;
    pending('AP2');
  }

  /** Checks `receipt` with `verifier` against the kept attempts and applies it if it is this operation's evidence. */
  observe(
    verifier: { verifyReceipt(receipt: unknown, check: ReceiptCheck): Promise<ReceiptResult> },
    receipt: unknown,
    transport: { readonly mode: 'decision'; readonly transportStatus: number } | { readonly mode: 'retrieval' },
  ): Promise<Observation> {
    void verifier;
    void receipt;
    void transport;
    return pending('AP2');
  }
}
