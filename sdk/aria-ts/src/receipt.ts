import { pending, type issued } from './internal';
import type { AttemptRefusal } from './operations';
import type { ReceiverSelf } from './presentation';
import type { Did } from './types';

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

/** Signs a refusal of one attempt. Operation receipts come only from {@link OperationLedger.settle}. */
export function buildAttemptRefusal(refusal: AttemptRefusal, receiver: ReceiverSelf): Promise<Receipt> {
  void refusal;
  void receiver;
  return pending('AP2');
}

/** What the client signed for one attempt: the evidence a receipt is checked against. */
export interface SentAttempt {
  readonly operationId: string;
  readonly requestDigest: string;
  readonly sender: { readonly did: Did; readonly credential: string };
}

/** The receiver the client expects: pinned by the client, never learnt from the answer. */
export interface ReceiverPin {
  readonly origin: string;
  readonly did: Did;
}

export type ReceiptCheck = {
  readonly receiver: ReceiverPin;
  /** The original attempt. Without it the binding is reported as unverifiable, not assumed. */
  readonly sent?: SentAttempt;
} & (
  /** A fresh answer to a request: transport status and signed status must agree. */
  | { readonly mode: 'decision'; readonly transportStatus: number }
  /** A stored receipt fetched later: HTTP 200 may carry a signed 422. */
  | { readonly mode: 'retrieval' }
  /** Kept evidence checked offline against the receiver's exact credential then. */
  | { readonly mode: 'historical' }
);

export type ReceiptFailure =
  | 'malformed'
  | 'unsupported_type'
  | 'wrong_receiver'
  | 'receiver_credential'
  | 'signature_invalid'
  | 'binding_mismatch'
  | 'status_mismatch';

/** What a valid receipt says. A valid receipt can say `rejected`: validity is not success. */
export interface ReceiptStatement {
  readonly [issued]: 'receipt';
  readonly receiptId: string;
  readonly operationId: string;
  readonly state: 'accepted' | 'completed' | 'rejected';
  readonly applies: 'operation' | 'attempt';
  readonly status: number;
  readonly code: string;
  readonly issuedAt: Date;
  readonly receiver: { readonly did: Did; readonly credential: string };
  readonly sender: { readonly did: Did; readonly credential: string };
}

export type ReceiptResult =
  | { readonly ok: true; readonly statement: ReceiptStatement; readonly binding: 'verified' | 'unverifiable' }
  | { readonly ok: false; readonly reason: ReceiptFailure };

/**
 * The client's view of one operation. Only operation receipts move it; an
 * attempt refusal is kept as evidence and leaves it where it was. It never
 * moves back, and two different final receipts make it `inconsistent`.
 */
export class OperationTracker {
  private current: 'unknown' | 'accepted' | 'completed' | 'rejected' | 'inconsistent' = 'unknown';
  private readonly evidence: ReceiptStatement[] = [];

  constructor(readonly operationId: string) {}

  get state(): 'unknown' | 'accepted' | 'completed' | 'rejected' | 'inconsistent' {
    return this.current;
  }

  get attempts(): readonly ReceiptStatement[] {
    return this.evidence;
  }

  apply(result: ReceiptResult): void {
    void result;
    pending('AP2');
  }
}
