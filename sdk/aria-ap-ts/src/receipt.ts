import { AriaUsageError, type Did, type Produced } from '@aria-registry/sdk';
import type { SignedAttempt, VerifiedReceiver } from './agent';

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

/** What the client signed for one attempt and must keep: plain data, the evidence its receipts are checked against. */
export interface SentAttempt {
  readonly operationId: string;
  readonly requestDigest: string;
  readonly sender: { readonly did: Did; readonly credential: string };
  readonly receiver: { readonly did: Did; readonly credential: string };
}

/** The receiver the client expects: pinned by the client, never learnt from the answer. */
export interface ReceiverPin {
  readonly origin: string;
  readonly did: Did;
}

export type ReceiptCheck = {
  /** The receiver the attempts were signed for: the receipt must name its exact credential and verify under its key. */
  readonly receiver: VerifiedReceiver;
  /**
   * Every attempt the client sent for this operation. The receipt's digest only
   * selects one; every binding is then checked against it. With none kept the
   * binding cannot be checked, and the receipt is refused.
   */
  readonly attempts: readonly SentAttempt[];
} & (
  /** A fresh answer to a request: transport status and signed status must agree. */
  | { readonly mode: 'decision'; readonly transportStatus: number }
  /** A stored receipt fetched later: HTTP 200 may carry a signed 422; only operation receipts are returned. */
  | { readonly mode: 'retrieval' }
);

export type ReceiptFailure =
  | 'malformed'
  | 'unsupported_type'
  | 'receiver_mismatch'
  | 'signature_invalid'
  /** The kept attempt the digest selects names another operation, sender or receiver, or no kept attempt has that digest. */
  | 'binding'
  | 'binding_unverifiable'
  | 'status_mismatch'
  /** A retrieval returned an attempt refusal, which is never an operation's outcome. */
  | 'not_operation';

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
  readonly requestDigest: string;
}

export type ReceiptResult =
  | { readonly ok: true; readonly statement: ReceiptStatement; readonly attempt: SentAttempt }
  | { readonly ok: false; readonly reason: ReceiptFailure };

export type OperationState = 'unknown' | 'accepted' | 'completed' | 'rejected' | 'inconsistent';

/** What one observation did to the tracker. */
export type Observation =
  /** A verified operation receipt bound to one of this operation's attempts moved the state, or confirmed it. */
  | { readonly applied: 'operation'; readonly state: OperationState }
  /** A verified refusal of one attempt: kept as evidence, the operation's state unchanged. */
  | { readonly applied: 'attempt'; readonly state: OperationState }
  /** Not this operation's evidence: nothing changed. */
  | { readonly applied: 'none'; readonly state: OperationState; readonly reason: ReceiptFailure };

type ReceiptVerifier = { verifyReceipt(receipt: unknown, check: ReceiptCheck): Promise<ReceiptResult> };

function namedReceiver(receipt: unknown): string | null {
  try {
    const r: unknown = typeof receipt === 'string' ? JSON.parse(receipt) : receipt;
    const credential = (r as { receiver?: { credential?: unknown } })?.receiver?.credential;
    return typeof credential === 'string' ? credential : null;
  } catch {
    return null;
  }
}

/**
 * The client's view of one operation at one receiver. It keeps every attempt
 * sent, checks each receipt against the attempt it names, and moves only on a
 * verified operation receipt bound to this operation. It never moves back; two
 * different final receipts make it `inconsistent`. A failure to send a later
 * attempt is that attempt's problem, never the operation's.
 */
export class OperationTracker {
  private current: OperationState = 'unknown';
  private terminal: string | null = null;
  private readonly sent: SentAttempt[] = [];
  private readonly receivers = new Map<string, VerifiedReceiver>();
  private readonly kept = new Map<string, ReceiptStatement>();

  constructor(readonly operation: { readonly operationId: string; readonly sender: Did; readonly receiver: ReceiverPin }) {}

  get state(): OperationState {
    return this.current;
  }

  /** True once any attempt of this operation was recorded: from then on, not sending a retry does not mean the operation was not sent. */
  get everSent(): boolean {
    return this.sent.length > 0;
  }

  get attempts(): readonly SentAttempt[] {
    return [...this.sent];
  }

  /** Every verified receipt of this operation, attempt refusals included. */
  get evidence(): readonly ReceiptStatement[] {
    return [...this.kept.values()];
  }

  /** Keeps an attempt before it is sent. */
  record(signed: SignedAttempt): void {
    const { sent, receiver } = signed;
    if (!sent) throw new AriaUsageError('a retrieval is not an attempt of the operation');
    const { operation } = this;
    if (sent.operationId !== operation.operationId || sent.sender.did !== operation.sender) throw new AriaUsageError('the attempt belongs to another operation or sender');
    if (receiver.pin.did !== operation.receiver.did || receiver.pin.origin !== operation.receiver.origin || sent.receiver.did !== operation.receiver.did) {
      throw new AriaUsageError('the attempt was signed for another receiver');
    }
    this.sent.push(sent);
    this.receivers.set(sent.receiver.credential, receiver);
  }

  /** Checks `receipt` against the kept attempts and the receiver they were signed for, and applies it if it is this operation's evidence. */
  async observe(verifier: ReceiptVerifier, receipt: unknown, transport: { readonly mode: 'decision'; readonly transportStatus: number } | { readonly mode: 'retrieval' }): Promise<Observation> {
    const receiver = this.receivers.get(namedReceiver(receipt) ?? '');
    if (!receiver) return { applied: 'none', state: this.current, reason: this.sent.length === 0 ? 'binding_unverifiable' : 'receiver_mismatch' };
    const checked = await verifier.verifyReceipt(receipt, { receiver, attempts: this.sent, ...transport });
    if (!checked.ok) return { applied: 'none', state: this.current, reason: checked.reason };
    const s = checked.statement;
    this.kept.set(s.receiptId, s);
    if (s.applies === 'attempt') return { applied: 'attempt', state: this.current };
    if (s.state === 'accepted') {
      if (this.current === 'unknown') this.current = 'accepted';
    } else if (this.terminal !== null && this.terminal !== s.receiptId) {
      this.current = 'inconsistent';
    } else if (this.current !== 'inconsistent') {
      this.terminal = s.receiptId;
      this.current = s.state;
    }
    return { applied: 'operation', state: this.current };
  }

  /** Applies a retrieval's answer: every stored operation receipt, oldest first. */
  async observeLookup(verifier: ReceiptVerifier, answer: { readonly history: readonly unknown[] }): Promise<OperationState> {
    for (const receipt of answer.history) await this.observe(verifier, receipt, { mode: 'retrieval' });
    return this.current;
  }
}
