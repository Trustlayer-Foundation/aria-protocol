import { AriaUsageError, type Verifier } from '@aria-registry/sdk';
import type { Admission, AdmissionInput } from './admission';
import type { ReceiverIdentityResult, SignedAttempt, SignRequestInput } from './agent';
import { pending } from './errors';
import { recall } from './internal/provenance';
import type { AttemptRefusal } from './operations';
import type { PresentationContext, PresentationResult, ReceiverSelf } from './presentation';
import type { Receipt, ReceiptCheck, ReceiptResult, ReceiverPin } from './receipt';
import type { HttpRequestLike } from './types';

/** Trusted configuration, from the adopter. */
export interface ApConfig {
  /**
   * The credential verifier of `@aria-registry/sdk` this instance builds on. Its
   * credential and status results are the only ones accepted, and they are read
   * through its `facts` and `standing`, never from their fields. ARIA AP has no
   * credential or status verification of its own.
   */
  readonly credentials: Verifier;
}

/**
 * One ARIA AP instance: the agent's and the receiver's side of the profile.
 * Its own results (presentations, admissions, receipt statements, refusals)
 * are accepted only by this instance, as the exact objects it returned.
 */
export interface Ap {
  /** Authenticates a request: holder key, bound to this receiver, operation and content. */
  verifyPresentation(request: HttpRequestLike, context: PresentationContext): Promise<PresentationResult>;
  /** The single admission decision, judged now. Refuses a presentation it did not produce, and status evidence its credential verifier did not produce for that exact credential. */
  admit(input: AdmissionInput): Promise<Admission>;
  /** Signs a refusal of one attempt. Operation receipts come only from `OperationLedger.settle`. */
  buildAttemptRefusal(refusal: AttemptRefusal, receiver: ReceiverSelf): Promise<Receipt>;
  /** Authenticates the receiver from its identity statement, before the client sends anything sensitive. */
  verifyReceiverIdentity(statement: unknown, pin: ReceiverPin, nonce: string): Promise<ReceiverIdentityResult>;
  /** Signs one attempt (RFC 9421 profile) and returns it with what the client must keep to check its receipt. */
  signRequest(input: SignRequestInput): Promise<SignedAttempt>;
  verifyReceipt(receipt: unknown, check: ReceiptCheck): Promise<ReceiptResult>;
}

const TRUST_INTERFACE = ['verifyCredential', 'checkStatus', 'facts', 'standing'] as const;

/** Creates an instance over `config.credentials`, which it keeps as given: it is the adopter's verifier, not a copy. */
export function createAp(config: ApConfig): Ap {
  const credentials = config?.credentials;
  if (!credentials || TRUST_INTERFACE.some((method) => typeof credentials[method] !== 'function')) {
    throw new AriaUsageError('ARIA AP needs a credential verifier from @aria-registry/sdk (createVerifier)');
  }

  const ap: Ap = {
    async verifyPresentation() {
      return pending('AP2');
    },

    async admit(input) {
      // Provenance first: only this instance's own presentation. Its status is then
      // read through `credentials.standing`, which refuses anything else (AP2).
      recall(ap, 'presentation', input?.presentation);
      return pending('AP2');
    },

    async buildAttemptRefusal() {
      return pending('AP2');
    },

    async verifyReceiverIdentity() {
      return pending('AP2');
    },

    async signRequest() {
      return pending('AP2');
    },

    async verifyReceipt() {
      return pending('AP2');
    },
  };
  return Object.freeze(ap);
}
