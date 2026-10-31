import type { Produced, VerifiedCredential } from '@aria-registry/sdk';
import type { RequestClass } from './presentation';
import type { ReceiverPin, SentAttempt } from './receipt';
import type { HttpRequestLike, Signer } from './types';

/**
 * The receiver's signed answer to `GET /.well-known/aria/identity?nonce&audience`
 * (provisional, D3): its credential document and a statement bound to the
 * client's nonce, carrying a single-use challenge for the client's next request.
 */
export interface IdentityResponse {
  readonly credential: unknown;
  readonly statement: IdentityStatement;
}

export interface IdentityStatement {
  readonly type: 'aria-ap-identity/1';
  /** The receiver's DID. */
  readonly subject: string;
  /** The exact credential instance whose holder key signs. */
  readonly credential: string;
  readonly origin: string;
  /** The client the statement is for. */
  readonly audience: string;
  /** The client's nonce, as sent. */
  readonly nonce: string;
  /** Single-use and short-lived: the `nonce` of the client's next signed request. */
  readonly challenge: string;
  readonly created: string;
  /** Over the canonical JSON of the statement without `proof.value`. */
  readonly proof: { readonly alg: 'ed25519'; readonly keyid: string; readonly value: string };
}

/** The receiver, authenticated for this client before anything sensitive is sent. */
export interface VerifiedReceiver extends Produced<'receiver'> {
  readonly pin: ReceiverPin;
  readonly credential: VerifiedCredential;
  /** The single-use challenge it issued, for the next request. */
  readonly challenge: string;
}

export type ReceiverIdentityFailure =
  | 'malformed'
  | 'credential'
  | 'unexpected_receiver'
  | 'origin'
  | 'audience'
  | 'nonce'
  | 'stale'
  | 'signature'
  | 'status';

export type ReceiverIdentityResult =
  | { readonly ok: true; readonly receiver: VerifiedReceiver }
  | { readonly ok: false; readonly reason: ReceiverIdentityFailure };

export interface SignRequestInput {
  readonly request: HttpRequestLike;
  readonly class: RequestClass;
  /** Required for every class that gets a receipt; reused unchanged on every retry of the operation. Absent for a retrieval. */
  readonly operationId?: string;
  /** A receiver this instance verified; its challenge becomes the request's nonce. */
  readonly receiver: VerifiedReceiver;
  /** The agent's own verified credential, presented by exact reference (URL and digest). */
  readonly credential: VerifiedCredential;
  /** The agent's holder key, outside the language model. */
  readonly signer: Signer;
  /** Headers the receiver's operation declares as semantic (e.g. `if-match`): signed when present. */
  readonly semanticHeaders?: readonly string[];
  /** Seconds the signature stays valid, at most 60. Default 30. */
  readonly windowSeconds?: number;
}

export interface SignedAttempt {
  readonly request: HttpRequestLike;
  /** What the client must keep to check this attempt's receipts; `null` for a retrieval, which gets none. */
  readonly sent: SentAttempt | null;
  /** The receiver it was signed for: receipts of this attempt are checked against its exact credential. */
  readonly receiver: VerifiedReceiver;
}
