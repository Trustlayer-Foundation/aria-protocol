import type { Produced, VerifiedCredential } from '@aria-registry/sdk';
import type { RequestClass } from './presentation';
import type { ReceiverPin, SentAttempt } from './receipt';
import type { HttpRequestLike, Signer } from './types';

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

/** How the agent presents its credential: by exact reference (default), or the document itself. */
export type CredentialPresentation =
  | { readonly by: 'reference'; readonly credentialId: string; readonly digest: string }
  | { readonly by: 'value'; readonly document: unknown };

export interface SignRequestInput {
  readonly request: HttpRequestLike;
  readonly class: RequestClass;
  /** Required for every class that gets a receipt; reused unchanged on every retry of the operation. */
  readonly operationId?: string;
  readonly receiver: VerifiedReceiver;
  readonly credential: CredentialPresentation;
  /** The agent's holder key, outside the language model. */
  readonly signer: Signer;
}

export interface SignedAttempt {
  readonly request: HttpRequestLike;
  /** What the client must keep to check this attempt's receipts. */
  readonly sent: SentAttempt;
}
