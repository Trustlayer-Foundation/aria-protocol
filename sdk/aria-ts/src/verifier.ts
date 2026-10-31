import type { Admission, AdmissionInput } from './admission';
import type { ReceiverIdentityResult } from './agent';
import type { CredentialResult, Inspection, VerifiedCredential } from './credential';
import { pending } from './internal';
import type { PresentationContext, PresentationResult } from './presentation';
import type { ReceiptCheck, ReceiptResult, ReceiverPin } from './receipt';
import type { StatusEvidence, StatusOptions } from './status';
import type { Did, HttpRequestLike, TrustLevel } from './types';

/** One issuer the verifier trusts, under a name every result carries. */
export interface TrustProfile {
  /** E.g. `demo` or `production`. */
  readonly id: string;
  readonly issuer: Did;
  readonly keys: { readonly mldsa65: Uint8Array; readonly ed25519: Uint8Array };
  /** Highest level this profile may assert; a credential claiming more fails. */
  readonly maxLevel: TrustLevel;
  /** Status lists this issuer publishes; a credential naming another fails. */
  readonly statusLists: readonly string[];
}

/** Bounds on everything the SDK fetches. Without it the verifier is offline and status is `unavailable`. */
export interface FetchPolicy {
  /** Origins it may fetch from (status lists, referenced credentials); redirects are not followed. */
  readonly allowedOrigins: readonly string[];
  /** Default 5000. */
  readonly timeoutMs?: number;
  /** Default 262144; the decompressed status list is bounded separately. */
  readonly maxBytes?: number;
}

/** Trusted configuration: everything here comes from the adopter, never from a message. */
export interface VerifierConfig {
  readonly trust: readonly TrustProfile[];
  readonly fetch?: FetchPolicy;
  readonly clock?: () => Date;
  /** Maximum age of signed status evidence, from the list's own `validFrom`. Default 3600. */
  readonly statusMaxAgeSeconds?: number;
  /** Tolerated clock skew on validity bounds. Default 5. */
  readonly skewSeconds?: number;
}

/**
 * A verifier with its own, fixed trust. Two verifiers never affect each other;
 * nothing in the package is configured globally.
 */
export interface Verifier {
  /** Verifies one document. Says nothing about who presents it or its status. */
  verifyCredential(document: unknown): CredentialResult;
  /** Status of the credential's exact document. */
  checkStatus(credential: VerifiedCredential, options?: StatusOptions): Promise<StatusEvidence>;
  /** Authenticates a request: holder key, bound to this receiver, operation and content. */
  verifyPresentation(request: HttpRequestLike, context: PresentationContext): Promise<PresentationResult>;
  /** The single admission decision. Checks at run time that its inputs are about the same document. */
  admit(input: AdmissionInput): Promise<Admission>;
  /** Authenticates the receiver from its identity statement, before the client sends anything sensitive. */
  verifyReceiverIdentity(statement: unknown, pin: ReceiverPin, nonce: string): Promise<ReceiverIdentityResult>;
  verifyReceipt(receipt: unknown, check: ReceiptCheck): Promise<ReceiptResult>;
}

export function createVerifier(config: VerifierConfig): Verifier {
  void config;
  return pending('S1');
}

/** Parses a credential without verifying anything. Its result cannot be passed where verification is required. */
export function inspectCredential(document: unknown): Inspection {
  void document;
  return pending('S1');
}
