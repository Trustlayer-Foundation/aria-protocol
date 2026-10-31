import type { CredentialBinding, Did, TrustLevel } from './types';

/** Type-only mark of values the SDK produces. The runtime boundary is the verifier's own record of each result. */
declare const produced: unique symbol;
export type Produced<K extends string> = { readonly [produced]: K };

/** Parsed fields of a credential nobody has verified. */
export interface Inspection {
  readonly kind: 'inspection';
  /** Always false: inspection never establishes anything. */
  readonly verified: false;
  readonly did: string | null;
  readonly credentialId: string | null;
  readonly issuer: string | null;
  readonly specVersion: string | null;
  readonly trustLevel: string | null;
  readonly scopes: readonly string[];
  readonly validFrom: string | null;
  readonly validUntil: string | null;
  /** Why parsing stopped, when it did. */
  readonly problem?: 'not_json' | 'not_a_credential';
}

/** Why a credential is not verified. Fixed names; no caller-supplied text. */
export type CredentialFailure =
  /** Not a JSON object within the size bound, or not valid against the schema of its `spec_version`. */
  | 'malformed'
  | 'unsupported_version'
  /** Proof metadata is not the trust profile's. Checking it does not make it signed. */
  | 'unsupported_proof'
  | 'untrusted_issuer'
  /** The level is above what the issuer's trust profile may assert. */
  | 'level_not_trusted'
  /** Either half of the composite issuer signature fails. */
  | 'signature_invalid'
  | 'not_yet_valid'
  | 'expired'
  /** A validity bound is not an instant, or the bounds are inverted. */
  | 'invalid_validity'
  /** Not the 32 raw bytes of an Ed25519 key, the ARIA 1.0 compatibility encoding, or not the subject's. */
  | 'holder_key_invalid'
  /** Valid against its schema but not its rules, e.g. `hitlRequired` outside `scope`. */
  | 'semantic_invalid'
  /** It names a status list its trust profile does not publish. */
  | 'status_list_untrusted';

export interface Principal {
  readonly did: string;
  readonly type: 'organization' | 'individual';
  /** An organization's asserted name; never a natural person's. */
  readonly legalName: string | null;
  readonly jurisdiction: string | null;
  readonly verificationStatus: 'self-declared' | 'registry-confirmed' | 'legal-verified';
}

/**
 * One exact issued document that conforms to its `spec_version`, is within its
 * validity interval and verifies under a trusted issuer. It says nothing about
 * who presents it, nor about its current status.
 *
 * A frozen view: the verifier that produced it keeps the authoritative copy, and
 * accepts this exact object only. A copy or an altered one is refused.
 */
export interface VerifiedCredential extends Produced<'credential'> {
  readonly kind: 'verified-credential';
  readonly binding: CredentialBinding;
  /** The agent's stable identity. */
  readonly did: Did;
  readonly issuer: Did;
  readonly specVersion: '1.0';
  readonly trustLevel: TrustLevel;
  readonly scopes: readonly string[];
  /** Scopes the receiver must not act on without a human's approval; a declaration, not an approval. */
  readonly hitlRequired: readonly string[];
  readonly delegationDepth: number;
  readonly principal: Principal;
  /** `id` and the key as published (multibase); the verifier keeps the decoded 32 bytes. */
  readonly holderKey: { readonly id: string; readonly publicKeyMultibase: string };
  /** Signed validity bounds (RFC 3339). There is no issuance time: `proof.created` is outside the signature. */
  readonly validFrom: string;
  readonly validUntil: string;
  /** Signed predecessor reference, as data. Verification never fetches it. */
  readonly previousCredentialId: string | null;
  readonly statusEntry: { readonly list: string; readonly index: number };
  /** Local time of this verification. */
  readonly verifiedAt: string;
}

/**
 * What a verifier established about one of its own credential results, read
 * through `Verifier.facts` from its record, never from the view. A fresh copy at
 * each call, holder key bytes included. Data, not evidence: no entry point of this
 * SDK or of ARIA AP accepts it in place of a result.
 */
export interface CredentialFacts {
  readonly binding: CredentialBinding;
  readonly did: Did;
  readonly issuer: Did;
  readonly trustLevel: TrustLevel;
  readonly scopes: readonly string[];
  readonly hitlRequired: readonly string[];
  readonly delegationDepth: number;
  /** The 32 raw bytes, already accepted by the strict key rule; a copy the caller owns. */
  readonly holderKey: { readonly id: string; readonly publicKey: Uint8Array };
  readonly validFrom: string;
  readonly validUntil: string;
}

export type CredentialResult =
  | { readonly ok: true; readonly credential: VerifiedCredential }
  | { readonly ok: false; readonly reason: CredentialFailure; readonly path?: string };
