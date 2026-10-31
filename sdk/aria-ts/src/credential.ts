import type { issued } from './internal';
import type { CredentialBinding, Did, TrustLevel } from './types';

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
  | 'malformed'
  | 'unsupported_version'
  /** Proof metadata is not the supported profile. Checking it does not make it signed. */
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
  /** Missing, or not the 32 raw bytes of the ARIA 1.0 compatibility profile. */
  | 'holder_key_invalid'
  /** Valid against its schema but not its rules, e.g. `hitlRequired` outside `scope`. */
  | 'semantic_invalid';

export interface Principal {
  readonly did: Did;
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
 */
export interface VerifiedCredential {
  readonly [issued]: 'credential';
  readonly binding: CredentialBinding;
  /** The agent's stable identity. */
  readonly did: Did;
  readonly issuer: Did;
  readonly specVersion: '1.0';
  readonly trustLevel: TrustLevel;
  readonly scopes: readonly string[];
  /** Scopes the receiver must not act on without a human's approval; a declaration, not an approval. */
  readonly hitlRequired: readonly string[];
  readonly principal: Principal;
  readonly holderKey: { readonly id: string; readonly ed25519: Uint8Array };
  /** Signed validity bounds. There is no issuance time: `proof.created` is outside the signature. */
  readonly validFrom: Date;
  readonly validUntil: Date;
  /** Signed predecessor reference, as data. Verification never fetches it. */
  readonly previousCredentialId: string | null;
  readonly statusEntry: { readonly list: string; readonly index: number };
  /** Local time of this verification. */
  readonly verifiedAt: Date;
}

export type CredentialResult =
  | { readonly ok: true; readonly credential: VerifiedCredential }
  | { readonly ok: false; readonly reason: CredentialFailure; readonly path?: string };
