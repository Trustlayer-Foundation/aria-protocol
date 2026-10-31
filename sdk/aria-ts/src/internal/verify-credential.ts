import { ed25519 } from '@noble/curves/ed25519.js';
import { sha256 } from '@noble/hashes/sha2.js';
import type { CredentialFailure, Principal } from '../credential';
import type { Did, TrustLevel } from '../types';
import { canonicalJson } from './canonical';
import { SUITE, verifyComposite, type IssuerKeys } from './composite';
import { fromBase58btc, toBase64 } from './encoding';
import { instant } from './instant';
import { schemaFailure } from './schema';

/** A trust profile as the verifier keeps it: copied and frozen at construction. */
export interface ProfileSnapshot {
  readonly id: string;
  readonly issuer: string;
  readonly verificationMethod: string;
  readonly keys: IssuerKeys;
  readonly maxLevel: TrustLevel;
  readonly statusLists: readonly string[];
  readonly onlineStatus: string | null;
}

/** What a verified credential is, as the verifier holds it. */
export interface CredentialSnapshot {
  readonly profile: ProfileSnapshot;
  readonly credentialId: string;
  readonly digest: string;
  readonly did: Did;
  readonly issuer: Did;
  readonly trustLevel: TrustLevel;
  readonly scopes: readonly string[];
  readonly hitlRequired: readonly string[];
  readonly delegationDepth: number;
  readonly principal: Principal;
  readonly holderKeyId: string;
  readonly holderKeyMultibase: string;
  readonly holderKey: Uint8Array;
  readonly validFrom: number;
  readonly validUntil: number;
  readonly previousCredentialId: string | null;
  readonly statusList: string;
  readonly statusIndex: number;
  readonly verifiedAt: number;
}

// Lowest first. Exported as TRUST_LEVELS and ranked by this verifier and by ARIA AP:
// frozen, so no consumer can reorder the ranking they apply.
export const LEVELS: readonly TrustLevel[] = Object.freeze(['L0', 'L1', 'L2', 'L3']);
const MAX_DOCUMENT_BYTES = 100 * 1024;

type Outcome = { readonly ok: true; readonly snapshot: CredentialSnapshot } | { readonly ok: false; readonly reason: CredentialFailure; readonly path?: string };

/** A private, plain-data copy of the input, or `null` when it is not a JSON object within the size bound. */
export function plainCopy(input: unknown): Record<string, unknown> | null {
  try {
    const text = typeof input === 'string' ? input : JSON.stringify(input);
    if (typeof text !== 'string' || new TextEncoder().encode(text).length > MAX_DOCUMENT_BYTES) return null;
    const value: unknown = JSON.parse(text);
    return value && typeof value === 'object' && !Array.isArray(value) ? (value as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

const fail = (reason: CredentialFailure, path?: string): Outcome => (path === undefined ? { ok: false, reason } : { ok: false, reason, path });

/**
 * Verifies one AID 1.0 document against the trust profiles, in a fixed order:
 * shape, version, schema, issuer, proof profile, both signatures, validity,
 * holder key, rules, level, status list. The first failure decides.
 */
export function verifyCredentialDocument(input: unknown, profiles: readonly ProfileSnapshot[], now: number, skewMs: number): Outcome {
  const doc = plainCopy(input);
  if (!doc) return fail('malformed', '/');
  const subject = doc.credentialSubject as Record<string, unknown> | undefined;
  if (!subject || typeof subject !== 'object') return fail('malformed', '/credentialSubject');
  if (subject.spec_version !== '1.0') return fail('unsupported_version', '/credentialSubject/spec_version');

  const schemaPath = schemaFailure(doc);
  if (schemaPath !== null) return fail('malformed', schemaPath);

  const profile = profiles.find((p) => p.issuer === doc.issuer);
  if (!profile) return fail('untrusted_issuer', '/issuer');

  const proof = doc.proof as Record<string, unknown>;
  if (
    proof.type !== 'DataIntegrityProof' ||
    proof.cryptosuite !== SUITE ||
    proof.proofPurpose !== 'assertionMethod' ||
    proof.verificationMethod !== profile.verificationMethod ||
    instant(proof.created) === null
  ) {
    return fail('unsupported_proof', '/proof');
  }
  if (typeof proof.proofValue !== 'string' || !verifyComposite(doc, proof.proofValue, profile.keys)) return fail('signature_invalid', '/proof/proofValue');

  const validFrom = instant(doc.validFrom);
  const validUntil = instant(doc.validUntil);
  if (validFrom === null || validUntil === null || validFrom >= validUntil) return fail('invalid_validity', '/validFrom');
  if (validFrom > now + skewMs) return fail('not_yet_valid', '/validFrom');
  if (validUntil <= now) return fail('expired', '/validUntil');

  const did = subject.id as Did;
  const holder = subject.holderKey as { id: string; publicKeyMultibase: string };
  const key = holder.publicKeyMultibase.startsWith('z') ? fromBase58btc(holder.publicKeyMultibase.slice(1)) : null;
  if (!key || key.length !== 32 || !holder.id.startsWith(`${did}#holder-key-`) || !acceptableEd25519Key(key)) return fail('holder_key_invalid', '/credentialSubject/holderKey');

  const scopes = subject.scope as string[];
  const hitl = (subject.hitlRequired as string[] | undefined) ?? [];
  if (!hitl.every((s) => scopes.includes(s))) return fail('semantic_invalid', '/credentialSubject/hitlRequired');

  const level = subject.trustLevel as TrustLevel;
  if (LEVELS.indexOf(level) > LEVELS.indexOf(profile.maxLevel)) return fail('level_not_trusted', '/credentialSubject/trustLevel');

  const status = doc.credentialStatus as { statusListCredential: string; statusListIndex: string };
  const index = Number(status.statusListIndex);
  if (!profile.statusLists.includes(status.statusListCredential)) return fail('status_list_untrusted', '/credentialStatus/statusListCredential');
  if (!/^(0|[1-9]\d*)$/.test(status.statusListIndex) || !Number.isSafeInteger(index)) return fail('semantic_invalid', '/credentialStatus/statusListIndex');

  const principal = subject.principal as Record<string, unknown>;
  return {
    ok: true,
    snapshot: {
      profile,
      credentialId: doc.id as string,
      digest: `sha-256=:${toBase64(sha256(new TextEncoder().encode(canonicalJson(doc))))}:`,
      did,
      issuer: doc.issuer as Did,
      trustLevel: level,
      scopes: [...scopes],
      hitlRequired: [...hitl],
      delegationDepth: (subject.delegationDepth as number | undefined) ?? 0,
      principal: {
        did: principal.did as string,
        type: principal.type === 'Person' ? 'individual' : 'organization',
        legalName: typeof principal.legalName === 'string' ? principal.legalName : null,
        jurisdiction: typeof principal.jurisdiction === 'string' ? principal.jurisdiction : null,
        verificationStatus: principal.verificationStatus as Principal['verificationStatus'],
      },
      holderKeyId: holder.id,
      holderKeyMultibase: holder.publicKeyMultibase,
      holderKey: key,
      validFrom,
      validUntil,
      previousCredentialId: typeof subject.previousCredentialId === 'string' ? subject.previousCredentialId : null,
      statusList: status.statusListCredential,
      statusIndex: index,
      verifiedAt: now,
    },
  };
}

/**
 * The authority's rule for a party's Ed25519 key (`ed25519_key_is_acceptable`):
 * the canonical encoding of a point, not of small order, without a torsion
 * component. An honestly generated key meets all of these; the identity point, a
 * second spelling of a key or a mixed-torsion key does not.
 */
export function acceptableEd25519Key(key: Uint8Array): boolean {
  if (key.length !== 32) return false;
  try {
    const point = ed25519.Point.fromBytes(key);
    const canonical = point.toBytes();
    return canonical.every((b, i) => b === key[i]) && !point.isSmallOrder() && point.isTorsionFree();
  } catch {
    return false;
  }
}
