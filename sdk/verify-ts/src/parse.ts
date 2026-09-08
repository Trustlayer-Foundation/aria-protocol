// ─────────────────────────────────────────────────────────
// @aria-registry/verify — Credential Parser (no signature checks)
// Part of the ARIA Protocol by TrustLayer Foundation
// https://aria.bar/docs/sdk
// ─────────────────────────────────────────────────────────

import type { ParsedCredential } from './types';

/** Maximum credential size in bytes (100 KB). */
const MAX_CREDENTIAL_SIZE = 100 * 1024;

/**
 * Parse an ARIA Agent Identity Document without verifying signatures.
 *
 * Extracts agent metadata, principal information, trust level, scopes,
 * and expiration status from a W3C Verifiable Credential. No cryptographic
 * operations are performed — this is a fast, trust-free inspection path.
 *
 * **Warning:** The returned data has NOT been verified against the
 * registry's signatures. Do not use for access control decisions.
 * Use {@link verifyAgent} for authenticated verification.
 *
 * @param input - The AID as a JSON string or parsed object. Maximum 100 KB.
 * @returns Parsed credential contents, or `null` if the input is
 *   not a structurally valid ARIA credential
 *
 * @example
 * ```typescript
 * import { parseCredential } from '@aria-registry/verify';
 *
 * const parsed = parseCredential(aidJson);
 * if (parsed) {
 *   console.log(parsed.agent, parsed.trustLevel, parsed.scopes);
 * }
 * ```
 *
 * @since 0.1.0
 */
export function parseCredential(input: unknown): ParsedCredential | null {
  try {
    // ── Input coercion ────────────────────────────────────

    let vc: Record<string, unknown>;

    if (typeof input === 'string') {
      if (input.length > MAX_CREDENTIAL_SIZE) {
        return null;
      }
      vc = JSON.parse(input) as Record<string, unknown>;
    } else if (input && typeof input === 'object' && !Array.isArray(input)) {
      vc = input as Record<string, unknown>;
    } else {
      return null;
    }

    // ── Structural validation ─────────────────────────────
    // A valid ARIA AID must have a top-level `id` and a `credentialSubject`
    // with agent-specific fields. In ARIA 1.0 the top-level `id` is a unique
    // credential-instance URL (W3C VC 2.0 §4.4) and the agent DID lives in
    // `credentialSubject.id`. Pre-cutover credentials reused the DID at the
    // top level — both shapes are accepted.

    if (typeof vc.id !== 'string') return null;
    if (!vc.credentialSubject || typeof vc.credentialSubject !== 'object') return null;

    const subject = vc.credentialSubject as Record<string, unknown>;

    const agentName = subject.agentName;
    const version = subject.version;
    const principal = subject.principal as Record<string, unknown> | undefined;
    const trustLevel = subject.trustLevel;
    const scopes = subject.scope;

    if (typeof agentName !== 'string') return null;
    if (typeof version !== 'string') return null;
    if (!principal || typeof principal !== 'object') return null;
    if (typeof trustLevel !== 'string') return null;
    if (!Array.isArray(scopes)) return null;

    const validFrom = vc.validFrom;
    const validUntil = vc.validUntil;

    if (typeof validFrom !== 'string') return null;
    if (typeof validUntil !== 'string') return null;

    // ── DID + credential-instance URL split ───────────────
    // ARIA 1.0: top-level id is an HTTPS URL (credential instance), DID is in
    //       credentialSubject.id.
    // v1.0: top-level id is the DID (no credential URL exists).

    const topLevelId = vc.id as string;
    const subjectId = typeof subject.id === 'string' ? (subject.id as string) : null;
    const isCredentialInstanceUrl = topLevelId.startsWith('https://');
    const did = isCredentialInstanceUrl ? (subjectId ?? topLevelId) : topLevelId;
    const credentialId = isCredentialInstanceUrl ? topLevelId : null;
    const previousCredentialId = typeof subject.previousCredentialId === 'string'
      ? (subject.previousCredentialId as string)
      : null;

    // ── Principal verification status ─────────────────────
    // ARIA 1.0 AID — machine-readable provenance of principal.name.

    const rawVerificationStatus = principal.verificationStatus;
    const verificationStatus =
      rawVerificationStatus === 'self-declared'
        || rawVerificationStatus === 'registry-confirmed'
        || rawVerificationStatus === 'legal-verified'
        ? rawVerificationStatus
        : null;

    // ── Build result ──────────────────────────────────────

    const expired = new Date(validUntil) < new Date();

    return {
      did,
      agent: agentName,
      version,
      principal: {
        // Support both formats: production AIDs use "legalName", test fixtures use "name"
        name: (principal.legalName as string) ?? (principal.name as string) ?? '',
        domain: (principal.domain as string) ?? null,
        jurisdiction: (principal.jurisdiction as string) ?? null,
        type: (principal.type as 'organization' | 'individual') ?? 'organization',
        verificationStatus,
      },
      trustLevel,
      scopes: scopes as string[],
      hitlRequired: (subject.hitlRequired as Record<string, unknown>) ?? null,
      issuedAt: validFrom,
      expiresAt: validUntil,
      expired,
      specVersion: typeof subject.spec_version === 'string' ? subject.spec_version : null,
      credentialId,
      previousCredentialId,
      rawVc: vc,
    };
  } catch {
    return null;
  }
}
