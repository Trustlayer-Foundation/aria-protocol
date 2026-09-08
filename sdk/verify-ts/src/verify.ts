// ─────────────────────────────────────────────────────────
// @aria-registry/verify — Core Verification Engine
// Part of the ARIA Protocol by TrustLayer Foundation
// https://aria.bar/docs/sdk
// ─────────────────────────────────────────────────────────

import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { ed25519 } from '@noble/curves/ed25519.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import { canonicalJson } from './canonical-json';
import { parseCredential } from './parse';
import {
  REGISTRY_PUBLIC_KEY_MLDSA65,
  REGISTRY_PUBLIC_KEY_ED25519,
  COMPOSITE_SUITE,
} from './registry-key';
import type { VerifyResult, VerifyOptions, PolicyConfig } from './types';

// ── Constants ─────────────────────────────────────────────

/** Maximum credential size in bytes (100 KB). */
const MAX_CREDENTIAL_SIZE = 100 * 1024;

/** Minimum byte length for a composite proof (4-byte length prefix). */
const COMPOSITE_PROOF_HEADER_SIZE = 4;

/** Trust level ordering for policy comparison. */
const TRUST_LEVEL_ORDER: Record<string, number> = {
  L0: 0,
  L1: 1,
  L2: 2,
  L3: 3,
};

/** Milliseconds per minute — used for human-readable offline-age messages. */
const MS_PER_MINUTE = 60 * 1000;

// ── Encoding Helpers ──────────────────────────────────────

/**
 * Convert a hex string to a Uint8Array.
 * @internal
 */
function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

/**
 * Decode a base64url string (RFC 4648 §5, no padding) to raw bytes.
 * @internal
 */
function base64urlToBytes(b64: string): Uint8Array {
  let base64 = b64.replace(/-/g, '+').replace(/_/g, '/');
  while (base64.length % 4 !== 0) {
    base64 += '=';
  }
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

// ── Composite Proof Decoding ──────────────────────────────
// Both signatures travel in one proofValue:
//   [4 bytes: PQ sig length (big-endian uint32)]
//   [PQ signature bytes]
//   [Classical signature bytes]
//
// Two encodings of those bytes are in circulation. Suite 1.0 emits multibase
// base64url -- a leading "u" per the multibase table -- because the VC v2
// context types proofValue as sec:multibase, and a bare base64 string claiming
// that datatype is not one. Credentials issued before the cutover carry the
// same bytes with no prefix. Verifiers accept both.
//
// For this suite the two cannot be confused: the header is always 0x00000CED,
// the ML-DSA-65 signature length, so a bare proofValue always begins "AAAM" and
// never "u". The decoder still checks the header rather than trusting the first
// character, so a suite whose header encodes differently stays decidable.

/** ML-DSA-65 signature length in bytes (FIPS 204). */
const ML_DSA_65_SIGNATURE_SIZE = 3309;

/** Ed25519 signature length in bytes (RFC 8032). */
const ED25519_SIGNATURE_SIZE = 64;

/**
 * Decode one reading of a proofValue, rejecting it unless the length header
 * accounts for every byte. This is what makes the multibase prefix detectable
 * rather than guessed: a bare base64url string that happens to begin with "u"
 * decodes to a header that does not describe its own length.
 */
function decodeCandidate(
  base64url: string,
): { pqSignature: Uint8Array; classicalSignature: Uint8Array } | null {
  try {
    const combined = base64urlToBytes(base64url);
    if (combined.length !== COMPOSITE_PROOF_HEADER_SIZE + ML_DSA_65_SIGNATURE_SIZE + ED25519_SIGNATURE_SIZE) {
      return null;
    }

    const view = new DataView(combined.buffer, combined.byteOffset, combined.byteLength);
    if (view.getUint32(0, false) !== ML_DSA_65_SIGNATURE_SIZE) return null; // big-endian

    return {
      pqSignature: combined.slice(COMPOSITE_PROOF_HEADER_SIZE, COMPOSITE_PROOF_HEADER_SIZE + ML_DSA_65_SIGNATURE_SIZE),
      classicalSignature: combined.slice(COMPOSITE_PROOF_HEADER_SIZE + ML_DSA_65_SIGNATURE_SIZE),
    };
  } catch {
    return null;
  }
}

/**
 * Decode a composite proofValue into its PQ and classical components.
 *
 * Accepts both the multibase form suite 1.0 emits (`u` + base64url) and the
 * bare base64url form issued before the cutover.
 *
 * @internal
 */
function decodeCompositeProof(
  proofValue: string,
): { pqSignature: Uint8Array; classicalSignature: Uint8Array } | null {
  // Read as multibase first when prefixed; fall back to reading the whole
  // string, so the header decides rather than the first character.
  const readings = proofValue.startsWith('u') ? [proofValue.slice(1), proofValue] : [proofValue];
  for (const reading of readings) {
    const decoded = decodeCandidate(reading);
    if (decoded) return decoded;
  }
  return null;
}

// ── Result Helpers ────────────────────────────────────────

/** Build a failed VerifyResult with sensible defaults for missing fields. */
function makeFailResult(reason: string, partial?: Partial<VerifyResult>): VerifyResult {
  return {
    valid: false,
    reason,
    did: partial?.did ?? '',
    agent: partial?.agent ?? '',
    version: partial?.version ?? '',
    principal: partial?.principal ?? {
      name: '', domain: null, jurisdiction: null, type: 'organization', verificationStatus: null,
    },
    trustLevel: partial?.trustLevel ?? '',
    specVersion: partial?.specVersion ?? null,
    credentialId: partial?.credentialId ?? null,
    previousCredentialId: partial?.previousCredentialId ?? null,
    scopes: partial?.scopes ?? [],
    hitlRequired: partial?.hitlRequired ?? null,
    issuedAt: partial?.issuedAt ?? '',
    expiresAt: partial?.expiresAt ?? '',
    expired: partial?.expired ?? false,
    signatures: partial?.signatures ?? { pqValid: false, classicalValid: false, suite: COMPOSITE_SUITE },
    revocationStatus: 'unknown',
    revocationCheckedAt: null,
    ...partial,
  };
}

// ── Policy Evaluation ─────────────────────────────────────

/**
 * Evaluate a policy against the agent's trust level, scopes, and principal
 * verification status.
 * @internal
 */
function evaluatePolicy(
  policy: PolicyConfig,
  trustLevel: string,
  scopes: string[],
  verificationStatus: 'self-declared' | 'registry-confirmed' | 'legal-verified' | null,
): { passed: boolean; reason?: string } {
  // Trust level check
  if (policy.minTrustLevel) {
    const requiredLevel = TRUST_LEVEL_ORDER[policy.minTrustLevel];
    const actualLevel = TRUST_LEVEL_ORDER[trustLevel];
    if (actualLevel === undefined || requiredLevel === undefined) {
      return { passed: false, reason: `TRUST_LEVEL: unknown level "${trustLevel}"` };
    }
    if (actualLevel < requiredLevel) {
      return {
        passed: false,
        reason: `TRUST_LEVEL: requires ${policy.minTrustLevel}, got ${trustLevel}`,
      };
    }
  }

  // Principal-verification check (ARIA 1.0)
  if (policy.requirePrincipalVerified) {
    if (verificationStatus === null) {
      return {
        passed: false,
        reason: 'PRINCIPAL_NOT_VERIFIED: credential predates ARIA 1.0 and carries no '
          + 'principal.verificationStatus field',
      };
    }
    if (verificationStatus === 'self-declared') {
      return {
        passed: false,
        reason: 'PRINCIPAL_NOT_VERIFIED: principal.verificationStatus is "self-declared"; '
          + 'requires "registry-confirmed" or "legal-verified"',
      };
    }
  }

  // Required scopes check
  if (policy.requiredScopes && policy.requiredScopes.length > 0) {
    const missing = policy.requiredScopes.filter(s => !scopes.includes(s));
    if (missing.length > 0) {
      return {
        passed: false,
        reason: `MISSING_SCOPES: ${missing.join(', ')}`,
      };
    }
  }

  // Offline age / revocation freshness check
  if (policy.maxOfflineAge !== null && policy.maxOfflineAge !== undefined) {
    if (policy.requireRevocationCheck && !policy.lastRevocationCheck) {
      return {
        passed: false,
        reason: 'REVOCATION_CHECK_REQUIRED: no revocation check has been performed',
      };
    }

    if (policy.lastRevocationCheck) {
      const age = Date.now() - policy.lastRevocationCheck;
      if (age > policy.maxOfflineAge) {
        return {
          passed: false,
          reason: `OFFLINE_TOO_LONG: last check was ${Math.round(age / MS_PER_MINUTE)} minutes ago, max allowed is ${Math.round(policy.maxOfflineAge / MS_PER_MINUTE)} minutes`,
        };
      }
    } else if (policy.requireRevocationCheck) {
      return {
        passed: false,
        reason: 'REVOCATION_CHECK_REQUIRED: no revocation check has been performed',
      };
    }
  }

  return { passed: true };
}

// ── Main Verification Function ────────────────────────────

/**
 * Verify an AI agent's identity offline using post-quantum cryptography.
 *
 * Checks both ML-DSA-65 (FIPS 204) and Ed25519 (RFC 8032) signatures
 * against the ARIA Registry root public key embedded in this SDK.
 * No network connection required.
 *
 * Verification steps:
 * 1. Parse and validate the credential structure
 * 2. Check expiration (`validUntil`)
 * 3. Verify ML-DSA-65 post-quantum signature
 * 4. Verify Ed25519 classical signature
 * 5. Verify content hash (if present)
 * 6. Evaluate policy constraints (if provided)
 *
 * @param input - The AID (Agent Identity Document) as a JSON string,
 *   parsed object, or W3C Verifiable Credential. Maximum 100 KB.
 * @param options - Optional verification settings including policy evaluation
 *   and the ability to skip signature checks for fast inspection
 * @returns Complete verification result with signature status, agent details,
 *   trust level, scopes, and optional policy evaluation
 *
 * @example
 * ```typescript
 * import { verifyAgent } from '@aria-registry/verify';
 *
 * const result = verifyAgent(credential);
 * if (result.valid) {
 *   console.log(`Agent ${result.did} verified at ${result.trustLevel}`);
 * }
 * ```
 *
 * @example
 * ```typescript
 * // With industry policy
 * import { verifyAgent, PolicyLevel } from '@aria-registry/verify';
 *
 * const result = verifyAgent(credential, {
 *   policy: PolicyLevel.FINANCIAL,
 * });
 * if (!result.policyResult?.passed) {
 *   console.log(`Policy failed: ${result.policyResult?.reason}`);
 * }
 * ```
 *
 * @since 0.1.0
 */
export function verifyAgent(input: unknown, options?: VerifyOptions): VerifyResult {
  // ── Input Validation ──────────────────────────────────
  // Reject null, oversized, and non-object inputs before
  // any parsing or cryptographic work.

  if (input === null || input === undefined) {
    return makeFailResult('INVALID_FORMAT: input is null or undefined');
  }

  let rawStr: string;
  if (typeof input === 'string') {
    if (input.length > MAX_CREDENTIAL_SIZE) {
      return makeFailResult(
        'INPUT_TOO_LARGE: credential exceeds maximum size of 100 KB. '
        + 'Ensure you are passing a single AID, not a batch.',
      );
    }
    rawStr = input;
  } else if (typeof input === 'object' && !Array.isArray(input)) {
    try {
      rawStr = JSON.stringify(input);
      if (rawStr.length > MAX_CREDENTIAL_SIZE) {
        return makeFailResult(
          'INPUT_TOO_LARGE: credential exceeds maximum size of 100 KB. '
          + 'Ensure you are passing a single AID, not a batch.',
        );
      }
    } catch {
      return makeFailResult('INVALID_FORMAT: cannot serialize input to JSON');
    }
  } else {
    return makeFailResult('INVALID_FORMAT: input must be a JSON string or object');
  }

  // ── Credential Parsing ────────────────────────────────
  // Delegate structural validation to parseCredential().
  // On failure, try to provide a more specific error.

  const parsed = parseCredential(rawStr);
  if (!parsed) {
    try {
      const obj = JSON.parse(rawStr);
      if (obj && typeof obj === 'object' && obj.credentialSubject) {
        return makeFailResult(
          'MISSING_FIELDS: required fields are missing from credentialSubject. '
          + 'Ensure agentName, version, principal, trustLevel, and scope are present.',
        );
      }
      return makeFailResult('MISSING_FIELDS: not a valid ARIA credential');
    } catch {
      return makeFailResult('INVALID_FORMAT: input is not valid JSON');
    }
  }

  const partial: Partial<VerifyResult> = {
    did: parsed.did,
    agent: parsed.agent,
    version: parsed.version,
    principal: parsed.principal,
    trustLevel: parsed.trustLevel,
    specVersion: parsed.specVersion,
    credentialId: parsed.credentialId,
    previousCredentialId: parsed.previousCredentialId,
    scopes: parsed.scopes,
    hitlRequired: parsed.hitlRequired,
    issuedAt: parsed.issuedAt,
    expiresAt: parsed.expiresAt,
    expired: parsed.expired,
  };

  // ── Expiration Check ──────────────────────────────────

  if (parsed.expired) {
    return makeFailResult('EXPIRED: credential has expired', {
      ...partial,
      expired: true,
      signatures: { pqValid: false, classicalValid: false, suite: COMPOSITE_SUITE },
    });
  }

  // ── Skip Signature Check (fast path) ──────────────────

  if (options?.skipSignatureCheck) {
    const result: VerifyResult = {
      valid: true,
      did: parsed.did,
      agent: parsed.agent,
      version: parsed.version,
      principal: parsed.principal,
      trustLevel: parsed.trustLevel,
      specVersion: parsed.specVersion,
      credentialId: parsed.credentialId,
      previousCredentialId: parsed.previousCredentialId,
      scopes: parsed.scopes,
      hitlRequired: parsed.hitlRequired,
      issuedAt: parsed.issuedAt,
      expiresAt: parsed.expiresAt,
      expired: false,
      signatures: { pqValid: false, classicalValid: false, suite: COMPOSITE_SUITE },
      revocationStatus: 'unknown',
      revocationCheckedAt: null,
    };

    if (options.policy) {
      result.policyResult = evaluatePolicy(options.policy, parsed.trustLevel, parsed.scopes, parsed.principal.verificationStatus);
    }

    return result;
  }

  // ── Signature Verification ────────────────────────────
  // Both signatures must verify (AND, not OR).
  // ML-DSA-65 is the post-quantum primary.
  // Ed25519 is the classical transition signature.
  //
  // Verification runs against the canonical JSON of the VC
  // without the proof object — identical to what ARIACORE signs.
  //
  // Two proof formats are supported:
  //   1. Production: single "proofValue" (base64url) with both
  //      signatures concatenated via length-prefix encoding
  //   2. Test fixtures: separate "proofValuePq" and
  //      "proofValueClassical" fields (hex-encoded)

  const vc = parsed.rawVc;
  const proof = vc.proof as Record<string, unknown> | undefined;

  if (!proof) {
    return makeFailResult(
      'INVALID_FORMAT: missing proof object. '
      + 'The credential must include a DataIntegrityProof with signature data.',
      partial,
    );
  }

  const vcWithoutProof = { ...vc };
  delete vcWithoutProof.proof;
  const canonicalPayload = canonicalJson(vcWithoutProof);
  const payloadBytes = new TextEncoder().encode(canonicalPayload);

  let pqValid = false;
  let classicalValid = false;

  const compositeProofValue = proof.proofValue as string | undefined;
  const separatePq = proof.proofValuePq as string | undefined;

  if (compositeProofValue && typeof compositeProofValue === 'string' && !separatePq) {
    // Production format: decode composite proof
    const decoded = decodeCompositeProof(compositeProofValue);
    if (decoded) {
      try {
        pqValid = ml_dsa65.verify(decoded.pqSignature, payloadBytes, REGISTRY_PUBLIC_KEY_MLDSA65);
      } catch {
        pqValid = false;
      }
      try {
        classicalValid = ed25519.verify(decoded.classicalSignature, payloadBytes, REGISTRY_PUBLIC_KEY_ED25519);
      } catch {
        classicalValid = false;
      }
    }
  } else {
    // Test format: separate hex-encoded fields
    if (separatePq && typeof separatePq === 'string') {
      try {
        const sigBytes = hexToBytes(separatePq);
        pqValid = ml_dsa65.verify(sigBytes, payloadBytes, REGISTRY_PUBLIC_KEY_MLDSA65);
      } catch {
        pqValid = false;
      }
    }
    const classicalSigHex = proof.proofValueClassical as string | undefined;
    if (classicalSigHex && typeof classicalSigHex === 'string') {
      try {
        const sigBytes = hexToBytes(classicalSigHex);
        classicalValid = ed25519.verify(sigBytes, payloadBytes, REGISTRY_PUBLIC_KEY_ED25519);
      } catch {
        classicalValid = false;
      }
    }
  }

  const signatures = { pqValid, classicalValid, suite: COMPOSITE_SUITE };

  if (!pqValid || !classicalValid) {
    const failedSigs = [];
    if (!pqValid) failedSigs.push('ML-DSA-65');
    if (!classicalValid) failedSigs.push('Ed25519');
    return makeFailResult(
      `SIGNATURE_INVALID: ${failedSigs.join(' and ')} signature verification failed. `
      + 'Ensure the credential was signed by the ARIA Registry and has not been modified.',
      { ...partial, signatures },
    );
  }

  // ── Content Hash Verification ─────────────────────────
  // Optional integrity check: if a contentHash is present in
  // the proof, verify it matches the SHA-256 of the canonical payload.

  const contentHash = proof.contentHash as string | undefined;
  if (contentHash && typeof contentHash === 'string') {
    const computed = bytesToHex(sha256(payloadBytes));
    if (computed !== contentHash) {
      return makeFailResult(
        'CONTENT_HASH_MISMATCH: the SHA-256 hash of the credential content does not match '
        + 'the hash recorded in the proof. The credential may have been modified after signing.',
        { ...partial, signatures },
      );
    }
  }

  // ── Policy Evaluation ─────────────────────────────────

  let policyResult: { passed: boolean; reason?: string } | undefined;
  if (options?.policy) {
    policyResult = evaluatePolicy(options.policy, parsed.trustLevel, parsed.scopes, parsed.principal.verificationStatus);
  }

  // ── Build Success Result ──────────────────────────────

  const result: VerifyResult = {
    valid: true,
    did: parsed.did,
    agent: parsed.agent,
    version: parsed.version,
    principal: parsed.principal,
    trustLevel: parsed.trustLevel,
    specVersion: parsed.specVersion,
    credentialId: parsed.credentialId,
    previousCredentialId: parsed.previousCredentialId,
    scopes: parsed.scopes,
    hitlRequired: parsed.hitlRequired,
    issuedAt: parsed.issuedAt,
    expiresAt: parsed.expiresAt,
    expired: false,
    signatures,
    revocationStatus: 'unknown',
    revocationCheckedAt: null,
  };

  if (policyResult) {
    result.policyResult = policyResult;
  }

  return result;
}
