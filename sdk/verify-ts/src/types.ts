// ─────────────────────────────────────────────────────────
// @aria-registry/verify — Type Definitions
// Part of the ARIA Protocol by TrustLayer Foundation
// https://aria.bar/docs/sdk
// ─────────────────────────────────────────────────────────

// ── Verification Result ───────────────────────────────────

/**
 * Complete result of an AID verification, including cryptographic
 * signature status, parsed agent metadata, and optional policy evaluation.
 *
 * Returned by {@link verifyAgent}. Even on failure, populated fields
 * contain whatever was successfully extracted before the check that failed.
 *
 * @since 0.1.0
 */
export interface VerifyResult {
  /** `true` when both cryptographic signatures verify and the credential is not expired. */
  valid: boolean;

  /**
   * Machine-readable failure code followed by a human-readable explanation.
   * Only present when `valid` is `false`.
   *
   * @example "SIGNATURE_INVALID: ML-DSA-65 signature verification failed"
   * @example "EXPIRED: credential has expired"
   */
  reason?: string;

  /** Decentralized Identifier of the agent (e.g. `"did:aria:example.com:my-agent"`). */
  did: string;

  /** Human-readable agent name as declared in the credential subject. */
  agent: string;

  /** Semantic version of the agent (e.g. `"1.0.1"`). */
  version: string;

  /** Principal (organization or individual) that controls this agent. */
  principal: {
    /** Legal or display name of the principal. */
    name: string;
    /** Domain associated with the principal, if domain-verified. */
    domain: string | null;
    /** ISO 3166-1 alpha-2 jurisdiction code (e.g. `"US"`, `"MX"`). */
    jurisdiction: string | null;
    /** Whether the principal is an organization or an individual. */
    type: 'organization' | 'individual';
    /**
     * Machine-readable provenance of `principal.name`.
     * - `"self-declared"` — registrant-asserted, no external check (L0, L1)
     * - `"registry-confirmed"` — confirmed against the Authoritative Source of the
     *   jurisdiction of incorporation (L2)
     * - `"legal-verified"` — backed by government-issued legal documents and admin review (L3)
     * - `null` — pre-v1.1 credential without this field
     *
     * Verifiers requiring a verified organizational identity should require
     * `verificationStatus !== "self-declared"` (or use the
     * {@link PolicyConfig.requirePrincipalVerified} option).
     *
     * @since 1.1.0
     */
    verificationStatus: 'self-declared' | 'registry-confirmed' | 'legal-verified' | null;
  };

  /**
   * ARIA trust level: `"L0"` (Anchored) through `"L3"` (Sovereign).
   * Higher levels require progressively stronger identity verification.
   */
  trustLevel: string;

  /**
   * Unique credential-instance identifier per W3C VC 2.0 §4.4 — the URL
   * embedded in the top-level `id` field. Equivalent to a TLS certificate
   * serial number; new on every reissuance.
   *
   * Format: `https://api.aria.bar/v1/credentials/{uuidv7}`. `null` for
   * pre-v1.1 credentials whose top-level id was the agent DID.
   *
   * @since 1.1.0
   */
  credentialId: string | null;

  /**
   * URL of the credential instance this AID supersedes. Set on every
   * reissuance after the first one. `null` for the very first AID issued
   * for a given agent and for pre-v1.1 credentials.
   *
   * @since 1.1.0
   */
  previousCredentialId: string | null;

  /**
   * Permission scopes granted to this agent (e.g. `["data:general:read"]`).
   * Scopes follow the `domain:resource:action` naming convention.
   */
  scopes: string[];

  /** Human-in-the-loop configuration, or `null` if HITL is not required. */
  hitlRequired: Record<string, unknown> | null;

  /** ISO 8601 timestamp of when the credential was issued. */
  issuedAt: string;

  /** ISO 8601 timestamp of when the credential expires. */
  expiresAt: string;

  /** `true` if `expiresAt` is in the past at the time of verification. */
  expired: boolean;

  /**
   * ARIA spec version declared in the credential (`"1.1"`, etc.).
   * `null` for credentials issued before this field was required.
   */
  specVersion: string | null;

  /** Detailed results of each cryptographic signature check. */
  signatures: {
    /** Whether the ML-DSA-65 (FIPS 204) post-quantum signature verified. */
    pqValid: boolean;
    /** Whether the Ed25519 (RFC 8032) classical signature verified. */
    classicalValid: boolean;
    /** Composite suite identifier (e.g. `"mldsa65-ed25519-2026"`). */
    suite: string;
  };

  /**
   * Revocation status of the credential.
   * - `"active"` — confirmed not revoked (online check passed)
   * - `"revoked"` — credential has been revoked
   * - `"unknown"` — no online check was performed (offline verification)
   */
  revocationStatus: 'active' | 'revoked' | 'unknown';

  /** ISO 8601 timestamp of the last online revocation check, or `null` if never checked. */
  revocationCheckedAt: string | null;

  /**
   * Result of policy evaluation, present only when a `policy` was supplied
   * in {@link VerifyOptions}.
   */
  policyResult?: {
    /** Whether all policy constraints were satisfied. */
    passed: boolean;
    /** Machine-readable reason for policy failure, if `passed` is `false`. */
    reason?: string;
  };
}

// ── Verification Options ──────────────────────────────────

/**
 * Options for {@link verifyAgent} controlling which checks to perform.
 *
 * @since 0.1.0
 */
export interface VerifyOptions {
  /**
   * Industry or custom policy to evaluate after signature verification.
   * Use one of the built-in {@link PolicyLevel} presets or provide your own.
   */
  policy?: PolicyConfig;

  /**
   * When `true`, skip cryptographic signature verification and only parse
   * the credential and check expiration. Useful for fast inspection in
   * trusted environments where the credential source is already authenticated.
   *
   * @default false
   */
  skipSignatureCheck?: boolean;
}

// ── Policy Configuration ──────────────────────────────────

/**
 * Policy constraints applied after cryptographic verification.
 * Policies encode industry-specific requirements for trust level,
 * permitted offline duration, required scopes, and revocation freshness.
 *
 * Use the built-in {@link PolicyLevel} presets (COMMERCE, FINANCIAL,
 * HEALTHCARE, GOVERNMENT, SOVEREIGN) or define your own.
 *
 * @example
 * ```typescript
 * const myPolicy: PolicyConfig = {
 *   maxOfflineAge: 4 * 60 * 60 * 1000, // 4 hours
 *   minTrustLevel: 'L2',
 *   requiredScopes: ['financial:invoice:approve'],
 * };
 * ```
 *
 * @since 0.1.0
 */
export interface PolicyConfig {
  /**
   * Maximum time in milliseconds that the credential can be trusted
   * offline without a revocation check.
   * - `null` — no limit (fully offline is acceptable)
   * - `number` — compared against `lastRevocationCheck` to determine freshness
   */
  maxOfflineAge: number | null;

  /**
   * Minimum ARIA trust level the agent must hold.
   * Verification order: `L0 < L1 < L2 < L3`.
   */
  minTrustLevel?: 'L0' | 'L1' | 'L2' | 'L3';

  /**
   * Scopes that must all be present in the agent's credential.
   * The check is AND-based: every scope listed must exist in the AID.
   */
  requiredScopes?: string[];

  /**
   * When `true`, the policy fails if no online revocation check has been
   * performed within the `maxOfflineAge` window.
   *
   * @default false
   */
  requireRevocationCheck?: boolean;

  /**
   * Unix timestamp (milliseconds) of the last known online revocation check
   * for this credential, as tracked by the calling system's cache.
   * Compared against `maxOfflineAge` to determine offline staleness.
   */
  lastRevocationCheck?: number;

  /**
   * When `true`, the policy fails for credentials whose
   * `principal.verificationStatus` is `"self-declared"` or `null`. Use this
   * to reject AIDs whose legal name was asserted by the registrant without
   * an external check (L0 and L1, plus pre-v1.1 credentials that have no
   * provenance field).
   *
   * @default false
   * @since 1.1.0
   */
  requirePrincipalVerified?: boolean;
}

// ── Parsed Credential ─────────────────────────────────────

/**
 * Credential contents extracted without cryptographic verification.
 * Returned by {@link parseCredential} for fast, trust-free inspection.
 *
 * **Warning:** Fields in this type have NOT been verified against the
 * registry's signatures. Do not use for access control decisions.
 *
 * @since 0.1.0
 */
export interface ParsedCredential {
  /**
   * Decentralized Identifier of the agent (e.g. `"did:aria:example.com:my-agent"`).
   * Stable across reissuances. For v1.1 credentials this is taken from
   * `credentialSubject.id`; for v1.0 credentials it falls back to the
   * top-level `id` field, which carried the DID in that schema version.
   */
  did: string;

  /** Human-readable agent name. */
  agent: string;

  /** Semantic version of the agent. */
  version: string;

  /** Principal (organization or individual) that controls this agent. */
  principal: {
    /** Legal or display name. */
    name: string;
    /** Associated domain, if any. */
    domain: string | null;
    /** ISO 3166-1 alpha-2 jurisdiction code. */
    jurisdiction: string | null;
    /** Principal classification. */
    type: 'organization' | 'individual';
    /**
     * Machine-readable provenance of `principal.name`.
     * Enum: `"self-declared"` (L0/L1) | `"registry-confirmed"` (L2) |
     * `"legal-verified"` (L3). `null` for pre-v1.1 credentials.
     *
     * @since 1.1.0
     */
    verificationStatus: 'self-declared' | 'registry-confirmed' | 'legal-verified' | null;
  };

  /** ARIA trust level (`"L0"` through `"L3"`). */
  trustLevel: string;

  /** Permission scopes granted to this agent. */
  scopes: string[];

  /** Human-in-the-loop configuration, or `null` if not required. */
  hitlRequired: Record<string, unknown> | null;

  /** ISO 8601 timestamp of when the credential was issued. */
  issuedAt: string;

  /** ISO 8601 timestamp of when the credential expires. */
  expiresAt: string;

  /** `true` if `expiresAt` is in the past at the time of parsing. */
  expired: boolean;

  /**
   * ARIA spec version declared in the credential (`"1.1"`, etc.).
   * `null` for credentials issued before this field was required.
   * @since 0.1.0
   */
  specVersion: string | null;

  /**
   * Unique credential-instance URL per W3C VC 2.0 §4.4 — the value of the
   * top-level `id` field. `null` for pre-v1.1 credentials whose top-level id
   * was the agent DID.
   *
   * @since 1.1.0
   */
  credentialId: string | null;

  /**
   * URL of the credential this AID supersedes (set on reissue), or `null`
   * for the first credential in the chain or pre-v1.1 credentials.
   *
   * @since 1.1.0
   */
  previousCredentialId: string | null;

  /**
   * The raw W3C Verifiable Credential as a plain object.
   * Includes the `proof` object and all JSON-LD context.
   */
  rawVc: Record<string, unknown>;
}

// ── Revocation Result ─────────────────────────────────────

/**
 * Result of an online revocation status check via the ARIA API.
 * Returned by {@link checkRevocation}.
 *
 * @since 0.1.0
 */
export interface RevocationResult {
  /** The DID that was checked. */
  did: string;

  /** Current revocation status as reported by the ARIA API. */
  status: 'active' | 'revoked';

  /** ISO 8601 timestamp of when this check was performed. */
  checkedAt: string;
}
