// ─────────────────────────────────────────────────────────
// @aria-registry/verify — Error Hierarchy
// Part of the ARIA Protocol by TrustLayer Foundation
// https://aria.bar/docs/sdk
// ─────────────────────────────────────────────────────────

/**
 * Base error for all ARIA verification failures.
 *
 * Every error carries a machine-readable `code` (e.g. `"INVALID_CREDENTIAL"`)
 * and a human-readable `message` explaining what went wrong.
 *
 * @since 0.1.0
 */
export class AriaVerifyError extends Error {
  /** Machine-readable error code (e.g. `"REVOCATION_CHECK_FAILED"`). */
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = 'AriaVerifyError';
    this.code = code;
  }
}

/**
 * Thrown when an online revocation check fails due to network issues,
 * timeouts, or an unexpected API response.
 *
 * This is the only error that indicates a network problem — all other
 * SDK operations are fully offline.
 *
 * @example
 * ```typescript
 * try {
 *   await checkRevocation('did:aria:example.com:agent');
 * } catch (err) {
 *   if (err instanceof RevocationCheckError) {
 *     console.log('Network issue:', err.message);
 *   }
 * }
 * ```
 *
 * @since 0.1.0
 */
export class RevocationCheckError extends AriaVerifyError {
  constructor(message: string) {
    super('REVOCATION_CHECK_FAILED', message);
    this.name = 'RevocationCheckError';
  }
}

/**
 * Thrown when the input cannot be recognized as a valid ARIA credential.
 * This covers malformed JSON, missing required fields, and structurally
 * invalid W3C Verifiable Credentials.
 *
 * @since 0.1.0
 */
export class InvalidCredentialError extends AriaVerifyError {
  constructor(message: string) {
    super('INVALID_CREDENTIAL', message);
    this.name = 'InvalidCredentialError';
  }
}
