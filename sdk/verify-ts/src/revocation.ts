// ─────────────────────────────────────────────────────────
// @aria-registry/verify — Online Revocation Check
// Part of the ARIA Protocol by TrustLayer Foundation
// https://aria.bar/docs/sdk
// ─────────────────────────────────────────────────────────
//
// This is the ONLY module in the SDK that requires network
// access. All other operations are fully offline.

import { RevocationCheckError } from './errors';
import type { RevocationResult } from './types';

// ── Constants ─────────────────────────────────────────────

/** Default ARIA API base URL for revocation checks. */
const DEFAULT_API_URL = 'https://api.aria.bar';

/** HTTP request timeout in milliseconds. */
const REQUEST_TIMEOUT_MS = 5_000;

// ── Types ─────────────────────────────────────────────────

/** Options for {@link checkRevocation}. */
interface RevocationOptions {
  /**
   * Base URL of the ARIA API.
   * @default "https://api.aria.bar"
   */
  apiUrl?: string;
}

// ── Revocation Check ──────────────────────────────────────

/**
 * Check the revocation status of an AID via the ARIA public API.
 *
 * This is the **only function in the SDK that requires internet access**.
 * It performs a single HTTP GET to the ARIA API's verification endpoint
 * and returns the current revocation status.
 *
 * @param did - The agent's DID to check (e.g. `"did:aria:example.com:my-agent"`)
 * @param options - Optional configuration (custom API URL)
 * @returns The revocation status with a timestamp of when the check was performed
 * @throws {RevocationCheckError} If the API is unreachable, returns a non-200
 *   status, or the request times out after 5 seconds
 *
 * @example
 * ```typescript
 * import { checkRevocation } from '@aria-registry/verify';
 *
 * try {
 *   const result = await checkRevocation('did:aria:example.com:agent');
 *   console.log(result.status); // 'active' | 'revoked'
 * } catch (err) {
 *   if (err instanceof RevocationCheckError) {
 *     console.log('API unreachable:', err.message);
 *   }
 * }
 * ```
 *
 * @example
 * ```typescript
 * // Against a local ARIA API instance
 * const result = await checkRevocation(did, {
 *   apiUrl: 'http://localhost:3003',
 * });
 * ```
 *
 * @since 0.1.0
 */
export async function checkRevocation(
  did: string,
  options?: RevocationOptions,
): Promise<RevocationResult> {
  const apiUrl = options?.apiUrl ?? DEFAULT_API_URL;
  const url = `${apiUrl}/v1/verify/${encodeURIComponent(did)}`;

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

    const response = await fetch(url, {
      method: 'GET',
      headers: { 'Accept': 'application/json' },
      signal: controller.signal,
    });

    clearTimeout(timeout);

    if (!response.ok) {
      throw new RevocationCheckError(
        `ARIA API returned HTTP ${response.status} (${response.statusText}). `
        + `Endpoint: ${url}`,
      );
    }

    const data = await response.json() as { status?: string };
    const status = data.status === 'revoked' ? 'revoked' as const : 'active' as const;

    return {
      did,
      status,
      checkedAt: new Date().toISOString(),
    };
  } catch (error) {
    if (error instanceof RevocationCheckError) {
      throw error;
    }
    const message = error instanceof Error ? error.message : 'Unknown error';
    throw new RevocationCheckError(
      `Failed to check revocation for ${did}: ${message}. `
      + `Ensure the ARIA API is reachable at ${apiUrl}.`,
    );
  }
}
