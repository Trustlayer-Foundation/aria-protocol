// ─────────────────────────────────────────────────────────
// @aria-registry/verify — Industry Policy Presets
// Part of the ARIA Protocol by TrustLayer Foundation
// https://aria.bar/docs/sdk
// ─────────────────────────────────────────────────────────
//
// Presets based on real regulatory standards:
//   COMMERCE    — no restrictions (general use)
//   FINANCIAL   — a confirmed legal entity behind the agent
//   HEALTHCARE  — a confirmed legal entity, checked recently
//   GOVERNMENT  — a confirmed legal entity, no self-declared principal
//   SOVEREIGN   — a person with power to bind the entity, hardware-held keys
//
// The presets are convenience defaults, not conformance claims: ARIA maps to
// selected frameworks (spec, Appendix B) and asserts equivalence to none.

import type { PolicyConfig } from './types';

// ── Time Constants ────────────────────────────────────────

const ONE_HOUR_MS = 60 * 60 * 1000;
const TWENTY_FOUR_HOURS_MS = 24 * ONE_HOUR_MS;
const FIFTEEN_MINUTES_MS = 15 * 60 * 1000;

// ── Policy Presets ────────────────────────────────────────

/**
 * Built-in policy presets for common industry verticals.
 *
 * Each preset defines minimum trust level, maximum offline duration,
 * and whether an online revocation check is mandatory.
 *
 * @example
 * ```typescript
 * import { verifyAgent, PolicyLevel } from '@aria-registry/verify';
 *
 * const result = verifyAgent(credential, {
 *   policy: PolicyLevel.FINANCIAL,
 * });
 *
 * if (result.policyResult?.passed) {
 *   // Agent meets financial services requirements
 * }
 * ```
 *
 * @since 0.1.0
 */
export const PolicyLevel: Record<string, PolicyConfig> = {
  /** General commerce — offline OK, no restrictions. */
  COMMERCE: {
    maxOfflineAge: null,
    minTrustLevel: 'L0' as const,
    requireRevocationCheck: false,
  },

  /** Financial services — max 24h offline, requires L2 minimum (NIST SP 800-63-4 / PCI-DSS). */
  FINANCIAL: {
    maxOfflineAge: TWENTY_FOUR_HOURS_MS,
    minTrustLevel: 'L2' as const,
    requireRevocationCheck: false,
  },

  /** Healthcare — max 1h offline, requires L1 minimum (HIPAA §164.312). */
  HEALTHCARE: {
    maxOfflineAge: ONE_HOUR_MS,
    minTrustLevel: 'L1' as const,
    requireRevocationCheck: false,
  },

  /** Government — max 1h offline, requires L2: a confirmed legal entity. */
  GOVERNMENT: {
    maxOfflineAge: ONE_HOUR_MS,
    minTrustLevel: 'L2' as const,
    requireRevocationCheck: false,
  },

  /** Military / Sovereign — max 15 min offline, requires L3, must check revocation (NIST IAL3). */
  SOVEREIGN: {
    maxOfflineAge: FIFTEEN_MINUTES_MS,
    minTrustLevel: 'L3' as const,
    requireRevocationCheck: true,
  },
} as const;
