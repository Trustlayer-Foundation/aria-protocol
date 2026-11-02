// ─────────────────────────────────────────────────────────
// @aria-registry/verify — Public API
// Offline AI Agent Identity Verification
// Part of the ARIA Protocol by TrustLayer Foundation
// https://aria.bar/docs/sdk
// ─────────────────────────────────────────────────────────

// Core verification
export { verifyAgent } from './verify';
export { parseCredential } from './parse';

// Status of the presented credential (requires network)
export { checkCredentialStatus } from './status';
export { checkRevocation } from './revocation';

// Industry policy presets
export { PolicyLevel } from './policies';

// Registry trust anchor (embedded public keys)
export {
  REGISTRY_PUBLIC_KEY_MLDSA65,
  REGISTRY_PUBLIC_KEY_ED25519,
  COMPOSITE_SUITE,
  setRegistryKeys,
} from './registry-key';

// Utilities
export { canonicalJson } from './canonical-json';

// Types
export type {
  VerifyResult,
  VerifyOptions,
  PolicyConfig,
  ParsedCredential,
  RevocationResult,
  CredentialStatusOptions,
  CredentialStatusResult,
} from './types';

// Errors
export { AriaVerifyError, RevocationCheckError, InvalidCredentialError } from './errors';
