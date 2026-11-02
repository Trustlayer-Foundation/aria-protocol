// The ARIA SDK: inspect and verify an agent's credential, and establish the
// status of that exact document. ARIA AP (requests, admission, receipts) is the
// separate package built on it.

export { createVerifier, inspectCredential } from './verifier';
export type { Verifier, VerifierConfig, TrustProfile, FetchPolicy } from './verifier';

export type { Inspection, CredentialResult, CredentialFailure, CredentialFacts, VerifiedCredential, Principal, Produced } from './credential';
export type { AuthenticCredential, AuthenticityFailure, AuthenticityResult, HistoricalFacts } from './credential';
export type { Standing, StandingState, StatusEvidence, StatusOptions, StatusUnavailable } from './status';
export type { RetainedStatus, RetainedStatusFailure, RetainedStatusResult } from './status';
export { canonicalJson } from './internal/canonical';
export { LEVELS as TRUST_LEVELS } from './internal/verify-credential';

export type { CredentialBinding, Did, TrustLevel } from './types';
export { parseDid } from './did';
export type { ParsedDid } from './did';
export { AriaUsageError } from './errors';
