// The ARIA SDK. Provisional package name, pending confirmation of its owner (D9).

export { createVerifier, inspectCredential } from './verifier';
export type { Verifier, VerifierConfig, TrustProfile, FetchPolicy } from './verifier';

export type { Inspection, CredentialResult, CredentialFailure, CredentialFacts, VerifiedCredential, Principal, Produced } from './credential';
export type { Standing, StandingState, StatusEvidence, StatusOptions, StatusUnavailable } from './status';
export { canonicalJson } from './internal/canonical';
export { LEVELS as TRUST_LEVELS } from './internal/verify-credential';

export type {
  RequestClass,
  MissingApproval,
  OperationDescriptor,
  ReceiverSelf,
  ChallengeStore,
  PresentationContext,
  PresentationFailure,
  PresentationResult,
  VerifiedPresentation,
} from './presentation';

export type { Admission, Admitted, AdmissionInput, AdmissionReason, ApprovalEvidence, ResourceAuthorizer } from './admission';

export { OperationLedger } from './operations';
export type {
  OperationKey,
  OperationStorage,
  StoredOperation,
  OperationClaim,
  RecordedOperationOutcome,
  AttemptRefusal,
  Begin,
  Settlement,
  Expected,
  Failure,
  LedgerOptions,
} from './operations';

export { buildAttemptRefusal, OperationTracker } from './receipt';
export type {
  Receipt,
  ReceiptCheck,
  ReceiptFailure,
  ReceiptResult,
  ReceiptStatement,
  ReceiverPin,
  SentAttempt,
  RetainedEvidence,
  HistoricalFindings,
  OperationState,
  Observation,
} from './receipt';

export { signRequest } from './agent';
export type { CredentialPresentation, ReceiverIdentityFailure, ReceiverIdentityResult, SignRequestInput, VerifiedReceiver } from './agent';

export type { CredentialBinding, Did, HttpRequestLike, Signer, TrustLevel } from './types';
export { NotYetImplemented, AriaUsageError } from './errors';
