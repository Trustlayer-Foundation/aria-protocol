// ARIA AP: the agent's and the receiver's side of the profile, built on the
// credential verifier of @aria-registry/sdk. Provisional package name (D9) and
// provisional wire profile (D3, D4, D5, D8).

export { createAp } from './ap';
export type { Ap, ApConfig } from './ap';

export type {
  RequestClass,
  MissingApproval,
  OperationDescriptor,
  ReceiverSelf,
  ChallengeStore,
  PresentationContext,
  PresentationResult,
  RequestInvalidReason,
  AuthenticationReason,
  VerifiedPresentation,
} from './presentation';
export { MemoryChallengeStore } from './challenges';

export type { Admission, Admitted, AdmissionInput, AdmissionReason, ApprovalEvidence, ResourceAuthorizer, LookupInput, LookupAdmission } from './admission';

export { OperationLedger, MemoryOperationStorage } from './operations';
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
  Reconciled,
} from './operations';

export { OperationTracker } from './receipt';
export type { Receipt, ReceiptCheck, ReceiptFailure, ReceiptResult, ReceiptStatement, ReceiverPin, SentAttempt, OperationState, Observation } from './receipt';

export type { IdentityResponse, IdentityStatement, ReceiverIdentityFailure, ReceiverIdentityResult, SignedAttempt, SignRequestInput, VerifiedReceiver } from './agent';

export type { HttpRequestLike, Signer } from './types';
export { StaleClaim, InvariantViolation } from './errors';
