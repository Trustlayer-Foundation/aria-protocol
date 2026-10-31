// ARIA AP: the agent's and the receiver's side of the profile, built on the
// credential verifier of @aria-registry/sdk. Provisional package name (D9).

export { createAp } from './ap';
export type { Ap, ApConfig } from './ap';

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

export { OperationTracker } from './receipt';
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

export type { CredentialPresentation, ReceiverIdentityFailure, ReceiverIdentityResult, SignedAttempt, SignRequestInput, VerifiedReceiver } from './agent';

export type { HttpRequestLike, Signer } from './types';
export { NotYetImplemented } from './errors';
