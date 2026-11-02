// Compile-time boundaries of the credential API. Each `@ts-expect-error` must stay
// an error: `tsc` fails if one of these lines starts to compile. The same
// boundaries hold at run time, since a cast gets past any type.
import { inspectCredential, type AuthenticCredential, type CredentialFacts, type RetainedStatus, type Standing, type StatusEvidence, type VerifiedCredential, type Verifier } from '@trustlayer-foundation/aria-sdk';

declare const verifier: Verifier;
declare const credential: VerifiedCredential;
declare const status: StatusEvidence;
declare const facts: CredentialFacts;
declare const standing: Standing;
declare const authentic: AuthenticCredential;
declare const retained: RetainedStatus;

export async function boundaries(): Promise<void> {
  // Inspection is not verification.
  const seen = inspectCredential({});
  // @ts-expect-error an inspection is not a verified credential
  await verifier.checkStatus(seen);

  // A verified credential cannot be typed by hand.
  // @ts-expect-error missing the SDK's private mark
  const forged: VerifiedCredential = { did: 'did:aria:x:y' };
  void forged;

  // What the trust interface returns is data, never a result.
  // @ts-expect-error facts are not a credential result
  verifier.standing(facts, status);
  // @ts-expect-error a standing is a judgment, not status evidence
  verifier.standing(credential, standing);

  // Historical authenticity is not current verification, and a retained list is not status evidence.
  // @ts-expect-error an authentic credential is not a verified one
  verifier.facts(authentic);
  // @ts-expect-error an authentic credential is not a verified one
  await verifier.checkStatus(authentic);
  // @ts-expect-error a retained status is not status evidence
  verifier.standing(credential, retained);
  // @ts-expect-error historical facts are read from an authentic credential only
  verifier.historicalFacts(credential);
  verifier.historicalFacts(authentic, retained);

  // A copy keeps the type, which is not the boundary: the verifier refuses it at run time (test/provenance.test.ts, test/standing.test.ts).
  const copy: VerifiedCredential = { ...credential, scopes: ['payments:transfer:create'] };
  void copy;
}
