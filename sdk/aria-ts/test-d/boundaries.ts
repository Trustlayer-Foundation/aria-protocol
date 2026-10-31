// Compile-time boundaries of the credential API. Each `@ts-expect-error` must stay
// an error: `tsc` fails if one of these lines starts to compile. The same
// boundaries hold at run time, since a cast gets past any type.
import { inspectCredential, type CredentialFacts, type Standing, type StatusEvidence, type VerifiedCredential, type Verifier } from '@aria-registry/sdk';

declare const verifier: Verifier;
declare const credential: VerifiedCredential;
declare const status: StatusEvidence;
declare const facts: CredentialFacts;
declare const standing: Standing;

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

  // A copy keeps the type, which is not the boundary: the verifier refuses it at run time (test/provenance.test.ts, test/standing.test.ts).
  const copy: VerifiedCredential = { ...credential, scopes: ['payments:transfer:create'] };
  void copy;
}
