// Checking an agent's credential, which is not the same as admitting a request:
// nothing here establishes who is calling.
import { createVerifier, inspectCredential, type TrustProfile } from '@trustlayer-foundation/aria-sdk';

declare const demoProfile: TrustProfile; // the trust profile the adopter configures
declare const document: unknown; // e.g. fetched from https://api.aria.bar/v1/aids/<did>

const verifier = createVerifier({
  trust: [demoProfile],
  fetch: { allowedOrigins: ['https://api.aria.bar'] },
});

export async function describe(): Promise<string> {
  // Inspection shows fields of anything, verified or not, and is labelled as such.
  const seen = inspectCredential(document);
  if (seen.problem) return `not a credential (${seen.problem})`;

  const checked = verifier.verifyCredential(document);
  if (!checked.ok) return `credential refused: ${checked.reason}`;
  const { credential } = checked;

  const status = await verifier.checkStatus(credential);
  // The evidence says what was observed and when; its standing says whether it holds now.
  const standing = verifier.standing(credential, status);
  switch (standing.state) {
    case 'good':
      return `${credential.did}, document ${credential.binding.credentialId}, is active (${standing.source})`;
    case 'revoked':
    case 'superseded':
      return `${credential.did}: this document is ${standing.state}`;
    case 'not_valid_now':
      return `${credential.did}: this document is outside its validity`;
    case 'unknown':
      // Unknown is not active.
      return `status could not be established: ${standing.reason}`;
  }
}
