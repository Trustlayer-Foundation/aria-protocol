// Checking an agent's credential, which is not the same as admitting a request:
// nothing here establishes who is calling.
import { createVerifier, inspectCredential, type TrustProfile } from '@aria-registry/sdk';

declare const demoProfile: TrustProfile; // the trust set the adopter configures (D2)
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
  switch (status.state) {
    case 'active':
      return `${credential.did}, document ${credential.binding.credentialId}, is active`;
    case 'revoked':
    case 'superseded':
      return `${credential.did}: this document is ${status.state}`;
    case 'unavailable':
      // Unknown is not active.
      return `status could not be established: ${status.reason}`;
  }
}
