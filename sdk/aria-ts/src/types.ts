/** A trust level an issuer may assert. */
export type TrustLevel = 'L0' | 'L1' | 'L2' | 'L3';

/** A `did:aria` identifier. */
export type Did = `did:aria:${string}`;

/** The exact issued document a result is about: never the agent's DID alone. */
export interface CredentialBinding {
  /** The credential's top-level `id`. */
  readonly credentialId: string;
  /** `sha-256=:<base64>:` of the document's canonical bytes. */
  readonly digest: string;
  /** The trust profile it was verified under. */
  readonly profile: string;
}
