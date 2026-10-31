/** A trust level an issuer may assert. */
export type TrustLevel = 'L0' | 'L1' | 'L2' | 'L3';

/** A `did:aria` identifier. */
export type Did = `did:aria:${string}`;

/** An HTTP request as the SDK reads it. Repeated headers are kept as arrays, so ambiguity is refused rather than merged. */
export interface HttpRequestLike {
  readonly method: string;
  /** Path and query exactly as received, e.g. `/v1/transfers?operation=…`. */
  readonly target: string;
  /** Header names in lower case. */
  readonly headers: Readonly<Record<string, string | readonly string[]>>;
  readonly body?: Uint8Array;
}

/** The exact issued document a result is about: never the agent's DID alone. */
export interface CredentialBinding {
  /** The credential's top-level `id`. */
  readonly credentialId: string;
  /** `sha-256=:<base64>:` of the document's canonical bytes. */
  readonly digest: string;
  /** The trust profile it was verified under. */
  readonly profile: string;
}

/** A signing capability the adopter keeps; the SDK never holds a private key. */
export interface Signer {
  /** DID URL of the key, e.g. `did:aria:bank.example:transfers#holder-key-1`. */
  readonly keyId: string;
  readonly algorithm: 'ed25519';
  sign(bytes: Uint8Array): Promise<Uint8Array>;
}
