/** An HTTP request as ARIA AP reads it. Repeated headers are kept as arrays, so ambiguity is refused rather than merged. */
export interface HttpRequestLike {
  readonly method: string;
  /** Path and query exactly as received, e.g. `/v1/transfers?operation=…`. */
  readonly target: string;
  /** Header names in lower case. */
  readonly headers: Readonly<Record<string, string | readonly string[]>>;
  readonly body?: Uint8Array;
}

/** A signing capability the adopter keeps; the SDK never holds a private key. */
export interface Signer {
  /** DID URL of the key, e.g. `did:aria:bank.example:transfers#holder-key-1`. */
  readonly keyId: string;
  readonly algorithm: 'ed25519';
  sign(bytes: Uint8Array): Promise<Uint8Array>;
}
