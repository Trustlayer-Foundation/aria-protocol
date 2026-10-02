// ─────────────────────────────────────────────────────────
// @aria-registry/verify — Credential Status
// Part of the ARIA Protocol by TrustLayer Foundation
// https://aria.bar/docs/sdk
// ─────────────────────────────────────────────────────────
//
// Whether the presented credential is still in force. A DID can hold a
// succession of credentials: a renewal issues a new one and revokes the
// previous one. Asking about the DID answers for the newest, so every check
// here is bound to the presented credential itself — its status-list entry, or
// its identifier compared with the one the online answer names.
//
// Anything that cannot be established is an error, never "active".

import { canonicalJson } from './canonical-json';
import { RevocationCheckError } from './errors';
import { parseCredential } from './parse';
import { base64urlToBytes, verifyCompositeProof } from './proof';
import type { CredentialStatusOptions, CredentialStatusResult } from './types';

/** Default ARIA API base URL. */
const DEFAULT_API_URL = 'https://api.aria.bar';

/** HTTP request timeout in milliseconds. */
const REQUEST_TIMEOUT_MS = 5_000;

/** Tolerated clock difference when reading a list's `validFrom`. */
const CLOCK_SKEW_MS = 60_000;

/** The most a status list may decompress to: 16 million entries. */
const MAX_LIST_BYTES = 2 * 1024 * 1024;

/**
 * Check whether the presented credential is still in force.
 *
 * Verify the credential with {@link verifyAgent} first: this call establishes
 * its status, not its authenticity.
 *
 * @param credential - The credential, as verified (object or JSON string).
 * @param options - How to check, and against which API.
 * @returns The credential's status and how it was established.
 * @throws {RevocationCheckError} If the status cannot be established: a
 *   network failure or timeout, a non-200 answer, a status list that does not
 *   verify, has expired or does not cover the credential, or an online answer
 *   without a recognized status.
 *
 * @example
 * ```typescript
 * import { verifyAgent, checkCredentialStatus } from '@aria-registry/verify';
 *
 * const result = verifyAgent(credential);
 * if (result.valid) {
 *   const { status } = await checkCredentialStatus(credential);
 *   if (status !== 'active') reject();
 * }
 * ```
 *
 * @since 1.2.0
 */
export async function checkCredentialStatus(
  credential: unknown,
  options?: CredentialStatusOptions,
): Promise<CredentialStatusResult> {
  const parsed = parseCredential(credential);
  if (!parsed) {
    throw new RevocationCheckError('not a valid ARIA credential');
  }
  if (!parsed.credentialId) {
    throw new RevocationCheckError(
      'the credential has no instance identifier (top-level id), so its own status cannot be checked',
    );
  }
  const via = options?.via ?? 'statusList';
  const status = via === 'online'
    ? await online(parsed.did, parsed.credentialId, options?.apiUrl ?? DEFAULT_API_URL)
    : await fromStatusList(parsed.rawVc, options?.apiUrl);
  return {
    did: parsed.did,
    credentialId: parsed.credentialId,
    status,
    via,
    checkedAt: new Date().toISOString(),
  };
}

// ── Online ────────────────────────────────────────────────

/**
 * `/v1/verify/{did}` answers for the DID's current credential and names it.
 * The presented credential is in force only if it is that one.
 */
async function online(
  did: string,
  credentialId: string,
  apiUrl: string,
): Promise<CredentialStatusResult['status']> {
  const answer = await fetchJson(`${apiUrl}/v1/verify/${encodeURIComponent(did)}`);
  if (typeof answer.credentialId !== 'string') {
    throw new RevocationCheckError('the answer does not name the credential it is about');
  }
  if (answer.status !== 'active' && answer.status !== 'revoked') {
    throw new RevocationCheckError('the answer carries no recognized revocation status');
  }
  if (answer.credentialId !== credentialId) {
    return 'superseded';
  }
  return answer.status;
}

// ── Status list ───────────────────────────────────────────

/**
 * The bit at the credential's own index in the signed list it names.
 */
async function fromStatusList(
  vc: Record<string, unknown>,
  apiUrl: string | undefined,
): Promise<'active' | 'revoked'> {
  const entry = vc.credentialStatus as Record<string, unknown> | undefined;
  const listUrl = entry?.statusListCredential;
  const indexText = entry?.statusListIndex;
  if (
    entry?.type !== 'BitstringStatusListEntry'
    || entry.statusPurpose !== 'revocation'
    || typeof listUrl !== 'string'
    || !listUrl.startsWith('https://')
    || typeof indexText !== 'string'
    || !/^(0|[1-9][0-9]{0,9})$/.test(indexText)
  ) {
    throw new RevocationCheckError('the credential names no revocation status-list entry');
  }
  const index = Number(indexText);

  const fetchUrl = apiUrl ? `${apiUrl}${new URL(listUrl).pathname}` : listUrl;
  const list = await fetchJson(fetchUrl);

  // The list the credential names, by the credential's issuer.
  const types = list.type;
  if (
    list.id !== listUrl
    || list.issuer !== vc.issuer
    || !Array.isArray(types)
    || !types.includes('BitstringStatusListCredential')
  ) {
    throw new RevocationCheckError('the status list is not the one the credential names');
  }

  // Signed by the registry, both halves.
  const proof = list.proof as Record<string, unknown> | undefined;
  if (!proof || typeof proof.proofValue !== 'string') {
    throw new RevocationCheckError('the status list carries no proof');
  }
  const unsigned = { ...list };
  delete unsigned.proof;
  const { pqValid, classicalValid } = verifyCompositeProof(
    proof.proofValue,
    new TextEncoder().encode(canonicalJson(unsigned)),
  );
  if (!pqValid || !classicalValid) {
    throw new RevocationCheckError('the status list signature does not verify');
  }

  // Within its validity. A list without an end has no bounded age, so a copy
  // taken before a revocation would read as current forever.
  const now = Date.now();
  const from = typeof list.validFrom === 'string' ? Date.parse(list.validFrom) : NaN;
  const until = typeof list.validUntil === 'string' ? Date.parse(list.validUntil) : NaN;
  if (!Number.isFinite(until)) {
    throw new RevocationCheckError('the status list states no validUntil, so its age is unbounded');
  }
  if (until <= now) {
    throw new RevocationCheckError('the status list has expired');
  }
  if (Number.isFinite(from) && from > now + CLOCK_SKEW_MS) {
    throw new RevocationCheckError('the status list is not valid yet');
  }

  const subject = list.credentialSubject as Record<string, unknown> | undefined;
  const encoded = subject?.encodedList;
  if (
    subject?.type !== 'BitstringStatusList'
    || subject.statusPurpose !== 'revocation'
    || typeof encoded !== 'string'
    || !encoded.startsWith('u')
  ) {
    throw new RevocationCheckError('the status list is not a revocation bitstring');
  }
  let bits: Uint8Array;
  try {
    bits = await gunzip(base64urlToBytes(encoded.slice(1)));
  } catch (error) {
    if (error instanceof RevocationCheckError) throw error;
    throw new RevocationCheckError('the status list does not decode');
  }
  const byte = Math.floor(index / 8);
  if (byte >= bits.length) {
    throw new RevocationCheckError("the status list does not cover the credential's index");
  }
  // Most significant bit first (W3C Bitstring Status List §3.2).
  return (bits[byte] >> (7 - (index % 8))) & 1 ? 'revoked' : 'active';
}

/** GZIP-decompress, refusing more than {@link MAX_LIST_BYTES}. */
async function gunzip(bytes: Uint8Array): Promise<Uint8Array> {
  const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream('gzip'));
  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.length;
    if (total > MAX_LIST_BYTES) {
      await reader.cancel();
      throw new RevocationCheckError('the status list is too large');
    }
    chunks.push(value);
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}

// ── Transport ─────────────────────────────────────────────

/** GET a JSON object; anything else is an error. */
async function fetchJson(url: string): Promise<Record<string, unknown>> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  try {
    const response = await fetch(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
      signal: controller.signal,
    });
    if (!response.ok) {
      throw new RevocationCheckError(`${url} answered HTTP ${response.status}`);
    }
    const body: unknown = await response.json();
    if (!body || typeof body !== 'object' || Array.isArray(body)) {
      throw new RevocationCheckError(`${url} did not answer with a JSON object`);
    }
    return body as Record<string, unknown>;
  } catch (error) {
    if (error instanceof RevocationCheckError) throw error;
    const message = error instanceof Error ? error.message : 'unknown error';
    throw new RevocationCheckError(`could not read ${url}: ${message}`);
  } finally {
    clearTimeout(timeout);
  }
}
