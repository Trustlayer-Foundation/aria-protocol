// ─────────────────────────────────────────────────────────
// @aria-registry/verify — Composite Proof
// Part of the ARIA Protocol by TrustLayer Foundation
// https://aria.bar/docs/sdk
// ─────────────────────────────────────────────────────────
//
// The issuer's composite proof, shared by credentials and status lists: both
// are signed over their canonical JSON without `proof`.

import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { ed25519 } from '@noble/curves/ed25519.js';
import { REGISTRY_PUBLIC_KEY_MLDSA65, REGISTRY_PUBLIC_KEY_ED25519 } from './registry-key';

/** Byte length of the composite proof's length prefix. */
const COMPOSITE_PROOF_HEADER_SIZE = 4;

/**
 * Decode a base64url string (RFC 4648 §5, no padding) to raw bytes.
 * @internal
 */
export function base64urlToBytes(b64: string): Uint8Array {
  let base64 = b64.replace(/-/g, '+').replace(/_/g, '/');
  while (base64.length % 4 !== 0) {
    base64 += '=';
  }
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

// ── Composite Proof Decoding ──────────────────────────────
// Both signatures travel in one proofValue:
//   [4 bytes: PQ sig length (big-endian uint32)]
//   [PQ signature bytes]
//   [Classical signature bytes]
//
// Two encodings of those bytes are in circulation. Suite 1.0 emits multibase
// base64url -- a leading "u" per the multibase table -- because the VC v2
// context types proofValue as sec:multibase, and a bare base64 string claiming
// that datatype is not one. Credentials issued before the cutover carry the
// same bytes with no prefix. Verifiers accept both.
//
// For this suite the two cannot be confused: the header is always 0x00000CED,
// the ML-DSA-65 signature length, so a bare proofValue always begins "AAAM" and
// never "u". The decoder still checks the header rather than trusting the first
// character, so a suite whose header encodes differently stays decidable.

/** ML-DSA-65 signature length in bytes (FIPS 204). */
const ML_DSA_65_SIGNATURE_SIZE = 3309;

/** Ed25519 signature length in bytes (RFC 8032). */
const ED25519_SIGNATURE_SIZE = 64;

/**
 * Decode one reading of a proofValue, rejecting it unless the length header
 * accounts for every byte. This is what makes the multibase prefix detectable
 * rather than guessed: a bare base64url string that happens to begin with "u"
 * decodes to a header that does not describe its own length.
 */
function decodeCandidate(
  base64url: string,
): { pqSignature: Uint8Array; classicalSignature: Uint8Array } | null {
  try {
    const combined = base64urlToBytes(base64url);
    if (combined.length !== COMPOSITE_PROOF_HEADER_SIZE + ML_DSA_65_SIGNATURE_SIZE + ED25519_SIGNATURE_SIZE) {
      return null;
    }

    const view = new DataView(combined.buffer, combined.byteOffset, combined.byteLength);
    if (view.getUint32(0, false) !== ML_DSA_65_SIGNATURE_SIZE) return null; // big-endian

    return {
      pqSignature: combined.slice(COMPOSITE_PROOF_HEADER_SIZE, COMPOSITE_PROOF_HEADER_SIZE + ML_DSA_65_SIGNATURE_SIZE),
      classicalSignature: combined.slice(COMPOSITE_PROOF_HEADER_SIZE + ML_DSA_65_SIGNATURE_SIZE),
    };
  } catch {
    return null;
  }
}

/**
 * Decode a composite proofValue into its PQ and classical components.
 *
 * Accepts both the multibase form suite 1.0 emits (`u` + base64url) and the
 * bare base64url form issued before the cutover.
 *
 * @internal
 */
export function decodeCompositeProof(
  proofValue: string,
): { pqSignature: Uint8Array; classicalSignature: Uint8Array } | null {
  // Read as multibase first when prefixed; fall back to reading the whole
  // string, so the header decides rather than the first character.
  const readings = proofValue.startsWith('u') ? [proofValue.slice(1), proofValue] : [proofValue];
  for (const reading of readings) {
    const decoded = decodeCandidate(reading);
    if (decoded) return decoded;
  }
  return null;
}

/**
 * Verify both halves of a composite `proofValue` over `payload`, under the
 * registry keys in force ({@link setRegistryKeys} can replace them).
 * @internal
 */
export function verifyCompositeProof(
  proofValue: string,
  payload: Uint8Array,
): { pqValid: boolean; classicalValid: boolean } {
  const decoded = decodeCompositeProof(proofValue);
  if (!decoded) return { pqValid: false, classicalValid: false };
  let pqValid = false;
  let classicalValid = false;
  try {
    pqValid = ml_dsa65.verify(decoded.pqSignature, payload, REGISTRY_PUBLIC_KEY_MLDSA65);
  } catch {
    pqValid = false;
  }
  try {
    classicalValid = ed25519.verify(decoded.classicalSignature, payload, REGISTRY_PUBLIC_KEY_ED25519);
  } catch {
    classicalValid = false;
  }
  return { pqValid, classicalValid };
}
