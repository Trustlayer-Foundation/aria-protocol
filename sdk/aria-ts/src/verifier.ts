import type { CredentialFacts, CredentialResult, Inspection, VerifiedCredential } from './credential';
import { AriaUsageError } from './errors';
import { fromOnline, fromStatusList, type StatusSnapshot } from './internal/check-status';
import { iso } from './internal/instant';
import { issue, recall } from './internal/provenance';
import { judge } from './internal/standing';
import { LEVELS, plainCopy, verifyCredentialDocument, type CredentialSnapshot, type ProfileSnapshot } from './internal/verify-credential';
import type { Standing, StatusEvidence, StatusOptions } from './status';
import type { Did, TrustLevel } from './types';

/** One issuer the verifier trusts. Its `id` is a label for results, never a trust identity. */
export interface TrustProfile {
  /** E.g. `demo` or `production`. */
  readonly id: string;
  readonly issuer: Did;
  /** The DID URL the issuer's proofs name, e.g. `did:aria:registry.aria.bar#key-1`. */
  readonly verificationMethod: string;
  readonly keys: { readonly mldsa65: Uint8Array; readonly ed25519: Uint8Array };
  /** Highest level this profile may assert; a credential claiming more fails. */
  readonly maxLevel: TrustLevel;
  /** Status lists this issuer publishes; a credential naming another fails. */
  readonly statusLists: readonly string[];
  /** The issuer's online status endpoint, to which the DID is appended, e.g. `https://api.aria.bar/v1/verify/`. */
  readonly onlineStatus?: string;
}

/** Bounds on everything the SDK fetches. Without it the verifier is offline and status is `unavailable`. */
export interface FetchPolicy {
  /** Exact origins it may fetch from; redirects are never followed. */
  readonly allowedOrigins: readonly string[];
  /** Default 5000. */
  readonly timeoutMs?: number;
  /** Default 262144; the decompressed status list is bounded separately. */
  readonly maxBytes?: number;
  /** The fetch implementation; the global one by default. */
  readonly fetch?: typeof fetch;
}

/** Trusted configuration: everything here comes from the adopter, never from a message. It is copied when the verifier is created. */
export interface VerifierConfig {
  readonly trust: readonly TrustProfile[];
  readonly fetch?: FetchPolicy;
  readonly clock?: () => Date;
  /** Maximum age of signed status-list evidence, from the list's own `validFrom`. Default 3600. */
  readonly statusMaxAgeSeconds?: number;
  /** Maximum age of an online status answer when admission uses it, from when it was fetched. Default 60. */
  readonly onlineStatusMaxAgeSeconds?: number;
  /** Tolerated clock skew on validity bounds. Default 5. */
  readonly skewSeconds?: number;
}

/**
 * A verifier with its own, fixed trust. Two verifiers never affect each other;
 * nothing in the package is configured globally. Results are accepted only by the
 * verifier that produced them, as the exact objects it returned.
 */
export interface Verifier {
  /** Verifies one document. Says nothing about who presents it or its status. */
  verifyCredential(document: unknown): CredentialResult;
  /** Status of the credential's exact document. */
  checkStatus(credential: VerifiedCredential, options?: StatusOptions): Promise<StatusEvidence>;
  /**
   * What this verifier established about `credential`, from its own record: a
   * fresh copy, holder key bytes included. This is how packages built on this one
   * (ARIA AP) read a credential. Throws `AriaUsageError` for anything this verifier
   * did not produce: a copy, an altered or hand-made object, another verifier's result.
   */
  facts(credential: VerifiedCredential): CredentialFacts;
  /**
   * Whether `credential` stands now: inside its signed validity, with `status`
   * being this verifier's evidence about that same result, still fresh under its
   * rules. Judged at every call with this verifier's clock. Throws like `facts`.
   */
  standing(credential: VerifiedCredential, status: StatusEvidence): Standing;
}

const ML_DSA_65_PUBLIC_KEY = 1952;
const ED25519_PUBLIC_KEY = 32;

function snapshotProfiles(trust: readonly TrustProfile[]): readonly ProfileSnapshot[] {
  if (!Array.isArray(trust) || trust.length === 0) throw new AriaUsageError('a verifier needs at least one trust profile');
  const profiles = trust.map((p): ProfileSnapshot => {
    if (!(p.keys?.mldsa65 instanceof Uint8Array) || p.keys.mldsa65.length !== ML_DSA_65_PUBLIC_KEY) throw new AriaUsageError(`profile ${p.id}: an ML-DSA-65 public key is ${ML_DSA_65_PUBLIC_KEY} bytes`);
    if (!(p.keys?.ed25519 instanceof Uint8Array) || p.keys.ed25519.length !== ED25519_PUBLIC_KEY) throw new AriaUsageError(`profile ${p.id}: an Ed25519 public key is ${ED25519_PUBLIC_KEY} bytes`);
    if (!LEVELS.includes(p.maxLevel)) throw new AriaUsageError(`profile ${p.id}: unknown level ${String(p.maxLevel)}`);
    if (p.onlineStatus !== undefined && !p.onlineStatus.startsWith('https://')) throw new AriaUsageError(`profile ${p.id}: the online status endpoint must be https`);
    return Object.freeze({
      id: String(p.id),
      issuer: String(p.issuer),
      verificationMethod: String(p.verificationMethod),
      // Uint8Array.from always allocates: a Buffer's slice() would alias the caller's bytes.
      keys: Object.freeze({ mldsa65: Uint8Array.from(p.keys.mldsa65), ed25519: Uint8Array.from(p.keys.ed25519) }),
      maxLevel: p.maxLevel,
      statusLists: Object.freeze([...p.statusLists].map(String)),
      onlineStatus: p.onlineStatus ?? null,
    });
  });
  if (new Set(profiles.map((p) => p.issuer)).size !== profiles.length) throw new AriaUsageError('two trust profiles name the same issuer');
  return Object.freeze(profiles);
}

const seconds = (value: number | undefined, fallback: number, name: string): number => {
  const v = value ?? fallback;
  if (!Number.isFinite(v) || v < 0) throw new AriaUsageError(`${name} must be a non-negative number`);
  return v * 1000;
};

function credentialView(s: CredentialSnapshot): VerifiedCredential {
  return {
    kind: 'verified-credential',
    binding: { credentialId: s.credentialId, digest: s.digest, profile: s.profile.id },
    did: s.did,
    issuer: s.issuer,
    specVersion: '1.0',
    trustLevel: s.trustLevel,
    scopes: [...s.scopes],
    hitlRequired: [...s.hitlRequired],
    delegationDepth: s.delegationDepth,
    principal: { ...s.principal },
    holderKey: { id: s.holderKeyId, publicKeyMultibase: s.holderKeyMultibase },
    validFrom: iso(s.validFrom),
    validUntil: iso(s.validUntil),
    previousCredentialId: s.previousCredentialId,
    statusEntry: { list: s.statusList, index: s.statusIndex },
    verifiedAt: iso(s.verifiedAt),
  } as unknown as VerifiedCredential;
}

function statusView(s: StatusSnapshot): StatusEvidence {
  const base = {
    kind: 'status-evidence',
    credential: { credentialId: s.credential.credentialId, digest: s.credential.digest, profile: s.credential.profile.id },
    fetchedAt: iso(s.fetchedAt),
    source: s.source,
    state: s.state,
  };
  if (s.state === 'unavailable') return { ...base, reason: s.reason } as unknown as StatusEvidence;
  if (s.source === 'status-list') {
    return { ...base, list: { url: s.list.url, index: s.list.index, validFrom: iso(s.list.validFrom), validUntil: iso(s.list.validUntil) } } as unknown as StatusEvidence;
  }
  return (s.currentCredentialId ? { ...base, currentCredentialId: s.currentCredentialId } : base) as unknown as StatusEvidence;
}

/** Creates a verifier from a copy of `config`; later changes to `config` or its keys do not reach it. */
export function createVerifier(config: VerifierConfig): Verifier {
  const profiles = snapshotProfiles(config.trust);
  const clock = config.clock ?? (() => new Date());
  const skewMs = seconds(config.skewSeconds, 5, 'skewSeconds');
  const statusMaxAgeMs = seconds(config.statusMaxAgeSeconds, 3600, 'statusMaxAgeSeconds');
  const onlineMaxAgeMs = seconds(config.onlineStatusMaxAgeSeconds, 60, 'onlineStatusMaxAgeSeconds');
  const bounds = config.fetch
    ? Object.freeze({
        allowedOrigins: Object.freeze([...config.fetch.allowedOrigins].map(String)),
        timeoutMs: config.fetch.timeoutMs ?? 5000,
        maxBytes: config.fetch.maxBytes ?? 262_144,
        fetch: config.fetch.fetch ?? globalThis.fetch.bind(globalThis),
      })
    : null;
  const now = (): number => {
    const t = clock().getTime();
    if (!Number.isFinite(t)) throw new AriaUsageError('the clock returned an invalid time');
    return t;
  };

  const verifier: Verifier = {
    verifyCredential(document) {
      const outcome = verifyCredentialDocument(document, profiles, now(), skewMs);
      if (!outcome.ok) return Object.freeze(outcome.path === undefined ? { ok: false, reason: outcome.reason } : { ok: false, reason: outcome.reason, path: outcome.path });
      return Object.freeze({ ok: true, credential: issue(verifier, 'credential', credentialView(outcome.snapshot), outcome.snapshot) });
    },

    async checkStatus(credential, options) {
      const snapshot = recall<CredentialSnapshot>(verifier, 'credential', credential);
      const context = { bounds, now, skewMs, maxAgeMs: statusMaxAgeMs };
      const status = options?.via === 'online' ? await fromOnline(snapshot, context) : await fromStatusList(snapshot, context);
      return issue(verifier, 'status', statusView(status), status);
    },

    facts(credential) {
      const s = recall<CredentialSnapshot>(verifier, 'credential', credential);
      return Object.freeze({
        binding: Object.freeze({ credentialId: s.credentialId, digest: s.digest, profile: s.profile.id }),
        did: s.did,
        issuer: s.issuer,
        trustLevel: s.trustLevel,
        scopes: Object.freeze([...s.scopes]),
        hitlRequired: Object.freeze([...s.hitlRequired]),
        delegationDepth: s.delegationDepth,
        // A typed array with elements cannot be frozen: each call returns a new copy instead.
        holderKey: Object.freeze({ id: s.holderKeyId, publicKey: Uint8Array.from(s.holderKey) }),
        validFrom: iso(s.validFrom),
        validUntil: iso(s.validUntil),
      });
    },

    standing(credential, status) {
      const c = recall<CredentialSnapshot>(verifier, 'credential', credential);
      const st = recall<StatusSnapshot>(verifier, 'status', status);
      const at = now();
      const judged = judge(c, st, { now: at, skewMs, statusMaxAgeMs, onlineMaxAgeMs });
      return Object.freeze({ kind: 'standing', ...judged, judgedAt: iso(at) }) as Standing;
    },
  };
  return Object.freeze(verifier);
}

/** Parses a credential without verifying anything. Its result cannot be passed where verification is required. */
export function inspectCredential(document: unknown): Inspection {
  const doc = plainCopy(document);
  const text = (v: unknown): string | null => (typeof v === 'string' ? v : null);
  if (!doc) {
    return Object.freeze({ kind: 'inspection', verified: false, did: null, credentialId: null, issuer: null, specVersion: null, trustLevel: null, scopes: Object.freeze([]), validFrom: null, validUntil: null, problem: 'not_json' });
  }
  const subject = doc.credentialSubject && typeof doc.credentialSubject === 'object' ? (doc.credentialSubject as Record<string, unknown>) : null;
  const scopes = Array.isArray(subject?.scope) ? subject.scope.filter((s): s is string => typeof s === 'string') : [];
  const inspection: Inspection = {
    kind: 'inspection',
    verified: false,
    did: text(subject?.id),
    credentialId: text(doc.id),
    issuer: text(doc.issuer),
    specVersion: text(subject?.spec_version),
    trustLevel: text(subject?.trustLevel),
    scopes: Object.freeze(scopes),
    validFrom: text(doc.validFrom),
    validUntil: text(doc.validUntil),
    ...(subject ? {} : { problem: 'not_a_credential' as const }),
  };
  return Object.freeze(inspection);
}
