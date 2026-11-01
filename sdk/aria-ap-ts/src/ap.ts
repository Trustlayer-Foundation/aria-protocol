import { AriaUsageError, canonicalJson, type CredentialFacts, type Verifier, type VerifiedCredential } from '@aria-registry/sdk';
import type { Admission, AdmissionInput, AdmissionReason, ApprovalEvidence, LookupAdmission, LookupInput } from './admission';
import type { IdentityResponse, IdentityStatement, ReceiverIdentityResult, SignedAttempt, SignRequestInput, VerifiedReceiver } from './agent';
import { digestField, fromBase64, fromBase64url, instantOf, instantText, isProfileOrigin, toBase64, toBase64url, utf8, UUID } from './internal/bytes';
import { strictVerify } from './internal/ed25519';
import { newReceiptId, refusalOf, register, type AdmissionSnapshot, type Internals, type PresentationSnapshot, type RefusalSnapshot } from './internal/instance';
import { judge, lookupRefusal, refusalFor } from './internal/judge';
import type { ApprovalSnapshot } from './internal/policy';
import { issue, recall } from './internal/provenance';
import { checkReceipt, isReceiverCode, RECEIPT_TYPE, REASONS, signReceipt, type ReceiverKey } from './internal/receipt';
import { authenticate, checkDescriptors, CLASSES, fieldsOf, PROFILE, prepareSignature } from './internal/request';
import { serializeInnerList } from './internal/sf';
import { AdmissionExpired } from './errors';
import type { AttemptRefusal } from './operations';
import type { ChallengeStore, OperationDescriptor, PresentationContext, PresentationResult, ReceiverSelf } from './presentation';
import type { Receipt, ReceiptCheck, ReceiptResult, ReceiptStatement, ReceiverPin } from './receipt';
import type { HttpRequestLike } from './types';

/** Trusted configuration, from the adopter. */
export interface ApConfig {
  /**
   * The credential verifier of `@aria-registry/sdk` this instance builds on. Its
   * credential and status results are the only ones accepted, and they are read
   * through its `facts` and `standing`, never from their fields. ARIA AP has no
   * credential or status verification of its own.
   */
  readonly credentials: Verifier;
  /** Signature windows, challenges, statements and receipts are judged and dated with it. Default: the system clock. */
  readonly clock?: () => Date;
}

/**
 * One ARIA AP instance: the agent's and the receiver's side of the profile.
 * Its own results (presentations, admissions, refusals, verified receivers,
 * receipt statements) are accepted only by this instance, as the exact objects
 * it returned.
 */
export interface Ap {
  /** Authenticates a request: holder key, bound to this receiver, operation and content. Failures are unsigned. */
  verifyPresentation(request: HttpRequestLike, context: PresentationContext): Promise<PresentationResult>;
  /** The single admission decision of an operation request, judged now. Refuses a presentation it did not produce, and status evidence its credential verifier did not produce for that exact credential. */
  admit(input: AdmissionInput): Promise<Admission>;
  /** Whether a retrieval may read the operation it names: a credential of the operation's sender that stands now. */
  admitLookup(input: LookupInput): Promise<LookupAdmission>;
  /** Signs a refusal of one attempt. Operation receipts come only from `OperationLedger.settle`. */
  buildAttemptRefusal(refusal: AttemptRefusal, receiver: ReceiverSelf): Promise<Receipt>;
  /** The receiver's signed identity statement for a client's nonce, with a fresh challenge for its next request. */
  identify(receiver: ReceiverSelf, request: { readonly nonce: string; readonly audience: string }, challenges: ChallengeStore): Promise<IdentityResponse>;
  /** Authenticates the receiver from its identity statement, before the client sends anything sensitive. */
  verifyReceiverIdentity(response: unknown, pin: ReceiverPin, expected: { readonly nonce: string; readonly audience: string }): Promise<ReceiverIdentityResult>;
  /** Signs one attempt and returns it with what the client must keep to check its receipts. */
  signRequest(input: SignRequestInput): Promise<SignedAttempt>;
  /** Checks a receipt against the receiver the attempts were signed for and the attempts the client kept. */
  verifyReceipt(receipt: unknown, check: ReceiptCheck): Promise<ReceiptResult>;
}

const TRUST_INTERFACE = ['verifyCredential', 'checkStatus', 'facts', 'standing'] as const;
const IDENTITY_TYPE = 'aria-ap-identity/1';
const STATEMENT_MAX_AGE_MS = 60_000;
const CHALLENGE_TTL_SECONDS = 60;
const NONCE = /^[A-Za-z0-9_-]{22,128}$/;
const CHALLENGE = /^[A-Za-z0-9._~+/=-]{8,256}$/;
const ORIGIN_RULE = 'an origin is https://host[:port], or http:// on a loopback host, in its canonical form without path, query, fragment or user information';

interface ReceiverSnapshot {
  /** After this instant (ms) the statement and its challenge are stale: identify the receiver again. */
  readonly freshUntil: number;
  readonly pin: ReceiverPin;
  readonly key: ReceiverKey;
}

const isObject = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);
const exactly = (o: unknown, keys: readonly string[]): o is Record<string, unknown> => isObject(o) && Object.keys(o).length === keys.length && keys.every((k) => Object.hasOwn(o, k));

/** Creates an instance over `config.credentials`, which it keeps as given: it is the adopter's verifier, not a copy. */
export function createAp(config: ApConfig): Ap {
  const credentials = config?.credentials;
  if (!credentials || TRUST_INTERFACE.some((method) => typeof credentials[method] !== 'function')) {
    throw new AriaUsageError('ARIA AP needs a credential verifier from @aria-registry/sdk (createVerifier)');
  }
  const clock = config.clock ?? (() => new Date());
  const now = (): number => {
    const t = clock().getTime();
    if (!Number.isFinite(t)) throw new AriaUsageError('the clock returned an invalid date');
    return t;
  };
  const internals: Internals = { credentials, now };
  const described = new WeakMap<readonly OperationDescriptor[], readonly OperationDescriptor[]>();

  function operationsOf(operations: readonly OperationDescriptor[]): readonly OperationDescriptor[] {
    let checked = described.get(operations);
    if (!checked) {
      try {
        checked = checkDescriptors(operations);
      } catch (error) {
        throw new AriaUsageError((error as Error).message);
      }
      described.set(operations, checked);
    }
    return checked;
  }

  /** The receiver's own facts, after checking that its DID, document and signer are its credential's. */
  function selfFacts(self: ReceiverSelf): CredentialFacts {
    const f = credentials.facts(self?.credential);
    if (f.did !== self.did) throw new AriaUsageError('the receiver credential is for another DID');
    if (self.signer?.keyId !== f.holderKey.id || self.signer.algorithm !== 'ed25519') throw new AriaUsageError("the receiver signer must be its credential's Ed25519 holder key");
    return f;
  }

  async function signed(signer: ReceiverSelf['signer'], bytes: Uint8Array): Promise<string> {
    const signature = await signer.sign(bytes);
    if (!(signature instanceof Uint8Array) || signature.length !== 64) throw new AriaUsageError('an Ed25519 signer returns 64 bytes');
    return toBase64url(signature);
  }

  function approvalOf(a: ApprovalEvidence | undefined): ApprovalSnapshot | null {
    if (a === undefined) return null;
    const expiresAt = instantOf(a?.expiresAt) ?? Number.NEGATIVE_INFINITY;
    return { sender: String(a?.sender), credentialId: String(a?.credentialId), operationId: String(a?.operationId), fingerprint: String(a?.fingerprint), expiresAt };
  }

  const ap: Ap = {
    async verifyPresentation(request, context) {
      const operations = operationsOf(context.operations);
      const { did: receiverDid, origin } = context.receiver;
      if (!isProfileOrigin(origin)) throw new AriaUsageError(ORIGIN_RULE);
      let credential: VerifiedCredential | null = null;
      const result = await authenticate(request, {
        origin,
        operations,
        now,
        challengeLive: (nonce) => context.challenges.live(nonce, receiverDid),
        consume: (nonce) => context.challenges.consume(nonce, receiverDid),
        resolve: async (url, digest) => {
          let document: unknown;
          try {
            document = await context.resolveCredential(url);
          } catch {
            return null;
          }
          if (document === null || document === undefined) return null;
          const verified = credentials.verifyCredential(document);
          if (!verified.ok) return null;
          const f = credentials.facts(verified.credential);
          if (f.binding.credentialId !== url || f.binding.digest !== digest) return null;
          credential = verified.credential;
          return { credentialId: url, digest, did: f.did, keyId: f.holderKey.id, publicKey: f.holderKey.publicKey };
        },
      });
      if (!result.ok) {
        const { status, reason } = result.failure;
        return status === 400 ? { ok: false, status, code: 'aria.request_invalid', reason } : { ok: false, status, code: 'aria.authentication_failed', reason };
      }
      const a = result.value;
      const snapshot: PresentationSnapshot = { credential: credential!, holder: a.holder, descriptor: a.descriptor, operationId: a.operationId, lookupOf: a.lookupOf, audience: a.audience, fingerprint: a.fingerprint, requestDigest: a.requestDigest, receiverDid, expiresAt: (a.expires + PROFILE.skewSeconds) * 1000 };
      const view = { kind: 'verified-presentation', credential: credential!, operation: a.descriptor, operationId: a.operationId, lookupOf: a.lookupOf, audience: a.audience, fingerprint: a.fingerprint, requestDigest: a.requestDigest };
      return { ok: true, presentation: issue(ap, 'presentation', view as never, snapshot) };
    },

    async admit(input) {
      const p = recall<PresentationSnapshot>(ap, 'presentation', input?.presentation);
      if (p.descriptor.class === 'retrieval') throw new AriaUsageError('a retrieval is admitted with admitLookup');
      if (typeof input.authorize !== 'function') throw new AriaUsageError('admission needs the resource decision of the application (authorize)');
      const approval = approvalOf(input.approval);
      // Read through the credential verifier, which refuses evidence it did not produce for this exact result.
      let outcome = judge(internals, p, input.status, approval);
      if (outcome.decision === 'expired') throw new AdmissionExpired('deadline');
      let code: string | undefined;
      if (outcome.decision === 'allow') {
        const decided = await input.authorize({ presentation: input.presentation });
        if (decided?.allowed !== true) {
          code = (decided as { code?: unknown } | undefined)?.code as string;
          if (typeof code !== 'string' || !isReceiverCode(code)) throw new AriaUsageError('a resource refusal carries a code of the receiver, such as bank.account_not_granted');
          outcome = { decision: 'deny', reason: 'forbidden' };
        } else {
          // The authorizer took time: standing, approval and the deadline are judged again.
          outcome = judge(internals, p, input.status, approval);
          if (outcome.decision === 'expired') throw new AdmissionExpired('deadline');
        }
      }
      const snapshot: AdmissionSnapshot = { decision: outcome.decision, presentation: p, status: input.status, approval };
      if (outcome.decision === 'allow') return issue(ap, 'admission', { decision: 'allow', presentation: input.presentation } as never, snapshot);
      const answer = refusalFor(outcome, code);
      const refusal = refusalOf(ap, {
        ...answer,
        operationId: p.operationId!,
        requestDigest: p.requestDigest,
        sender: { did: p.holder.did, credential: p.holder.credentialId },
        receiverDid: p.receiverDid,
      });
      const view =
        outcome.decision === 'deny'
          ? { decision: 'deny', reason: outcome.reason as AdmissionReason, ...(code === undefined ? {} : { code }), refusal }
          : { decision: 'indeterminate', reason: outcome.reason, refusal };
      return issue(ap, 'admission', view as never, snapshot);
    },

    async admitLookup(input) {
      const p = recall<PresentationSnapshot>(ap, 'presentation', input?.presentation);
      if (p.descriptor.class !== 'retrieval') throw new AriaUsageError('only a retrieval is admitted with admitLookup');
      if (now() > p.expiresAt) throw new AdmissionExpired('deadline');
      if (p.audience !== p.receiverDid) return Object.freeze({ decision: 'deny', status: 403, code: 'aria.audience_mismatch' });
      const refused = lookupRefusal(credentials.standing(p.credential, input.status).state);
      if (refused) return Object.freeze({ decision: 'deny', ...refused });
      const key = { receiver: p.receiverDid, sender: p.holder.did, operationId: p.lookupOf! };
      return issue(ap, 'lookup', { decision: 'allow', key } as never, { key, presentation: p, status: input.status });
    },

    async buildAttemptRefusal(refusal, receiver) {
      const r = recall<RefusalSnapshot>(ap, 'refusal', refusal);
      if (receiver?.did !== r.receiverDid) throw new AriaUsageError('the refusal was made by another receiver');
      const f = selfFacts(receiver);
      if (REASONS[r.code]?.http !== r.status && !(isReceiverCode(r.code) && r.status === 403)) throw new AriaUsageError('not a signed attempt refusal');
      return signReceipt(
        {
          type: RECEIPT_TYPE,
          id: newReceiptId(),
          request: { id: r.operationId, sender: r.sender, digest: r.requestDigest },
          receiver: { did: receiver.did, credential: f.binding.credentialId },
          issuedAt: instantText(now()),
          outcome: { state: 'rejected', applies: 'attempt', status: r.status, code: r.code },
        },
        receiver.signer,
      );
    },

    async identify(receiver, request, challenges) {
      const f = selfFacts(receiver);
      if (!isProfileOrigin(receiver.origin)) throw new AriaUsageError(ORIGIN_RULE);
      if (!NONCE.test(request?.nonce ?? '') || typeof request.audience !== 'string' || !request.audience.startsWith('did:aria:')) {
        throw new AriaUsageError('an identity request names a base64url nonce and the client DID');
      }
      let digest: string | null = null;
      try {
        digest = digestField(utf8(canonicalJson(receiver.document)));
      } catch {
        digest = null;
      }
      if (digest !== f.binding.digest) throw new AriaUsageError('the receiver document is not its verified credential');
      const challenge = await challenges.issue(receiver.did, CHALLENGE_TTL_SECONDS);
      if (!CHALLENGE.test(challenge)) throw new AriaUsageError('a challenge is 8 to 256 URL-safe characters');
      const unsigned = { type: IDENTITY_TYPE, subject: receiver.did, credential: f.binding.credentialId, origin: receiver.origin, audience: request.audience, nonce: request.nonce, challenge, created: instantText(now()) };
      const proof = { alg: 'ed25519' as const, keyid: receiver.signer.keyId };
      const value = await signed(receiver.signer, utf8(canonicalJson({ ...unsigned, proof })));
      const statement = { ...unsigned, proof: { ...proof, value } } as IdentityStatement;
      return Object.freeze({ credential: receiver.document, statement: Object.freeze(statement) });
    },

    async verifyReceiverIdentity(response, pin, expected) {
      const fail = (reason: Extract<ReceiverIdentityResult, { ok: false }>['reason']): ReceiverIdentityResult => ({ ok: false, reason });
      const keys = ['type', 'subject', 'credential', 'origin', 'audience', 'nonce', 'challenge', 'created', 'proof'];
      const s = isObject(response) ? response.statement : undefined;
      if (!exactly(response, ['credential', 'statement']) || !exactly(s, keys) || !exactly(s.proof, ['alg', 'keyid', 'value'])) return fail('malformed');
      if (s.type !== IDENTITY_TYPE || keys.slice(1, -1).some((k) => typeof s[k] !== 'string') || !CHALLENGE.test(s.challenge as string) || !NONCE.test(s.nonce as string) || !isProfileOrigin(s.origin)) return fail('malformed');
      const proof = s.proof as Record<string, unknown>;
      const created = instantOf(s.created);
      if (created === null) return fail('malformed');

      const verified = credentials.verifyCredential(response.credential);
      if (!verified.ok) return fail('credential');
      const f = credentials.facts(verified.credential);
      if (f.binding.credentialId !== s.credential || f.did !== s.subject) return fail('credential');
      if (s.subject !== pin.did) return fail('unexpected_receiver');
      // A pin outside the origin rule matches no statement.
      if (!isProfileOrigin(pin.origin) || s.origin !== pin.origin) return fail('origin');
      if (s.audience !== expected.audience) return fail('audience');
      if (s.nonce !== expected.nonce) return fail('nonce');
      const t = now();
      if (created > t + PROFILE.skewSeconds * 1000 || t - created > STATEMENT_MAX_AGE_MS) return fail('stale');
      const signature = typeof proof.value === 'string' ? fromBase64url(proof.value) : null;
      const { proof: _, ...unsigned } = s;
      const bytes = utf8(canonicalJson({ ...unsigned, proof: { alg: proof.alg, keyid: proof.keyid } }));
      if (proof.alg !== 'ed25519' || proof.keyid !== f.holderKey.id || !signature || !strictVerify(signature, bytes, f.holderKey.publicKey)) return fail('signature');
      const standing = credentials.standing(verified.credential, await credentials.checkStatus(verified.credential));
      if (standing.state !== 'good') return fail('status');
      // Fetching status took time: the statement, and the challenge it carries, must still be fresh.
      if (now() - created > STATEMENT_MAX_AGE_MS) return fail('stale');

      const snapshot: ReceiverSnapshot = {
        freshUntil: created + STATEMENT_MAX_AGE_MS,
        pin: { origin: pin.origin, did: pin.did },
        key: { did: f.did, credentialId: f.binding.credentialId, keyId: f.holderKey.id, publicKey: f.holderKey.publicKey },
      };
      const view = { pin: snapshot.pin, credential: verified.credential, challenge: s.challenge };
      return { ok: true, receiver: issue(ap, 'receiver', view as never as VerifiedReceiver, snapshot) };
    },

    async signRequest(input) {
      const receiver = recall<ReceiverSnapshot>(ap, 'receiver', input?.receiver);
      if (now() > receiver.freshUntil) throw new AriaUsageError('the receiver statement and its challenge are no longer fresh: identify the receiver again');
      const f = credentials.facts(input.credential);
      if (input.signer?.keyId !== f.holderKey.id || input.signer.algorithm !== 'ed25519') throw new AriaUsageError("the signer must be the credential's Ed25519 holder key");
      const rule = CLASSES[input.class];
      if (!rule) throw new AriaUsageError(`unknown request class ${String(input.class)}`);
      const { method, target, headers } = input.request;
      const body = input.request.body ?? new Uint8Array();
      if (!rule.methods.includes(method)) throw new AriaUsageError(`${method} is not a ${input.class} method`);
      if (typeof target !== 'string' || !target.startsWith('/') || target.includes('#')) throw new AriaUsageError('the target is a path and query');
      if (rule.body === 'required' ? body.length === 0 : body.length > 0) throw new AriaUsageError(`a ${input.class} request ${rule.body === 'required' ? 'has' : 'has no'} body`);
      if (rule.receipt ? !UUID.test(input.operationId ?? '') : input.operationId !== undefined) {
        throw new AriaUsageError(rule.receipt ? 'the operation id is a lower-case UUID, the same on every retry' : 'a retrieval names its operation in the query');
      }
      const fields = fieldsOf(headers);
      for (const reserved of ['aria-operation', 'aria-credential', 'aria-audience', 'content-digest', 'signature-input', 'signature']) {
        if (fields.has(reserved)) throw new AriaUsageError(`${reserved} is set by signRequest`);
      }
      const windowSeconds = input.windowSeconds ?? 30;
      if (!Number.isInteger(windowSeconds) || windowSeconds < 1 || windowSeconds > PROFILE.maxWindowSeconds) throw new AriaUsageError('the window is 1 to 60 seconds');
      const created = Math.floor(now() / 1000);
      const credentialDigest = fromBase64(f.binding.digest.slice('sha-256=:'.length, -1))!;
      let prepared: ReturnType<typeof prepareSignature>;
      try {
        prepared = prepareSignature({
        method,
        target,
        origin: receiver.pin.origin,
        headers,
        body,
        class: input.class,
        operationId: rule.receipt ? input.operationId! : null,
        credential: { url: f.binding.credentialId, digest: credentialDigest },
        audience: receiver.key.did,
        semanticHeaders: (input.semanticHeaders ?? []).map((h) => h.toLowerCase()).filter((h) => fields.has(h)),
        nonce: (input.receiver as VerifiedReceiver).challenge,
        keyId: f.holderKey.id,
        created,
        expires: created + windowSeconds,
        });
      } catch (error) {
        throw new AriaUsageError(`the request cannot be signed as given: ${(error as Error).message}`);
      }
      const signature = await input.signer.sign(utf8(prepared.base));
      if (!(signature instanceof Uint8Array) || signature.length !== 64) throw new AriaUsageError('an Ed25519 signer returns 64 bytes');
      const signedHeaders = { ...prepared.headers, 'signature-input': `${PROFILE.label}=${serializeInnerList(prepared.params)}`, signature: `${PROFILE.label}=:${toBase64(signature)}:` };
      const request: HttpRequestLike = Object.freeze({ method, target, headers: Object.freeze(signedHeaders), ...(body.length > 0 ? { body } : {}) });
      const sent = rule.receipt
        ? Object.freeze({
            operationId: input.operationId!,
            requestDigest: digestField(utf8(prepared.base)),
            sender: Object.freeze({ did: f.did, credential: f.binding.credentialId }),
            receiver: Object.freeze({ did: receiver.key.did, credential: receiver.key.credentialId }),
          })
        : null;
      return Object.freeze({ request, sent, receiver: input.receiver });
    },

    async verifyReceipt(receipt, check) {
      const receiver = recall<ReceiverSnapshot>(ap, 'receiver', check?.receiver);
      const mode = check.mode === 'decision' ? { mode: 'decision' as const, transportStatus: check.transportStatus } : { mode: 'retrieval' as const, ...(check.transportStatus === undefined ? {} : { transportStatus: check.transportStatus }) };
      if (check.mode !== 'decision' && check.mode !== 'retrieval') throw new AriaUsageError('a receipt is checked as a decision or a retrieval');
      const r = checkReceipt(receipt, receiver.key, check.attempts ?? [], mode);
      if (!r.ok) return r;
      const x = r.receipt;
      const view = {
        receiptId: x.id,
        operationId: x.request.id,
        state: x.outcome.state,
        applies: x.outcome.applies,
        status: x.outcome.status,
        code: x.outcome.code,
        issuedAt: x.issuedAt,
        receiver: { ...x.receiver },
        sender: { ...x.request.sender },
        requestDigest: x.request.digest,
        digest: digestField(utf8(canonicalJson(x))),
      };
      return { ok: true, statement: issue(ap, 'receipt', view as never as ReceiptStatement, view), attempt: r.attempt };
    },
  };
  Object.freeze(ap);
  register(ap, internals);
  return ap;
}
