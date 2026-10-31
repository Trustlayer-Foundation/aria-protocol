import { canonicalJson, type Did } from '@aria-registry/sdk';
import type { OperationDescriptor, RequestClass } from '../presentation';
import type { HttpRequestLike } from '../types';
import { digestField, sameBytes, toBase64, utf8, UUID } from './bytes';
import { acceptableKey, strictVerify } from './ed25519';
import { isInnerList, parseDictionary, parseItem, serializeInnerList, sfStringOf, type BareItem, type InnerList, type Item, type Member } from './sf';
import { sha256 } from '@noble/hashes/sha2.js';

// The ARIA AP HTTP profile (provisional, D3): RFC 9421 with one signature labelled
// `aria`, the components each class fixes, a single-use receiver challenge as the
// nonce, and the authentication order of conformance/ap/profile.json.

export const PROFILE = { label: 'aria', tag: 'aria-ap/1', alg: 'ed25519', maxWindowSeconds: 60, skewSeconds: 5 } as const;

interface ClassRule {
  readonly methods: readonly string[];
  readonly body: 'required' | 'forbidden';
  readonly components: readonly string[];
  readonly receipt: boolean;
}

export const CLASSES: Readonly<Record<RequestClass, ClassRule>> = Object.freeze({
  'unsafe-body': { methods: ['POST', 'PUT', 'PATCH'], body: 'required', components: ['@method', '@target-uri', 'content-type', 'content-digest', 'aria-operation', 'aria-credential', 'aria-audience'], receipt: true },
  'unsafe-empty': { methods: ['DELETE', 'POST', 'PATCH'], body: 'forbidden', components: ['@method', '@target-uri', 'content-digest', 'aria-operation', 'aria-credential', 'aria-audience'], receipt: true },
  'safe-receiptable': { methods: ['GET'], body: 'forbidden', components: ['@method', '@target-uri', 'aria-operation', 'aria-credential', 'aria-audience'], receipt: true },
  retrieval: { methods: ['GET'], body: 'forbidden', components: ['@method', '@target-uri', 'aria-credential', 'aria-audience'], receipt: false },
});

const PARAMS = ['created', 'expires', 'nonce', 'keyid', 'alg', 'tag'];
const ARIA_FIELDS = ['aria-operation', 'aria-credential', 'aria-audience', 'content-digest', 'signature-input', 'signature'];

export type Fields = ReadonlyMap<string, readonly string[]>;

/** Header fields by lower-case name, every instance kept: ambiguity is refused where it matters, never merged. */
export function fieldsOf(headers: HttpRequestLike['headers']): Fields {
  const out = new Map<string, string[]>();
  for (const [name, value] of Object.entries(headers ?? {})) {
    const k = name.toLowerCase();
    out.set(k, [...(out.get(k) ?? []), ...(typeof value === 'string' ? [value] : [...value])]);
  }
  return out;
}

const trimField = (value: string): string => value.replace(/^[ \t]+|[ \t]+$/g, '');

/** `type/subtype` in lower case with parameters sorted by name, or `null`. */
export function normalizeMediaType(value: string): string | null {
  const [type = '', ...rest] = value.split(';');
  const t = type.trim().toLowerCase();
  if (!/^[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+$/.test(t)) return null;
  const params: [string, string][] = [];
  for (const p of rest) {
    const at = p.indexOf('=');
    if (at < 0) return null;
    params.push([p.slice(0, at).trim().toLowerCase(), p.slice(at + 1).trim()]);
  }
  params.sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return [t, ...params.map(([k, v]) => `${k}=${v}`)].join(';');
}

/** `{name}` in a descriptor path matches exactly one non-empty segment. */
function pathMatches(pattern: string, path: string): boolean {
  const want = pattern.split('/');
  const got = path.split('/');
  return want.length === got.length && want.every((w, i) => (/^\{[^/{}]+\}$/.test(w) ? got[i] !== '' : w === got[i]));
}

/** The receiver's operations, checked once: each class's methods, one normalised media type for bodies, lower-case header names. */
export function checkDescriptors(operations: readonly OperationDescriptor[]): readonly OperationDescriptor[] {
  return operations.map((d) => {
    const rule = CLASSES[d.class];
    if (!rule || !rule.methods.includes(d.method)) throw new TypeError(`operation ${d.name}: ${d.method} is not a ${d.class} method`);
    if (!d.path.startsWith('/') || d.path.includes('?')) throw new TypeError(`operation ${d.name}: the path is absolute and has no query`);
    if (rule.receipt && (typeof d.scope !== 'string' || typeof d.minLevel !== 'string')) throw new TypeError(`operation ${d.name}: a receiptable operation names its scope and minimum level`);
    if (d.class === 'retrieval' && (d.query?.length !== 1 || d.query[0] !== 'operation')) throw new TypeError(`operation ${d.name}: a retrieval takes exactly the operation parameter`);
    const mediaType = d.class === 'unsafe-body' ? normalizeMediaType(d.mediaType ?? '') : null;
    if (d.class === 'unsafe-body' && !mediaType) throw new TypeError(`operation ${d.name}: a body operation declares its one media type`);
    const semantic = (d.semanticHeaders ?? []).map((h) => h.toLowerCase());
    if (semantic.some((h) => ARIA_FIELDS.includes(h) || h === 'content-type')) throw new TypeError(`operation ${d.name}: ${semantic.join(', ')} cannot be semantic headers`);
    return Object.freeze({ ...d, ...(mediaType ? { mediaType } : {}), query: Object.freeze([...(d.query ?? [])]), semanticHeaders: Object.freeze(semantic) });
  });
}

/** What the receiver established about the presented credential, from its credential verifier. */
export interface Holder {
  readonly credentialId: string;
  readonly digest: string;
  readonly did: Did;
  readonly keyId: string;
  readonly publicKey: Uint8Array;
}

export interface AuthContext {
  /** The receiver's configured origin: `@target-uri` is built from it, never from a client header. */
  readonly origin: string;
  readonly operations: readonly OperationDescriptor[];
  readonly now: number;
  /** Whether the challenge is live, without consuming it. */
  readonly challengeLive: (nonce: string) => Promise<boolean>;
  /** The exact credential named by URL and digest, verified; `null` when it cannot be. */
  readonly resolve: (url: string, digest: string) => Promise<Holder | null>;
  /** Consumes the challenge once the signature verified; `false` if it is no longer live. */
  readonly consume: (nonce: string) => Promise<boolean>;
}

export type InvalidReason = 'method' | 'target' | 'operation_unknown' | 'body' | 'media_type' | 'query' | 'operation_id';
export type AuthReason = 'signature' | 'window' | 'digest' | 'challenge' | 'unsigned_operation' | 'credential';
export type AuthFailure = { readonly status: 400; readonly reason: InvalidReason } | { readonly status: 401; readonly reason: AuthReason };

export interface Authenticated {
  readonly descriptor: OperationDescriptor;
  readonly operationId: string | null;
  readonly lookupOf: string | null;
  readonly audience: string;
  readonly fingerprint: string | null;
  readonly requestDigest: string;
  readonly holder: Holder;
}

const invalid = (reason: InvalidReason) => ({ ok: false as const, failure: { status: 400 as const, reason } });
const refused = (reason: AuthReason) => ({ ok: false as const, failure: { status: 401 as const, reason } });

function single(fields: Fields, name: string): string | null {
  const values = fields.get(name);
  return values?.length === 1 ? values[0]! : null;
}

/** RFC 9421 signature base over `covered`, or `null` when a covered field is absent, repeated, or holds a line break or NUL. */
export function signatureBase(method: string, targetUri: string, fields: Fields, covered: readonly string[], signatureParams: InnerList): string | null {
  const lines: string[] = [];
  for (const name of covered) {
    let value: string | null;
    if (name === '@method') value = method;
    else if (name === '@target-uri') value = targetUri;
    else value = single(fields, name);
    if (value === null || /[\r\n\0]/.test(value)) return null;
    lines.push(`"${name}": ${name.startsWith('@') ? value : trimField(value)}`);
  }
  lines.push(`"@signature-params": ${serializeInnerList(signatureParams)}`);
  return lines.join('\n');
}

/**
 * The operation's logical content: class, method, path, declared query and semantic
 * headers, media type and content digest. Excludes the challenge, times, key and
 * signature, so retries with fresh signatures share it.
 */
export function fingerprintOf(d: OperationDescriptor, url: URL, fields: Fields, body: Uint8Array): string {
  const object: Record<string, unknown> = {
    class: d.class,
    method: d.method,
    path: url.pathname,
    query: Object.fromEntries((d.query ?? []).filter((n) => url.searchParams.has(n)).map((n) => [n, url.searchParams.get(n)])),
    semanticHeaders: Object.fromEntries((d.semanticHeaders ?? []).filter((h) => fields.has(h)).map((h) => [h, fields.get(h)![0]])),
  };
  if (d.class === 'unsafe-body') {
    object.mediaType = d.mediaType;
    object.contentDigest = digestField(body);
  }
  if (d.class === 'unsafe-empty') object.contentDigest = digestField(new Uint8Array());
  return digestField(utf8(canonicalJson(object)));
}

/** The receiver's authentication, in the profile's order. Every failure is unsigned. */
export async function authenticate(request: HttpRequestLike, ctx: AuthContext): Promise<{ ok: true; value: Authenticated } | { ok: false; failure: AuthFailure }> {
  const fields = fieldsOf(request.headers);
  const body = request.body ?? new Uint8Array();

  // 1. A supported method and exactly one described operation.
  if (!['GET', 'POST', 'PUT', 'PATCH', 'DELETE'].includes(request.method)) return invalid('method');
  if (typeof request.target !== 'string' || !request.target.startsWith('/') || request.target.includes('#')) return invalid('target');
  let url: URL;
  try {
    url = new URL(request.target, ctx.origin);
  } catch {
    return invalid('target');
  }
  if (url.origin !== ctx.origin || url.href !== ctx.origin + request.target) return invalid('target');
  const matches = ctx.operations.filter((x) => x.method === request.method && pathMatches(x.path, url.pathname));
  if (matches.length !== 1) return invalid('operation_unknown');
  const d = matches[0]!;
  const rule = CLASSES[d.class];

  // 2. The class's body rule, and the descriptor's one media type.
  if (rule.body === 'forbidden' && body.length > 0) return invalid('body');
  if (rule.body === 'required') {
    if (body.length === 0) return invalid('body');
    const ct = single(fields, 'content-type');
    if (ct === null || normalizeMediaType(ct) !== d.mediaType) return invalid('media_type');
  }

  // 3. Only declared query parameters, each at most once; a retrieval names one operation.
  const names = [...url.searchParams.keys()];
  if (new Set(names).size !== names.length || names.some((n) => !(d.query ?? []).includes(n))) return invalid('query');
  const lookupOf = d.class === 'retrieval' ? url.searchParams.get('operation') : null;
  if (d.class === 'retrieval' && !UUID.test(lookupOf ?? '')) return invalid('query');

  // 4. The signed operation reference: exactly once as a UUID on receiptable classes, absent on retrieval.
  const opField = fields.get('aria-operation');
  let operationId: string | null = null;
  if (d.class === 'retrieval') {
    if (opField) return invalid('operation_id');
  } else {
    if (opField?.length !== 1) return invalid('operation_id');
    operationId = sfStringOf(opField[0]!);
    if (operationId === null || !UUID.test(operationId)) return invalid('operation_id');
  }

  // 5. Exactly one signature, labelled aria.
  const si = single(fields, 'signature-input');
  const sg = single(fields, 'signature');
  if (si === null || sg === null) return refused('signature');
  let inputs: ReturnType<typeof parseDictionary>;
  let signatures: ReturnType<typeof parseDictionary>;
  try {
    inputs = parseDictionary(si);
    signatures = parseDictionary(sg);
  } catch {
    return refused('signature');
  }
  const input = inputs.get(PROFILE.label);
  const signature = signatures.get(PROFILE.label);
  if (inputs.size !== 1 || signatures.size !== 1 || !input || !signature || !isInnerList(input) || isInnerList(signature)) return refused('signature');
  const [items, params] = input;

  // 6. Covered components: exactly the class's, plus the descriptor's semantic headers present.
  const covered = items.map(([name, p]) => (typeof name === 'string' && p.size === 0 ? name : null));
  const semantic = (d.semanticHeaders ?? []).filter((h) => fields.has(h));
  const required = [...rule.components, ...semantic];
  if (operationId !== null && !covered.includes('aria-operation')) return refused('unsigned_operation');
  if (required.includes('content-digest') && !covered.includes('content-digest')) return refused('digest');
  if (covered.includes(null) || new Set(covered).size !== covered.length) return refused('signature');
  if (covered.length !== required.length || required.some((c) => !covered.includes(c))) return refused('signature');

  // 7. Exactly the profile's parameters, then the window.
  if (params.size !== PARAMS.length || PARAMS.some((k) => !params.has(k))) return refused('signature');
  const created = params.get('created');
  const expires = params.get('expires');
  const nonce = params.get('nonce');
  const keyid = params.get('keyid');
  if (params.get('alg') !== PROFILE.alg || params.get('tag') !== PROFILE.tag) return refused('signature');
  if (typeof created !== 'number' || typeof expires !== 'number' || typeof nonce !== 'string' || typeof keyid !== 'string') return refused('signature');
  const now = ctx.now / 1000;
  if (expires <= created || expires - created > PROFILE.maxWindowSeconds || created > now + PROFILE.skewSeconds || expires < now - PROFILE.skewSeconds) {
    return refused('window');
  }

  // 8. Content-Digest of the exact content: empty content for unsafe-empty.
  if (rule.components.includes('content-digest')) {
    const cd = single(fields, 'content-digest');
    if (cd === null) return refused('digest');
    let member: Member | undefined;
    try {
      member = parseDictionary(cd).get('sha-256');
    } catch {
      return refused('digest');
    }
    if (!member || isInnerList(member) || !(member[0] instanceof Uint8Array) || !sameBytes(member[0], sha256(body))) return refused('digest');
  }

  // 9. A challenge this receiver issued, live and not consumed. Consumed only after the signature.
  if (!(await ctx.challengeLive(nonce))) return refused('challenge');

  // 10. The exact credential named, its digest, its holder key, and that key's acceptability.
  const ac = single(fields, 'aria-credential');
  if (ac === null) return refused('credential');
  let credentialItem: Item;
  try {
    credentialItem = parseItem(ac);
  } catch {
    return refused('credential');
  }
  const [credentialUrl, credentialParams] = credentialItem;
  const presentedDigest = credentialParams.get('digest');
  if (typeof credentialUrl !== 'string' || !(presentedDigest instanceof Uint8Array) || presentedDigest.length !== 32 || credentialParams.size !== 1) return refused('credential');
  const digest = `sha-256=:${toBase64(presentedDigest)}:`;
  const holder = await ctx.resolve(credentialUrl, digest);
  if (!holder || holder.credentialId !== credentialUrl || holder.digest !== digest || holder.keyId !== keyid || !acceptableKey(holder.publicKey)) return refused('credential');

  // 11. Strict Ed25519 over the base rebuilt from the receiver's own origin.
  const base = signatureBase(request.method, ctx.origin + request.target, fields, covered as string[], input);
  const signatureBytes = signature[0];
  if (base === null || !(signatureBytes instanceof Uint8Array) || signature[1].size !== 0 || !strictVerify(signatureBytes, utf8(base), holder.publicKey)) {
    return refused('signature');
  }

  // 12. Authenticated: the challenge is consumed, atomically in the adopter's store.
  if (!(await ctx.consume(nonce))) return refused('challenge');

  const audience = sfStringOf(single(fields, 'aria-audience') ?? '') ?? '';
  return {
    ok: true,
    value: {
      descriptor: d,
      operationId,
      lookupOf,
      audience,
      fingerprint: d.class === 'retrieval' ? null : fingerprintOf(d, url, fields, body),
      requestDigest: digestField(utf8(base)),
      holder,
    },
  };
}

export interface SigningInput {
  readonly method: string;
  readonly target: string;
  readonly origin: string;
  readonly headers: HttpRequestLike['headers'];
  readonly body: Uint8Array;
  readonly class: RequestClass;
  readonly operationId: string | null;
  readonly credential: { readonly url: string; readonly digest: Uint8Array };
  readonly audience: string;
  readonly semanticHeaders: readonly string[];
  readonly nonce: string;
  readonly keyId: string;
  readonly created: number;
  readonly expires: number;
}

/** The headers the agent adds and the base it signs; the signature itself comes from the adopter's `Signer`. */
export function prepareSignature(input: SigningInput): { readonly headers: Record<string, string | readonly string[]>; readonly base: string; readonly params: InnerList } {
  const rule = CLASSES[input.class];
  const headers: Record<string, string | readonly string[]> = {};
  for (const [name, value] of fieldsOf(input.headers)) headers[name] = value.length === 1 ? value[0]! : value;
  if (rule.components.includes('content-digest')) headers['content-digest'] = digestField(input.body);
  if (input.operationId !== null) headers['aria-operation'] = `"${input.operationId}"`;
  headers['aria-credential'] = `"${input.credential.url}";digest=:${toBase64(input.credential.digest)}:`;
  headers['aria-audience'] = `"${input.audience}"`;
  const covered = [...rule.components, ...input.semanticHeaders];
  const params = new Map<string, BareItem>([
    ['created', input.created],
    ['expires', input.expires],
    ['nonce', input.nonce],
    ['keyid', input.keyId],
    ['alg', PROFILE.alg],
    ['tag', PROFILE.tag],
  ]);
  const list: InnerList = [covered.map((c): Item => [c, new Map()]), params];
  const base = signatureBase(input.method, input.origin + input.target, fieldsOf(headers), covered, list);
  if (base === null) throw new TypeError('a covered header is missing or repeated');
  return { headers, base, params: list };
}
