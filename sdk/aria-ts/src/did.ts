import type { Did } from './types';

/**
 * The `did:aria` identifier grammar (specification §3.1): four shapes, two subject
 * kinds crossed with two anchoring modes. The same rules as the authority's parser
 * and the shared vectors (`conformance/vectors/abnf-cases.json`).
 *
 * Verifying a credential does not apply it: a signed 1.0 document is read under its
 * own schema. Use it for identifiers being created or compared.
 */
export type ParsedDid =
  /** An agent under a domain its principal has verified. */
  | { readonly shape: 'agent-domain-form'; readonly did: Did; readonly domain: string; readonly slug: string }
  /** An agent under a registry namespace. */
  | { readonly shape: 'agent-registry-form'; readonly did: Did; readonly host: string; readonly account: string; readonly slug: string }
  /** An organization that has verified a domain. */
  | { readonly shape: 'principal-domain-form'; readonly did: Did; readonly domain: string }
  /** An organization without a verified domain: no host, so it survives a registry move. */
  | { readonly shape: 'principal-registry-form'; readonly did: Did; readonly account: string };

const LABEL = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/;
const ACCOUNT = /^u-[A-Za-z0-9]{8}$/;
const SLUG = /^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/;
const PRINCIPAL = 'org';

const domain = (s: string) => s.split('.').every((label) => LABEL.test(label));
const slug = (s: string) => s !== PRINCIPAL && SLUG.test(s);

/** The parts of a `did:aria` identifier, or `null` when it is not one. */
export function parseDid(value: unknown): ParsedDid | null {
  if (typeof value !== 'string' || !value.startsWith('did:aria:')) return null;
  const did = value as Did;
  const parts = value.slice('did:aria:'.length).split(':');
  if (parts.length === 2) {
    const [first, second] = parts as [string, string];
    if (second === PRINCIPAL) {
      // A first part that starts with `u-` is a registry account, or nothing.
      if (first.startsWith('u-')) return ACCOUNT.test(first) ? Object.freeze({ shape: 'principal-registry-form', did, account: first }) : null;
      return domain(first) ? Object.freeze({ shape: 'principal-domain-form', did, domain: first }) : null;
    }
    return domain(first) && slug(second) ? Object.freeze({ shape: 'agent-domain-form', did, domain: first, slug: second }) : null;
  }
  if (parts.length === 3) {
    const [host, account, name] = parts as [string, string, string];
    return domain(host) && ACCOUNT.test(account) && slug(name) ? Object.freeze({ shape: 'agent-registry-form', did, host, account, slug: name }) : null;
  }
  return null;
}
