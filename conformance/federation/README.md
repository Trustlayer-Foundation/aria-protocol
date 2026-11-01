# Federation exchanges

> **Status:** draft, with the contract it checks. The authority implements this
> exchange; TLF has not yet adopted it as the normative federation contract.

What a Registration Authority sends the ARIA authority and what the authority must
answer, as shared cases. The contract is [`federation/openapi.yaml`](../../federation/openapi.yaml)
with the shapes in [`federation/exchange.schema.json`](../../federation/exchange.schema.json).

```
check.mjs                    checks the contract against itself and the exchanges against the contract
identifiers.json             DIDs the schema must accept and reject exactly as the authority's parser does
exchanges/
  tlf-config.json            the authority parameters the exchanges assume
  fixtures/ra-register.json  accredited RAs and their public test keys
  fixtures/issuer-key.json   the public half of the test issuer key
  vectors/vectors.json       54 exchanges: requests and expected answers, step by step
```

## Run it

```bash
cd conformance && npm install
node federation/check.mjs
```

It checks, with no authority running:

- the contract's operations are the six `/v1/authority/<op>` paths, each refers to
  its own request schema, and every refusal code travels with exactly one HTTP status;
- an accepted request passes its operation's schema, and its answer passes the answer
  schema (an issued credential against `schema/aid-1.0.json`);
- a request refused for its shape fails the schema where the refusal points;
- a request refused for anything else passes the schema: up to the envelope when the
  refusal comes before the payload is read (400, 401, 413), in full otherwise;
- every refusal's body, as the contract says the authority sends it, passes the
  schema of its status: `code`, `path`, a `correlation_id` (any UUID stands for
  the random one), and the request's own `request_id` when the vector says it is
  echoed; before and after authentication, and for an unreadable body;
- each DID in `identifiers.json` is accepted or rejected by the schema as listed;
- twelve controls, accepted and rejected, show these checks can tell the difference.

## Run it against an authority

Each exchange runs against a fresh authority with the RAs of `ra-register.json`
accredited, the DIDs of `taken_dids` already issued to another RA, and its clock
fixed at each step's `now`. Its resolver answers what the `dns` steps have set for each
binding record name (no record until one is set); `domain_binding` in `tlf-config.json`
is its policy, and a vector may adjust it (`policy.domain_binding`) or run without a
resolver (`resolver: false`), as an authority that reads no records. Refusals are compared by status, code, path and whether
`request_id` is echoed (it must then be the request's own), and each refusal body
must pass the schema of its status; no `sentinels` value may appear in a refusal. A
`same_as_step` answer must equal that earlier answer. An answer given in full
(`expect.body`) is compared byte for byte after canonical JSON: that holds only for
an authority that derives identifiers as the reference authority does in its
replay. Another implementation compares those answers by schema and by the values
the request determines.

The ARIA authority replays every exchange in its own tests, checks every refusal it
sends against the schema of its status, and runs `identifiers.json` through its own
DID parser.

## What the exchanges cover

Issuance and revocation at L0: complete issuance for a person and an organization,
an enrollment window's prior authorization, retries of reserve and mint (including a
fresh assertion after every window has passed), revocation and its replay, revocation
by an unrelated RA; refusals for shape, unreadable JSON, each half of each composite
signature (request, attestation, agent statement), payload digest, assertion window,
operation, standing and accreditation, DID form and availability, accounts managed by
another RA, bindings between statement, attestation and reservation, check sets, HITL
scopes, oversized attestations and consumed reservations, with planted values that
must never be echoed.

Domain bindings and L1 (contract r4): a binding pending until its record is seen and
an L1 reservation that waits for it; bind, publish, check, reserve and mint at L1 for
an organization and a person, and with an enrollment window's authorization; the
same binding when binding again, and a new one after expiry; a removed record and a
resolver failure at the mint (stale observation), with recovery by the same request;
DNSSEC required against an unsigned zone; another RA's binding as unknown; an RA
without L1 accreditation; a domain under the registry host; unbinding, before and
after issuance, and a binding that cannot be ended or checked again; no resolver;
the same request ID with another payload; L1 attestation rules (a check of another
level, a stale identity check, a missing assurance class, consent after capture, an
attested domain that is not the DID's). L2 is refused (`level_not_supported`): this
authority does not issue it.

The L0 exchanges were selected from the authority contract's candidate vectors; the
binding and L1 exchanges come from a reference model of candidate r4. Where r4 does
not fix a refusal's path, the path is the one the authority gives.

**Outside shared exchanges:** a lost database acknowledgement cannot be written as a
request and an answer. The authority tests it on its own side: a commit whose
acknowledgement is lost answers 503 `unavailable`, and the same request then returns
the recorded answer with one credential issued; a connection lost before the commit
leaves nothing, and the same request then issues once.

**Not covered:** L2 issuance, which no authority performs yet, and renewal, which is
off unless an authority enables it.

The exchanges are synthetic, and every key is a test key derived from a public label.
No real principal, credential or key appears here.
