# Federation exchanges

> **Status:** draft, with the contract it checks. The authority implements this
> exchange; TLF has not yet adopted it as the normative federation contract.

What a Registration Authority sends the ARIA authority and what the authority must
answer, as shared cases. The contract is [`federation/openapi.yaml`](../../federation/openapi.yaml)
with the shapes in [`federation/exchange.schema.json`](../../federation/exchange.schema.json).

```
check.mjs                    checks the contract against itself and the exchanges against the contract
exchanges/
  tlf-config.json            the authority parameters the exchanges assume
  fixtures/ra-register.json  accredited RAs and their public test keys
  fixtures/issuer-key.json   the public half of the test issuer key
  vectors/vectors.json       31 exchanges: requests and expected answers, step by step
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
- seven controls show these checks can fail.

## Run it against an authority

Each exchange runs against a fresh authority with the RAs of `ra-register.json`
accredited, the DIDs of `taken_dids` already issued to another RA, and its clock
fixed at each step's `now`. Refusals are compared by status, code, path and whether
`request_id` is echoed; no `sentinels` value may appear in a refusal. A `same_as_step`
answer must equal that earlier answer. An answer given in full (`expect.body`) is
compared byte for byte after canonical JSON: that holds only for an authority that
derives identifiers as the reference authority does in its replay. Another
implementation compares those answers by schema and by the values the request
determines.

The ARIA authority replays every exchange in its own tests.

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

**Not covered yet:** exchanges for L1 and L2 issuance and for the domain-binding
operations (`domain-bind`, `domain-check`, `domain-unbind`). Their shapes, paths and
refusal codes are in the contract and checked here; their behaviour is covered only by
the authority's own tests until shared exchanges exist. Renewal is not part of these
exchanges: it is off unless an authority enables it.

The exchanges are synthetic, and every key is a test key derived from a public label.
No real principal, credential or key appears here.
