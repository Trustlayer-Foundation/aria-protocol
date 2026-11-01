# ARIA AP conformance (provisional)

> **Status:** provisional. The vectors encode the options recommended for decisions
> D3 (transport), D4 (receipt), D5 (scopes) and D8 (human approval). None of those
> decisions is taken; the profile is not adopted and nothing here is frozen. Expect
> the vectors to change when the decisions are made.

ARIA AP is the profile an agent uses to call a receiver with its ARIA credential: the
receiver's identity, a signed request, an admission decision, and a signed receipt. This
package holds its vectors and a checker that judges them without the generator's code.

```
profile.json            the provisional profile: identity, classes, components, order, reasons, ATP mapping
generate.mjs            builds the request, fingerprint, receipt and identity vectors (deterministic)
check.mjs               the independent checker; exits 1 on any failure
model.mjs               reference state machine for the sequences, with deliberate mutants
vectors/requests.json   67 requests and the receiver's expected answer
vectors/fingerprints.json  operation fingerprints and which ones must match
vectors/receipts.json   34 receipts, each with the client's kept evidence and a mode
vectors/sequences.json  23 sequences of attempts, outcomes, lookups and client state
vectors/scopes.json     scope grammar, exact admission and policy patterns
vectors/identity.json   34 receiver identity statements and what the client concludes
```

## Running it

```bash
cd conformance/ap
npm install --no-audit --no-fund
npm test                          # node check.mjs [--verbose] [--report <file>]
npm run generate && git diff --exit-code -- vectors   # the committed vectors are current
```

## How the checker stays independent

- **Signature base:** rebuilt by `http-message-signatures` from the request and the
  `Signature-Input` it carries, from the receiver's configured origin. The generator
  writes its own base; the two agree on every authenticated vector.
- **Structured fields:** parsed by `structured-headers`.
- **Canonical JSON:** RFC 8785 via `canonicalize`. For the receipt and fingerprint data
  models (objects, strings, integers, ASCII keys) it yields the same bytes as ARIA
  canonical JSON, which the generator uses.
- **Rules:** the receiver's authentication order, the identity statement's order, the
  receipt rules and the scope rules are written in `check.mjs`, not imported. The AID 1.0
  scope pattern is read from `schema/aid-1.0.json`, and the identity statement's syntax
  (origin, created, nonce, challenge) from `schema/aria-ap-identity-1.json`.
- **Keys:** synthetic. Each seed is SHA-256 of a public label in `generate.mjs`; the
  vectors carry public keys only. They are test material and trusted nowhere.

Ed25519 is the same library on both sides; the strict rule is applied by the checker:
the holder key and `R` canonical, not small order and torsion free, and `S < L`. With
both points in the prime-order subgroup the cofactored and cofactorless equations
agree, so implementations cannot diverge on a valid vector.

## Controls

`npm test` also fails if any control fails:

- every expectation, mutated, must stop matching;
- every accepted request and every valid receipt, with one signature bit flipped, must
  be refused;
- each strict-Ed25519 vector must be accepted by the lenient verifier it targets
  (ZIP-215 or cofactored), so it really separates strict from lenient;
- each of the 14 mutants in `model.mjs` must fail at least one sequence.

## Provisional choices

| Decision | Encoded here |
|---|---|
| D3 | RFC 9421, one signature labelled `aria`, tag `aria-ap/1`; a fresh single-use receiver challenge as `nonce` for **every** request, retrieval included, delivered in the receiver's identity statement (`aria-ap-identity/1`, 60 s). The WIMSE binding is a candidate alternative, not covered. |
| D4 | `aria-ap-receipt/1`: `id`, `request`, `receiver`, `issuedAt`, `outcome`, plus `type` and `proof`; everything but `proof.value` is signed. Refusals are signed only after authentication. `rejected/attempt` never moves an operation. A revoked credential authorizes no lookup; a current credential of the same DID retrieves the original receipt (REQ-037, SEQ-R2a). |
| D5 | New grants `namespace:resource:action`; signed 1.0 documents read under their own pattern; exact comparison; policy patterns may end in `:*` and a matching deny wins (`aria.scope_denied`, judged after `aria.scope_missing`). |
| D8 | `refuse` only: a missing, foreign or expired approval rejects the attempt and claims nothing. `hold` is deferred and has no vectors. |

## Coverage of the AP proposal §5.9

| # | Vectors |
|---|---|
| 1–4 | RCP-01, RCP-02, RCP-03, RCP-04 |
| 5 | RCP-05a–d (`proof.alg` and `keyid` are signed: RCP-05c) |
| 6 | RCP-06a–d |
| 7 | RCP-07a–c |
| 8 | RCP-08a–c |
| 9 | RCP-09, SEQ-R2d |
| 10 | RCP-10a–d |
| 11 | RCP-11a–b |
| 12 | RCP-12a–d (historical evidence) |
| 13 | SEQ-R1a–d |
| 14–18 | SEQ-R2a, SEQ-R2b, SEQ-R2c, SEQ-R2d, SEQ-R2e |
| 19 | REQ-008, REQ-009, REQ-012–REQ-017 |
| 20 | REQ-030, REQ-031, REQ-034–REQ-036 |
| 21 | REQ-004, REQ-005, fingerprints `json-42`/`text-42`, SEQ-R2c |
| 22 | REQ-002, SEQ-CH2 |
| 23 | SEQ-D8 (`refuse` only) |
| 24 | SEQ-R1c |

Beyond the list: strict possession (REQ-060–REQ-068), challenges (REQ-032, REQ-033,
REQ-038, REQ-039, SEQ-CH1–CH3; refused at the expiry instant, REQ-072), window and digest
(REQ-041–REQ-046), exact parsing (a target taken as sent, a repeated covered field, and
only canonical byte sequences: REQ-053–REQ-056), freshness after asynchronous steps
(resolution and consumption crossing the window: REQ-090–REQ-092), the receiver's identity
(pins, credential, audience, nonce, freshness and its boundaries, signature, encodings,
IDNA, status, status crossing the age limit, order: IDN-001–IDN-034), reconciliation
and compare-and-set storage (SEQ-REC1–REC5: an uncertain claim stays locked without an
assurance, a running worker is never released, a remote effect that lands after local
uncertainty runs once, an observation of an older claim never releases its successor;
SEQ-CAS1–CAS3), a business rejection
(SEQ-R2f) and two terminal receipts (SEQ-INC1).

## Who runs each part

| Vectors | Independent judge | ARIA AP SDK adapter (`sdk/aria-ap-ts/test/`) |
|---|---|---|
| requests | `check.mjs` | `vectors-requests.test.ts`: the request rules through `MemoryChallengeStore`, with each vector's timeline |
| fingerprints | `check.mjs` | `vectors-requests.test.ts` |
| receipts | `check.mjs` | `vectors-receipts.test.ts`; RCP-12a–d (historical) are skipped until the SDK verifies historical receipts |
| identity | `check.mjs` | `vectors-identity.test.ts`: the identity core that `verifyReceiverIdentity` runs |
| scopes: grammar | `check.mjs` | `document10`: the credential verifier, over signed AID 1.0 documents; `newGrant` is issuance's rule (C2), reused by ARIA AP only as the grammar of exact policy patterns |
| scopes: admission, policy | `check.mjs` | `vectors-scopes.test.ts`: the admission rules and the receiver's scope policy |
| sequences | `model.mjs` | `vectors-sequences.test.ts`: the real ledger and tracker |

The adapters stand in for the credential verifier with the vectors' verified views; the
SDK suites also run the same rules over a real verifier.

## Not covered yet

- Challenge delivery other than the identity round trip, such as a response header.
- Credential verification itself: requests and identity statements carry verified views
  of credentials (`context.credentials`); full AID documents are S1's vectors.
- Status evidence and policy at admission beyond audience and scopes: the sequences take
  the admission result as given.
- The WIMSE binding, by-value credentials, `hold`, delegation, and the demo's emulated
  post-quantum receipt signature.
