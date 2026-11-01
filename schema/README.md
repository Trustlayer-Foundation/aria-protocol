# Schemas

JSON Schemas (draft 2020-12) of the documents ARIA defines. A schema is the authority on
a document's shape; prose that disagrees with it is a bug. A published `$id` never
changes: a new shape is a new file.

Conforming to a schema is a shape check only. It never establishes that a document is
genuine, that a signature is valid, or that anything is authorized; the SDKs and the
conformance vectors check those separately.

## ARIA 1.0

| Schema | Document | Status |
|---|---|---|
| [`aid-1.0.json`](aid-1.0.json) | The ARIA Identity Document, `spec_version: "1.0"` | Draft until the issuance cutover; embedded byte for byte in the ARIA SDK |
| [`aria-ap-receipt-1.json`](aria-ap-receipt-1.json) | An ARIA AP receipt, `aria-ap-receipt/1` | Format decided (D4: one format with the HTTP status and code); shipped byte for byte in ARIA AP |
| [`aria-ap-identity-1.json`](aria-ap-identity-1.json) | An ARIA AP receiver identity response, statement `aria-ap-identity/1` | Decided (D3); shipped byte for byte in ARIA AP |
| [`aria-ap-lookup-1.json`](aria-ap-lookup-1.json) | The answer to an ARIA AP retrieval: `current` and `history` | **Provisional** (the rest of D4); shipped byte for byte in ARIA AP |

The ARIA AP schemas change with the decisions they depend on. Rules JSON Schema cannot
express (strict parsing of receipts, signatures, bindings) are in their `$comment` and in
the [ARIA AP API contract](../sdk/aria-ap-ts/API.md).

## Published, not the current workflow

| Schema | Status |
|---|---|
| [`enrollment-manifest-v1.json`](enrollment-manifest-v1.json) | A published contract of an earlier enrollment workflow: a per-agent token, an `_aria-enroll` record and an administrator's second factor as the last step. The current enrollment does not use it: a registration authority opens an enrollment window, and the agent submits a statement signed with keys it generated itself. The versioned contract for that enrollment is pending and is not yet in this repository. This file stays unchanged; its own `spec_version` value does not make it current. |

## Historical compatibility

Not part of the ARIA 1.0 path. Kept unchanged because something already issued or
published depends on them; see [`DEPRECATIONS.md`](../DEPRECATIONS.md).

| Schema | Why it stays |
|---|---|
| [`aid-v1.2.json`](aid-v1.2.json) | Credentials issued before the cutover declare `spec_version: "1.2"` and validate against it; its path is cited from the W3C DID Method Registry. Kept until the last such credential expires or is revoked. |
| [`atp-policy-v1.json`](atp-policy-v1.json) | The DNS policy of ATP, deprecated in favour of ARIA AP; its `$id` was published. |
| [`intent-declaration-v1.json`](intent-declaration-v1.json) | ATP's intent declaration, deprecated with it; its `$id` was published. |
