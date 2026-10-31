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
| [`enrollment-manifest-v1.json`](enrollment-manifest-v1.json) | The enrollment manifest an agent's controller submits | In force |
| [`aria-ap-receipt-1.json`](aria-ap-receipt-1.json) | An ARIA AP receipt, `aria-ap-receipt/1` | **Provisional** (decisions D3, D4); shipped byte for byte in ARIA AP |
| [`aria-ap-identity-1.json`](aria-ap-identity-1.json) | An ARIA AP receiver identity response, statement `aria-ap-identity/1` | **Provisional** (D3); shipped byte for byte in ARIA AP |
| [`aria-ap-lookup-1.json`](aria-ap-lookup-1.json) | The answer to an ARIA AP retrieval: `current` and `history` | **Provisional** (D4); shipped byte for byte in ARIA AP |

The ARIA AP schemas change with the decisions they depend on. Rules JSON Schema cannot
express (strict parsing of receipts, signatures, bindings) are in their `$comment` and in
the [ARIA AP API contract](../sdk/aria-ap-ts/API.md).

## Historical compatibility

Not part of the ARIA 1.0 path. Kept unchanged because something already issued or
published depends on them; see [`DEPRECATIONS.md`](../DEPRECATIONS.md).

| Schema | Why it stays |
|---|---|
| [`aid-v1.2.json`](aid-v1.2.json) | Credentials issued before the cutover declare `spec_version: "1.2"` and validate against it; its path is cited from the W3C DID Method Registry. Kept until the last such credential expires or is revoked. |
| [`atp-policy-v1.json`](atp-policy-v1.json) | The DNS policy of ATP, deprecated in favour of ARIA AP; its `$id` was published. |
| [`intent-declaration-v1.json`](intent-declaration-v1.json) | ATP's intent declaration, deprecated with it; its `$id` was published. |
