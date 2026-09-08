# ARIA Specification v1.1 — Agent Trust Protocol (ATP)

> **Superseded — public preview.** This text belongs to the preview line (labeled 1.0–1.2,
> April–August 2026, no production adoption). The stable specification is **ARIA 1.0**
> (September 7, 2026) at [aria.bar/spec](https://aria.bar/spec); see [`../README.md`](../README.md).
> Kept verbatim for verifiers of preview credentials.

> **Section status:** Stable since v1.0 (April 1, 2026). No semantic changes in v1.1
> — see [`../CHANGELOG.md`](../CHANGELOG.md) for the v1.1 schema clarifications
> (top-level `id` URL, `previousCredentialId`, `principal.verificationStatus`).
>
> **Specification decisions locked March 22, 2026:**
> - Intent declarations: cryptographically signed (included in ML-DSA envelope)
> - Enforcement model: three modes (monitor / warn / strict)
> - Scope matching: wildcard (`commerce.*` matches `commerce.read`)
> - Trust Ledger records credential lifecycle events ONLY (issuance, renewal,
>   suspension, revocation, expiry, tombstone). Per-ATP-event admit/reject
>   decisions are queued for the Agent Interaction Log — a future system,
>   deferred beyond v1.0.
> - Trust Record = single entry in the Trust Ledger.

---

## §XX.0 — Overview

ARIA gives agents a passport. ATP is customs.

The Agent Trust Protocol defines the interaction that occurs when an AI agent presents its credentials to a receiving system. It is a three-phase handshake — Declare, Evaluate, Admit — that binds the agent's identity (AID) and stated intent to the receiving system's published admission policy.

No other protocol defines this interaction. MCP handles tool connectivity. A2A handles agent communication. OAuth handles authorization tokens. None of them define the moment where an agent must identify itself, declare its purpose, and be evaluated against a published trust policy before access is granted. ATP fills that gap.

ATP is to AI agent admission what DMARC (RFC 7489) is to email authentication: a DNS-published policy record that enables receiving systems to evaluate and enforce trust requirements — with a graduated adoption model that lets organizations start with visibility before moving to enforcement.

**Marketing name:** Agent Trust Policy (the DNS record and the concept).
**Spec name:** Agent Trust Protocol (the full three-phase interaction).

---

## §XX.1 — The Three Phases

### Phase 1: Declare

The agent arrives at a receiving system carrying two payloads:

**Payload A — Agent Identity Document (AID).** The agent's passport. Contains: DID, trust level (L0–L3), scopes, principal, public key, proof (ML-DSA signature), delegation chain (if any), issuer, expiry, spec version. Defined in §05 (AID Document).

**Payload B — Intent Declaration.** The agent's customs form. A structured, machine-readable statement of WHY the agent is here and WHAT it intends to do. The intent declaration is signed — included in the ML-DSA signature envelope alongside the AID. This makes the declared intent non-repudiable: the agent cryptographically committed to its stated purpose at the moment of the interaction.

**Intent Declaration fields:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `purpose` | string | MUST | Human-readable statement of operational purpose. E.g., "Accounts payable reconciliation for Q2 2026." |
| `target_resource` | string | SHOULD | Specific resource or endpoint the agent intends to access. E.g., "invoice:4471" or "api/v2/customers". |
| `principal_ref` | string | MUST | Reference to the principal (legal entity or person) on whose behalf the agent acts. DID or LEI. |
| `action_requested` | string | MUST | The action the agent intends to perform. MUST use ARIA Scope Registry namespace format. E.g., "commerce.read" or "invoice.fetch". |
| `context` | string | SHOULD | Operational context, authorization framework, or session reference. E.g., "PO framework PO-2026-Q2". |
| `dataUsage` | string[] | SHOULD | W3C Data Privacy Vocabulary (DPV) purpose categories. Valid values: `dpv:CommercialResearch`, `dpv:ServiceProvision`, `dpv:TransactionManagement`, etc. Custom purposes permitted with `custom:` prefix. |
| `retention` | string (ISO 8601) | SHOULD | Maximum duration the agent will retain any data accessed during this interaction. E.g., "P90D" (90 days). |
| `constraints` | string[] | MAY | Self-declared operational constraints. E.g., ["MXN transactions only", "domestic suppliers"]. |
| `session_id` | string | MAY | Unique session identifier for correlating multiple interactions within one logical operation. |

**Signing requirement (NORMATIVE):** The intent declaration MUST be included within the ML-DSA signature envelope. A Declare payload with an unsigned intent declaration MUST be treated as if no intent was provided. This enables:
- **Non-repudiation:** The agent cannot later deny what it declared.
- **Audit integrity:** The Trust Ledger records exactly what was declared, cryptographically bound to the agent's identity.
- **Drift detection:** Over time, declared intent can be compared against actual behavior.

**Design rationale:** Intent is ARIA's most original contribution to the identity standards landscape. Scope says WHAT an agent can do. Intent says WHY it is doing it right now. Without signing, intent is a suggestion. With signing, intent is a legal instrument.

### Phase 2: Evaluate

The receiving system evaluates the Declare payload against its published Agent Trust Policy (see §XX.2). Evaluation is deterministic — given the same AID + intent + policy, the result is always the same.

**Evaluation sequence (NORMATIVE):**

1. **Credential validity.** Is the AID signature valid? Is the credential expired? Is the credential revoked (check StatusList via P4)? If any fail → ATP-401.

2. **Trust level.** Does the agent's trust level meet or exceed the policy's `min=` requirement? If not → ATP-403.

3. **Scope matching.** Does the agent carry all scopes listed in the policy's `req=` field? Wildcard matching: `commerce.*` in the policy is satisfied by any scope beginning with `commerce.` in the AID (e.g., `commerce.read`, `commerce.write`). If the agent carries any scope listed in the policy's `deny=` field → ATP-406.

4. **Delegation depth.** If the agent is delegated, does its delegation chain depth exceed the policy's `depth=` limit? If so → ATP-462.

5. **Intent completeness.** Does the intent declaration include all fields listed in the policy's `intent=` requirement? E.g., if the policy says `intent=purpose,principal_ref` and the intent is missing `principal_ref` → ATP-451.

6. **Qualifier conditions.** If the policy includes `qualify=` rules, evaluate them. E.g., `qualify=sector:healthcare>iso27001` means: if the agent's AID declares a healthcare-sector scope, it must also carry an ISO 27001 attestation. Missing qualifier → ATP-460.

7. **Rate limiting.** Has the agent exceeded the per-agent request cap defined in `rate=`? If so → ATP-429.

If all checks pass → ATP-200 (Admitted).

**Evaluation is local.** The receiving system performs evaluation using its own published policy and the presented credentials. No callback to the ARIA registry is required at evaluation time (the AID is self-contained and the StatusList is cached locally). This means ATP adds zero network round-trips beyond the initial credential presentation.

### Phase 3: Admit

The result of evaluation — admit or reject — is:

1. **Communicated to the agent** via an ATP response code (see §XX.4).
2. **Queued for the Agent Interaction Log** (see §XX.5). The Agent Interaction Log is a separate future system that will record per-ATP-event admit/reject decisions. It is intentionally distinct from the Trust Ledger, which records credential lifecycle events only. Implementation deferred beyond v1.0; ATP responses are returned without persistence in the meantime.
3. **Optionally reported** to the aggregate reporting endpoint defined in the policy's `rua=` field, enabling DMARC-style visibility reports.

**Enforcement modes determine what "reject" means:**

| Mode | Behavior | Use case |
|------|----------|----------|
| `enforce=monitor` | Log everything. Admit all agents regardless of compliance. Non-compliant agents are flagged in the Trust Ledger but not blocked. | First deployment. Visibility phase. "Turn on the lights and see what's hitting your API." |
| `enforce=warn` | Admit all agents. Non-compliant agents receive an ATP warning header (`X-ATP-Warning: 403`) and are flagged in the Trust Ledger. The API MAY handle warned agents differently (reduced permissions, rate limiting, human review queue). | Training wheels. Transition phase. |
| `enforce=strict` | Reject non-compliant agents. Non-compliant agents receive an ATP error response and are not granted access. | Full enforcement. Production security. |

**Design rationale:** DMARC adoption data shows that domains which launched with `p=none` (monitoring) achieved 3x higher eventual adoption of `p=reject` compared to domains that attempted immediate enforcement. Graduated enforcement is an adoption engine, not a weakness.

---

## §XX.2 — Agent Trust Policy (DNS Record Format)

An Agent Trust Policy is a DNS TXT record published at `_aria-policy.<domain>`. It is analogous to a DMARC record at `_dmarc.<domain>`.

**Record format (NORMATIVE):**

```
_aria-policy.bank.com. IN TXT "v=ATP1; min=L2; enforce=strict; req=commerce.*,invoice.*; deny=identity.represent.human; intent=purpose,principal_ref; depth=3; rate=100/hr; qualify=sector:finance>sox; rua=https://bank.com/atp-reports"
```

**Field definitions:**

| Tag | Required | Default | Description |
|-----|----------|---------|-------------|
| `v` | MUST | — | Protocol version. Always `ATP1` for v1.x. |
| `min` | MUST | L0 | Minimum trust level: `L0`, `L1`, `L2`, or `L3`. |
| `enforce` | MUST | monitor | Enforcement mode: `monitor`, `warn`, or `strict`. |
| `req` | MAY | (none) | Required scopes. Comma-separated. Wildcard: `commerce.*` matches any `commerce.<action>`. Hierarchical: `commerce` alone matches all `commerce.*` children. |
| `deny` | MAY | (none) | Prohibited scopes. Agent carrying any listed scope is rejected (in strict mode) or flagged (in monitor/warn mode). |
| `intent` | MAY | (none) | Required intent fields. Comma-separated field names from the Intent Declaration schema. |
| `depth` | MAY | 4 | Maximum delegation chain depth. Integer 0–4. |
| `rate` | MAY | (none) | Per-agent rate limit. Format: `N/hr` or `N/min`. |
| `qualify` | MAY | (none) | Conditional requirements. Format: `condition>requirement`. Multiple conditions separated by comma. |
| `rua` | MAY | (none) | Aggregate report URI. HTTPS endpoint where ATP sends periodic compliance reports. Modeled on DMARC `rua`. |
| `ttl` | MAY | 3600 | Policy cache TTL in seconds. How long agents should cache this policy before re-fetching. |

**DNS size considerations:** A fully specified ATP record is approximately 200–300 bytes. DNS TXT records support up to 255 bytes per string, with multiple strings concatenated. A typical ATP record fits in a single TXT string. Complex policies with many qualifier rules may require string concatenation, which is natively supported by DNS resolvers.

**HTTPS discovery (RECOMMENDED):** In addition to the DNS TXT record, organizations SHOULD publish the same policy as a JSON document at `https://<domain>/.well-known/aria-atp`. This enables faster discovery (no DNS lookup latency) and richer policy expression (JSON supports nested structures). The DNS record remains the canonical source — if the DNS record and the HTTPS endpoint disagree, the DNS record takes precedence.

**Policy inheritance (FUTURE EXTENSION, v2.0):** A policy at `_aria-policy.acme.com` applies to all subdomains unless overridden. Defined in the Future Extensions appendix; not normative in v1.0.

---

## §XX.3 — Transport Bindings

ATP is transport-agnostic. The Declare phase can occur over any protocol. This section defines normative bindings for HTTP and MCP, with informative guidance for A2A.

### HTTP Transport (NORMATIVE)

The agent includes its ATP Declare payload as an HTTP header on the first request:

```
POST /api/v2/invoices/4471 HTTP/1.1
Host: bank.com
Authorization: Bearer <access_token>
X-ARIA-AID: <base64url-encoded signed AID>
X-ARIA-Intent: <base64url-encoded signed intent declaration>
```

The receiving system evaluates the headers against its ATP policy and responds:

**On admission (ATP-200):**
```
HTTP/1.1 200 OK
X-ATP-Result: 200
X-ATP-Receipt: <signed receipt token, optional>
```

**On rejection (ATP-403, strict mode):**
```
HTTP/1.1 403 Forbidden
X-ATP-Result: 403
X-ATP-Reason: trust_level_insufficient
X-ATP-Required: min=L2
X-ATP-Presented: L1
```

**On warning (ATP-403, warn mode):**
```
HTTP/1.1 200 OK
X-ATP-Warning: 403
X-ATP-Reason: trust_level_insufficient
```

### MCP Transport (NORMATIVE)

When an agent connects to an MCP server to invoke a tool, the ATP Declare payload is included as structured metadata in the MCP session initialization or tool invocation:

```json
{
  "method": "tools/call",
  "params": {
    "name": "fetch_invoice",
    "arguments": { "invoice_id": "4471" },
    "aria": {
      "aid": "<signed AID>",
      "intent": "<signed intent declaration>"
    }
  }
}
```

The MCP server evaluates the `aria` metadata against its published ATP policy before executing the tool. If evaluation fails, the server returns an MCP error with the ATP response code in the error data.

**Design note:** This binding extends MCP without breaking it. MCP servers that do not support ARIA ignore the `aria` field. MCP servers that support ARIA evaluate it before tool execution. Backward compatibility is preserved.

### A2A Transport (INFORMATIVE)

Google's Agent-to-Agent Protocol (A2A) defines Agent Cards for discovery. The ARIA-A2A bridge (§17) maps an AID into an Agent Card's verified identity field. For ATP, the intent declaration is included as an extension field in the A2A task request. Full A2A transport binding will be published as a companion specification.

---

## §XX.4 — Response Codes

| Code | Name | Meaning | Trigger |
|------|------|---------|---------|
| ATP-200 | Admitted | Agent passed all policy checks. | All evaluation steps pass. |
| ATP-401 | Credential invalid | AID is revoked, expired, or signature fails verification. | P4 StatusList check or signature verification failure. |
| ATP-403 | Trust insufficient | Agent's trust level is below the policy minimum. | `min=L2` but agent presents L0 or L1. |
| ATP-406 | Scope mismatch | Agent is missing required scopes or carries prohibited scopes. | `req=` not satisfied or `deny=` triggered. |
| ATP-429 | Rate limited | Agent has exceeded the per-agent request cap. | `rate=` exceeded. |
| ATP-451 | Intent incomplete | Agent's intent declaration is missing required fields. | `intent=` fields not present in declaration. |
| ATP-460 | Qualifier missing | Agent meets base requirements but fails a conditional qualifier. | `qualify=` condition triggered, attestation not present. |
| ATP-462 | Delegation too deep | Agent's delegation chain exceeds the policy maximum. | `depth=` exceeded. |

**Response code design rationale:** ATP codes are intentionally modeled on HTTP status codes for developer familiarity. 2xx = success, 4xx = client (agent) error. The specific codes (451, 460, 462) are chosen to avoid collision with standard HTTP codes while remaining in the 4xx family.

---

## §XX.5 — Agent Interaction Log [PLANNED — future extension]

ATP interaction events (declare, admit, reject) will be recorded in the Agent Interaction Log — a separate system from the Trust Ledger. Deferred beyond v1.0 with no committed delivery date. The schema below represents the intended design.

**Trust Record schema for ATP events:**

| Field | Type | Description |
|-------|------|-------------|
| `event_type` | string | `atp:declare`, `atp:admit`, `atp:reject` |
| `timestamp` | ISO 8601 | UTC timestamp of the event |
| `agent_did` | string | The agent's DID |
| `agent_trust_level` | string | L0–L3 at time of interaction |
| `receiver_domain` | string | The domain that published the ATP policy |
| `policy_version` | string | Hash of the ATP policy at time of evaluation |
| `intent_hash` | string | SHA-256 hash of the signed intent declaration |
| `intent_purpose` | string | The `purpose` field from the intent declaration (cleartext for queryability) |
| `result_code` | string | ATP response code (200, 401, 403, etc.) |
| `result_reason` | string | Human-readable reason (e.g., "trust_level_insufficient") |
| `enforcement_mode` | string | The policy's enforcement mode at time of evaluation |
| `chain_hash` | string | SHA-256 hash linking this record to the previous entry |

**Retention:** Interaction events are retained for a minimum of 7 years, consistent with financial regulatory requirements (SOX, MiFID II, GDPR Article 17(3)(e)).

**Queryability:** Trust Records are queryable by agent DID, receiver domain, result code, time range, and trust level. Enterprise subscribers receive real-time webhook notifications for rejection events (ATP-4xx). Aggregate reports are delivered to the `rua=` endpoint on a configurable schedule (daily/weekly/monthly).

**Integrity:** The Trust Ledger is modeled on Certificate Transparency (RFC 9162). Append-only. SHA-256 hash-chained. Every entry is cryptographically linked to its predecessor. Any modification, insertion, or deletion breaks the chain and is detectable by any auditor. The Trust Ledger is not a blockchain — it requires no consensus mechanism, no mining, no gas fees. It is a signed, hash-chained log operated by the ARIA registry and auditable by anyone.

---

## §XX.6 — DMARC Parallel

ATP is designed to follow DMARC's adoption trajectory. The parallel is intentional and structural:

| DMARC | ATP |
|-------|-----|
| Domain publishes `_dmarc.domain.com` TXT record | Domain publishes `_aria-policy.domain.com` TXT record |
| Record specifies email authentication policy | Record specifies agent trust requirements |
| `p=none` (monitor) → `p=quarantine` → `p=reject` | `enforce=monitor` → `enforce=warn` → `enforce=strict` |
| `rua=` sends aggregate reports | `rua=` sends aggregate reports |
| Receiving mail server evaluates sender's DKIM/SPF | Receiving API evaluates agent's AID + intent |
| Failures are logged and optionally rejected | Failures are logged as Trust Records and optionally rejected |
| Adoption reached 80% of major domains over 8 years | Target: 10% of API-publishing organizations within 3 years |

**Key difference:** DMARC authenticates the *sender* of an email. ATP authenticates the *agent* AND evaluates its *declared intent*. ATP is DMARC + a customs form. No email authentication protocol has ever required the sender to declare *why* it's sending the email. ARIA does.

---

## §XX.7 — Scope Matching Rules

ATP policies use wildcard and hierarchical scope matching to keep policy records concise.

**Matching rules (NORMATIVE):**

| Policy `req=` value | Agent scope | Match? |
|---------------------|-------------|--------|
| `commerce.read` | `commerce.read` | Yes — exact match |
| `commerce.*` | `commerce.read` | Yes — wildcard matches any action under namespace |
| `commerce.*` | `commerce.write` | Yes |
| `commerce.*` | `invoice.read` | No — different namespace |
| `commerce` | `commerce.read` | Yes — bare namespace matches all children |
| `commerce` | `commerce.write.bulk` | Yes — matches at any depth |
| `*.read` | `commerce.read` | No — leading wildcards are NOT supported |

**Prohibition matching:** The `deny=` field uses the same matching rules. `deny=identity.*` prohibits any agent carrying any scope in the `identity` namespace.

**Scope conflict resolution:** If a scope matches both `req=` and `deny=`, the denial takes precedence. An agent carrying `commerce.read` against a policy with `req=commerce.*; deny=commerce.read` is rejected (ATP-406). Denials always win.

---

## §XX.8 — Qualifier System

Qualifiers are conditional requirements layered on top of base ATP policy rules. They enable sector-specific and context-specific trust requirements without inflating the base policy.

**Qualifier syntax:** `qualify=<condition>><requirement>`

**Examples:**

| Qualifier | Meaning |
|-----------|---------|
| `qualify=sector:healthcare>iso27001` | If agent declares healthcare scope, must carry ISO 27001 attestation |
| `qualify=sector:finance>sox` | If agent declares finance scope, must carry SOX compliance attestation |
| `qualify=delegation>iso42001` | If agent is delegated (not direct), must carry ISO 42001 attestation |
| `qualify=level:L3>hsm` | If agent claims L3, must prove HSM-bound key (FIPS 140-3 Level 2+) |

**Qualifier evaluation:** Qualifiers are evaluated after all base checks pass. If a qualifier condition matches (the agent meets the left side) and the requirement is not satisfied (the agent lacks the right side), the result is ATP-460 (Qualifier missing).

**Qualifier attestations** are carried as optional fields in the AID (see §05 AID Document, attestations array). The qualifier system does not introduce new credential types — it references attestations already defined in the AID schema.

---

## §XX.9 — Security Considerations

**Replay attacks.** A signed AID + intent payload could be captured and replayed. Mitigation: the `session_id` field in the intent declaration SHOULD include a nonce or timestamp. Receiving systems SHOULD reject intent declarations older than 5 minutes. DPoP (RFC 9449) token binding at P3 (Present) provides additional replay protection.

**Policy spoofing.** An attacker could attempt to publish a false ATP policy for a domain they don't control. Mitigation: ATP policies are DNS TXT records. Publishing a TXT record requires domain control — the same security model that protects DMARC, SPF, and DKIM. DNS hijacking is a DNS infrastructure problem, not an ATP problem.

**Intent lying.** An agent could sign an intent declaration that doesn't match its actual behavior. Mitigation: signed intents will be captured in the Agent Interaction Log (future system) for post-hoc analysis. Intent-drift detection can then identify agents whose declared intent consistently diverges from actual access patterns. This is a detection mechanism, not a prevention mechanism — consistent with ARIA's role as an accountability layer, not an enforcement engine. Until the Agent Interaction Log ships, drift analysis depends on receivers' own request logs.

**Downgrade attacks.** An attacker could strip the ARIA headers from an HTTP request, making the agent appear to be a non-ARIA client. Mitigation: in `enforce=strict` mode, the receiving system rejects requests without ARIA headers entirely. In `enforce=monitor` mode, headerless requests SHOULD be recorded in the receiver's own observability stack (future Agent Interaction Log entries when available), providing visibility even without enforcement.

**DNS caching.** ATP policy changes propagate at DNS TTL speed (default 3600 seconds / 1 hour). During the TTL window, agents may evaluate against a stale policy. Mitigation: the `ttl=` field allows organizations to set shorter TTLs for policies that change frequently. The `/.well-known/aria-atp` HTTPS endpoint provides an immediate-update path for time-sensitive changes.

---

## §XX.10 — Relationship to Other ARIA Sections

ATP is not a layer in the P1–P6 protocol stack. It is a protocol that **traverses** the stack:

| ATP Phase | Protocol Layers Used |
|-----------|---------------------|
| Declare | P1 (Anchor — DID resolution), P2 (Certify — credential verification), P3 (Present — credential presentation + DPoP binding) |
| Evaluate | P4 (Protect — revocation check via StatusList) |
| Admit | Trust Ledger (logging), P5 (Revoke — lifecycle checks, expiry, orphaned principal detection) |

**Sections absorbed into ATP:**
- §11 (Intent Architecture) → ATP §XX.1, Phase 1 (Intent Declaration schema and signing requirements)
- §18 (Counterparty Policy Declaration / CPD) → ATP §XX.2 (Agent Trust Policy DNS record format)

**Sections that reference ATP:**
- §09 (MCP Integration) — now references ATP MCP transport binding
- §12 (Revocation & Transparency) — Trust Ledger terminology updated; ATP event types added
- §17 (A2A Identity Bridge) — now references ATP A2A transport binding
- §22 (Auditing & Non-Repudiation) — Trust Records are the primary audit artifact

---

## §XX.11 — Glossary Updates

| Old Term | New Term | Definition |
|----------|----------|------------|
| Credential Transparency Log (CTL) | **Trust Ledger** (TL) | The append-only, hash-chained system that records every ARIA and ATP event. The system. |
| (new) | **Trust Record** (TR) | A single entry in the Trust Ledger. One interaction, one audit entry. The evidence. |
| Counterparty Policy Declaration (CPD) | **Agent Trust Policy** | The DNS TXT record at `_aria-policy.*` that defines an organization's agent admission requirements. |
| (new) | **Agent Trust Protocol** (ATP) | The three-phase handshake (Declare, Evaluate, Admit) between an agent and a receiving system. |
| Intent Architecture | (absorbed into ATP §XX.1) | The intent declaration is now Phase 1 of the ATP handshake, not a standalone section. |
