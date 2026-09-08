# ARIA Protocol Specification v1.1

> **Superseded — public preview.** This text belongs to the preview line (labeled 1.0–1.2,
> April–August 2026, no production adoption). The stable specification is **ARIA 1.0**
> (September 7, 2026) at [aria.bar/spec](https://aria.bar/spec); see [`../README.md`](../README.md).
> Kept verbatim for verifiers of preview credentials.

> **Status:** Published — April 1, 2026 (v1.0). Schema clarified to v1.1 — April 28, 2026.
> **Canonical version:** [aria.bar/spec](https://aria.bar/spec)
> **Filed with NIST:** March 9, 2026 (NIST-2025-0035)
>
> **What changed in v1.1** (see [CHANGELOG](../CHANGELOG.md) for detail):
> - `principal.verificationStatus` is now a required, machine-readable enum on the AID
>   (`self-declared` / `registry-confirmed` / `legal-verified`) so a verifier can act
>   on identity provenance without interpreting trustLevel separately.
> - The W3C VC top-level `id` is now a unique credential-instance URL per W3C VC 2.0 §4.4
>   — equivalent to a TLS certificate serial number. The agent DID continues to live in
>   `credentialSubject.id`.
> - `credentialSubject.previousCredentialId` (optional) chains issuances explicitly.

This document provides an overview of the ARIA Protocol specification.
The full interactive specification is available at [aria.bar/spec](https://aria.bar/spec).

## Table of contents

| § | Section | Description |
|---|---------|-------------|
| 00 | Why This Exists | The problem of unverified AI agents |
| 01 | The Protocol | Six-layer architecture (P1–P6) |
| 02 | Trust Levels | L0 Anchored → L3 Sovereign |
| 03 | DID Method | did:aria — DNS-anchored resolution |
| 04 | AID Document | W3C Verifiable Credential format |
| 05 | Agent Trust Protocol | ATP — Declare, Evaluate, Admit |
| 06 | Scope Registry | namespace:resource:action + 8 immutable actions |
| 07 | Delegation & HITL | Max 4 hops, human-in-the-loop tiers |
| 08 | Credential Lifecycle | 6 states: active → tombstoned |
| 09 | Revocation & Trust Ledger | StatusList 2021 + hash-chained lifecycle log |
| 10 | Post-Quantum Cryptography | ML-DSA-65 + Ed25519 composite AND |
| 11 | Authentication & Key Recovery | Multi-factor, successor principal |
| 12 | MCP Integration | Tool-based agent identity |
| 13 | Enterprise Integration | SCIM, OIDC, AuthZEN bridges |
| 14 | Commerce Integration | Visa TAP, Stripe ACP, x402 |
| 15 | A2A Identity Bridge | Google A2A Agent Card mapping |
| 16 | Integration Map | 20+ protocol integrations |
| 17 | Compliance Rosetta Stone | NIST, EU AI Act, Colorado AI Act, HIPAA mapping |
| 18 | Security Architecture | Threat model and mitigations |
| 19 | Prompt Injection Defense | Scope containment, delegation ceiling |
| 20 | Audit & Non-Repudiation | Trust Records, delegation chain snapshots |
| 21 | Privacy & Data Governance | W3C DPV, GDPR alignment |
| 22 | Offline & QR Verification | Self-contained credential verification |
| 23 | Versioning & Compatibility | Semantic versioning, migration paths |
| 24 | Advanced Patterns | Multi-principal, model provenance, robotics |
| 25 | Governance | TrustLayer Foundation, TSC, anti-capture |
| 26 | Trust Seals | Sector, Compliance, Capability attestations |

## Read the full spec

The complete specification with interactive navigation, code examples, and integration details is available at:

**[aria.bar/spec](https://aria.bar/spec)**

## Implementation status

| Component | Status | URL |
|-----------|--------|-----|
| ARIA Registry (platform) | Live | [registry.aria.bar](https://registry.aria.bar) |
| ARIA API (public, read-only) | Live | [api.aria.bar](https://api.aria.bar) |
| ARIA Core (backend) | Live | core.aria.bar (internal) |
| SDK (TypeScript) | Published | [@aria-registry/verify](https://npmjs.com/package/@aria-registry/verify) |
| SDK (Python) | Planned | Q2 2026 |
| SDK (Go) | Planned | Q2 2026 |
| ATP — evaluation engine | Live | 6/7 checks implemented |
| ATP — intent declaration | Live | Completeness check (signed intent = Phase 3) |
| ATP — qualifier system | Planned | [NOT YET IMPLEMENTED] |
| Agent Interaction Log | Designed | [PLANNED — future system] |
