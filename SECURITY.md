# Security Policy

## Reporting a vulnerability

If you discover a security vulnerability in the ARIA Protocol specification, SDK, or infrastructure, please report it responsibly.

**Email:** security@trustlayer.foundation

**Response SLA:**
- Acknowledgment within 48 hours
- Initial assessment within 7 business days
- Fix timeline communicated within 14 business days

**Scope:**
- ARIA Protocol specification (this repo)
- @aria-registry/verify SDK
- api.aria.bar public API
- registry.aria.bar platform

**Out of scope:**
- Third-party implementations of ARIA
- Social engineering attacks
- Denial of service

## Cryptographic considerations

ARIA uses ML-DSA-65 (FIPS 204) + Ed25519 (RFC 8032) in composite AND mode. The @noble/post-quantum library used by the SDK has not yet received an independent security audit for its ML-DSA implementation. The Noble hash and curve libraries (used internally) have been audited by Trail of Bits, Kudelski Security, and Cure53.

TrustLayer Foundation plans to co-finance an audit of @noble/post-quantum's ML-DSA implementation. See the SDK README for current audit status.

## Responsible disclosure

We follow coordinated disclosure. Please do not open public issues for security vulnerabilities. Use the email above.

Emergency security fixes are applied immediately, with a 30-day retroactive public comment period. The TSC ratifies all emergency fixes.
