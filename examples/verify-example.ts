/**
 * ARIA Protocol — Agent Verification Example
 *
 * Demonstrates how to use the @aria-registry/verify SDK to:
 *   1. Resolve an agent's AID from the ARIA API
 *   2. Verify the AID offline (signature, expiry, revocation)
 *   3. Evaluate the agent against a local ATP policy
 *
 * @aria-registry/verify is the official TypeScript SDK for ARIA verification.
 * It performs all cryptographic operations locally — no network calls are
 * required after the initial AID fetch and StatusList cache.
 *
 * ARIA Protocol v1.0
 */

import {
  verifyAgent,
  resolveAID,
  evaluatePolicy,
  PolicyLevel,
  type AID,
  type VerificationResult,
  type PolicyEvaluation,
  type ATPPolicy,
  type IntentDeclaration,
} from '@aria-registry/verify';

// ---------------------------------------------------------------------------
// Example 1: Basic agent verification
// ---------------------------------------------------------------------------

async function basicVerification(): Promise<void> {
  const agentDID = 'did:aria:aria.bar:u-cmDoHhM3:ordering-agent';

  // Resolve the AID from the ARIA public API (api.aria.bar).
  // This fetches the full AID document including the composite proof.
  const aid: AID = await resolveAID(agentDID);

  // Verify the AID offline. This performs:
  //   - Composite signature verification (ML-DSA-65 + Ed25519)
  //   - Credential expiry check (validFrom / validUntil)
  //   - Revocation check via cached W3C Bitstring StatusList
  //   - DNS anchor integrity check (SHA-256 hash comparison)
  const result: VerificationResult = await verifyAgent(aid);

  if (result.valid) {
    console.log(`Agent verified: ${aid.credentialSubject.agentName}`);
    console.log(`Trust level: ${aid.credentialSubject.trustLevel}`);
    console.log(`Scopes: ${aid.credentialSubject.scope.join(', ')}`);
    console.log(`Issuer: ${aid.issuer}`);
    console.log(`Valid until: ${aid.validUntil}`);
  } else {
    console.error(`Verification failed: ${result.reason}`);
    // result.reason is one of:
    //   'signature_invalid' — composite proof did not verify
    //   'expired'           — credential past validUntil
    //   'revoked'           — bit set in StatusList
    //   'dns_mismatch'      — DNS anchor hash does not match AID
    //   'not_yet_valid'     — current time before validFrom
  }
}

// ---------------------------------------------------------------------------
// Example 2: Policy evaluation with ATP
// ---------------------------------------------------------------------------

async function policyEvaluation(): Promise<void> {
  const agentDID = 'did:aria:aria.bar:u-cmDoHhM3:ordering-agent';
  const aid: AID = await resolveAID(agentDID);

  // Define the local ATP policy (this would typically be parsed from your
  // DNS TXT record at _aria-policy.<your-domain> or loaded from config).
  const policy: ATPPolicy = {
    v: 'ATP1',
    min: PolicyLevel.L1,
    enforce: 'strict',
    req: ['commerce.*'],
    deny: ['identity.represent.human'],
    intent: ['purpose', 'principal_ref'],
    depth: 3,
    rate: '100/hr',
  };

  // The intent declaration from the incoming agent request.
  // In production, this arrives as a signed payload in the X-ARIA-Intent
  // header (HTTP) or the aria.intent field (MCP).
  const intent: IntentDeclaration = {
    purpose: 'Retrieve product catalog for quarterly procurement planning',
    principal_ref: 'did:aria:acme.bar:org',
    action_requested: 'commerce.read',
    target_resource: 'api/v2/catalog',
    dataUsage: ['dpv:ServiceProvision'],
    retention: 'P90D',
  };

  // Evaluate the agent + intent against the policy.
  // This is a local, deterministic evaluation — no network calls.
  const evaluation: PolicyEvaluation = evaluatePolicy(aid, intent, policy);

  switch (evaluation.code) {
    case 200:
      // ATP-200: Agent admitted
      console.log('Agent admitted');
      console.log(`Trust level: ${evaluation.presentedLevel} (required: ${evaluation.requiredLevel})`);
      break;

    case 401:
      // ATP-401: Credential invalid (signature, expired, revoked)
      console.error(`Credential invalid: ${evaluation.reason}`);
      break;

    case 403:
      // ATP-403: Trust level insufficient
      console.error(`Trust level insufficient: presented ${evaluation.presentedLevel}, required ${evaluation.requiredLevel}`);
      break;

    case 406:
      // ATP-406: Prohibited scope detected
      console.error(`Denied scope detected: ${evaluation.deniedScopes?.join(', ')}`);
      break;

    case 429:
      // ATP-429: Rate limit exceeded
      console.error(`Rate limit exceeded: ${evaluation.rateLimit}`);
      break;

    case 451:
      // ATP-451: Intent fields incomplete
      console.error(`Missing intent fields: ${evaluation.missingFields?.join(', ')}`);
      break;

    case 460:
      // ATP-460: Qualifier condition not met
      console.error(`Qualifier failed: ${evaluation.failedQualifier}`);
      break;

    case 462:
      // ATP-462: Delegation depth exceeded
      console.error(`Delegation depth ${evaluation.presentedDepth} exceeds limit ${evaluation.maxDepth}`);
      break;

    default:
      console.error(`Unknown ATP code: ${evaluation.code}`);
  }
}

// ---------------------------------------------------------------------------
// Example 3: Middleware integration (Express/Hono-style)
// ---------------------------------------------------------------------------

/**
 * ATP middleware for HTTP servers.
 *
 * Extracts the AID and intent from request headers, verifies the agent,
 * evaluates the policy, and either admits or rejects the request based
 * on the enforcement mode.
 */
async function atpMiddleware(
  req: { headers: Record<string, string> },
  res: { setHeader: (k: string, v: string) => void; status: (code: number) => { json: (body: unknown) => void } },
  next: () => void,
  policy: ATPPolicy,
): Promise<void> {
  const aidHeader = req.headers['x-aria-aid'];
  const intentHeader = req.headers['x-aria-intent'];

  // If no ARIA headers, skip ATP evaluation (agent is unidentified).
  if (!aidHeader) {
    if (policy.enforce === 'strict') {
      res.setHeader('X-ATP-Result', '401');
      res.status(401).json({ error: 'ARIA credentials required' });
      return;
    }
    next();
    return;
  }

  // Decode and verify the AID.
  const aid: AID = JSON.parse(Buffer.from(aidHeader, 'base64url').toString());
  const verification = await verifyAgent(aid);

  if (!verification.valid) {
    res.setHeader('X-ATP-Result', '401');
    res.setHeader('X-ATP-Reason', verification.reason);
    res.status(401).json({ error: 'AID verification failed', reason: verification.reason });
    return;
  }

  // Decode intent (if present).
  const intent: IntentDeclaration | undefined = intentHeader
    ? JSON.parse(Buffer.from(intentHeader, 'base64url').toString())
    : undefined;

  // Evaluate against policy.
  const evaluation = evaluatePolicy(aid, intent, policy);

  if (evaluation.code === 200) {
    res.setHeader('X-ATP-Result', '200');
    next();
    return;
  }

  // Handle non-200 based on enforcement mode.
  if (policy.enforce === 'strict') {
    res.setHeader('X-ATP-Result', String(evaluation.code));
    res.setHeader('X-ATP-Reason', evaluation.reason ?? 'policy_violation');
    res.status(evaluation.code === 429 ? 429 : 403).json({
      error: 'ATP policy violation',
      code: evaluation.code,
      reason: evaluation.reason,
    });
    return;
  }

  if (policy.enforce === 'warn') {
    res.setHeader('X-ATP-Warning', String(evaluation.code));
    res.setHeader('X-ATP-Reason', evaluation.reason ?? 'policy_violation');
  }

  // In monitor or warn mode, admit the agent regardless.
  next();
}

// ---------------------------------------------------------------------------
// Run examples
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  console.log('--- Basic Verification ---');
  await basicVerification();

  console.log('\n--- Policy Evaluation ---');
  await policyEvaluation();
}

main().catch(console.error);
