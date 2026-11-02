// Before, with @aria-registry/verify 1.x:
//
//   const result = verifyAgent(credential, { policy: { requiredScopes: ['payments:transfer:create'] } });
//   if (result.valid) execute();
//
// `valid` could be true with the signature check skipped, the requested policy
// failed, the status never checked, and nobody proving the holder key. It is not
// a decision to run anything. After: the decision is the admission, and only `allow` runs.
import type { Ap, HttpRequestLike, OperationDescriptor, PresentationContext } from '@trustlayer-foundation/aria-ap';
import type { Verifier } from '@trustlayer-foundation/aria-sdk';

declare const verifier: Verifier; // @trustlayer-foundation/aria-sdk: credential and status
declare const ap: Ap; // @trustlayer-foundation/aria-ap: createAp({ credentials: verifier })
declare const context: PresentationContext;
declare const operation: OperationDescriptor;
declare function execute(): Promise<void>;

export async function guarded(request: HttpRequestLike): Promise<number> {
  const presented = await ap.verifyPresentation(request, { ...context, operations: [operation] });
  if (!presented.ok) return presented.status;

  const status = await verifier.checkStatus(presented.presentation.credential);
  const admission = await ap.admit({
    presentation: presented.presentation,
    status,
    authorize: async () => ({ allowed: true }),
  });
  if (admission.decision !== 'allow') return admission.refusal.status;

  await execute();
  return 200;
}
