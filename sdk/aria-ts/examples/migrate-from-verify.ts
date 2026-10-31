// Before, with @aria-registry/verify 1.x:
//
//   const result = verifyAgent(credential, { policy: { requiredScopes: ['payments:transfer:create'] } });
//   if (result.valid) execute();
//
// `valid` could be true with the signature check skipped, the requested policy
// failed, the status never checked, and nobody proving the holder key. It is not
// a decision to run anything. After: the decision is the admission, and only `allow` runs.
import type { HttpRequestLike, OperationDescriptor, PresentationContext, Verifier } from '@aria-registry/sdk';

declare const verifier: Verifier;
declare const context: PresentationContext;
declare const operation: OperationDescriptor;
declare function execute(): Promise<void>;

export async function guarded(request: HttpRequestLike): Promise<number> {
  const presented = await verifier.verifyPresentation(request, { ...context, operations: [operation] });
  if (!presented.ok) return presented.status;

  const status = await verifier.checkStatus(presented.presentation.credential);
  const admission = await verifier.admit({
    presentation: presented.presentation,
    status,
    authorize: async () => ({ allowed: true }),
  });
  if (admission.decision !== 'allow') return admission.refusal.status;

  await execute();
  return 200;
}
