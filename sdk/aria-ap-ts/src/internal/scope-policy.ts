import { AriaUsageError } from '@aria-registry/sdk';
import type { ScopeRule } from '../admission';

// The receiver's scope policy (D5, provisional): patterns are three-segment scopes, or
// two segments followed by `:*`. Credential scopes are never patterns; they compare exactly.

const SEGMENT = '[a-z][a-z0-9_]*';
const SCOPE = new RegExp(`^${SEGMENT}:${SEGMENT}:${SEGMENT}$`);
const PATTERN = new RegExp(`^${SEGMENT}:${SEGMENT}:(?:${SEGMENT}|\\*)$`);

/** A frozen copy of the receiver's rules, or `null` without a policy; a rule outside the grammar is a usage error. */
export function scopePolicyOf(rules: unknown): readonly ScopeRule[] | null {
  if (rules === undefined) return null;
  if (!Array.isArray(rules)) throw new AriaUsageError('a scope policy is a list of rules');
  return Object.freeze(
    rules.map((r: unknown) => {
      const { effect, pattern } = (typeof r === 'object' && r !== null ? r : {}) as Record<string, unknown>;
      if ((effect !== 'allow' && effect !== 'deny') || typeof pattern !== 'string' || !PATTERN.test(pattern)) {
        throw new AriaUsageError('a scope rule is { effect: allow | deny, pattern: namespace:resource:action or namespace:resource:* }');
      }
      return Object.freeze({ effect, pattern });
    }),
  );
}

/** Whether the policy admits `scope`: a matching deny wins, otherwise a matching allow is needed. */
export function scopeAllowed(rules: readonly ScopeRule[], scope: string): boolean {
  const matches = (p: string) => (p.endsWith(':*') ? SCOPE.test(scope) && scope.startsWith(p.slice(0, -1)) : p === scope);
  if (rules.some((r) => r.effect === 'deny' && matches(r.pattern))) return false;
  return rules.some((r) => r.effect === 'allow' && matches(r.pattern));
}
