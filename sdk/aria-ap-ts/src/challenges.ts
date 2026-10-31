import { AriaUsageError, type Did } from '@aria-registry/sdk';
import { randomToken } from './internal/bytes';
import type { ChallengeStore } from './presentation';

/**
 * The reference `ChallengeStore`, in memory: the demo's and the tests'. Checking
 * and consuming happen in one synchronous step, so within one process a challenge
 * is consumed once. Nothing survives a restart or is shared between processes.
 * The identity endpoint that issues challenges is anonymous: rate-limit it; this
 * store refuses to hold more than `maxLive` live challenges.
 */
export class MemoryChallengeStore implements ChallengeStore {
  readonly #challenges = new Map<string, { readonly audience: Did; readonly expires: number }>();
  readonly #clock: () => Date;
  readonly #maxLive: number;

  constructor(clock: () => Date = () => new Date(), options: { readonly maxLive?: number } = {}) {
    this.#clock = clock;
    this.#maxLive = options.maxLive ?? 10_000;
  }

  async issue(audience: Did, ttlSeconds: number): Promise<string> {
    if (!Number.isInteger(ttlSeconds) || ttlSeconds < 1 || ttlSeconds > 60) throw new AriaUsageError('a challenge lives between 1 and 60 seconds');
    const now = this.#clock().getTime();
    for (const [c, entry] of this.#challenges) if (entry.expires <= now) this.#challenges.delete(c);
    if (this.#challenges.size >= this.#maxLive) throw new AriaUsageError('too many live challenges: rate-limit the identity endpoint');
    const challenge = randomToken(16);
    this.#challenges.set(challenge, { audience, expires: now + ttlSeconds * 1000 });
    return challenge;
  }

  async live(challenge: string, audience: Did): Promise<boolean> {
    return this.#live(challenge, audience);
  }

  async consume(challenge: string, audience: Did): Promise<boolean> {
    if (!this.#live(challenge, audience)) return false;
    this.#challenges.delete(challenge);
    return true;
  }

  #live(challenge: string, audience: Did): boolean {
    const entry = this.#challenges.get(challenge);
    return entry !== undefined && entry.audience === audience && entry.expires > this.#clock().getTime();
  }
}
