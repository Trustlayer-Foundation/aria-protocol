import { AriaUsageError, type Did } from '@aria-registry/sdk';
import { randomToken } from './internal/bytes';
import type { ChallengeStore } from './presentation';

/**
 * The reference `ChallengeStore`, in memory: the demo's and the tests'. Checking
 * and consuming happen in one synchronous step, so within one process a challenge
 * is consumed once. Nothing survives a restart or is shared between processes.
 */
export class MemoryChallengeStore implements ChallengeStore {
  readonly #challenges = new Map<string, { readonly audience: Did; readonly expires: number }>();
  readonly #clock: () => Date;

  constructor(clock: () => Date = () => new Date()) {
    this.#clock = clock;
  }

  async issue(audience: Did, ttlSeconds: number): Promise<string> {
    if (!Number.isInteger(ttlSeconds) || ttlSeconds < 1 || ttlSeconds > 60) throw new AriaUsageError('a challenge lives between 1 and 60 seconds');
    const now = this.#clock().getTime();
    for (const [c, entry] of this.#challenges) if (entry.expires <= now) this.#challenges.delete(c);
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
