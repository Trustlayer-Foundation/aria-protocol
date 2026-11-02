/** A claim this worker held was settled, released or taken by another: stop, and roll back whatever this worker started. */
export class StaleClaim extends Error {
  constructor() {
    super('the operation is no longer claimed by this worker');
    this.name = 'StaleClaim';
  }
}

/** The adopter's record of an effect contradicts the operation's record: an effect and its outcome commit together, so one cannot exist without the other. */
export class InvariantViolation extends Error {
  constructor(detail: string) {
    super(`operation record and effect disagree: ${detail}`);
    this.name = 'InvariantViolation';
  }
}

/**
 * An admission, or a lookup admission, no longer authorizes new work: its request's
 * signature window has ended (`deadline`), or the credential no longer stands
 * (`standing`, with the status and code to answer). Admit a fresh attempt.
 */
export class AdmissionExpired extends Error {
  constructor(
    readonly why: 'deadline' | 'standing',
    readonly status?: 403 | 503,
    readonly code?: string,
  ) {
    super(why === 'deadline' ? 'the admission outlived its request' : `the credential no longer stands (${code})`);
    this.name = 'AdmissionExpired';
  }
}
