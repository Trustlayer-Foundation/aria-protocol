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
