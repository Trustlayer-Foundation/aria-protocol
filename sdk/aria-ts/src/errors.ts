/** Raised by every entry point whose behavior a later increment implements. */
export class NotYetImplemented extends Error {
  constructor(readonly increment: 'AP2') {
    super(`not implemented before ${increment}`);
    this.name = 'NotYetImplemented';
  }
}

/**
 * A value that this verifier did not produce was passed where one of its results
 * is required: a copy, an altered object, a result of another verifier, or a
 * hand-made one. A programming error, never a verification outcome.
 */
export class AriaUsageError extends TypeError {
  constructor(message: string) {
    super(message);
    this.name = 'AriaUsageError';
  }
}

export function pending(increment: 'AP2'): never {
  throw new NotYetImplemented(increment);
}
