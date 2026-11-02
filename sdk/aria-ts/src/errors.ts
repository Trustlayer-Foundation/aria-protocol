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
