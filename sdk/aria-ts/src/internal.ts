/**
 * Values only the SDK creates carry this key, which the package does not export:
 * a consumer cannot type one by hand, and S1 checks it again at run time, since a
 * cast is not a security boundary.
 */
export const issued: unique symbol = Symbol('aria.issued');

/** Raised by every entry point whose behavior a later increment implements. */
export class NotYetImplemented extends Error {
  constructor(readonly increment: 'S1' | 'AP2') {
    super(`not implemented before ${increment}`);
    this.name = 'NotYetImplemented';
  }
}

export function pending(increment: 'S1' | 'AP2'): never {
  throw new NotYetImplemented(increment);
}
