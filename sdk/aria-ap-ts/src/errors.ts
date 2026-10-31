/** Raised by every entry point whose behavior a later increment implements. */
export class NotYetImplemented extends Error {
  constructor(readonly increment: 'AP2') {
    super(`not implemented before ${increment}`);
    this.name = 'NotYetImplemented';
  }
}

export function pending(increment: 'AP2'): never {
  throw new NotYetImplemented(increment);
}
