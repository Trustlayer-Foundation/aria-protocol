import { fromBase64, toBase64 } from './bytes';

// Structured Field Values (RFC 8941), the subset the ARIA AP profile uses: items,
// inner lists and dictionaries of strings, tokens, integers, byte sequences and
// booleans, with parameters. Stricter than the RFC where it would merge: a
// repeated dictionary key or parameter is refused instead of overwritten, and
// decimals are refused (the profile has none). Every parser throws `SfError`.

export class Token {
  constructor(readonly value: string) {}
}

export type BareItem = string | Token | number | boolean | Uint8Array;
export type Params = ReadonlyMap<string, BareItem>;
export type Item = readonly [BareItem, Params];
export type InnerList = readonly [readonly Item[], Params];
export type Member = Item | InnerList;

export class SfError extends Error {}

const KEY = /^[a-z*][a-z0-9_.*-]*/;
const TOKEN = /^[A-Za-z*][!#$%&'*+\-.^_`|~0-9A-Za-z:/]*/;

class Reader {
  at = 0;
  constructor(readonly text: string) {}
  get rest(): string {
    return this.text.slice(this.at);
  }
  peek(): string | undefined {
    return this.text[this.at];
  }
  fail(why: string): never {
    throw new SfError(`${why} at ${this.at}`);
  }
  spaces(): void {
    while (this.peek() === ' ') this.at++;
  }
  ows(): void {
    while (this.peek() === ' ' || this.peek() === '\t') this.at++;
  }
  done(): void {
    this.spaces();
    if (this.at !== this.text.length) this.fail('trailing characters');
  }
}

function key(r: Reader): string {
  const m = KEY.exec(r.rest);
  if (!m) return r.fail('key');
  r.at += m[0].length;
  return m[0];
}

function bareItem(r: Reader): BareItem {
  const c = r.peek();
  if (c === '-' || (c !== undefined && c >= '0' && c <= '9')) {
    const m = /^-?[0-9]{1,15}/.exec(r.rest);
    if (!m) return r.fail('integer');
    r.at += m[0].length;
    if (r.peek() === '.') r.fail('decimals are not used');
    return Number(m[0]);
  }
  if (c === '"') {
    r.at++;
    let out = '';
    for (;;) {
      const ch = r.peek();
      if (ch === undefined) return r.fail('unterminated string');
      r.at++;
      if (ch === '"') return out;
      if (ch === '\\') {
        const next = r.peek();
        if (next !== '"' && next !== '\\') r.fail('escape');
        out += next;
        r.at++;
        continue;
      }
      const code = ch.charCodeAt(0);
      if (code < 0x20 || code > 0x7e) r.fail('string character');
      out += ch;
    }
  }
  if (c === ':') {
    const end = r.text.indexOf(':', r.at + 1);
    if (end < 0) return r.fail('unterminated byte sequence');
    const bytes = fromBase64(r.text.slice(r.at + 1, end));
    if (!bytes) return r.fail('byte sequence');
    r.at = end + 1;
    return bytes;
  }
  if (c === '?') {
    const v = r.text[r.at + 1];
    if (v !== '0' && v !== '1') return r.fail('boolean');
    r.at += 2;
    return v === '1';
  }
  const m = TOKEN.exec(r.rest);
  if (!m) return r.fail('item');
  r.at += m[0].length;
  return new Token(m[0]);
}

function params(r: Reader): Params {
  const out = new Map<string, BareItem>();
  while (r.peek() === ';') {
    r.at++;
    r.spaces();
    const k = key(r);
    if (out.has(k)) r.fail('repeated parameter');
    let value: BareItem = true;
    if (r.peek() === '=') {
      r.at++;
      value = bareItem(r);
    }
    out.set(k, value);
  }
  return out;
}

function item(r: Reader): Item {
  const value = bareItem(r);
  return [value, params(r)];
}

function member(r: Reader): Member {
  if (r.peek() !== '(') return item(r);
  r.at++;
  const items: Item[] = [];
  for (;;) {
    r.spaces();
    if (r.peek() === ')') {
      r.at++;
      return [items, params(r)];
    }
    items.push(item(r));
    const next = r.peek();
    if (next !== ' ' && next !== ')') r.fail('inner list');
  }
}

export function parseItem(text: string): Item {
  const r = new Reader(text);
  r.spaces();
  const out = item(r);
  r.done();
  return out;
}

export function parseDictionary(text: string): ReadonlyMap<string, Member> {
  const r = new Reader(text);
  const out = new Map<string, Member>();
  r.spaces();
  while (r.at < text.length) {
    const k = key(r);
    if (out.has(k)) r.fail('repeated key');
    if (r.peek() === '=') {
      r.at++;
      out.set(k, member(r));
    } else {
      out.set(k, [true, params(r)]);
    }
    r.ows();
    if (r.at === text.length) break;
    if (r.peek() !== ',') r.fail('dictionary');
    r.at++;
    r.ows();
    if (r.at === text.length) r.fail('trailing comma');
  }
  return out;
}

export const isInnerList = (m: Member): m is InnerList => Array.isArray(m[0]);

/** The string an item holds when it is a plain sf-string without parameters, else `null`. */
export function sfStringOf(text: string): string | null {
  try {
    const [value, p] = parseItem(text);
    return typeof value === 'string' && p.size === 0 ? value : null;
  } catch {
    return null;
  }
}

export function serializeBare(value: BareItem): string {
  if (typeof value === 'string') {
    if (!/^[\x20-\x7e]*$/.test(value)) throw new SfError('string character');
    return `"${value.replace(/[\\"]/g, (c) => `\\${c}`)}"`;
  }
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) throw new SfError('integer');
    return String(value);
  }
  if (typeof value === 'boolean') return value ? '?1' : '?0';
  if (value instanceof Uint8Array) return `:${toBase64(value)}:`;
  return value.value;
}

export function serializeParams(p: Params): string {
  return [...p].map(([k, v]) => (v === true ? `;${k}` : `;${k}=${serializeBare(v)}`)).join('');
}

export const serializeItem = ([value, p]: Item): string => serializeBare(value) + serializeParams(p);

export const serializeInnerList = ([items, p]: InnerList): string => `(${items.map(serializeItem).join(' ')})${serializeParams(p)}`;
