import Ajv2020 from 'ajv/dist/2020.js';
import addFormatsModule from 'ajv-formats';
import schema from './aid-1.0.schema.json' with { type: 'json' };

// A byte-identical copy of `schema/aid-1.0.json`; a test compares the two.
const addFormats = ((addFormatsModule as unknown as { default?: typeof addFormatsModule }).default ?? addFormatsModule);
const ajv = new Ajv2020({ strict: false, allErrors: false });
addFormats(ajv);
const validate = ajv.compile(schema);

/** `null` when `document` conforms to the ARIA 1.0 AID schema; otherwise the JSON pointer of the first failure. */
export function schemaFailure(document: unknown): string | null {
  if (validate(document)) return null;
  const first = validate.errors?.[0];
  return first ? first.instancePath || '/' : '/';
}
