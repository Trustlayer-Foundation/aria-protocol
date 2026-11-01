// The schema example of the ARIA AP API contract, exactly; check-pair runs it
// against the installed packages through ap-exchange.mjs.
import Ajv2020 from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';
import aid from '@trustlayer-foundation/aria-sdk/schemas/aid-1.0.json' with { type: 'json' };
import receipt from '@trustlayer-foundation/aria-ap/schemas/aria-ap-receipt-1.json' with { type: 'json' };
import identity from '@trustlayer-foundation/aria-ap/schemas/aria-ap-identity-1.json' with { type: 'json' };
import lookup from '@trustlayer-foundation/aria-ap/schemas/aria-ap-lookup-1.json' with { type: 'json' };

const ajv = new Ajv2020();
ajv.addKeyword('_comment'); // annotations in aid-1.0.json, not validation keywords
ajv.addKeyword('_status');
addFormats(ajv); // the instants are date-time: formats must be asserted
ajv.addSchema([aid, receipt]);

export const validReceipt = ajv.getSchema(receipt.$id);
export const validIdentity = ajv.compile(identity);
export const validLookup = ajv.compile(lookup);
