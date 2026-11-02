// Reference model of the ARIA AP operation rules, for vectors/sequences.json.
//
// It is the smallest state machine that satisfies the sequences, not the SDK: receiver
// challenges, the operation record with compare-and-set claims, the two receipt sources,
// retrieval, and the client's operation state. AP2 runs the same sequences through an
// adapter exposing `step(step) → { result, client }`.
//
// `mutant` switches on one deliberate defect; check.mjs requires every mutant to fail at
// least one sequence, so the sequences are shown to detect it.

const HTTP = {
  'aria.audience_mismatch': 403,
  'aria.credential_expired': 403,
  'aria.credential_revoked': 403,
  'aria.credential_superseded': 403,
  'aria.level_insufficient': 403,
  'aria.scope_missing': 403,
  'aria.approval_required': 403,
  'aria.approval_invalid': 403,
  'aria.delegation_unsupported': 403,
  'aria.status_unavailable': 503,
};
const OUTCOME = {
  completed: { http: 201, code: 'aria.completed' },
  accepted: { http: 202, code: 'aria.accepted' },
};

export const MUTANTS = [
  'admission-completes',
  'deny-claims',
  'no-fingerprint',
  'challenge-reuse',
  'uncertain-releases',
  'no-cas',
  'resume-twice',
  'reconcile-regenerates',
  'reconcile-unmarked',
  'reconcile-unassured',
  'stale-observation',
  'lookup-revoked',
  'attempt-refusal-moves',
  'accepted-downgrades',
];

export function createReference({ issued = [], mutant = null } = {}) {
  const challenges = { issued: new Set(issued), consumed: new Set() };
  const records = new Map();
  // Effects that reached the world, counted when they happen, apart from the record.
  const effects = new Map();
  const effected = (operation) => effects.set(operation, (effects.get(operation) ?? 0) + 1);
  const receipts = new Map();
  const attempts = new Map();
  const clients = new Map();

  const is = (name) => mutant === name;
  const refusal = (code, http = HTTP[code] ?? 409) => ({ http, receipt: { state: 'rejected', applies: 'attempt', code } });
  const unauthenticated = { http: 401, code: 'aria.authentication_failed', subtype: 'challenge' };

  function consume(label) {
    if (!challenges.issued.has(label) || challenges.consumed.has(label)) return false;
    if (!is('challenge-reuse')) challenges.consumed.add(label);
    return true;
  }

  function governing(record) {
    const list = record.receipts.map((label) => receipts.get(label));
    const terminal = list.filter((r) => r.state !== 'accepted');
    return (terminal[0] ?? list.at(-1))?.label ?? null;
  }

  function newReceipt(operation, label, outcome) {
    const state = typeof outcome === 'string' ? outcome : 'rejected';
    const { http, code } = OUTCOME[state] ?? { http: 422, code: outcome.rejected };
    receipts.set(label, { label, operation, state, applies: 'operation', http, code });
    return { http, receipt: label };
  }

  // ---- client: the operation state moves only on operation receipts
  function client(operation) {
    if (!clients.has(operation)) clients.set(operation, { state: 'unknown', terminal: null, everSent: false });
    return clients.get(operation);
  }
  function observeReceipt(operation, r) {
    const c = client(operation);
    if (r.applies === 'attempt') {
      if (is('attempt-refusal-moves')) c.state = 'rejected';
      return;
    }
    if (r.state === 'accepted') {
      if (c.state === 'unknown' || is('accepted-downgrades')) c.state = 'accepted';
      return;
    }
    if (c.terminal && c.terminal !== r.label) c.state = 'inconsistent';
    else if (c.state !== 'inconsistent') {
      c.terminal = r.label;
      c.state = r.state;
    }
  }
  function observe(operation, result) {
    if (result.receipt && typeof result.receipt === 'string') observeReceipt(operation, receipts.get(result.receipt));
    else if (result.receipt) observeReceipt(operation, result.receipt);
    if (result.http === 200 && result.history) for (const label of result.history) observeReceipt(operation, receipts.get(label));
  }

  // ---- receiver steps
  const steps = {
    attempt(s) {
      attempts.set(s.attempt, s.operation);
      client(s.operation).everSent = true;
      if (s.arrived === false) return { lost: true };
      if (!consume(s.challenge)) return unauthenticated;
      const record = records.get(s.operation);
      if (s.admission !== 'allow') {
        if (is('deny-claims') && !record) records.set(s.operation, { state: 'claimed', fingerprint: s.fingerprint, revision: 1, claim: s.attempt, receipts: [], effects: 0 });
        return refusal(s.admission.deny);
      }
      if (!record) {
        const created = { state: 'claimed', fingerprint: s.fingerprint, revision: 1, claim: s.attempt, receipts: [], effects: 0 };
        records.set(s.operation, created);
        if (is('admission-completes')) {
          created.state = 'completed';
          created.claim = null;
          effected(s.operation);
          created.receipts.push(`${s.attempt}-admitted`);
          return newReceipt(s.operation, `${s.attempt}-admitted`, 'completed');
        }
        return { claimed: true };
      }
      if (record.fingerprint !== s.fingerprint && !is('no-fingerprint')) return refusal('aria.idempotency_conflict', 409);
      if (record.claim) return refusal('aria.operation_in_progress', 409);
      const label = governing(record);
      return { http: receipts.get(label).http, receipt: label };
    },

    settle(s) {
      const operation = attempts.get(s.attempt);
      const record = operation && records.get(operation);
      if (!record) return { error: 'no_claim' };
      if (record.claim !== s.attempt && !is('no-cas')) return { error: 'stale_claim' };
      record.state = typeof s.outcome === 'string' ? s.outcome : 'rejected';
      record.claim = null;
      record.uncertain = false;
      record.revision += 1;
      // A transactional effect commits with its outcome; an external one was counted when it landed.
      if (s.outcome === 'completed' && !s.external) effected(operation);
      record.receipts.push(s.receipt);
      return newReceipt(operation, s.receipt, s.outcome);
    },

    fail(s) {
      const operation = attempts.get(s.attempt);
      const record = operation && records.get(operation);
      if (!record || record.claim !== s.attempt) return { error: 'stale_claim' };
      if (s.how === 'uncertain' && !is('uncertain-releases')) {
        record.uncertain = true;
        record.revision += 1;
        return { kept: true };
      }
      release(operation, record);
      return { released: true };
    },

    reconcile(s) {
      const record = records.get(s.operation);
      if (!record) return s.committed ? { error: 'invariant_violation' } : { absent: true };
      if (record.claim) {
        if (s.committed) return { error: 'invariant_violation' };
        if (s.observed !== record.claim && !is('stale-observation')) return { error: 'stale_observation' };
        if (!record.uncertain && !is('reconcile-unmarked')) return { kept: 'active' };
        if (!s.assurance && !is('reconcile-unassured')) return { kept: 'unassured' };
        release(s.operation, record);
        return { released: true };
      }
      if (!s.committed) return { error: 'invariant_violation' };
      const label = governing(record);
      return { receipt: is('reconcile-regenerates') ? `${label}-regenerated` : label };
    },

    resume(s) {
      attempts.set(s.attempt, s.operation);
      const record = records.get(s.operation);
      if (!record || record.state !== 'accepted') return { error: 'not_accepted' };
      if (record.fingerprint !== s.fingerprint) return { error: 'fingerprint_mismatch' };
      if (record.claim && !is('resume-twice')) return { refused: 'aria.operation_in_progress' };
      if (s.admission !== 'allow') return { denied: s.admission.deny };
      record.claim = s.attempt;
      record.revision += 1;
      return { claimed: true };
    },

    effect(s) {
      effected(attempts.get(s.attempt));
      return { applied: true };
    },

    lookup(s) {
      if (!consume(s.challenge)) return unauthenticated;
      if (s.credential === 'revoked' && !is('lookup-revoked')) return { http: 403, code: 'aria.credential_revoked', signed: false };
      const record = records.get(s.operation);
      if (!record) return { http: 404, code: 'aria.operation_unknown', signed: false };
      return { http: 200, current: governing(record), history: [...record.receipts] };
    },

    'client-observe'(s) {
      receipts.set(s.receipt.label, { ...s.receipt, operation: s.operation });
      return { observed: s.receipt.label };
    },

    check(s) {
      const record = records.get(s.operation);
      return {
        effects: effects.get(s.operation) ?? 0,
        record: record?.state ?? 'absent',
        receipts: record ? [...record.receipts] : [],
        everSent: client(s.operation).everSent,
      };
    },
  };

  // Released without effect: back to no record, or to `accepted` when resumed from it.
  function release(operation, record) {
    if (record.receipts.length === 0) records.delete(operation);
    else {
      record.state = 'accepted';
      record.claim = null;
      record.uncertain = false;
      record.revision += 1;
    }
  }

  return {
    step(s) {
      const handler = steps[s.do];
      if (!handler) throw new Error(`unknown step ${s.do}`);
      const result = handler(s);
      const operation = s.operation ?? attempts.get(s.attempt);
      const delivered = s.delivered !== false && !['check', 'reconcile', 'resume', 'effect'].includes(s.do);
      if (delivered && operation) {
        if (s.do === 'client-observe') observeReceipt(operation, receipts.get(s.receipt.label));
        else observe(operation, result);
      }
      return { result, client: operation ? client(operation).state : undefined };
    },
  };
}

function equal(a, b) {
  return JSON.stringify(sortKeys(a)) === JSON.stringify(sortKeys(b));
}
function sortKeys(v) {
  if (Array.isArray(v)) return v.map(sortKeys);
  if (v && typeof v === 'object') return Object.fromEntries(Object.keys(v).sort().map((k) => [k, sortKeys(v[k])]));
  return v;
}

/** Runs one sequence; returns the failed expectations, empty when it holds. */
export async function runSequence(sequence, create) {
  const impl = await create({ issued: sequence.issued });
  const failures = [];
  for (const [index, s] of sequence.steps.entries()) {
    const { result, client } = await impl.step(s);
    if (s.expect !== undefined && !equal(result, s.expect)) {
      failures.push({ step: index + 1, do: s.do, expected: s.expect, got: result });
    }
    if (s.client !== undefined && client !== s.client) {
      failures.push({ step: index + 1, do: s.do, expected: { client: s.client }, got: { client } });
    }
  }
  return failures;
}
