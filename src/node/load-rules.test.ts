import test from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { loadRulesFromDir } from './load-rules.ts';

const rulesDir = fileURLToPath(new URL('../../rules/', import.meta.url));

test('every shipped rule loads, has sources with dates, and is sorted', async () => {
  const rules = await loadRulesFromDir(rulesDir);
  for (const r of rules) {
    assert.ok(r.sources.length > 0, r.id);
    for (const s of r.sources) assert.match(s.verified, /^\d{4}-\d{2}-\d{2}$/, r.id);
  }
  assert.deepEqual(rules.map((r) => r.id), [...rules.map((r) => r.id)].sort());
});
