import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { Ajv } from 'ajv';
import addFormats from 'ajv-formats';
import { renderSarif } from './sarif.ts';
import { buildReport } from '../../test/render-fixtures.ts';

const root = new URL('../../', import.meta.url).pathname;
const schema = JSON.parse(await readFile(`${root}test/schemas/sarif-2.1.0.json`, 'utf8'));
const ajv = new Ajv({ strict: false, allErrors: true });
addFormats.default(ajv);

type Sarif = { runs: { tool: { driver: { rules: { id: string; properties: { version: number } }[] } }; results: { ruleId: string; kind: string; level: string; locations: { physicalLocation?: { artifactLocation: { uri: string }; region?: { startLine: number } } }[]; partialFingerprints: { [k: string]: string } }[] }[] };

test('SARIF validates against the 2.1.0 schema and carries one rule per rule that ran', async () => {
  const report = await buildReport();
  const doc = JSON.parse(renderSarif(report)) as Sarif;
  assert.ok(ajv.validate(schema, doc), JSON.stringify(ajv.errors?.slice(0, 3)));
  const run = doc.runs[0]!;
  assert.deepEqual(run.tool.driver.rules.map((r) => r.id), report.rules.map((r) => r.id));
  assert.ok(run.tool.driver.rules.every((r) => r.properties.version >= 1));
});

test('results are the findings a person must act on, with the fingerprint and the file', async () => {
  const report = await buildReport();
  const doc = JSON.parse(renderSarif(report, { uri: (f) => `terraform/${f}`, line: (file, f) => (f.resource.address.endsWith('.defaulted') ? 7 : undefined) })) as Sarif;
  const results = doc.runs[0]!.results;
  const expected = report.findings.filter((f) => f.status === 'fail' || f.status === 'not_configurable' || f.status === 'unknown');
  assert.equal(results.length, expected.length);
  assert.ok(results.length > 0);
  for (const [i, r] of results.entries()) {
    const f = expected[i]!;
    assert.equal(r.ruleId, f.rule.id);
    assert.equal(r.kind, f.status === 'unknown' ? 'review' : 'fail');
    assert.equal(r.partialFingerprints['edgepq/v1'], f.fingerprint);
    assert.match(r.locations[0]!.physicalLocation!.artifactLocation.uri, /^terraform\//);
  }
  const located = results.find((r) => r.locations[0]!.physicalLocation!.region);
  assert.equal(located?.locations[0]!.physicalLocation!.region!.startLine, 7);
  assert.ok(results.every((r) => ['error', 'warning', 'note'].includes(r.level)));
  /* No pass is listed: the findings JSON has those. */
  assert.ok(!results.some((r) => r.kind === 'pass'));
});

test('output never claims safety or compliance', async () => {
  const s = renderSarif(await buildReport());
  assert.doesNotMatch(s, /quantum[- ]safe|compliant/i);
});
