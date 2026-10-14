import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { Ajv2020 } from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';
import { buildReport } from '../../test/render-fixtures.ts';
import { renderJson } from './json.ts';
import { NOT_COVERED } from './not-covered.ts';

const parse = (s: string): any => JSON.parse(s);
const schema = JSON.parse(await readFile(new URL('../../schema/findings.schema.json', import.meta.url), 'utf8'));
const ajv = new Ajv2020({ strict: true, allErrors: true });
addFormats.default(ajv);
const compiled = ajv.compile(schema);
const validate = Object.assign((d: unknown): boolean => compiled(d) as boolean, { get errors() { return compiled.errors; } });

test('rendered JSON validates against findings.schema.json and round-trips', async () => {
  const report = await buildReport([], true);
  const text = renderJson(report);
  const doc = parse(text);
  assert.ok(validate(doc), JSON.stringify(validate.errors));
  assert.equal(JSON.stringify(doc, null, 2) + '\n', text);
  assert.deepEqual(doc.findings, JSON.parse(JSON.stringify(report.findings)));
  assert.deepEqual(doc.coverage.not_covered, NOT_COVERED);
  assert.equal(doc.summary.resources_scanned, report.resources.length);
  assert.equal(doc.summary.rules_run, report.rules.length);
  const s = doc.summary.by_status;
  assert.equal(s.fail + s.not_configurable + s.unknown + s.pass + s.not_applicable, report.findings.length);
  assert.ok(s.fail > 0 && s.pass > 0 && s.unknown > 0, 'fixtures cover all three statuses');
});

test('the schema rejects a document with a missing section and an unknown status', async () => {
  const doc = parse(renderJson(await buildReport()));
  assert.equal(validate({ ...doc, coverage: undefined }), false);
  doc.findings[0].status = 'safe';
  assert.equal(validate(doc), false);
});

test('plan and aws inputs validate too', async () => {
  const base = await buildReport();
  const plan = parse(renderJson({ ...base, input: { kind: 'plan', file: 'plan.json', skipped: [{ address: 'x.y', reason: 'no config' }] } }));
  assert.ok(validate(plan), JSON.stringify(validate.errors));
  assert.equal(plan.coverage.skipped.length, 1);
  const aws = parse(renderJson({ ...base, input: { kind: 'aws', accounts: ['111111111111'], regions: ['eu-west-1'], not_checked: [{ account: '111111111111', region: 'eu-west-1', service: 'kms', reason: 'AccessDenied' }] } }));
  assert.ok(validate(aws), JSON.stringify(validate.errors));
  assert.equal(aws.coverage.not_checked.length, 1);
});
